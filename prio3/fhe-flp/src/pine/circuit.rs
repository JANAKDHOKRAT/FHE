//! PINE's two validity circuits and its measurement encoding, over
//! FieldPrio2 (PINE's `Field32`), following the reference implementation
//! `draft-chen-cfrg-vdaf-pine` at commit 4d11ac8 (`poc/flp_pine.py`).
//!
//! * [`NormEquality`]: the claimed squared L2 norm equals the squared norm
//!   of the gradient, as field elements. No joint randomness.
//! * [`Main`]: every claimed bit is a bit, the claimed squared norm is in
//!   `[0, B^2]`, and the wraparound tests: each reported dot product of the
//!   gradient with a random `{-1, 0, 1}` vector is in range, so that the
//!   field equality of [`NormEquality`] holds over the integers.
//!
//! Both are prio [`Flp`]s: proving, querying and deciding are prio's
//! unchanged code. `tests/pine_upstream.rs` checks the encoding, the
//! wraparound tests and both circuits against the reference test vectors.
//!
//! [`NormEquality::linear_map`] and [`Main::linear_map`] give the verifier
//! as an affine map of `(input, proof)` in closed form;
//! [`check_linear_map`] compares it with prio's `query`.
use crate::protocol::{from_u64, to_u64};
use crate::{Error, Field, PLAIN_MOD, Result};
use prio::field::{FieldElement, FieldElementWithInteger, NttFriendlyFieldElement};
use prio::flp::gadgets::{Mul, ParallelSum, ParallelSumGadget, PolyEval};
use prio::flp::{Flp, FlpError, Gadget};
use rand_core::Rng;

/// The reference parameters (`ALPHA`, `NUM_WR_CHECKS`, `NUM_WR_SUCCESSES`).
pub const ALPHA: f64 = 8.7;
pub const NUM_WR_CHECKS: usize = 100;
pub const NUM_WR_SUCCESSES: usize = 100;

/// What both circuits share: the lengths and bounds of an encoded
/// measurement `gradient || v bits || u bits || (wr bits, success bit) * r`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shape {
    dimension: usize,
    l2_norm_bound: u64,
    num_frac_bits: u32,
    norm_bits: usize,
    wr_bound: u64,
    wr_bits: usize,
}

impl Shape {
    /// `l2_norm_bound` bounds the norm of the encoded (integer) gradient:
    /// a real bound `b` with `num_frac_bits` fractional bits is
    /// `b * 2^num_frac_bits`. The reference's field-size requirements are
    /// enforced.
    pub fn new(dimension: usize, l2_norm_bound: u64, num_frac_bits: u32) -> Result<Self> {
        let err = |m: &str| Error::Flp(format!("PINE parameters: {m}"));
        let p = PLAIN_MOD as u128;
        let b = l2_norm_bound as u128;
        if dimension == 0 {
            return Err(err("the dimension must be positive"));
        }
        if num_frac_bits >= 128 {
            return Err(err("at most 127 fractional bits"));
        }
        if b == 0 || 2 * b > p || b * b >= p {
            return Err(err("the squared L2-norm bound must be positive and below the field modulus"));
        }
        let sq = b * b;
        // Range check of the squared norm ([ROCT23] Figure 1): q > 3 B^2 + 2.
        if p - 2 <= 3 * sq {
            return Err(err("the norm range check needs p > 3 B^2 + 2"));
        }
        // The smallest power of 2 that is at least ceil(alpha * B) + 1,
        // computed in binary64 as the reference computes it.
        let wr = ((ALPHA * l2_norm_bound as f64).ceil() as u128 + 1).next_power_of_two();
        // [ROCT23] Lemma 3.3: q >= max(wr^2 / 4000, 2600 wr, 2 r).
        if p < 2 * NUM_WR_CHECKS as u128 || p < 2600 * wr || wr * wr > 4000 * p {
            return Err(err("the wraparound check needs p >= max(wr^2 / 4000, 2600 wr, 2 r)"));
        }
        Ok(Self {
            dimension,
            l2_norm_bound,
            num_frac_bits,
            norm_bits: (128 - sq.leading_zeros()) as usize,
            wr_bound: wr as u64,
            wr_bits: (128 - (2 * wr - 1).leading_zeros()) as usize,
        })
    }

    pub fn dimension(&self) -> usize {
        self.dimension
    }
    pub fn l2_norm_bound(&self) -> u64 {
        self.l2_norm_bound
    }
    pub fn num_frac_bits(&self) -> u32 {
        self.num_frac_bits
    }
    /// Bits of each of the two range-checked values of the squared norm.
    pub fn norm_bits(&self) -> usize {
        self.norm_bits
    }
    pub fn wr_bound(&self) -> u64 {
        self.wr_bound
    }
    /// Bits of one range-checked wraparound test result.
    pub fn wr_bits(&self) -> usize {
        self.wr_bits
    }
    /// `gradient || v bits || u bits`: what fixes the wraparound tests.
    pub fn gradient_and_norm_len(&self) -> usize {
        self.dimension + 2 * self.norm_bits
    }
    /// The bit-checked part: the norm bits and, per wraparound test, the
    /// result bits and the success bit.
    pub fn bit_checked_len(&self) -> usize {
        2 * self.norm_bits + (self.wr_bits + 1) * NUM_WR_CHECKS
    }
    /// What a client sends: gradient and bit-checked part.
    pub fn meas_len(&self) -> usize {
        self.dimension + self.bit_checked_len()
    }
    /// What the circuits read: the measurement and the dot products of the
    /// wraparound tests, which the verifier computes from the gradient.
    pub fn input_len(&self) -> usize {
        self.meas_len() + NUM_WR_CHECKS
    }
    /// Index of wraparound test `i`'s result bits in the measurement.
    fn wr_start(&self, i: usize) -> usize {
        self.dimension + 2 * self.norm_bits + i * (self.wr_bits + 1)
    }

    /// The reference's `encode_float`: `round(x * 2^num_frac_bits)` with
    /// ties to even, NaN, infinities and subnormals refused. Also refused:
    /// a coordinate beyond the norm bound (no valid report contains it).
    pub fn encode_gradient(&self, measurement: &[f64]) -> Result<Vec<i64>> {
        if measurement.len() != self.dimension {
            return Err(Error::Flp("unexpected gradient dimension".into()));
        }
        let scale = 2f64.powi(self.num_frac_bits as i32);
        measurement
            .iter()
            .map(|&x| {
                if !x.is_finite() || (x != 0.0 && x.abs() < f64::MIN_POSITIVE) {
                    return Err(Error::Flp("NaN, infinite and subnormal floats are refused".into()));
                }
                let q = (x * scale).round_ties_even();
                if q.abs() > self.l2_norm_bound as f64 {
                    return Err(Error::Flp("a coordinate exceeds the L2-norm bound".into()));
                }
                Ok(q as i64)
            })
            .collect()
    }

    /// `gradient || v bits || u bits` with `v = |g|^2` and `u = B^2 - |g|^2`
    /// over the integers. A gradient whose encoded norm exceeds the bound is
    /// refused: clip before encoding.
    pub fn encode_gradient_and_norm(&self, measurement: &[f64]) -> Result<Vec<Field>> {
        let q = self.encode_gradient(measurement)?;
        let sq_bound = (self.l2_norm_bound as u128) * (self.l2_norm_bound as u128);
        let sq: u128 = q.iter().map(|&x| (x as i128 * x as i128) as u128).sum();
        if sq > sq_bound {
            return Err(Error::Flp("the encoded gradient exceeds the L2-norm bound".into()));
        }
        let mut out: Vec<Field> = q.iter().map(|&x| signed(x)).collect();
        out.extend(bits(sq as u64, self.norm_bits));
        out.extend(bits((sq_bound - sq) as u64, self.norm_bits));
        Ok(out)
    }

    /// The `{-1, 0, 1}` vectors of the wraparound tests, test after test:
    /// two bits of the stream per coordinate, `00 -> -1`, `01, 10 -> 0`,
    /// `11 -> 1`, four coordinates per byte, a fresh byte for every test's
    /// first coordinate (the reference's `run_wr_checks`).
    pub fn wr_vectors<S: Rng>(&self, stream: &mut S) -> Vec<i8> {
        let d = self.dimension;
        let mut out = Vec::with_capacity(NUM_WR_CHECKS * d);
        let mut buf = vec![0u8; d.div_ceil(4)];
        for _ in 0..NUM_WR_CHECKS {
            stream.fill_bytes(&mut buf);
            for k in 0..d {
                out.push(match buf[k / 4] >> (2 * (k % 4)) & 3 {
                    0 => -1,
                    3 => 1,
                    _ => 0,
                });
            }
        }
        out
    }

    /// The dot product of the gradient with each test vector.
    pub fn wr_results(&self, gradient: &[Field], vectors: &[i8]) -> Vec<Field> {
        vectors
            .chunks(self.dimension)
            .map(|v| {
                let mut s = Field::zero();
                for (&g, &c) in gradient.iter().zip(v) {
                    match c {
                        1 => s += g,
                        -1 => s -= g,
                        _ => {}
                    }
                }
                s
            })
            .collect()
    }

    /// The bit-checked wraparound part of a measurement and the dot
    /// products. A test passes when its dot product is in
    /// `[-wr_bound + 1, wr_bound]`; all tests must pass
    /// (`NUM_WR_SUCCESSES = NUM_WR_CHECKS`), otherwise `None`: the client retries
    /// with other test vectors.
    pub fn encode_wr_checks(&self, gradient: &[Field], vectors: &[i8]) -> Option<(Vec<Field>, Vec<Field>)> {
        let results = self.wr_results(gradient, vectors);
        let mut out = Vec::with_capacity((self.wr_bits + 1) * NUM_WR_CHECKS);
        for &r in &results {
            let v = to_u64(r + from_u64(self.wr_bound - 1));
            if v > 2 * self.wr_bound - 1 {
                return None;
            }
            out.extend(bits(v, self.wr_bits));
            out.push(Field::one());
        }
        Some((out, results))
    }

    /// The reference's `decode`: centered lift divided by `2^num_frac_bits`.
    pub fn decode(&self, output: &[Field]) -> Vec<f64> {
        let scale = 2f64.powi(self.num_frac_bits as i32);
        output
            .iter()
            .map(|&x| {
                let v = to_u64(x);
                let centered = if v > PLAIN_MOD / 2 { -((PLAIN_MOD - v) as f64) } else { v as f64 };
                centered / scale
            })
            .collect()
    }
}

fn signed(x: i64) -> Field {
    if x >= 0 { from_u64(x as u64) } else { -from_u64(x.unsigned_abs()) }
}

fn bits(v: u64, n: usize) -> impl Iterator<Item = Field> {
    (0..n).map(move |j| from_u64(v >> j & 1))
}

fn decode_bits(b: &[Field]) -> Field {
    let mut weight = Field::one();
    let mut v = Field::zero();
    for &x in b {
        v += x * weight;
        weight += weight;
    }
    v
}

/// Sum of the gadget over `values` cut into chunks of the gadget's arity,
/// the last one padded with zeros (the reference's `parallel_sum`).
fn parallel_sum(g: &mut [Box<dyn Gadget<Field>>], arity: usize, values: &[Field]) -> std::result::Result<Field, FlpError> {
    let mut sum = Field::zero();
    let mut padded = vec![Field::zero(); arity];
    for block in values.chunks(arity) {
        padded[..block.len()].copy_from_slice(block);
        padded[block.len()..].fill(Field::zero());
        sum += g[0].eval(&padded)?;
    }
    Ok(sum)
}

fn share_inverse(num_shares: usize) -> std::result::Result<Field, FlpError> {
    if num_shares == 0 || num_shares as u64 >= PLAIN_MOD {
        return Err(FlpError::InvalidParameter("invalid share count".into()));
    }
    Ok(from_u64(num_shares as u64).inv())
}

fn check_chunk(chunk: usize) -> Result<()> {
    if chunk == 0 {
        return Err(Error::Flp("PINE parameters: the chunk length must be positive".into()));
    }
    Ok(())
}

/// The reference's `PineValidNormEquality`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormEquality {
    shape: Shape,
    chunk: usize,
}

impl NormEquality {
    pub fn new(shape: Shape, chunk: usize) -> Result<Self> {
        check_chunk(chunk)?;
        Ok(Self { shape, chunk })
    }
    pub fn shape(&self) -> &Shape {
        &self.shape
    }
    fn calls(&self) -> usize {
        self.shape.dimension.div_ceil(self.chunk)
    }

    /// The verifier `query(input, proof, [t], [], 1)` as rows over
    /// `input || proof` and constants.
    pub fn linear_map(&self, t: Field) -> Result<Affine> {
        let s = &self.shape;
        let dom = Domain::new(self.calls(), t)?;
        let (il, a) = (self.input_len(), self.chunk);
        let mut m = Affine::zero(self.verifier_len(), il + self.proof_len());
        // Output: v - sum of the gadget outputs.
        for j in 0..s.norm_bits {
            m.rows[0][s.dimension + j] = from_u64(1 << j);
        }
        for k in 1..=self.calls() {
            m.rows[0][il + a + 2 * k] = -Field::one();
        }
        // Wire j of call k reads gradient coordinate (k - 1) * chunk + j.
        for i in 0..s.dimension {
            m.rows[1 + i % a][i] = dom.lagrange[i / a + 1];
        }
        dom.proof_rows(&mut m, il, a);
        Ok(m)
    }
}

impl Flp for NormEquality {
    type Field = Field;
    fn gadget(&self) -> Vec<Box<dyn Gadget<Field>>> {
        vec![Box::new(ParallelSum::new(
            PolyEval::new(vec![Field::zero(), Field::zero(), Field::one()], self.calls()),
            self.chunk,
        ))]
    }
    fn num_gadgets(&self) -> usize {
        1
    }
    fn input_len(&self) -> usize {
        self.shape.input_len()
    }
    fn proof_len(&self) -> usize {
        self.chunk + 2 * ((self.calls() + 1).next_power_of_two() - 1) + 1
    }
    fn verifier_len(&self) -> usize {
        self.chunk + 2
    }
    fn joint_rand_len(&self) -> usize {
        0
    }
    fn eval_output_len(&self) -> usize {
        1
    }
    fn prove_rand_len(&self) -> usize {
        self.chunk
    }
    fn valid(
        &self,
        g: &mut Vec<Box<dyn Gadget<Field>>>,
        input: &[Field],
        joint_rand: &[Field],
        _num_shares: usize,
    ) -> std::result::Result<Vec<Field>, FlpError> {
        self.valid_call_check(input, joint_rand)?;
        let s = &self.shape;
        let computed = parallel_sum(g, self.chunk, &input[..s.dimension])?;
        Ok(vec![decode_bits(&input[s.dimension..s.dimension + s.norm_bits]) - computed])
    }
}

/// The reference's `PineValid`: every check but the norm equality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Main {
    shape: Shape,
    chunk: usize,
}

impl Main {
    pub fn new(shape: Shape, chunk: usize) -> Result<Self> {
        check_chunk(chunk)?;
        Ok(Self { shape, chunk })
    }
    pub fn shape(&self) -> &Shape {
        &self.shape
    }
    fn bit_calls(&self) -> usize {
        self.shape.bit_checked_len().div_ceil(self.chunk)
    }
    fn calls(&self) -> usize {
        self.bit_calls() + NUM_WR_CHECKS.div_ceil(self.chunk)
    }
    /// Degree of the circuit output in the joint randomness: the bit checks
    /// in `r_bit`, the wraparound checks in `r_wr`, then the cubic in
    /// `r_final`. An invalid input passes a random point with probability at
    /// most `(bit_checked_len - 1 + NUM_WR_CHECKS - 1 + 3) / p` (union bound
    /// over the three Schwartz-Zippel steps).
    pub fn joint_rand_degree(&self) -> usize {
        self.shape.bit_checked_len() + NUM_WR_CHECKS + 1
    }

    /// The verifier `query(input, proof, [t], joint_rand, 1)` as rows over
    /// `input || proof` and constants.
    pub fn linear_map(&self, t: Field, joint_rand: &[Field]) -> Result<Affine> {
        let [r_bit, r_wr, r_final] = joint_rand else {
            return Err(Error::Flp("the main circuit takes 3 joint random elements".into()));
        };
        let s = &self.shape;
        let c = self.chunk;
        let dom = Domain::new(self.calls(), t)?;
        let (il, a) = (self.input_len(), 2 * c);
        let mut m = Affine::zero(self.verifier_len(), il + self.proof_len());
        let (d, nb, wb) = (s.dimension, s.norm_bits, s.wr_bits);

        // Output: bit checks + r (v + u - B^2) + r^2 wraparound checks + r^3 (successes - tau).
        let r2 = *r_final * *r_final;
        let r3 = r2 * *r_final;
        for k in 1..=self.calls() {
            m.rows[0][il + a + 2 * k] = if k <= self.bit_calls() { Field::one() } else { r2 };
        }
        for j in 0..nb {
            m.rows[0][d + j] = *r_final * from_u64(1 << j);
            m.rows[0][d + nb + j] = *r_final * from_u64(1 << j);
        }
        m.constants[0] = -(*r_final * from_u64(s.l2_norm_bound * s.l2_norm_bound)) - r3 * from_u64(NUM_WR_SUCCESSES as u64);

        // Bit checks: call i / c + 1 multiplies r_bit^i x_i by (x_i - 1).
        let mut power = Field::one();
        for i in 0..s.bit_checked_len() {
            let l = dom.lagrange[i / c + 1];
            let w = 1 + 2 * (i % c);
            m.rows[w][d + i] = l * power;
            m.rows[w + 1][d + i] = l;
            m.constants[w + 1] -= l;
            power *= *r_bit;
        }
        // Wraparound checks: r_wr^i (dot_i - (v_i - (wr_bound - 1))) times the success bit.
        power = Field::one();
        for i in 0..NUM_WR_CHECKS {
            m.rows[0][s.wr_start(i) + wb] = r3;
            let l = dom.lagrange[self.bit_calls() + i / c + 1];
            let w = 1 + 2 * (i % c);
            let lp = l * power;
            // The result and success bits are bit-checked too: these wires
            // already read them in the bit-check calls, so add.
            m.rows[w][s.meas_len() + i] = lp;
            for j in 0..wb {
                m.rows[w][s.wr_start(i) + j] -= lp * from_u64(1 << j);
            }
            m.constants[w] += lp * from_u64(s.wr_bound - 1);
            m.rows[w + 1][s.wr_start(i) + wb] += l;
            power *= *r_wr;
        }
        dom.proof_rows(&mut m, il, a);
        Ok(m)
    }
}

impl Flp for Main {
    type Field = Field;
    fn gadget(&self) -> Vec<Box<dyn Gadget<Field>>> {
        vec![Box::new(ParallelSum::new(Mul::new(self.calls()), self.chunk))]
    }
    fn num_gadgets(&self) -> usize {
        1
    }
    fn input_len(&self) -> usize {
        self.shape.input_len()
    }
    fn proof_len(&self) -> usize {
        2 * self.chunk + 2 * ((self.calls() + 1).next_power_of_two() - 1) + 1
    }
    fn verifier_len(&self) -> usize {
        2 * self.chunk + 2
    }
    fn joint_rand_len(&self) -> usize {
        3
    }
    fn eval_output_len(&self) -> usize {
        1
    }
    fn prove_rand_len(&self) -> usize {
        2 * self.chunk
    }
    fn valid(
        &self,
        g: &mut Vec<Box<dyn Gadget<Field>>>,
        input: &[Field],
        joint_rand: &[Field],
        num_shares: usize,
    ) -> std::result::Result<Vec<Field>, FlpError> {
        self.valid_call_check(input, joint_rand)?;
        let inv = share_inverse(num_shares)?;
        let s = &self.shape;
        let (d, nb, wb) = (s.dimension, s.norm_bits, s.wr_bits);
        let (r_bit, r_wr, r_final) = (joint_rand[0], joint_rand[1], joint_rand[2]);

        let mut mul_inputs = Vec::with_capacity(2 * s.bit_checked_len());
        let mut power = Field::one();
        for &x in &input[d..d + s.bit_checked_len()] {
            mul_inputs.extend([power * x, x - inv]);
            power *= r_bit;
        }
        let bit_checks = parallel_sum(g, 2 * self.chunk, &mul_inputs)?;

        mul_inputs.clear();
        let mut success_count = Field::zero();
        power = Field::one();
        for i in 0..NUM_WR_CHECKS {
            let start = s.wr_start(i);
            let computed = decode_bits(&input[start..start + wb]) - from_u64(s.wr_bound - 1) * inv;
            let success = input[start + wb];
            mul_inputs.extend([power * (input[s.meas_len() + i] - computed), success]);
            success_count += success;
            power *= r_wr;
        }
        let wr_checks = parallel_sum(g, 2 * self.chunk, &mul_inputs)?;

        let norm_range = decode_bits(&input[d..d + nb]) + decode_bits(&input[d + nb..d + 2 * nb]) - from_u64(s.l2_norm_bound * s.l2_norm_bound) * inv;
        let success_check = success_count - from_u64(NUM_WR_SUCCESSES as u64) * inv;
        Ok(vec![
            bit_checks + r_final * norm_range + r_final * r_final * wr_checks + r_final * r_final * r_final * success_check,
        ])
    }
}

/// A verifier as `rows[i] . (input || proof) + constants[i]`.
pub struct Affine {
    pub rows: Vec<Vec<Field>>,
    pub constants: Vec<Field>,
}

impl Affine {
    fn zero(rows: usize, len: usize) -> Self {
        Self {
            rows: vec![vec![Field::zero(); len]; rows],
            constants: vec![Field::zero(); rows],
        }
    }
    pub fn apply(&self, z: &[Field]) -> Vec<Field> {
        self.rows
            .iter()
            .zip(&self.constants)
            .map(|(row, &c)| row.iter().zip(z).fold(c, |acc, (&a, &b)| acc + a * b))
            .collect()
    }
}

/// The evaluation weights of prio's proof encoding for a gadget of degree 2
/// with `calls` calls, at the query point `t`.
///
/// prio (VDAF draft 18) keeps polynomials by their values: a wire polynomial
/// by its values at the `P`-th roots of unity `alpha^k` (`P` the next power
/// of 2 above `calls`; value 0 is the wire seed, value `k` the wire's input
/// in call `k`), and the gadget polynomial, of degree at most `2 (P - 1)`,
/// by its values at `omega^i`, `i < 2 P - 1`, `omega^2 = alpha`. So the
/// gadget's output in call `k` is the proof element at `2 k`.
struct Domain {
    /// `L_k(t)`, `k = 0 ..= calls`: the wire polynomial at `t` is
    /// `sum_k value_k L_k(t)`.
    lagrange: Vec<Field>,
    /// `w_i(t)`, `i < 2 P - 1`: the gadget polynomial at `t` is
    /// `sum_i value_i w_i(t)`.
    gadget: Vec<Field>,
}

impl Domain {
    fn new(calls: usize, t: Field) -> Result<Self> {
        let p_len = (calls + 1).next_power_of_two();
        let s = 2 * p_len;
        let omega = Field::root(s.trailing_zeros() as usize).ok_or_else(|| Error::Flp(format!("the field has no root of unity of order {s}")))?;
        let t_p = t.pow(p_len as u32);
        let t_s = t_p * t_p;
        if t_s == Field::one() {
            return Err(Error::Flp("the query point is a root of unity of the proof's domain".into()));
        }
        let mut x = Vec::with_capacity(s);
        let mut cur = Field::one();
        for _ in 0..s {
            x.push(cur);
            cur *= omega;
        }
        // 1 / (t - x_i), all at once: prefix products, one inversion.
        let diffs: Vec<Field> = x.iter().map(|&xi| t - xi).collect();
        let mut prefix = Vec::with_capacity(s);
        let mut acc = Field::one();
        for &dv in &diffs {
            prefix.push(acc);
            acc *= dv;
        }
        let mut inv_acc = acc.inv();
        let mut inv = vec![Field::zero(); s];
        for i in (0..s).rev() {
            inv[i] = inv_acc * prefix[i];
            inv_acc *= diffs[i];
        }
        // Over all P-th roots: L_k(t) = alpha^k (t^P - 1) / (P (t - alpha^k)).
        let cw = (t_p - Field::one()) * from_u64(p_len as u64).inv();
        let lagrange = (0..=calls).map(|k| cw * x[2 * k] * inv[2 * k]).collect();
        // Over the first S - 1 of the S-th roots (barycentric weights from
        // prod_{j != i, j < S} (x_i - x_j) = S / x_i):
        // w_i(t) = (t^S - 1) x_i (x_i - x_{S-1}) / (S (t - x_{S-1}) (t - x_i)).
        let cg = (t_s - Field::one()) * from_u64(s as u64).inv() * inv[s - 1];
        let gadget = (0..s - 1).map(|i| cg * x[i] * (x[i] - x[s - 1]) * inv[i]).collect();
        Ok(Self { lagrange, gadget })
    }

    /// The rows' proof part: the wire seeds and the gadget polynomial at `t`.
    fn proof_rows(&self, m: &mut Affine, input_len: usize, arity: usize) {
        for w in 0..arity {
            m.rows[1 + w][input_len + w] = self.lagrange[0];
        }
        m.rows[1 + arity][input_len + arity..].copy_from_slice(&self.gadget);
    }
}

/// Compares a closed-form verifier map with prio's `query` at `z = input ||
/// proof`. Used with random `z` and randomness when a task is created and in
/// the tests.
pub fn check_linear_map<T: Flp<Field = Field>>(typ: &T, map: &Affine, z: &[Field], t: Field, joint_rand: &[Field]) -> Result<()> {
    let il = typ.input_len();
    if map.apply(z) != typ.query(&z[..il], &z[il..], &[t], joint_rand, 1)? {
        return Err(Error::Flp("the closed-form verifier map disagrees with prio's query".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prio::vdaf::xof::{IntoFieldVec, Xof, XofTurboShake128};

    fn stream(tag: u8) -> impl Rng {
        XofTurboShake128::seed_stream(&[tag; 32], &[b"pine circuit tests"], &[])
    }

    /// An honest input `measurement || dot products` for `floats`.
    fn honest(shape: &Shape, floats: &[f64], tag: u8) -> Vec<Field> {
        let mut input = shape.encode_gradient_and_norm(floats).unwrap();
        let vectors = shape.wr_vectors(&mut stream(tag));
        let (wr_bits, results) = shape.encode_wr_checks(&input[..shape.dimension], &vectors).unwrap();
        input.extend(wr_bits);
        input.extend(results);
        input
    }

    #[test]
    fn parameters_outside_the_reference_guards_are_refused() {
        assert!(Shape::new(0, 16, 4).is_err());
        assert!(Shape::new(3, 0, 4).is_err());
        // p > 3 B^2 + 2 fails from B = 37833 on.
        assert!(Shape::new(3, 37832, 4).is_ok());
        assert!(Shape::new(3, 37833, 4).is_err());
        assert!(Shape::new(3, 65536, 4).is_err());
        let s = Shape::new(20, 128, 7).unwrap();
        // The reference's test vector 0: 15 norm bits, wr_bound 2048, 12 result bits.
        assert_eq!((s.norm_bits, s.wr_bound, s.wr_bits, s.meas_len()), (15, 2048, 12, 1350));
        assert!(Main::new(s.clone(), 0).is_err());
        assert!(NormEquality::new(s, 0).is_err());
    }

    #[test]
    fn encoding_rounds_to_even_and_refuses_what_the_reference_refuses() {
        let s = Shape::new(4, 128, 2).unwrap();
        // 0.125 * 4 = 0.5 -> 0, 0.375 * 4 = 1.5 -> 2, -0.625 * 4 = -2.5 -> -2.
        assert_eq!(s.encode_gradient(&[0.125, 0.375, -0.625, 1.0]).unwrap(), vec![0, 2, -2, 4]);
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, f64::MIN_POSITIVE / 2.0] {
            assert!(s.encode_gradient(&[bad, 0.0, 0.0, 0.0]).is_err());
        }
        assert!(s.encode_gradient(&[0.0; 3]).is_err());
        // Norm exactly at the bound is accepted, one step beyond is refused.
        assert!(s.encode_gradient_and_norm(&[32.0, 0.0, 0.0, 0.0]).is_ok());
        assert!(s.encode_gradient_and_norm(&[32.0, 0.25, 0.0, 0.0]).is_err());
        assert!(s.encode_gradient_and_norm(&[32.25, 0.0, 0.0, 0.0]).is_err());
        let enc = s.encode_gradient_and_norm(&[-1.0, 0.5, 0.0, 0.0]).unwrap();
        assert_eq!(enc[0], -from_u64(4));
        assert_eq!(s.decode(&enc[..4]), vec![-1.0, 0.5, 0.0, 0.0]);
    }

    #[test]
    fn wraparound_vectors_have_the_reference_distribution_and_layout() {
        let s = Shape::new(1001, 128, 2).unwrap();
        let v = s.wr_vectors(&mut stream(1));
        assert_eq!(v.len(), NUM_WR_CHECKS * 1001);
        let ones = v.iter().filter(|&&c| c == 1).count() as f64 / v.len() as f64;
        let minus = v.iter().filter(|&&c| c == -1).count() as f64 / v.len() as f64;
        assert!((ones - 0.25).abs() < 0.01 && (minus - 0.25).abs() < 0.01, "{ones} {minus}");
        // Each test starts on a fresh byte: 251 bytes per test for d = 1001.
        let mut raw = vec![0u8; 251 * 2];
        stream(1).fill_bytes(&mut raw);
        assert_eq!(v[1001], [-1i8, 0, 0, 1][(raw[251] & 3) as usize]);
    }

    #[test]
    fn honest_inputs_satisfy_both_circuits_and_each_violation_is_caught() {
        let shape = Shape::new(9, 128, 4).unwrap();
        let floats = [1.5, -2.25, 0.0, 3.0, -0.5, 0.75, 4.0, -1.0, 2.0];
        let x = honest(&shape, &floats, 2);
        let jr: Vec<Field> = stream(3).into_field_vec(3);
        let zero = vec![Field::zero()];
        for chunk in [1, 5, 150] {
            let (ne, main) = (NormEquality::new(shape.clone(), chunk).unwrap(), Main::new(shape.clone(), chunk).unwrap());
            assert_eq!(ne.valid(&mut ne.gadget(), &x, &[], 1).unwrap(), zero);
            assert_eq!(main.valid(&mut main.gadget(), &x, &jr, 1).unwrap(), zero);
            let (d, nb, ml) = (shape.dimension, shape.norm_bits, shape.meas_len());
            // A gradient coordinate that no longer matches the claimed norm.
            let mut bad = x.clone();
            bad[0] += Field::one();
            assert_ne!(ne.valid(&mut ne.gadget(), &bad, &[], 1).unwrap(), zero);
            // A non-bit, v + u != B^2, a wrong result bit, a cleared success
            // bit, a dot product that is not the claimed one.
            for (i, delta) in [
                (d, from_u64(2)),
                (d + 1, Field::one()),
                (d + nb, Field::one()),
                (shape.wr_start(7), Field::one()),
                (shape.wr_start(7) + shape.wr_bits, -Field::one()),
                (ml + 99, Field::one()),
            ] {
                let mut bad = x.clone();
                bad[i] += delta;
                assert_ne!(main.valid(&mut main.gadget(), &bad, &jr, 1).unwrap(), zero, "chunk {chunk} index {i}");
            }
        }
    }

    /// A gradient whose squared norm is `B^2 + p` over the integers has the
    /// field norm `B^2`: the norm checks alone accept it. Its wraparound
    /// tests leave the range, so the client cannot claim them all.
    #[test]
    fn a_norm_that_wraps_the_field_fails_the_wraparound_tests() {
        let shape = Shape::new(64, 128, 0).unwrap();
        // 64 coordinates of 8191 and one adjusted: |g|^2 = 128^2 mod p is not
        // needed exactly; any huge vector fails the range of the dot products.
        let gradient: Vec<Field> = (0..64).map(|i| from_u64(8191 + i)).collect();
        let vectors = shape.wr_vectors(&mut stream(4));
        assert!(shape.encode_wr_checks(&gradient, &vectors).is_none());
    }

    #[test]
    fn closed_form_verifier_maps_agree_with_prio_query() {
        let mut s = stream(5);
        for (d, bound, chunks) in [(3usize, 16u64, vec![1, 2, 7]), (20, 128, vec![4, 150]), (300, 1024, vec![3, 64])] {
            let shape = Shape::new(d, bound, 3).unwrap();
            for chunk in chunks {
                let ne = NormEquality::new(shape.clone(), chunk).unwrap();
                let main = Main::new(shape.clone(), chunk).unwrap();
                for _ in 0..3 {
                    let r: Vec<Field> = (&mut s).into_field_vec(4);
                    let z: Vec<Field> = (&mut s).into_field_vec(ne.input_len() + ne.proof_len());
                    check_linear_map(&ne, &ne.linear_map(r[0]).unwrap(), &z, r[0], &[]).unwrap();
                    let z: Vec<Field> = (&mut s).into_field_vec(main.input_len() + main.proof_len());
                    check_linear_map(&main, &main.linear_map(r[0], &r[1..]).unwrap(), &z, r[0], &r[1..]).unwrap();
                }
                // Roots of unity of the proof's domain are refused, as prio refuses them.
                assert!(ne.linear_map(Field::one()).is_err());
                assert!(main.linear_map(-Field::one(), &[Field::one(); 3]).is_err());
            }
        }
    }

    #[test]
    fn prio_proves_and_decides_both_circuits() {
        let shape = Shape::new(9, 128, 4).unwrap();
        let x = honest(&shape, &[1.5, -2.25, 0.0, 3.0, -0.5, 0.75, 4.0, -1.0, 2.0], 6);
        let mut s = stream(7);
        let (ne, main) = (NormEquality::new(shape.clone(), 4).unwrap(), Main::new(shape.clone(), 150).unwrap());
        let jr: Vec<Field> = (&mut s).into_field_vec(3);
        let t: Vec<Field> = (&mut s).into_field_vec(1);
        let pr: Vec<Field> = (&mut s).into_field_vec(ne.prove_rand_len());
        let proof = ne.prove(&x, &pr, &[]).unwrap();
        assert!(ne.decide(&ne.query(&x, &proof, &t, &[], 1).unwrap()).unwrap());
        let pr: Vec<Field> = (&mut s).into_field_vec(main.prove_rand_len());
        let proof = main.prove(&x, &pr, &jr).unwrap();
        assert!(main.decide(&main.query(&x, &proof, &t, &jr, 1).unwrap()).unwrap());
        let mut bad = x.clone();
        bad[shape.dimension] += Field::one();
        assert!(!main.decide(&main.query(&bad, &proof, &t, &jr, 1).unwrap()).unwrap());
    }
}
