//! PINE arithmetic circuits. No protocol/release API: challenge binding is required.
//! Source: draft-chen reference 4d11ac8, poc/flp_pine.py.
use prio::field::FieldElement;
use prio::field::FieldPrio2 as F;
use prio::flp::gadgets::{Mul, ParallelSum, ParallelSumGadget, PolyEval};
use prio::flp::{Flp, FlpError, Gadget};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Circuit {
    dimension: usize,
    bound: u32,
    checks: usize,
    successes: usize,
    wrap: u32,
    norm_bits: usize,
    wrap_bits: usize,
    norm_only: bool,
    chunk: usize,
}
impl Circuit {
    pub fn new(
        dimension: usize,
        bound: u32,
        checks: usize,
        successes: usize,
        norm_only: bool,
    ) -> Result<Self, FlpError> {
        Self::with_chunk(dimension, bound, checks, successes, norm_only, 1)
    }
    pub fn with_chunk(
        dimension: usize,
        bound: u32,
        checks: usize,
        successes: usize,
        norm_only: bool,
        chunk: usize,
    ) -> Result<Self, FlpError> {
        let error = || FlpError::InvalidParameter("unsupported PINE parameters".into());
        if dimension > 1_000_000
            || checks > 1_000_000
            || chunk == 0
            || chunk > 4096
            || dimension == 0
            || bound == 0
            || checks == 0
            || successes == 0
            || successes > checks
        {
            return Err(error());
        }
        let p = 4293918721u128;
        let b = bound as u128;
        let ceil = (87 * b).div_ceil(10);
        let wrap = (ceil + 1).next_power_of_two();
        if p <= 3 * b * b + 2 || p < 2600 * wrap || wrap * wrap > 4000 * p || p < 2 * checks as u128
        {
            return Err(error());
        }
        let norm_bits = (128 - (b * b).leading_zeros()) as usize;
        let wrap_bits = (128 - (2 * wrap - 1).leading_zeros()) as usize;
        let s = Self {
            dimension,
            bound,
            checks,
            successes,
            wrap: wrap as u32,
            norm_bits,
            wrap_bits,
            norm_only,
            chunk,
        };
        // Bound allocations and the 2W interpolation domain supported by FieldPrio2.
        if s.input_len() > 1_000_000 || 2 * (s.calls() + 1).next_power_of_two() > 1 << 20 {
            return Err(error());
        }
        Ok(s)
    }
    fn bit_len(&self) -> usize {
        2 * self.norm_bits + (self.wrap_bits + 1) * self.checks
    }
    fn calls(&self) -> usize {
        if self.norm_only {
            self.dimension.div_ceil(self.chunk)
        } else {
            self.bit_len().div_ceil(self.chunk) + self.checks.div_ceil(self.chunk)
        }
    }
    fn arity(&self) -> usize {
        self.chunk * if self.norm_only { 1 } else { 2 }
    }
    fn sum_gadget(&self, g: &mut [Box<dyn Gadget<F>>], values: &[F]) -> Result<F, FlpError> {
        let mut sum = F::zero();
        for block in values.chunks(self.arity()) {
            let mut padded = vec![F::zero(); self.arity()];
            padded[..block.len()].copy_from_slice(block);
            sum += g[0].eval(&padded)?;
        }
        Ok(sum)
    }
    fn decode(bits: &[F]) -> F {
        let mut weight = F::one();
        let mut v = F::zero();
        for &b in bits {
            v += b * weight;
            weight += weight;
        }
        v
    }
}
impl Flp for Circuit {
    type Field = F;
    fn gadget(&self) -> Vec<Box<dyn Gadget<F>>> {
        if self.norm_only {
            vec![Box::new(ParallelSum::new(
                PolyEval::new(vec![F::zero(), F::zero(), F::one()], self.calls()),
                self.chunk,
            ))]
        } else {
            vec![Box::new(ParallelSum::new(
                Mul::new(self.calls()),
                self.chunk,
            ))]
        }
    }
    fn num_gadgets(&self) -> usize {
        1
    }
    fn input_len(&self) -> usize {
        self.dimension + self.bit_len() + self.checks
    }
    fn proof_len(&self) -> usize {
        self.arity() + 2 * ((self.calls() + 1).next_power_of_two() - 1) + 1
    }
    fn verifier_len(&self) -> usize {
        self.arity() + 2
    }
    fn joint_rand_len(&self) -> usize {
        if self.norm_only { 0 } else { 3 }
    }
    fn eval_output_len(&self) -> usize {
        1
    }
    fn prove_rand_len(&self) -> usize {
        self.arity()
    }
    fn valid(
        &self,
        g: &mut Vec<Box<dyn Gadget<F>>>,
        input: &[F],
        joint: &[F],
        shares: usize,
    ) -> Result<Vec<F>, FlpError> {
        self.valid_call_check(input, joint)?;
        if shares == 0 || shares as u128 >= 4293918721 {
            return Err(FlpError::InvalidParameter("invalid share count".into()));
        }
        let inv = F::from(shares as u32).inv();
        let d = self.dimension;
        let nb = self.norm_bits;
        let v = Self::decode(&input[d..d + nb]);
        if self.norm_only {
            let sum = self.sum_gadget(g, &input[..d])?;
            return Ok(vec![v - sum]);
        }
        let u = Self::decode(&input[d + nb..d + 2 * nb]);
        let mut bit_inputs = Vec::new();
        let mut power = F::one();
        for &x in &input[d..d + self.bit_len()] {
            bit_inputs.extend([power * x, x - inv]);
            power *= joint[0];
        }
        let bit = self.sum_gadget(g, &bit_inputs)?;
        let mut wr_inputs = Vec::new();
        let mut count = F::zero();
        power = F::one();
        for i in 0..self.checks {
            let start = d + 2 * nb + i * (self.wrap_bits + 1);
            let claimed =
                Self::decode(&input[start..start + self.wrap_bits]) - F::from(self.wrap - 1) * inv;
            let success = input[start + self.wrap_bits];
            let dot = input[d + self.bit_len() + i];
            wr_inputs.extend([power * (dot - claimed), success]);
            count += success;
            power *= joint[1];
        }
        let quadratic = self.sum_gadget(g, &wr_inputs)?;
        let r = joint[2];
        Ok(vec![
            bit + r * (v + u - F::from(self.bound * self.bound) * inv)
                + r * r * quadratic
                + r * r * r * (count - F::from(self.successes as u32) * inv),
        ])
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn zero_witness(c: &Circuit) -> Vec<F> {
        let mut x = vec![F::zero(); c.input_len()];
        for j in 0..c.norm_bits {
            x[c.dimension + c.norm_bits + j] = F::from(((c.bound * c.bound) >> j) & 1);
        }
        for i in 0..c.checks {
            let k = c.dimension + 2 * c.norm_bits + i * (c.wrap_bits + 1);
            for j in 0..c.wrap_bits {
                x[k + j] = F::from(((c.wrap - 1) >> j) & 1);
            }
            x[k + c.wrap_bits] = F::from(u32::from(i < c.successes));
        }
        x
    }
    #[test]
    fn proof_query_decide_and_tampering() {
        for chunk in [1, 2, 3, 7, 32] {
            for norm in [true, false] {
                let c = Circuit::with_chunk(3, 16, 100, 100, norm, chunk).unwrap();
                let x = zero_witness(&c);
                let jr = if norm {
                    vec![]
                } else {
                    vec![F::from(31), F::from(37), F::from(41)]
                };
                assert_eq!(
                    c.valid(&mut c.gadget(), &x, &jr, 1).unwrap(),
                    vec![F::zero()]
                );
                let proof = c
                    .prove(&x, &vec![F::from(101); c.prove_rand_len()], &jr)
                    .unwrap();
                let query = vec![F::from(1000003)];
                let verifier = c.query(&x, &proof, &query, &jr, 1).unwrap();
                assert!(c.decide(&verifier).unwrap());
                let mut bad = x.clone();
                bad[if norm { 0 } else { c.dimension }] += F::one();
                let v = c.query(&bad, &proof, &query, &jr, 1).unwrap();
                assert!(!c.decide(&v).unwrap());
            }
        }
    }
    #[test]
    fn refuses_parameters_outside_reference_guards() {
        assert!(Circuit::new(3, 65536, 100, 100, false).is_err());
        assert!(Circuit::new(3, 16, 100, 101, false).is_err());
    }
    #[test]
    fn chunk_layout_preserves_arbitrary_field_arithmetic() {
        for norm in [true, false] {
            let baseline = Circuit::with_chunk(17, 16, 100, 73, norm, 1).unwrap();
            for trial in 0..32u32 {
                let input: Vec<F> = (0..baseline.input_len())
                    .map(|i| {
                        F::from(
                            (i as u32)
                                .wrapping_mul(2654435761)
                                .wrapping_add(trial * 7919)
                                % 4293918721,
                        )
                    })
                    .collect();
                let jr = if norm {
                    vec![]
                } else {
                    vec![
                        F::from(31 + trial),
                        F::from(37 + trial),
                        F::from(41 + trial),
                    ]
                };
                for shares in [1, 2, 3] {
                    let expected = baseline
                        .valid(&mut baseline.gadget(), &input, &jr, shares)
                        .unwrap();
                    for chunk in [2, 3, 7, 16, 32, 100] {
                        let c = Circuit::with_chunk(17, 16, 100, 73, norm, chunk).unwrap();
                        assert_eq!(
                            c.valid(&mut c.gadget(), &input, &jr, shares).unwrap(),
                            expected,
                            "norm={norm} trial={trial} shares={shares} chunk={chunk}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn actual_bgv_query_matches_prio_with_arbitrary_padding() {
        use openfhe_tbgv_rs::{Context, keygen_first};
        let p = 4293918721u64;
        let ctx = Context::new_single(p, 128, 60, 55, 3).unwrap();
        let (pk, sk) = keygen_first(&ctx).unwrap();
        let n = ctx.ring_dim() as usize;
        for norm in [true, false] {
            let c = Circuit::with_chunk(3, 16, 100, 100, norm, 3).unwrap();
            let jr = if norm {
                vec![]
            } else {
                vec![F::from(31), F::from(37), F::from(41)]
            };
            let qr = vec![F::from(1000003)];
            let il = c.input_len();
            let size = il + c.proof_len();
            assert!(size <= n);
            let zero = vec![F::zero(); size];
            let constants = c.query(&zero[..il], &zero[il..], &qr, &jr, 1).unwrap();
            let mut rows = vec![vec![F::zero(); size]; c.verifier_len()];
            for j in 0..size {
                let mut basis = zero.clone();
                basis[j] = F::one();
                let v = c.query(&basis[..il], &basis[il..], &qr, &jr, 1).unwrap();
                for k in 0..rows.len() {
                    rows[k][j] = v[k] - constants[k];
                }
            }
            let good = zero_witness(&c);
            let proof = c
                .prove(&good, &vec![F::from(101); c.prove_rand_len()], &jr)
                .unwrap();
            for hostile in [false, true] {
                let mut z = good.clone();
                z.extend(&proof);
                if hostile {
                    for (i, x) in z.iter_mut().enumerate() {
                        *x = F::from((i as u32).wrapping_mul(2654435761) % 4293918721);
                    }
                }
                let want = c.query(&z[..il], &z[il..], &qr, &jr, 1).unwrap();
                let mut coefficients = vec![123456789u64; n]; // Arbitrary off-support plaintext.
                for (dst, x) in coefficients.iter_mut().zip(&z) {
                    *dst = u32::from(*x) as u64;
                }
                let ct = ctx
                    .encrypt(&pk, &ctx.coef_plaintext(&coefficients).unwrap())
                    .unwrap();
                let mut got = Vec::new();
                for (k, row) in rows.iter().enumerate() {
                    let mut polynomial = vec![0u64; n];
                    polynomial[0] = u32::from(row[0]) as u64;
                    for j in 1..size {
                        polynomial[n - j] = (p - u32::from(row[j]) as u64) % p;
                    }
                    let product = ctx
                        .mult_plain(&ct, &ctx.coef_plaintext(&polynomial).unwrap())
                        .unwrap();
                    let result = ctx
                        .add_plain(
                            &product,
                            &ctx.coef_plaintext(&[u32::from(constants[k]) as u64])
                                .unwrap(),
                        )
                        .unwrap();
                    got.push(F::from(sk.decrypt_coeffs(&result, &[0]).unwrap()[0] as u32));
                }
                assert_eq!(got, want, "norm={norm}, hostile={hostile}");
                if !hostile {
                    assert!(c.decide(&got).unwrap());
                }
            }
        }
    }
}
