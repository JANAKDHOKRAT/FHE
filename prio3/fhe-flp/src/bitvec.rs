//! `BitVec`: a vector of bits, aggregated element-wise. The language is
//! Prio3SumVec's with `max_measurement = 1` (draft-irtf-cfrg-vdaf, SumVec),
//! but the validity circuit uses no joint randomness.
//!
//! Why: Prio3SumVec compresses its range checks with *joint* randomness that
//! the client derives from its input shares before proving. Here the input
//! and the proof travel in one ciphertext, so there is no input commitment
//! to derive it from. Instead the circuit outputs one range check per
//! element, `x_i^2 - x_i`, and the generic FLP (`prio::flp::Flp::query`)
//! compresses multiple outputs with the *verifier's* query randomness. The
//! cost is a proof of O(len) field elements instead of O(sqrt(len)); in this
//! protocol the proof shares one fixed-size ciphertext with the input, so
//! the report does not grow while `len + proofs * proof_len` fits the ring.
//!
//! Gadget: one `Mul` called `len` times (degree 2, arity 2), as in
//! Prio3Count with `len` calls. Base soundness per proof (BBCGGI19 Thm 4.3,
//! as the draft's `plot_prio3_multiproof_robustness.py` computes it):
//! `2 len / (p - len)`, plus `1/p` for the random linear compression.
use prio::field::{FieldElementWithInteger, NttFriendlyFieldElement};
use prio::flp::gadgets::Mul;
use prio::flp::{Flp, FlpError, Gadget, Type};
use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitVec<F> {
    len: usize,
    _field: PhantomData<F>,
}

impl<F: NttFriendlyFieldElement> BitVec<F> {
    pub fn new(len: usize) -> Result<Self, FlpError> {
        if len == 0 {
            return Err(FlpError::InvalidParameter("len must be at least 1".into()));
        }
        Ok(Self { len, _field: PhantomData })
    }

    /// Number of calls of the single `Mul` gadget.
    pub fn calls(&self) -> usize {
        self.len
    }
}

/// `prio::flp::wire_poly_len` and `gadget_poly_len` (crate-private there),
/// reproduced verbatim from prio 0.18.1 `src/flp.rs`.
fn wire_poly_len(num_calls: usize) -> usize {
    (1 + num_calls).next_power_of_two()
}
fn gadget_poly_len(gadget_degree: usize, wire_poly_len: usize) -> usize {
    gadget_degree * (wire_poly_len - 1) + 1
}

impl<F: NttFriendlyFieldElement> Flp for BitVec<F> {
    type Field = F;

    fn gadget(&self) -> Vec<Box<dyn Gadget<F>>> {
        vec![Box::new(Mul::new(self.len))]
    }

    fn num_gadgets(&self) -> usize {
        1
    }

    fn valid(&self, g: &mut Vec<Box<dyn Gadget<F>>>, input: &[F], joint_rand: &[F], _num_shares: usize) -> Result<Vec<F>, FlpError> {
        self.valid_call_check(input, joint_rand)?;
        let mut out = Vec::with_capacity(self.len);
        for &x in input {
            out.push(g[0].eval(&[x, x])? - x);
        }
        Ok(out)
    }

    fn input_len(&self) -> usize {
        self.len
    }

    fn proof_len(&self) -> usize {
        // arity (wire seeds) + gadget polynomial, as Flp::prove lays it out
        2 + gadget_poly_len(2, wire_poly_len(self.len))
    }

    fn verifier_len(&self) -> usize {
        // circuit output, two wire evaluations, one gadget evaluation
        4
    }

    fn joint_rand_len(&self) -> usize {
        0
    }

    fn eval_output_len(&self) -> usize {
        self.len
    }

    fn prove_rand_len(&self) -> usize {
        2
    }
}

impl<F: NttFriendlyFieldElement> Type for BitVec<F> {
    type Measurement = Vec<bool>;
    type AggregateResult = Vec<F::Integer>;

    fn encode_measurement(&self, measurement: &Vec<bool>) -> Result<Vec<F>, FlpError> {
        if measurement.len() != self.len {
            return Err(FlpError::Encode(format!(
                "unexpected measurement length: got {}; want {}",
                measurement.len(),
                self.len
            )));
        }
        Ok(measurement.iter().map(|&b| if b { F::one() } else { F::zero() }).collect())
    }

    fn truncate(&self, input: Vec<F>) -> Result<Vec<F>, FlpError> {
        self.truncate_call_check(&input)?;
        Ok(input)
    }

    fn decode_result(&self, data: &[F], _num_measurements: usize) -> Result<Vec<F::Integer>, FlpError> {
        if data.len() != self.len {
            return Err(FlpError::Decode(format!("unexpected aggregate length: got {}; want {}", data.len(), self.len)));
        }
        Ok(data.iter().map(|&x| <F as FieldElementWithInteger>::Integer::from(x)).collect())
    }

    fn output_len(&self) -> usize {
        self.len
    }
}

/// Closed-form verifier rows for the FLP of a circuit made of ONE `Mul`
/// gadget called `calls` times on `(x_i, x_i)` with outputs
/// `g(x_i, x_i) - x_i` (prio's `Count`: `calls = 1`; `BitVec`: `calls =
/// len`), compressed with `query_rand[..calls]` when `compress`.
///
/// Derived from prio 0.18.1 `Flp::query` and `QueryShimGadget` (src/flp.rs)
/// with `W = wire_poly_len(calls)` and the gadget polynomial of
/// `G = 2W - 1` values on the 2W-th roots of unity, extended to 2W values by
/// `extend_values_to_power_of_2` (the unique degree <= 2W-2 interpolant):
///
/// * row 0, the circuit output: `sum_i c_i (gp[2(i+1)] - x_i)` (the shim
///   returns `evals[(i+1) * step]` with `step = 2`, an original value);
/// * rows 1, 2, the wire polynomials at `r`: `l^W_0(r) seed_k +
///   sum_i l^W_{i+1}(r) x_i`;
/// * row 3, the gadget polynomial at `r`: `sum_j (l^2W_j(r) -
///   w^(j+1) l^2W_{2W-1}(r)) gp[j]`, since the extended value is
///   `-sum_j w^(j+1) gp[j]` (zero top coefficient).
///
/// `l^n_j(x) = w_n^j (x^n - 1) / (n (x - w_n^j))` with prio's roots
/// `w_n = F::root(log2 n)`, or `[x = w_n^j]` when `x^n = 1`.
/// Returns rows over `input || proof` and the (zero) constants.
/// `Task::new` checks the result against `Flp::query` at random points.
pub fn mul_bits_map<F: NttFriendlyFieldElement>(calls: usize, compress: bool, query_rand: &[F]) -> (Vec<Vec<F>>, Vec<F>) {
    let w = wire_poly_len(calls);
    let g = gadget_poly_len(2, w);
    let (il, pl) = (calls, 2 + g);
    let r = *query_rand.last().expect("query randomness");
    let comp: Vec<F> = if compress { query_rand[..calls].to_vec() } else { vec![F::one(); calls] };
    let mut rows = vec![vec![F::zero(); il + pl]; 4];
    for i in 0..calls {
        rows[0][i] -= comp[i];
        rows[0][il + 2 + 2 * (i + 1)] += comp[i];
    }
    let lw = lagrange_at::<F>(w, r);
    for k in 0..2 {
        rows[1 + k][il + k] = lw[0];
        rows[1 + k][..calls].copy_from_slice(&lw[1..calls + 1]);
    }
    let l2 = lagrange_at::<F>(2 * w, r);
    let root = F::root((2 * w).trailing_zeros() as usize).expect("2W-th root of unity");
    let mut wp = root; // w^(j+1)
    for j in 0..g {
        rows[3][il + 2 + j] = l2[j] - wp * l2[2 * w - 1];
        wp *= root;
    }
    (rows, vec![F::zero(); 4])
}

/// All Lagrange basis polynomials on prio's n-th roots of unity, at `x`.
fn lagrange_at<F: NttFriendlyFieldElement>(n: usize, x: F) -> Vec<F> {
    let root = F::root(n.trailing_zeros() as usize).expect("n-th root of unity");
    let mut powers = Vec::with_capacity(n);
    let mut p = F::one();
    for _ in 0..n {
        powers.push(p);
        p *= root;
    }
    if let Some(i) = powers.iter().position(|&wi| wi == x) {
        let mut out = vec![F::zero(); n];
        out[i] = F::one();
        return out;
    }
    let mut xn = F::one();
    for _ in 0..n {
        xn *= x;
    }
    let n_int = match <F as FieldElementWithInteger>::Integer::try_from(n) {
        Ok(v) => v,
        Err(_) => unreachable!("n is a power of two below the field's 2-adicity"),
    };
    let n_inv = F::from(n_int).inv();
    let common = (xn - F::one()) * n_inv;
    powers.iter().map(|&wi| wi * common * (x - wi).inv()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prio::field::FieldPrio2;
    use prio::flp::types::Count;

    fn check<T: Flp<Field = FieldPrio2>>(typ: &T, calls: usize, compress: bool, qr: &[FieldPrio2]) {
        let (rows, c) = mul_bits_map(calls, compress, qr);
        let n = typ.input_len() + typ.proof_len();
        for t in 0..3u32 {
            let z: Vec<FieldPrio2> = (0..n as u32)
                .map(|i| FieldPrio2::from(i.wrapping_mul(2_654_435_761).wrapping_add(t * 31) % 4_000_000_000))
                .collect();
            let want = typ.query(&z[..typ.input_len()], &z[typ.input_len()..], qr, &[], 1).unwrap();
            for (r, row) in rows.iter().enumerate() {
                let got = row.iter().zip(&z).fold(c[r], |a, (&x, &y)| a + x * y);
                assert_eq!(got, want[r], "row {r}");
            }
        }
    }

    #[test]
    fn closed_form_equals_prio_query() {
        check(&Count::<FieldPrio2>::new(), 1, false, &[FieldPrio2::from(987_654_321u32)]);
        for len in [1usize, 2, 3, 7, 100, 255] {
            let t = BitVec::<FieldPrio2>::new(len).unwrap();
            let qr: Vec<FieldPrio2> = (0..t.query_rand_len() as u32)
                .map(|i| FieldPrio2::from(1_000_003u32.wrapping_mul(i + 1)))
                .collect();
            check(&t, len, len > 1, &qr);
        }
    }

    #[test]
    fn closed_form_on_a_gadget_point_that_is_a_2w_th_root() {
        // r^W = -1: not refused by query (only W-th roots are), and the
        // 2W-point Lagrange basis degenerates to an indicator.
        let len = 100;
        let t = BitVec::<FieldPrio2>::new(len).unwrap();
        let w = wire_poly_len(len);
        let r = FieldPrio2::root((2 * w).trailing_zeros() as usize).unwrap().pow(3);
        let mut qr: Vec<FieldPrio2> = (0..len as u32).map(|i| FieldPrio2::from(17 + i)).collect();
        qr.push(r);
        check(&t, len, true, &qr);
    }
}
