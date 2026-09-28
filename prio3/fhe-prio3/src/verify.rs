//! The homomorphic validity check.
//!
//! For a report with encoded slots `x_0..x_{m-1}` and linear constraints
//! `L_l(x) = sum_i c_{l,i} x_i + c_{l,0}`, repetition `j` computes
//!
//! ```text
//! E_j = sum_i r_{j,i} * x_i (x_i - 1)  +  sum_l r_{j,m+l} * L_l(x)
//! ```
//!
//! with all `r` derived by an XOF from the task configuration and the report
//! identifier (a hash of the ciphertexts), so they are fixed only after the
//! client has committed to its ciphertexts. If the report is valid every
//! term is zero. If it is not, the vector of terms is non-zero and each
//! `E_j` is zero with probability exactly `1/p` over the choice of `r_j`.
//!
//! The aggregators then reveal `E_j * rho_j`, where `rho_j` is the sum of
//! per-aggregator uniformly random masks encrypted under the joint key. For
//! a valid report this is 0; for an invalid one it is uniform in `F_p`
//! provided at least one aggregator's mask is honest, so nothing beyond the
//! verdict is revealed.

use crate::config::TaskConfig;
use crate::error::Result;
use crate::field::Field;
use crate::layout::Layout;
use crate::messages::ReportId;
use crate::xof::Xof;
use openfhe_tbgv_rs::{Ciphertext, Context, Plaintext, PublicKey};
use rand::RngCore;

/// Plaintext coefficient vectors for one report.
///
/// `bit_coeffs[c][j]` and `lin_coeffs[c][j]` are row-length vectors that are
/// non-zero only on the first `chunk_len(c)` slots. Multiplying a chunk by
/// them *before* any rotation guarantees that slots outside the encoded
/// measurement, which a malicious client controls freely, never enter the
/// check.
pub struct Challenge {
    pub bit_coeffs: Vec<Vec<Vec<u64>>>,
    pub lin_coeffs: Vec<Vec<Vec<u64>>>,
    /// Constant term of each repetition (placed at the block's first slot).
    pub constants: Vec<u64>,
}

impl Challenge {
    pub fn derive(cfg: &TaskConfig, field: &Field, layout: &Layout, report_id: &ReportId) -> Self {
        let m = layout.input_len;
        let k = layout.repetitions;
        let constraints = cfg.measurement_type.linear_constraints(field);
        let mut xof = Xof::new(b"verify", &[&cfg.binding(), report_id]);

        // r[j] = (r_{j,0..m}, r_{j,m..m+L})
        let mut r: Vec<Vec<u64>> = Vec::with_capacity(k);
        for _ in 0..k {
            r.push((0..m + constraints.len()).map(|_| xof.next_field_elem(field)).collect());
        }

        // Per repetition, fold the linear constraints into one coefficient per input.
        let mut lin: Vec<Vec<u64>> = vec![vec![0u64; m]; k];
        let mut constants = vec![0u64; k];
        for (j, rj) in r.iter().enumerate() {
            for (l, c) in constraints.iter().enumerate() {
                let w = rj[m + l];
                for &(i, coef) in &c.coeffs {
                    lin[j][i] = field.add(lin[j][i], field.mul(w, coef));
                }
                constants[j] = field.add(constants[j], field.mul(w, c.constant));
            }
        }

        let mut bit_coeffs = Vec::with_capacity(layout.num_chunks);
        let mut lin_coeffs = Vec::with_capacity(layout.num_chunks);
        for c in 0..layout.num_chunks {
            let range = layout.chunk_range(c);
            let mut bc_j = Vec::with_capacity(k);
            let mut lc_j = Vec::with_capacity(k);
            for j in 0..k {
                let mut bc = vec![0u64; layout.row];
                let mut lc = vec![0u64; layout.row];
                for (local, global) in range.clone().enumerate() {
                    bc[local] = r[j][global];
                    lc[local] = lin[j][global];
                }
                bc_j.push(bc);
                lc_j.push(lc);
            }
            bit_coeffs.push(bc_j);
            lin_coeffs.push(lc_j);
        }
        Self { bit_coeffs, lin_coeffs, constants }
    }

    fn constant_vector(&self, layout: &Layout) -> Vec<u64> {
        let mut v = vec![0u64; layout.row];
        for (j, &c) in self.constants.iter().enumerate() {
            v[layout.result_slot(j)] = c;
        }
        v
    }
}

/// Cached plaintexts that do not depend on the report.
pub struct Circuit {
    ctx: Context,
    layout: Layout,
    ones: Plaintext,
    selector: Plaintext,
}

impl Circuit {
    pub fn new(ctx: &Context, layout: &Layout) -> Result<Self> {
        let ones = ctx.plaintext(&vec![1u64; layout.row])?;
        let mut sel = vec![0u64; layout.row];
        for j in 0..layout.repetitions {
            sel[layout.result_slot(j)] = 1;
        }
        let selector = ctx.plaintext(&sel)?;
        Ok(Self { ctx: ctx.clone(), layout: layout.clone(), ones, selector })
    }

    /// Computes `S`, the ciphertext whose slot `result_slot(j)` holds `E_j`.
    /// Depth 2. Other slots hold partial sums and are never decrypted.
    pub fn check_sum(&self, chunks: &[Ciphertext], ch: &Challenge) -> Result<Ciphertext> {
        let ctx = &self.ctx;
        let l = &self.layout;
        let mut total: Option<Ciphertext> = None;
        for (c, ct) in chunks.iter().enumerate() {
            let x_minus_one = ctx.sub_plain(ct, &self.ones)?;
            let e = ctx.mult(ct, &x_minus_one)?;
            for j in 0..l.repetitions {
                // Coefficients first (they vanish outside the encoded slots), rotation second.
                let bit_term = ctx.mult_plain(&e, &ctx.plaintext(&ch.bit_coeffs[c][j])?)?;
                let lin_term = ctx.mult_plain(ct, &ctx.plaintext(&ch.lin_coeffs[c][j])?)?;
                let mut term = ctx.add(&bit_term, &lin_term)?;
                if j > 0 {
                    term = ctx.rotate(&term, l.replicate_rotation(j))?;
                }
                total = Some(match total {
                    None => term,
                    Some(t) => ctx.add(&t, &term)?,
                });
            }
        }
        let t = total.expect("at least one chunk and one repetition");
        let mut s = ctx.add_plain(&t, &ctx.plaintext(&ch.constant_vector(l))?)?;
        for d in l.block_sum_rotations() {
            s = ctx.add(&s, &ctx.rotate(&s, d)?)?;
        }
        Ok(s)
    }

    /// Fresh encrypted mask: uniform field elements at the result slots,
    /// zero elsewhere.
    pub fn make_mask(&self, pk: &PublicKey, field: &Field, rng: &mut dyn RngCore) -> Result<Ciphertext> {
        let mut v = vec![0u64; self.layout.row];
        for j in 0..self.layout.repetitions {
            v[self.layout.result_slot(j)] = uniform_field_elem(field, rng);
        }
        Ok(self.ctx.encrypt(pk, &self.ctx.plaintext(&v)?)?)
    }

    /// `u = S * ((sum of masks) * selector)`. Depth 3. Only the result slots
    /// of `u` can be non-zero.
    pub fn apply_masks(&self, s: &Ciphertext, masks: &[&Ciphertext]) -> Result<Ciphertext> {
        let ctx = &self.ctx;
        let mut sum = masks[0].try_clone()?;
        for m in &masks[1..] {
            sum = ctx.add(&sum, m)?;
        }
        let selected = ctx.mult_plain(&sum, &self.selector)?;
        Ok(ctx.mult(s, &selected)?)
    }

    /// True iff every result slot of the fused decryption is zero.
    pub fn verdict(&self, fused: &[u64]) -> bool {
        (0..self.layout.repetitions).all(|j| fused.get(self.layout.result_slot(j)) == Some(&0))
    }
}

/// Uniform in `[0, p)` by rejection sampling from the OS RNG.
pub fn uniform_field_elem(field: &Field, rng: &mut dyn RngCore) -> u64 {
    let p = field.modulus();
    loop {
        let v = rng.next_u32() as u64;
        if v < p {
            return v;
        }
    }
}
