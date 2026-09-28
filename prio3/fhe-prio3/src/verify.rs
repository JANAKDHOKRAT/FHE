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
//! Verdict mode then reveals `E_j * rho_j`, where `rho_j` is the sum of
//! per-aggregator uniformly random masks encrypted under the joint key: 0
//! for a valid report, uniform in `F_p` otherwise.
//!
//! Silent mode instead computes `valid = prod_j (1 - E_j^(p-1))` (Fermat),
//! multiplies the report by it, and never decrypts anything per report.

use crate::config::TaskConfig;
use crate::error::Result;
use crate::field::Field;
use crate::layout::{Layout, LayoutKind};
use crate::messages::ReportId;
use crate::xof::Xof;
use openfhe_tbgv_rs::{Ciphertext, Context, Plaintext, PublicKey};
use rand::RngCore;

/// Plaintext coefficient vectors for one report.
///
/// `bit_coeffs[c][j]` and `lin_coeffs[c][j]` are row-length vectors that are
/// non-zero only at the client slots of chunk `c`. Multiplying a chunk by
/// them *before* any rotation guarantees that slots outside the encoded
/// measurement, which a malicious client controls freely, never enter the
/// check.
pub struct Challenge {
    pub bit_coeffs: Vec<Vec<Vec<u64>>>,
    pub lin_coeffs: Vec<Vec<Vec<u64>>>,
    /// Constant term of each repetition.
    pub constants: Vec<u64>,
    pub group: usize,
}

impl Challenge {
    /// `group` is the report's group in a batched layout (0 otherwise). The
    /// coefficients are placed at that group's slots only, so a client that
    /// packs values anywhere else has them ignored.
    pub fn derive(cfg: &TaskConfig, field: &Field, layout: &Layout, report_id: &ReportId, group: usize) -> Self {
        let m = layout.input_len;
        let k = layout.repetitions;
        let constraints = cfg.measurement_type.linear_constraints(field);
        let mut xof = Xof::new(b"verify", &[&cfg.binding(), report_id]);

        let mut r: Vec<Vec<u64>> = Vec::with_capacity(k);
        for _ in 0..k {
            r.push((0..m + constraints.len()).map(|_| xof.next_field_elem(field)).collect());
        }

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
                    let slot = layout.group_slot(group, local);
                    bc[slot] = r[j][global];
                    lc[slot] = lin[j][global];
                }
                bc_j.push(bc);
                lc_j.push(lc);
            }
            bit_coeffs.push(bc_j);
            lin_coeffs.push(lc_j);
        }
        Self { bit_coeffs, lin_coeffs, constants, group }
    }

    /// Constant vector: repetition `j`'s constant at its position 0 (blocked:
    /// slot `j*block`; interleaved/batched: slot `j + classes*group`).
    fn constant_vector(&self, layout: &Layout) -> Vec<u64> {
        let mut v = vec![0u64; layout.row];
        for (j, &c) in self.constants.iter().enumerate() {
            let slot = match layout.kind {
                LayoutKind::Blocked => layout.result_slot(j),
                LayoutKind::Interleaved | LayoutKind::Batched => j + layout.classes * self.group,
            };
            v[slot] = c;
        }
        v
    }
}

/// Cached plaintexts that do not depend on the report.
pub struct Circuit {
    ctx: Context,
    layout: Layout,
    plain_mod: u64,
    ones: Plaintext,
    /// Blocked only: 1 at result slots, 0 elsewhere.
    selector: Option<Plaintext>,
}

impl Circuit {
    pub fn new(ctx: &Context, layout: &Layout) -> Result<Self> {
        let ones = ctx.plaintext(&vec![1u64; layout.row])?;
        let selector = match layout.kind {
            LayoutKind::Blocked => {
                let mut sel = vec![0u64; layout.row];
                for j in 0..layout.repetitions {
                    sel[layout.result_slot(j)] = 1;
                }
                Some(ctx.plaintext(&sel)?)
            }
            LayoutKind::Interleaved | LayoutKind::Batched => None,
        };
        Ok(Self { ctx: ctx.clone(), layout: layout.clone(), plain_mod: ctx.plain_mod(), ones, selector })
    }

    /// One report's contribution `T`: coefficient-multiplied bit and linear
    /// terms of every chunk, each repetition rotated onto its class (or block),
    /// plus the constants. Depth 2. Coefficients are applied before any
    /// rotation, so slots outside the report's encoded positions never enter.
    pub fn report_terms(&self, chunks: &[Ciphertext], ch: &Challenge) -> Result<Ciphertext> {
        let ctx = &self.ctx;
        let l = &self.layout;
        let mut total: Option<Ciphertext> = None;
        for (c, ct) in chunks.iter().enumerate() {
            let x_minus_one = ctx.sub_plain(ct, &self.ones)?;
            let e = ctx.mult(ct, &x_minus_one)?;
            for j in 0..l.repetitions {
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
        Ok(ctx.add_plain(&t, &ctx.plaintext(&ch.constant_vector(l))?)?)
    }

    /// Sums every repetition's terms into its result position(s): `S`.
    /// Blocked: slot `result_slot(j)`; interleaved/batched: every slot of
    /// the class. Rotations only, no level.
    pub fn class_sums(&self, t: &Ciphertext) -> Result<Ciphertext> {
        let mut s = t.try_clone()?;
        for d in self.layout.sum_rotations() {
            s = self.ctx.add(&s, &self.ctx.rotate(&s, d)?)?;
        }
        Ok(s)
    }

    /// `S` for a single report (verdict mode and unbatched silent mode).
    pub fn check_sum(&self, chunks: &[Ciphertext], ch: &Challenge) -> Result<Ciphertext> {
        let t = self.report_terms(chunks, ch)?;
        self.class_sums(&t)
    }

    /// Batched silent mode: restricts a chunk ciphertext to its own group's
    /// element slots. Everything a client put elsewhere is zeroed, so it can
    /// neither enter another group's sum nor be multiplied by another
    /// report's validity bit. One plaintext multiplication (level 1).
    pub fn mask_to_group(&self, ct: &Ciphertext, chunk: usize, group: usize) -> Result<Ciphertext> {
        let l = &self.layout;
        let mut ind = vec![0u64; l.row];
        for i in 0..l.chunk_len(chunk) {
            ind[l.group_slot(group, i)] = 1;
        }
        Ok(self.ctx.mult_plain(ct, &self.ctx.plaintext(&ind)?)?)
    }

    /// Batched silent mode: a ciphertext with `valid_group` at slot
    /// `group_slot(group, 0)` and zero elsewhere, from `G`. One plaintext
    /// multiplication at the last level (4 limbs).
    pub fn count_of_group(&self, g: &Ciphertext, group: usize) -> Result<Ciphertext> {
        let l = &self.layout;
        let mut ind = vec![0u64; l.row];
        ind[l.group_slot(group, 0)] = 1;
        Ok(self.ctx.mult_plain(g, &self.ctx.plaintext(&ind)?)?)
    }

    /// Batched silent mode: moves group `group`'s slots onto group 0's by
    /// composing the power-of-two fold rotations. Cheap at the last level.
    pub fn fold_to_group0(&self, ct: &Ciphertext, group: usize) -> Result<Ciphertext> {
        let l = &self.layout;
        let mut out = ct.try_clone()?;
        let mut bit = 0;
        while (1usize << bit) < l.groups {
            if (group >> bit) & 1 == 1 {
                out = self.ctx.rotate(&out, (l.classes << bit) as i32)?;
            }
            bit += 1;
        }
        Ok(out)
    }

    /// Verdict mode. Fresh encrypted mask: uniform field elements at the
    /// result slots, zero elsewhere.
    pub fn make_mask(&self, pk: &PublicKey, field: &Field, rng: &mut dyn RngCore) -> Result<Ciphertext> {
        let mut v = vec![0u64; self.layout.row];
        for j in 0..self.layout.repetitions {
            v[self.layout.result_slot(j)] = uniform_field_elem(field, rng);
        }
        Ok(self.ctx.encrypt(pk, &self.ctx.plaintext(&v)?)?)
    }

    /// Verdict mode. `u = S * ((sum of masks) * selector)`. Depth 3. Only
    /// the result slots of `u` can be non-zero.
    pub fn apply_masks(&self, s: &Ciphertext, masks: &[&Ciphertext]) -> Result<Ciphertext> {
        let ctx = &self.ctx;
        let mut sum = masks[0].try_clone()?;
        for m in &masks[1..] {
            sum = ctx.add(&sum, m)?;
        }
        let selected = ctx.mult_plain(&sum, self.selector.as_ref().expect("blocked layout"))?;
        Ok(ctx.mult(s, &selected)?)
    }

    /// Verdict mode. True iff every result slot of the fused decryption is zero.
    pub fn verdict(&self, fused: &[u64]) -> bool {
        (0..self.layout.repetitions).all(|j| fused.get(self.layout.result_slot(j)) == Some(&0))
    }

    /// Post-validation second moments for one report in `group`: for every
    /// value pair `a <= b` a ciphertext holding `v_a * v_b` at the group's
    /// element-0 slot and zero elsewhere. Depth 3: weighted bits (1),
    /// alignment mask (2), product (3). Each value is recomposed from its
    /// own bit slots with plaintext weights `2^t` and zero everywhere else,
    /// so nothing the client wrote outside that value's bit slots enters,
    /// whatever the widths of neighbouring values.
    pub fn moment_products(&self, ct: &Ciphertext, group: usize) -> Result<Vec<Ciphertext>> {
        let l = &self.layout;
        let map = l.moments.as_ref().expect("moments enabled");
        let stride = l.element_stride();
        let window = l.moment_window();
        let ctx = &self.ctx;
        let mut ind0 = vec![0u64; l.row];
        ind0[l.group_slot(group, 0)] = 1;
        let ind0 = ctx.plaintext(&ind0)?;
        let mut values = Vec::with_capacity(map.len());
        for &(start, bits) in map {
            let mut w = vec![0u64; l.row];
            for t in 0..bits as usize {
                w[l.group_slot(group, start + t)] = 1u64 << t;
            }
            // z is zero outside this value's bit slots, so the tree's window
            // may exceed the value's width without touching a neighbour.
            let mut z = ctx.mult_plain(ct, &ctx.plaintext(&w)?)?;
            let mut d = 1usize;
            while d < window {
                z = ctx.add(&z, &ctx.rotate(&z, (stride * d) as i32)?)?;
                d *= 2;
            }
            let aligned = if start == 0 { z } else { ctx.rotate(&z, (start * stride) as i32)? };
            values.push(ctx.mult_plain(&aligned, &ind0)?);
        }
        let mut out = Vec::with_capacity(l.moment_pairs());
        for a in 0..values.len() {
            for b in a..values.len() {
                out.push(if a == b { ctx.square(&values[a])? } else { ctx.mult(&values[a], &values[b])? });
            }
        }
        Ok(out)
    }

    /// `x^(p-1)` slot-wise by left-to-right square-and-multiply.
    fn fermat(&self, x: &Ciphertext) -> Result<Ciphertext> {
        let e = self.plain_mod - 1;
        let bits = 64 - e.leading_zeros();
        let mut acc = x.try_clone()?;
        for b in (0..bits - 1).rev() {
            acc = self.ctx.square(&acc)?;
            if (e >> b) & 1 == 1 {
                acc = self.ctx.mult(&acc, x)?;
            }
        }
        Ok(acc)
    }

    /// Silent mode. From `S` computes `G`: for the interleaved layout every
    /// slot holds `valid`; for the batched layout every class-0 slot of
    /// group `r` holds `valid_r` (other slots of the group hold products that
    /// straddle groups and are never used). Depth `fermat + log2(classes)`
    /// on top of `S`.
    pub fn silent_validity(&self, s: &Ciphertext) -> Result<Ciphertext> {
        debug_assert_ne!(self.layout.kind, LayoutKind::Blocked);
        let ctx = &self.ctx;
        let f = self.fermat(s)?; // slot in class j: [E_j != 0]
        let mut g = ctx.negate(&ctx.sub_plain(&f, &self.ones)?)?; // 1 - f
        for d in self.layout.product_rotations() {
            g = ctx.mult(&g, &ctx.rotate(&g, d)?)?;
        }
        Ok(g)
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
