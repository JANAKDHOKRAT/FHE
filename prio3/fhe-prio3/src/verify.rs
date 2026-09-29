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
        let constraints = cfg.measurement_type.linear_constraints();
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
                for (i, coef) in c.field_coeffs(field) {
                    lin[j][i] = field.add(lin[j][i], field.mul(w, coef));
                }
                constants[j] = field.add(constants[j], field.mul(w, c.field_constant(field)));
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

    /// Post-validation second moments for one report in `group`, one
    /// ciphertext per [`crate::layout::MomentTerm`] of the layout in its order.
    ///
    /// Each value is split into digits of `D` bits. Digit `i` of value `v`
    /// is recomposed from the value's own bit slots with plaintext weights
    /// `2^(t mod D)` (zero everywhere else, so nothing the client wrote
    /// outside that value's bit slots enters, whatever the widths of
    /// neighbouring values), summed over a window of `D` elements
    /// ([`Self::window_sum`]) into element `i*D` after alignment, and
    /// masked to those positions. A term with shift `s` is the slot-wise
    /// product of one value's digits with the other's moved by `s` digits,
    /// so position `i` holds `d_a[i] * d_b[i+s]` (see [`crate::layout::MomentTerm`]) at the
    /// group's element slot `i*D` and every other slot is zero.
    ///
    /// Depth 3: weighted bits (1), alignment mask (2), product (3). Costs
    /// per report: per value `log2(window)` window rotations plus at most
    /// `popcount` offset rotations, one alignment rotation and `k_v - 1`
    /// digit shifts; per pair `k_a + k_b - 1` multiplications (`k_a` for a
    /// square).
    pub fn moment_products(&self, chunks: &[Ciphertext], group: usize) -> Result<Vec<Ciphertext>> {
        let l = &self.layout;
        let map = l.moments.as_ref().expect("moments enabled");
        let stride = l.element_stride();
        let window = l.moment_window();
        let d = l.moment_digit as usize;
        let ctx = &self.ctx;
        // per value: its digits moved down by 0, 1, .., k-1 digit positions
        let mut values: Vec<Vec<Ciphertext>> = Vec::with_capacity(map.len());
        for &(start, bits) in map {
            // the value's bits live in one chunk (checked by the config)
            let k = l.chunk_of(start);
            let local = start - l.chunk_range(k).start;
            let mut w = vec![0u64; l.row];
            for t in 0..bits as usize {
                w[l.group_slot(group, local + t)] = 1u64 << (t % d);
            }
            let z = ctx.mult_plain(&chunks[k], &ctx.plaintext(&w)?)?;
            let z = self.window_sum(z, window, stride)?;
            let aligned = if local == 0 { z } else { ctx.rotate(&z, (local * stride) as i32)? };
            let digits = l.moment_digits(bits);
            let mut m = vec![0u64; l.row];
            for i in 0..digits {
                m[l.group_slot(group, i * d)] = 1;
            }
            let mut shifted = vec![ctx.mult_plain(&aligned, &ctx.plaintext(&m)?)?];
            for _ in 1..digits {
                let next = ctx.rotate(shifted.last().expect("one"), (d * stride) as i32)?;
                shifted.push(next);
            }
            values.push(shifted);
        }
        let terms = l.moment_terms();
        let mut out = Vec::with_capacity(terms.len());
        for t in terms {
            let (x, y) = if t.shift >= 0 { (&values[t.a][0], &values[t.b][t.shift as usize]) } else { (&values[t.a][(-t.shift) as usize], &values[t.b][0]) };
            out.push(if t.a == t.b && t.shift == 0 { ctx.square(x)? } else { ctx.mult(x, y)? });
        }
        Ok(out)
    }

    /// Slot `x` of the result is `z[x] + z[x + stride] + .. + z[x + (w-1)*stride]`.
    /// Doubling sums `P_1, P_2, P_4, ..` cover windows of powers of two; the
    /// set bits of `w` pick some of them, each moved to its offset by
    /// rotations by powers of two below it. Only rotations by `stride * 2^j`
    /// with `2^(j+1) <= w` are used (`Layout::moment_rotations`).
    fn window_sum(&self, z: Ciphertext, w: usize, stride: usize) -> Result<Ciphertext> {
        let ctx = &self.ctx;
        let mut acc: Option<Ciphertext> = None;
        let mut offset = 0usize;
        let mut p = z;
        let mut span = 1usize;
        loop {
            if w & span != 0 {
                let mut t = p.try_clone()?;
                let mut bit = 1usize;
                while bit <= offset {
                    if offset & bit != 0 {
                        t = ctx.rotate(&t, (stride * bit) as i32)?;
                    }
                    bit *= 2;
                }
                acc = Some(match acc {
                    None => t,
                    Some(a) => ctx.add(&a, &t)?,
                });
                offset += span;
            }
            if 2 * span > w {
                break;
            }
            p = ctx.add(&p, &ctx.rotate(&p, (stride * span) as i32)?)?;
            span *= 2;
        }
        Ok(acc.expect("w >= 1"))
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
