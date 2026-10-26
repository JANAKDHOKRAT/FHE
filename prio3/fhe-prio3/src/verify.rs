//! The homomorphic validity check.
//!
//! For a report with encoded slots `x_0..x_{m-1}` and linear constraints
//! `L_l(x) = sum_i c_{l,i} x_i + c_{l,0}`, repetition `j` computes
//!
//! ```text
//! E_j = sum_i r_{j,i} * x_i (x_i - 1)  +  sum_l r_{j,m+l} * L_l(x)
//! ```
//!
//! with all `r` derived by an XOF from the task configuration, the task's
//! secret verify key (`keys::VerifyKey`, held by the aggregators only) and
//! the report identifier (a hash of the ciphertexts). They are fixed only
//! after the client has committed to its ciphertexts, and the client cannot
//! compute them at all: it cannot search offline for ciphertexts that pass.
//! Each submitted report is one attempt. If the report is valid every
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
use crate::keys::VerifyKey;
use crate::layout::{Layout, LayoutKind};
use crate::messages::ReportId;
use crate::xof::Xof;
use openfhe_tbgv_rs::{Ciphertext, Context, Plaintext, PublicKey};
use rand::RngCore;

/// Plaintext coefficient vectors for one report, or for every report of a
/// silent-mode batch at once.
///
/// `bit_coeffs[c][j]` and `lin_coeffs[c][j]` are row-length vectors that are
/// non-zero only at the client slots of chunk `c` of the reports they were
/// derived for. Multiplying a chunk by them *before* any rotation
/// guarantees that slots outside the encoded measurement, which a
/// malicious client controls freely, never enter the check. In a batch,
/// each report's coefficients occupy its own group's slots, so the batch
/// challenge is the disjoint union of the per-report challenges and every
/// slot sees exactly what it would have seen with the report alone.
pub struct Challenge {
    pub bit_coeffs: Vec<Vec<Vec<u64>>>,
    pub lin_coeffs: Vec<Vec<Vec<u64>>>,
    /// Constant terms, already at their slots: repetition `j` of the report
    /// in group `r` at `result_slot(j)` (blocked) or `j + classes*r`
    /// (interleaved, batched).
    pub constants: Vec<u64>,
}

impl Challenge {
    /// The challenge of one report. `group` is the report's group in a
    /// batched layout (0 otherwise). The coefficients are placed at that
    /// group's slots only, so a client that packs values anywhere else has
    /// them ignored. `verify_key` is the task's secret verify key: without
    /// it the coefficients are unpredictable (SHAKE128 keyed with 256
    /// secret bits).
    pub fn derive(cfg: &TaskConfig, field: &Field, layout: &Layout, verify_key: &VerifyKey, report_id: &ReportId, group: usize) -> Self {
        Self::derive_batch(cfg, field, layout, verify_key, &[(group, *report_id)])
    }

    /// The challenges of every `(group, report id)` of a batch, each derived
    /// exactly as [`Self::derive`] would derive it alone and written into
    /// its group's slots. Groups must be distinct.
    pub fn derive_batch(cfg: &TaskConfig, field: &Field, layout: &Layout, verify_key: &VerifyKey, reports: &[(usize, ReportId)]) -> Self {
        let m = layout.input_len;
        let k = layout.repetitions;
        let constraints = cfg.measurement_type.linear_constraints();
        let binding = cfg.binding();
        let mut bit_coeffs: Vec<Vec<Vec<u64>>> = (0..layout.num_chunks).map(|_| vec![vec![0u64; layout.row]; k]).collect();
        let mut lin_coeffs = bit_coeffs.clone();
        let mut constants = vec![0u64; layout.row];
        for (group, report_id) in reports {
            let mut xof = Xof::new(b"verify", &[verify_key.as_bytes(), &binding, report_id]);
            let mut r: Vec<Vec<u64>> = Vec::with_capacity(k);
            for _ in 0..k {
                r.push((0..m + constraints.len()).map(|_| xof.next_field_elem(field)).collect());
            }
            let mut lin: Vec<Vec<u64>> = vec![vec![0u64; m]; k];
            for (j, rj) in r.iter().enumerate() {
                let mut constant = 0u64;
                for (l, c) in constraints.iter().enumerate() {
                    let w = rj[m + l];
                    for (i, coef) in c.field_coeffs(field) {
                        lin[j][i] = field.add(lin[j][i], field.mul(w, coef));
                    }
                    constant = field.add(constant, field.mul(w, c.field_constant(field)));
                }
                let slot = match layout.kind {
                    LayoutKind::Blocked => layout.result_slot(j),
                    LayoutKind::Interleaved | LayoutKind::Batched => j + layout.classes * group,
                };
                constants[slot] = constant;
            }
            for c in 0..layout.num_chunks {
                for (local, global) in layout.chunk_range(c).enumerate() {
                    let slot = layout.group_slot(*group, local);
                    for j in 0..k {
                        bit_coeffs[c][j][slot] = r[j][global];
                        lin_coeffs[c][j][slot] = lin[j][global];
                    }
                }
            }
        }
        Self {
            bit_coeffs,
            lin_coeffs,
            constants,
        }
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
    /// Per chunk: 1 at the element slots (class 0) of every group.
    group_masks: Vec<Plaintext>,
    /// Per chunk: 1 at the element slots of group 0 only.
    group0_masks: Vec<Plaintext>,
    /// 1 at slot `group_slot(0, 0)` only.
    count0_mask: Plaintext,
    /// 1 at every element slot of group 0 (`group_slot(0, i)`, `i < block`).
    spread0_mask: Plaintext,
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
        let mut group_masks = Vec::with_capacity(layout.num_chunks);
        let mut group0_masks = Vec::with_capacity(layout.num_chunks);
        for c in 0..layout.num_chunks {
            let mut all = vec![0u64; layout.row];
            let mut g0 = vec![0u64; layout.row];
            for i in 0..layout.chunk_len(c) {
                for r in 0..layout.groups {
                    all[layout.group_slot(r, i)] = 1;
                }
                g0[layout.group_slot(0, i)] = 1;
            }
            group_masks.push(ctx.plaintext(&all)?);
            group0_masks.push(ctx.plaintext(&g0)?);
        }
        let mut count0 = vec![0u64; layout.row];
        count0[layout.group_slot(0, 0)] = 1;
        let mut spread0 = vec![0u64; layout.row];
        for i in 0..layout.block {
            spread0[layout.group_slot(0, i)] = 1;
        }
        Ok(Self {
            ctx: ctx.clone(),
            layout: layout.clone(),
            plain_mod: ctx.plain_mod(),
            ones,
            selector,
            group_masks,
            group0_masks,
            count0_mask: ctx.plaintext(&count0)?,
            spread0_mask: ctx.plaintext(&spread0)?,
        })
    }

    /// Silent mode: restricts an accumulated chunk ciphertext to the element
    /// slots of every group (class 0). What a client put anywhere else is
    /// zeroed, so it can neither enter a sum nor be multiplied by another
    /// report's validity bit. One plaintext multiplication (level 1).
    pub fn mask_all_groups(&self, ct: &Ciphertext, chunk: usize) -> Result<Ciphertext> {
        Ok(self.ctx.mult_plain(ct, &self.group_masks[chunk])?)
    }

    /// Secret-shared upload: restricts the sum of the key parties'
    /// contributions of chunk `chunk` to the element slots of the listed
    /// groups (one plaintext multiplication, the level the per-report group
    /// mask uses with ciphertext upload). Whatever a party wrote anywhere
    /// else (another class, an empty group, a constraint slot) is zeroed,
    /// so it can neither enter a sum nor be multiplied by a report's
    /// validity bit without passing through that report's check.
    pub fn mask_to_groups(&self, ct: &Ciphertext, chunk: usize, groups: &[usize]) -> Result<Ciphertext> {
        let l = &self.layout;
        let mut m = vec![0u64; l.row];
        for &r in groups {
            if r >= l.groups {
                return Err(crate::error::Error::Protocol(format!("group {r} outside the layout")));
            }
            for i in 0..l.chunk_len(chunk) {
                m[l.group_slot(r, i)] = 1;
            }
        }
        Ok(self.ctx.mult_plain(ct, &self.ctx.plaintext(&m)?)?)
    }

    /// Silent mode: `valid_r` at slot `group_slot(r, 0)` of every listed
    /// group `r`, zero elsewhere, from `G`. Only the groups that hold a
    /// report in this batch are listed: an empty group's check value is
    /// zero and its validity bit is therefore 1, so it must not be counted.
    /// One plaintext multiplication at the last level of the chain.
    pub fn count_of_groups(&self, g: &Ciphertext, groups: &[usize]) -> Result<Ciphertext> {
        let l = &self.layout;
        let mut ind = vec![0u64; l.row];
        for &r in groups {
            ind[l.group_slot(r, 0)] = 1;
        }
        Ok(self.ctx.mult_plain(g, &self.ctx.plaintext(&ind)?)?)
    }

    /// Batched silent mode: sums every group's slots into group 0's by the
    /// doubling tree over the group fold rotations. Rotations only, no
    /// level. The other groups' slots then hold partial sums over subsets
    /// of the reports and must never be decrypted: [`Self::finalize_chunk`]
    /// and its siblings zero them.
    /// The validity bits of `groups` at every element slot of each group
    /// (`G` holds report `r`'s bit at every slot of group `r`). After the
    /// fold at the close ([`Self::finalize_spread`]) every element slot of
    /// group 0 holds the valid count: the input of the gated release's
    /// batch-size gate, which must reach every slot a released value uses.
    pub fn spread_of_groups(&self, g: &Ciphertext, groups: &[usize]) -> Result<Ciphertext> {
        let l = &self.layout;
        let mut ind = vec![0u64; l.row];
        for &r in groups {
            for i in 0..l.block {
                ind[l.group_slot(r, i)] = 1;
            }
        }
        Ok(self.ctx.mult_plain(g, &self.ctx.plaintext(&ind)?)?)
    }
    /// Fold and group-0 mask of the spread count (see [`Self::spread_of_groups`]).
    pub fn finalize_spread(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        if self.layout.groups == 1 {
            return ct.try_clone().map_err(Into::into);
        }
        Ok(self.ctx.mult_plain(&self.fold_all_groups(ct)?, &self.spread0_mask)?)
    }
    pub fn fold_all_groups(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        let mut out = ct.try_clone()?;
        for d in self.layout.group_fold_keys() {
            out = self.ctx.add(&out, &self.ctx.rotate(&out, d)?)?;
        }
        Ok(out)
    }

    /// Batched silent mode: folds a per-group accumulator of chunk `chunk`
    /// into group 0 and zeroes every other slot (one plaintext
    /// multiplication, the last level of the batched chain). Identity for a
    /// single-group layout, whose accumulators are already clean.
    pub fn finalize_chunk(&self, ct: &Ciphertext, chunk: usize) -> Result<Ciphertext> {
        if self.layout.groups == 1 {
            return ct.try_clone().map_err(Into::into);
        }
        Ok(self.ctx.mult_plain(&self.fold_all_groups(ct)?, &self.group0_masks[chunk])?)
    }

    /// As [`Self::finalize_chunk`] for the valid-count accumulator.
    pub fn finalize_count(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        if self.layout.groups == 1 {
            return ct.try_clone().map_err(Into::into);
        }
        Ok(self.ctx.mult_plain(&self.fold_all_groups(ct)?, &self.count0_mask)?)
    }

    /// As [`Self::finalize_chunk`] for a second-moment accumulator: keeps
    /// the product cells of term `t` at group 0.
    pub fn finalize_moment(&self, ct: &Ciphertext, t: crate::layout::MomentTerm) -> Result<Ciphertext> {
        let l = &self.layout;
        if l.groups == 1 {
            return ct.try_clone().map_err(Into::into);
        }
        let d = l.moment_digit as usize;
        let mut m = vec![0u64; l.row];
        for (pos, _, _) in l.moment_term_cells(t) {
            m[l.group_slot(0, pos * d)] = 1;
        }
        Ok(self.ctx.mult_plain(&self.fold_all_groups(ct)?, &self.ctx.plaintext(&m)?)?)
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
        Ok(ctx.add_plain(&t, &ctx.plaintext(&ch.constants)?)?)
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
        self.moment_products_of_groups(chunks, &[group])
    }

    /// [`Self::moment_products`] for several groups at once: the digit masks
    /// select every listed group's slots, and the alignment rotations,
    /// which move whole element positions, act on all groups alike.
    pub fn moment_products_of_groups(&self, chunks: &[Ciphertext], groups: &[usize]) -> Result<Vec<Ciphertext>> {
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
            for &group in groups {
                for t in 0..bits as usize {
                    w[l.group_slot(group, local + t)] = 1u64 << (t % d);
                }
            }
            let z = ctx.mult_plain(&chunks[k], &ctx.plaintext(&w)?)?;
            let z = self.window_sum(z, window, stride)?;
            let aligned = if local == 0 { z } else { ctx.rotate(&z, (local * stride) as i32)? };
            let digits = l.moment_digits(bits);
            let mut m = vec![0u64; l.row];
            for &group in groups {
                for i in 0..digits {
                    m[l.group_slot(group, i * d)] = 1;
                }
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
            let (x, y) = if t.shift >= 0 {
                (&values[t.a][0], &values[t.b][t.shift as usize])
            } else {
                (&values[t.a][(-t.shift) as usize], &values[t.b][0])
            };
            out.push(if t.a == t.b && t.shift == 0 { ctx.square(x)? } else { ctx.mult(x, y)? });
        }
        Ok(out)
    }

    /// Slot `x` of the result is `z[x] + z[x + stride] + .. + z[x + (w-1)*stride]`.
    /// Doubling sums `P_1, P_2, P_4, ..` cover windows of powers of two; the
    /// set bits of `w` pick some of them, each moved to its offset by
    /// rotations by powers of two below it. Only rotations by `stride * 2^j`
    /// with `2^(j+1) <= w` are used (`Layout::moment_rotations`).
    pub fn window_sum(&self, z: Ciphertext, w: usize, stride: usize) -> Result<Ciphertext> {
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

    /// Silent mode, exact check (Eq. 9 of the paper): `G` with
    /// `a_r = prod_l (1 - e_l^(p-1))` over every residual `e_l` of the
    /// report in group `r`, at every class-0 slot of each listed group (the
    /// same places [`Self::silent_validity`] puts its bit, so gating, counts
    /// and the release are unchanged). `acc` is the batch accumulator, one
    /// ciphertext per chunk, already zero outside the listed groups' element
    /// slots (the per-report group mask, or the share-upload batch mask).
    /// See [`exact_circuit`].
    pub fn exact_validity(&self, cfg: &TaskConfig, field: &Field, acc: &[Ciphertext], groups: &[usize]) -> Result<Ciphertext> {
        exact_circuit(
            &CipherOps {
                ctx: &self.ctx,
                ones: &self.ones,
            },
            &self.layout,
            cfg,
            field,
            acc,
            groups,
        )
    }
}

/// The slot operations of the exact check, so that one implementation
/// ([`exact_circuit`]) runs on ciphertexts and on plaintext slot vectors.
/// `rotate(v, d)` is a left rotation: slot `s` of the result is slot
/// `s + d` (modulo the row) of `v`, OpenFHE's convention.
pub trait SlotOps {
    type V;
    fn add(&self, a: &Self::V, b: &Self::V) -> Result<Self::V>;
    fn mult(&self, a: &Self::V, b: &Self::V) -> Result<Self::V>;
    fn square(&self, a: &Self::V) -> Result<Self::V>;
    fn mult_plain(&self, a: &Self::V, w: &[u64]) -> Result<Self::V>;
    fn add_plain(&self, a: &Self::V, w: &[u64]) -> Result<Self::V>;
    /// `a - 1` in every slot.
    fn sub_one(&self, a: &Self::V) -> Result<Self::V>;
    /// `1 - a` in every slot.
    fn one_minus(&self, a: &Self::V) -> Result<Self::V>;
    fn rotate(&self, a: &Self::V, d: i32) -> Result<Self::V>;
}

struct CipherOps<'a> {
    ctx: &'a Context,
    ones: &'a Plaintext,
}

impl SlotOps for CipherOps<'_> {
    type V = Ciphertext;
    fn add(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        Ok(self.ctx.add(a, b)?)
    }
    fn mult(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        Ok(self.ctx.mult(a, b)?)
    }
    fn square(&self, a: &Ciphertext) -> Result<Ciphertext> {
        Ok(self.ctx.square(a)?)
    }
    fn mult_plain(&self, a: &Ciphertext, w: &[u64]) -> Result<Ciphertext> {
        Ok(self.ctx.mult_plain(a, &self.ctx.plaintext(w)?)?)
    }
    fn add_plain(&self, a: &Ciphertext, w: &[u64]) -> Result<Ciphertext> {
        Ok(self.ctx.add_plain(a, &self.ctx.plaintext(w)?)?)
    }
    fn sub_one(&self, a: &Ciphertext) -> Result<Ciphertext> {
        Ok(self.ctx.sub_plain(a, self.ones)?)
    }
    fn one_minus(&self, a: &Ciphertext) -> Result<Ciphertext> {
        Ok(self.ctx.negate(&self.ctx.sub_plain(a, self.ones)?)?)
    }
    fn rotate(&self, a: &Ciphertext, d: i32) -> Result<Ciphertext> {
        Ok(self.ctx.rotate(a, d)?)
    }
}

/// `x^(p-1)` slot-wise by left-to-right square-and-multiply
/// ([`TaskConfig::fermat_depth`] levels).
fn fermat_with<O: SlotOps>(ops: &O, p: u64, x: &O::V) -> Result<O::V> {
    let e = p - 1;
    let bits = 64 - e.leading_zeros();
    let mut acc = ops.square(x)?;
    if (e >> (bits - 2)) & 1 == 1 {
        acc = ops.mult(&acc, x)?;
    }
    for b in (0..bits - 2).rev() {
        acc = ops.square(&acc)?;
        if (e >> b) & 1 == 1 {
            acc = ops.mult(&acc, x)?;
        }
    }
    Ok(acc)
}

/// The exact check over a batched layout whose `repetitions` are the
/// residue classes it uses: one per chunk, then one per linear constraint.
///
/// Residuals, one value `R`: chunk `c`'s bit residuals `x(x-1)` in class
/// `c`, each element at its own position; linear constraint `k`
/// (`sum_i c_i x_i + c_0`) summed over the positions by the wrapping
/// position sums and placed in class `chunks + k` at every position. Every
/// other slot of a listed group is zero. One Fermat chain then tests every
/// slot at once, and the product of `1 - R^(p-1)` over the group's
/// positions (the position-sum rotations, now multiplying) and then its
/// classes leaves `a_r` at the group's class-0 slots: the position product
/// gives slot `(r, j, i)` the product over class `j` of group `r` (it wraps
/// the row within one class and group), the class product gives class 0
/// the product over the group's classes. A zero slot contributes `1`; the
/// linear residual's copies contribute the same flag `block` times, and a
/// flag is idempotent. Nothing is combined before it is tested, so
/// residuals that cancel in a sum (2 and 336449 modulo 786433: residuals 2
/// and -2) are caught.
///
/// Depth on top of `acc`: 1 (residuals; the linear sums are a plaintext
/// multiplication at the same level) + Fermat + `log2(classes * block)`.
pub fn exact_circuit<O: SlotOps>(ops: &O, l: &Layout, cfg: &TaskConfig, field: &Field, acc: &[O::V], groups: &[usize]) -> Result<O::V> {
    let constraints = cfg.measurement_type.linear_constraints();
    if l.kind != LayoutKind::Batched || acc.len() != l.num_chunks || l.repetitions != l.num_chunks + constraints.len() {
        return Err(crate::error::Error::Protocol("exact check: accumulator does not match the layout".into()));
    }
    if let Some(&r) = groups.iter().find(|&&r| r >= l.groups) {
        return Err(crate::error::Error::Protocol(format!("group {r} outside the layout")));
    }
    let mut terms: Vec<O::V> = Vec::with_capacity(l.repetitions);
    for (c, x) in acc.iter().enumerate() {
        let e = ops.mult(x, &ops.sub_one(x)?)?;
        terms.push(if c == 0 { e } else { ops.rotate(&e, l.replicate_rotation(c))? });
    }
    let mut constants = vec![0u64; l.row];
    for (k, lc) in constraints.iter().enumerate() {
        let coeffs: Vec<(usize, u64)> = lc.field_coeffs(field).collect();
        let mut v: Option<O::V> = None;
        for (c, x) in acc.iter().enumerate() {
            let range = l.chunk_range(c);
            let mut w = vec![0u64; l.row];
            let mut any = false;
            for &(i, coef) in &coeffs {
                if range.contains(&i) {
                    for &r in groups {
                        w[l.group_slot(r, i - range.start)] = coef;
                    }
                    any = true;
                }
            }
            if any {
                let t = ops.mult_plain(x, &w)?;
                v = Some(match v {
                    None => t,
                    Some(a) => ops.add(&a, &t)?,
                });
            }
        }
        let Some(mut v) = v else {
            return Err(crate::error::Error::Protocol("exact check: a linear constraint touches no element".into()));
        };
        // every position of the group's class 0 now holds sum_i c_i x_i
        for d in l.sum_rotations() {
            v = ops.add(&v, &ops.rotate(&v, d)?)?;
        }
        let class = l.num_chunks + k;
        let constant = lc.field_constant(field);
        for &r in groups {
            for i in 0..l.block {
                constants[l.group_slot(r, i) + class] = constant;
            }
        }
        terms.push(ops.rotate(&v, l.replicate_rotation(class))?);
    }
    let mut r_v = terms.remove(0);
    for t in &terms {
        r_v = ops.add(&r_v, t)?;
    }
    if !constraints.is_empty() {
        r_v = ops.add_plain(&r_v, &constants)?;
    }
    let f = fermat_with(ops, field.modulus(), &r_v)?;
    let mut g = ops.one_minus(&f)?;
    for d in l.sum_rotations().into_iter().chain(l.product_rotations()) {
        g = ops.mult(&g, &ops.rotate(&g, d)?)?;
    }
    Ok(g)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CollectorPolicy, EXACT_ROW};
    use crate::types::{Measurement, MeasurementType};
    use rand::{Rng, SeedableRng};

    /// Plaintext slot vectors modulo `p`, with OpenFHE's rotation convention.
    struct PlainOps {
        f: Field,
    }
    impl SlotOps for PlainOps {
        type V = Vec<u64>;
        fn add(&self, a: &Vec<u64>, b: &Vec<u64>) -> Result<Vec<u64>> {
            Ok(a.iter().zip(b).map(|(&x, &y)| self.f.add(x, y)).collect())
        }
        fn mult(&self, a: &Vec<u64>, b: &Vec<u64>) -> Result<Vec<u64>> {
            Ok(a.iter().zip(b).map(|(&x, &y)| self.f.mul(x, y)).collect())
        }
        fn square(&self, a: &Vec<u64>) -> Result<Vec<u64>> {
            self.mult(a, a)
        }
        fn mult_plain(&self, a: &Vec<u64>, w: &[u64]) -> Result<Vec<u64>> {
            self.mult(a, &w.to_vec())
        }
        fn add_plain(&self, a: &Vec<u64>, w: &[u64]) -> Result<Vec<u64>> {
            self.add(a, &w.to_vec())
        }
        fn sub_one(&self, a: &Vec<u64>) -> Result<Vec<u64>> {
            Ok(a.iter().map(|&x| self.f.sub(x, 1)).collect())
        }
        fn one_minus(&self, a: &Vec<u64>) -> Result<Vec<u64>> {
            Ok(a.iter().map(|&x| self.f.sub(1, x)).collect())
        }
        fn rotate(&self, a: &Vec<u64>, d: i32) -> Result<Vec<u64>> {
            let n = a.len() as i64;
            Ok((0..n).map(|s| a[(s + d as i64).rem_euclid(n) as usize]).collect())
        }
    }

    fn random_measurement(t: &MeasurementType, rng: &mut impl Rng) -> Measurement {
        match t {
            MeasurementType::Count => Measurement::Count(rng.gen_bool(0.5)),
            MeasurementType::Sum { max_measurement } => Measurement::Sum(rng.gen_range(0..=*max_measurement)),
            MeasurementType::SumVec { length, max_measurement } => Measurement::SumVec((0..*length).map(|_| rng.gen_range(0..=*max_measurement)).collect()),
            MeasurementType::BoundedSumVec { bounds } => Measurement::SumVec(bounds.iter().map(|&b| rng.gen_range(0..=b)).collect()),
            MeasurementType::Histogram { length } => Measurement::Histogram(rng.gen_range(0..*length)),
            MeasurementType::MultihotCountVec { length, max_weight } => {
                let mut v = vec![false; *length];
                for _ in 0..rng.gen_range(0..=*max_weight) {
                    v[rng.gen_range(0..*length)] = true;
                }
                Measurement::MultihotCountVec(v)
            }
        }
    }

    /// The predicate `V_T` of the paper, computed directly: every
    /// coordinate a bit and every linear constraint zero modulo `p`.
    fn valid(t: &MeasurementType, f: &Field, x: &[u64]) -> bool {
        x.iter().all(|&v| v <= 1)
            && t.linear_constraints().iter().all(|c| {
                let mut s = c.field_constant(f);
                for (i, coef) in c.field_coeffs(f) {
                    s = f.add(s, f.mul(coef, x[i]));
                }
                s == 0
            })
    }

    /// One report's encoding, valid or broken in one of the ways a
    /// malicious client can break it.
    fn report(t: &MeasurementType, f: &Field, rng: &mut impl Rng) -> Vec<u64> {
        let mut x = t.encode(&random_measurement(t, rng)).unwrap();
        let m = x.len();
        match rng.gen_range(0..8) {
            0..=2 => {}
            3 => x[rng.gen_range(0..m)] = rng.gen_range(2..f.modulus()),
            4 => x[rng.gen_range(0..m)] = 2,
            5 => {
                // the cancellation pair: residuals 2 and -2
                let i = rng.gen_range(0..m);
                x[i] = 2;
                if m > 1 {
                    x[(i + 1) % m] = 336_449;
                }
            }
            6 => {
                // bits only, any pattern (breaks one-hot and weight constraints)
                for v in x.iter_mut() {
                    *v = rng.gen_range(0..2);
                }
            }
            _ => {
                for v in x.iter_mut() {
                    *v = rng.gen_range(0..f.modulus());
                }
            }
        }
        x
    }

    /// The exact circuit, evaluated on plaintext slots, puts at every
    /// class-0 element slot of every listed group exactly the predicate of
    /// that group's report, for every type and slot shape, full and partly
    /// filled batches, and clients that write junk all over the row (which
    /// the per-report group mask removes before the circuit, as the
    /// aggregator does). The cancellation pair is rejected.
    #[test]
    fn exact_circuit_computes_the_predicate_in_every_group() {
        let f = Field::new(crate::config::SILENT_PLAIN_MOD).unwrap();
        assert_eq!(f.mul(2, 1), 2);
        assert_eq!(f.mul(336_449, 336_448), f.modulus() - 2, "the cancellation pair's residuals are 2 and -2");
        let ops = PlainOps { f };
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x0004_5719);
        let split = |t: MeasurementType| {
            let mut c = TaskConfig::new_exact([1; 32], t.clone(), 2);
            c.collectors = (0..t.num_elements())
                .map(|e| CollectorPolicy {
                    elements: vec![e],
                    moments: false,
                    seal_key: [9; 32],
                })
                .collect();
            let (_, classes, block) = c.exact_shape();
            c.silent_batch_groups = EXACT_ROW / (classes * block);
            c
        };
        let cfgs = vec![
            TaskConfig::new_exact([1; 32], MeasurementType::Count, 2),
            TaskConfig::new_exact([1; 32], MeasurementType::Sum { max_measurement: 3 }, 2),
            TaskConfig::new_exact([1; 32], MeasurementType::Sum { max_measurement: 100 }, 2),
            TaskConfig::new_exact([1; 32], MeasurementType::Histogram { length: 3 }, 2),
            TaskConfig::new_exact([1; 32], MeasurementType::Histogram { length: 5 }, 2),
            TaskConfig::new_exact([1; 32], MeasurementType::MultihotCountVec { length: 4, max_weight: 2 }, 2),
            split(MeasurementType::SumVec { length: 2, max_measurement: 3 }),
            split(MeasurementType::BoundedSumVec { bounds: vec![1, 5] }),
        ];
        for cfg in cfgs {
            cfg.validate().unwrap();
            let t = cfg.measurement_type.clone();
            let l = cfg.layout(EXACT_ROW).unwrap();
            let (chunks, classes, block) = cfg.exact_shape();
            assert_eq!((l.num_chunks, l.classes, l.block, l.groups), (chunks, classes, block, cfg.silent_batch_groups));
            let mut rejected_pairs = 0;
            for fill in [l.groups, l.groups / 2 + 1, 1] {
                let mut groups: Vec<usize> = (0..l.groups).collect();
                for i in (1..groups.len()).rev() {
                    groups.swap(i, rng.gen_range(0..=i));
                }
                groups.truncate(fill);
                // what clients write outside their own slots (zeroed by the mask)
                let junk: Vec<u64> = (0..l.row).map(|_| rng.gen_range(0..f.modulus())).collect();
                let mut acc = vec![vec![0u64; l.row]; l.num_chunks];
                let mut expect = vec![None; l.groups];
                for &r in &groups {
                    let x = report(&t, &f, &mut rng);
                    expect[r] = Some(valid(&t, &f, &x));
                    if x.contains(&336_449) && x.contains(&2) {
                        rejected_pairs += 1;
                        assert_eq!(expect[r], Some(false));
                    }
                    for (c, a) in acc.iter_mut().enumerate() {
                        // the client's ciphertext: its elements at its group's
                        // slots and junk everywhere else
                        let mut slots = junk.clone();
                        for (local, global) in l.chunk_range(c).enumerate() {
                            slots[l.group_slot(r, local)] = x[global];
                        }
                        // the aggregator's per-report group mask
                        let mut mask = vec![0u64; l.row];
                        for i in 0..l.chunk_len(c) {
                            mask[l.group_slot(r, i)] = 1;
                        }
                        let masked = ops.mult_plain(&slots, &mask).unwrap();
                        *a = ops.add(a, &masked).unwrap();
                    }
                }
                let g = exact_circuit(&ops, &l, &cfg, &f, &acc, &groups).unwrap();
                for &r in &groups {
                    let want = expect[r].unwrap() as u64;
                    for i in 0..l.block {
                        assert_eq!(g[l.group_slot(r, i)], want, "{t:?}: group {r} position {i}");
                    }
                }
            }
            assert!(rejected_pairs > 0 || t.input_len() == 1, "{t:?}: the cancellation pair was exercised");
        }
    }

    /// The layout refuses an accumulator of the wrong shape and groups
    /// outside the row.
    #[test]
    fn exact_circuit_refuses_mismatched_inputs() {
        let f = Field::new(crate::config::SILENT_PLAIN_MOD).unwrap();
        let ops = PlainOps { f };
        let cfg = TaskConfig::new_exact([1; 32], MeasurementType::Histogram { length: 3 }, 2);
        let l = cfg.layout(EXACT_ROW).unwrap();
        let acc = vec![vec![0u64; l.row]; l.num_chunks];
        assert!(exact_circuit(&ops, &l, &cfg, &f, &acc, &[l.groups]).is_err());
        assert!(exact_circuit(&ops, &l, &cfg, &f, &[], &[0]).is_err());
        let other = TaskConfig::new_exact([1; 32], MeasurementType::Count, 2);
        assert!(exact_circuit(&ops, &other.layout(EXACT_ROW).unwrap(), &cfg, &f, &acc, &[0]).is_err());
    }
}
