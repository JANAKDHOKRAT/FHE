//! Verifiable decryption: a verifier learns whether the partial
//! decryptions it received are those of the ciphertexts it holds, without
//! any party proving anything about its key.
//!
//! Why it is needed. Every decryption in the protocol fuses one partial
//! decryption per aggregator. A malicious aggregator can shift its partial
//! by any `Δ`, which shifts the decrypted plaintext by a value it chooses.
//! Unchecked, that lets it change a released aggregate, and in silent mode
//! it lets it change the decrypted count of valid reports on which every
//! honest aggregator bases the `min_batch_size` release decision: shifting
//! a batch with one valid report up to the minimum makes the honest
//! aggregators release that one report to a colluding collector.
//!
//! Blinded known-answer check. For accumulators `c_1..c_A` (grouped by
//! metadata, see [`groups`]) the verifier draws, per check, exponents
//! `k_a` in `[0, 2N)` and randomness `(u, e0, e1)` and forms
//!
//! ```text
//!     C = sum_a X^(k_a) c_a + Z,      Z = (b u + t e0, a u + t e1)
//! ```
//!
//! an encryption of `sum_a X^(k_a) m_a` (slot `s`: `sum_a w_s^(k_a) m_a[s]`,
//! `w_s` the slot values of `X`, primitive `2N`-th roots of unity mod `t`).
//! `Z` is a public-key encryption of zero, so `C` hides the `k_a`
//! (RLWE). Every aggregator commits to its partial decryptions of the checks
//! before the verifier reveals `(k, u, e0, e1)`; the aggregators then rebuild
//! `C` from their own accumulators and the opening and reveal their partials
//! only if it matches, so the verifier cannot use a "check" to have
//! anything else decrypted. The verifier accepts only if, in every slot,
//! the fused check equals `sum_a w_s^(k_a)` times the fused accumulators,
//! and every fusion stays below `q0 / 4` before it is reduced mod `t`
//! ([`Context::fuse_magnitude`]; honest fusions measured 12+ bits below).
//!
//! Soundness sketch. The magnitude bound makes every accepted fusion the
//! honest value plus the cheater's shift without a wrap modulo `q0`, so the
//! plaintext shifts `δ_a` (fixed when the accumulator partials were
//! released) and `δ'` (fixed when the check partials were committed) enter
//! linearly, and the check passes only if `δ'[s] = sum_a w_s^(k_a) δ_a[s]` in
//! every slot. If some `δ_a[s] ≠ 0`, the right side takes a different value
//! for each of the `2N` values of `k_a` (`w_s` has order `2N`), and `k_a` is
//! hidden when `δ'` is fixed, so one check passes with probability at most
//! `1/(2N)` plus the RLWE advantage; [`check_count`] checks give
//! `2^-CHECK_SECURITY_BITS`. The full argument, with its assumptions, is in
//! `SECURITY.md`.
//!
//! What it does not do: identify which aggregator cheated (only that one
//! did), or stop an aggregator from refusing to answer.

use crate::error::{Error, Result};
use openfhe_tbgv_rs::{Ciphertext, CiphertextMeta, Context, PartialDecryption, PublicKey};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Soundness target of the checks, in bits.
pub const CHECK_SECURITY_BITS: u32 = 80;
/// Bound of the centered binomial noise `e0, e1` of the blinding encryption
/// (variance `ETA / 2`, as the Gaussian of OpenFHE's own encryptions).
pub const ETA: i8 = 20;

pub const VDEC_DOMAIN: &[u8] = b"fhe-prio3/1 vdec";

/// Checks per metadata group for ring dimension `n`: each passes a cheater
/// with probability at most `1/(2n)`.
pub fn check_count(n: usize) -> usize {
    let bits = (2 * n as u64).ilog2();
    CHECK_SECURITY_BITS.div_ceil(bits) as usize
}

/// The opening of one check: its group, one exponent per accumulator of
/// the group, and the blinding randomness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckOpening {
    pub group: u32,
    pub ks: Vec<u32>,
    pub u: Vec<i8>,
    pub e0: Vec<i8>,
    pub e1: Vec<i8>,
}

/// Everything a verifier reveals after the commitments, in check order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opening {
    pub checks: Vec<CheckOpening>,
}

/// Accumulators grouped by metadata (checks add ciphertexts of one shape
/// only, so no level adjustment happens at the bottom of the chain). Each
/// group lists accumulator indices in ascending order; groups are ordered
/// by their first index.
pub fn groups(accs: &[&Ciphertext]) -> Result<Vec<Vec<usize>>> {
    let mut keys: Vec<CiphertextMeta> = Vec::new();
    let mut out: Vec<Vec<usize>> = Vec::new();
    for (i, c) in accs.iter().enumerate() {
        let m = c.meta()?;
        match keys.iter().position(|k| *k == m) {
            Some(g) => out[g].push(i),
            None => {
                keys.push(m);
                out.push(vec![i]);
            }
        }
    }
    Ok(out)
}

/// Centered binomial sample in `[-ETA, ETA]`: the difference of the
/// popcounts of two independent `ETA`-bit uniform words.
fn cbd(rng: &mut impl Rng) -> i8 {
    const MASK: u64 = (1 << ETA) - 1;
    let w: u64 = rng.r#gen();
    (w & MASK).count_ones() as i8 - ((w >> ETA) & MASK).count_ones() as i8
}

/// Draws a fresh opening for `accs` (secret until the commitments are in).
/// `rng` (the operating system's generator in the protocol) seeds a
/// ChaCha-based CSPRNG (`StdRng`) for the bulk sampling: millions of
/// samples per draw, one system call.
pub fn draw(ctx: &Context, accs: &[&Ciphertext], rng: &mut impl Rng) -> Result<Opening> {
    let mut rng = StdRng::from_rng(rng).map_err(|e| Error::Protocol(format!("seeding the check sampler: {e}")))?;
    let rng = &mut rng;
    let n = ctx.ring_dim() as usize;
    let mut checks = Vec::new();
    for (g, members) in groups(accs)?.iter().enumerate() {
        for _ in 0..check_count(n) {
            checks.push(CheckOpening {
                group: g as u32,
                ks: members.iter().map(|_| rng.gen_range(0..2 * n as u32)).collect(),
                u: (0..n).map(|_| rng.gen_range(-1i8..=1)).collect(),
                e0: (0..n).map(|_| cbd(rng)).collect(),
                e1: (0..n).map(|_| cbd(rng)).collect(),
            });
        }
    }
    Ok(Opening { checks })
}

/// The check ciphertexts an opening defines over `accs`. Deterministic, so
/// the aggregators rebuild exactly what the verifier sent. Refuses an
/// opening of the wrong shape or with randomness outside its ranges.
pub fn build(ctx: &Context, pk: &PublicKey, accs: &[&Ciphertext], opening: &Opening) -> Result<Vec<Ciphertext>> {
    let n = ctx.ring_dim() as usize;
    let gs = groups(accs)?;
    let per = check_count(n);
    if opening.checks.len() != gs.len() * per {
        return Err(Error::Protocol(format!("vdec: {} checks, expected {}", opening.checks.len(), gs.len() * per)));
    }
    let mut out = Vec::with_capacity(opening.checks.len());
    for (i, ch) in opening.checks.iter().enumerate() {
        let g = i / per;
        if ch.group as usize != g || ch.ks.len() != gs[g].len() {
            return Err(Error::Protocol("vdec: check opening does not match the accumulator groups".into()));
        }
        if ch.ks.iter().any(|&k| k as usize >= 2 * n) {
            return Err(Error::Protocol("vdec: exponent out of range".into()));
        }
        if ch.u.len() != n || ch.e0.len() != n || ch.e1.len() != n {
            return Err(Error::Protocol("vdec: blinding randomness has the wrong length".into()));
        }
        if ch.u.iter().any(|&x| !(-1..=1).contains(&x)) || ch.e0.iter().chain(&ch.e1).any(|&x| !(-ETA..=ETA).contains(&x)) {
            return Err(Error::Protocol("vdec: blinding randomness out of range".into()));
        }
        let mut sum: Option<Ciphertext> = None;
        for (&a, &k) in gs[g].iter().zip(&ch.ks) {
            let term = ctx.mult_monomial(accs[a], k)?;
            sum = Some(match sum {
                None => term,
                Some(s) => ctx.add(&s, &term)?,
            });
        }
        let sum = sum.expect("groups are non-empty");
        let z = ctx.zero_encryption(pk, &sum, &ch.u, &ch.e0, &ch.e1)?;
        out.push(ctx.add(&sum, &z)?);
    }
    Ok(out)
}

/// Whether two ciphertexts are the same object (metadata and residues).
pub fn same(a: &Ciphertext, b: &Ciphertext) -> Result<bool> {
    Ok(a.meta()? == b.meta()? && a.export_residues()? == b.export_residues()?)
}

/// Commitment to one encoded partial decryption.
pub fn commit(context: &[u8], partial: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((VDEC_DOMAIN.len() as u32).to_le_bytes());
    h.update(VDEC_DOMAIN);
    h.update((context.len() as u64).to_le_bytes());
    h.update(context);
    h.update(Sha256::digest(partial));
    h.finalize().into()
}

/// A fusion of every aggregator's partial decryption, checked to stay below
/// `q0 / 4` before its reduction mod `t`; returns all `N` slots.
pub fn fuse_checked(ctx: &Context, partials: &[&PartialDecryption], what: &str) -> Result<Vec<u64>> {
    let (mx, q0) = ctx.fuse_magnitude(partials)?;
    if mx >= q0 / 4 {
        return Err(Error::Protocol(format!("vdec: {what}: fused value reaches q0/4 (a partial decryption is not what it should be, or the ciphertext's noise overflowed)")));
    }
    Ok(ctx.fuse(partials, ctx.ring_dim() as usize)?)
}

/// Powers of the slot values of `X`: slot `s` raised to `k` in O(1), from
/// discrete logarithms to the base `w_0` (every `w_s` is an odd power of it).
pub struct SlotPowers {
    p: u64,
    table: Vec<u64>,
    log: Vec<u32>,
}

impl SlotPowers {
    pub fn new(ctx: &Context) -> Result<Self> {
        let p = ctx.plain_mod();
        let w = ctx.monomial_slots()?;
        let two_n = 2 * w.len();
        let mut table = Vec::with_capacity(two_n);
        let mut x = 1u64;
        for _ in 0..two_n {
            table.push(x);
            x = ((x as u128 * w[0] as u128) % p as u128) as u64;
        }
        if x != 1 {
            return Err(Error::Protocol("vdec: slot value of X is not a 2N-th root of unity".into()));
        }
        let mut index = std::collections::HashMap::with_capacity(two_n);
        for (j, &v) in table.iter().enumerate() {
            if index.insert(v, j as u32).is_some() {
                return Err(Error::Protocol("vdec: slot value of X is not a primitive 2N-th root of unity".into()));
            }
        }
        let log = w.iter().map(|v| index.get(v).copied().ok_or_else(|| Error::Protocol("vdec: slot values of X are not powers of one root".into()))).collect::<Result<Vec<_>>>()?;
        Ok(Self { p, table, log })
    }

    fn pow(&self, slot: usize, k: u32) -> u64 {
        let two_n = self.table.len() as u64;
        self.table[((self.log[slot] as u64 * k as u64) % two_n) as usize]
    }
}

/// The verifier's acceptance test: for every check and every slot, the
/// fused check equals `sum_a w_s^(k_a) fused_a[s]` mod `t`. `fused_accs`
/// and `fused_checks` hold all `N` slots, in accumulator and check order.
pub fn verify(powers: &SlotPowers, accs_groups: &[Vec<usize>], fused_accs: &[Vec<u64>], fused_checks: &[Vec<u64>], opening: &Opening) -> Result<()> {
    if fused_checks.len() != opening.checks.len() {
        return Err(Error::Protocol("vdec: wrong number of fused checks".into()));
    }
    let p = powers.p as u128;
    for (i, (ch, got)) in opening.checks.iter().zip(fused_checks).enumerate() {
        let members = accs_groups.get(ch.group as usize).ok_or_else(|| Error::Protocol("vdec: unknown group".into()))?;
        for (s, &g) in got.iter().enumerate() {
            let mut want = 0u128;
            for (&a, &k) in members.iter().zip(&ch.ks) {
                want += powers.pow(s, k) as u128 * fused_accs[a][s] as u128 % p;
            }
            if (want % p) as u64 != g {
                return Err(Error::Protocol(format!("vdec: check {i} fails in slot {s}: an aggregator's partial decryption is not a decryption of the agreed ciphertexts")));
            }
        }
    }
    Ok(())
}
