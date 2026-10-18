//! Well-formed encryptions: a zero-knowledge proof that a ciphertext a party
//! contributes is a public-key encryption with short randomness.
//!
//! Why it is needed. The gated release (`gate.rs`) has every key party add
//! ciphertexts of its own to ciphertexts the others decrypt: masks that
//! hide a value being re-encrypted, and random factors that hide a gate's
//! value. Their plaintexts can be anything (a party gains nothing from
//! choosing them), but their *noise* cannot: a contribution with oversized
//! noise makes the noise of everything computed from it depend on the
//! plaintexts it is multiplied with, and whoever fuses the final partial
//! decryptions reads that noise at full precision, above the honest
//! parties' flooding. That would expose suppressed cells and batches below
//! the minimum. The runtime flooding bound (`vdec::check_flooding`) only
//! helps when the fuser is honest; here the fuser can be the adversary.
//!
//! Statement. For a ciphertext `C` with the metadata of a fresh encryption,
//! knowledge of `(m, u, e0, e1)` with `C = Enc(m; u, e0, e1) =
//! (b u + t e0 + m, a u + t e1)` under the joint public key `(b, a)`.
//!
//! Protocol (Fiat–Shamir, `R` parallel repetitions). The prover draws
//! masking `(m', u', e0', e1')`, `m'` uniform mod `t`, `u'` uniform in
//! `[-B_U, B_U]`, `e'` uniform in `[-B_E, B_E]`, and forms
//! `A_i = Enc(m'; u', e0', e1')`. The challenges `c_i = X^(k_i)`, `k_i` in
//! `[0, 2N)`, are hashed from the context, `C` and every `A_i`. It answers
//! `z = (m' + c m mod t, u' + c u, e0' + c e0 + κ, e1' + c e1)` (`κ` the
//! carry of the plaintext sum mod `t`, in `{-1, 0, 1}`), and restarts if any
//! coefficient falls outside `B - β` (`β` the bound of the secret it masks),
//! so every accepted response is uniform on its range whatever the secret
//! (rejection sampling: zero knowledge, statistically perfect). The
//! verifier checks the ranges, rebuilds `A_i = Enc(z) - c_i C` and the
//! challenges from them.
//!
//! Soundness. Two accepting answers for one set of `A_i` with `k ≠ k'`
//! give `(X^k - X^k') C = Enc(Δz)`; `2 / (X^k - X^k')` has coefficients in
//! `{-1, 0, 1}` in `Z[X]/(X^N + 1)` (Benhamouda, Camenisch, Krenn,
//! Lyubashevsky, Neven 2014), so `2C = Enc(m''; u'', e0'', e1'')` with
//! `|u''| <= 2 N B_U`, `|e''| <= 2 N (B_E + 1)`. A prover that cannot
//! open `2C` that way answers at most one of the `2N` challenges per
//! repetition: success `(1/2N)^R`, `2^-85` with `R = 5` at `N = 65536`.
//! The protocol therefore uses the **effective** contribution `2C`
//! ([`effective`]); an honest prover encrypts half its intended plaintext.
//! A cheater who does not guess `k` keeps its accepted randomness within
//! about `B_U` and `B_E` per coefficient (the response must stay in range
//! for the challenge it gets); the extraction bound `2N B` is the proven
//! worst case. Either way the effective noise is a bounded multiple of an
//! honest encryption's, far below the flooding margins measured in
//! `tests/gate_noise.rs`.

use crate::error::{Error, Result};
use openfhe_tbgv_rs::{Ciphertext, Context, PublicKey};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const WFE_DOMAIN: &[u8] = b"fhe-prio3/1 wfe";
/// Bound of the honest `u` (ternary).
pub const BETA_U: i32 = 1;
/// Bound of the honest `e0, e1` (centered binomial, as `vdec::ETA`).
pub const BETA_E: i32 = crate::vdec::ETA as i32;
/// Masking range of `u'`.
pub const B_U: i32 = 1 << 24;
/// Masking range of `e0', e1'`.
pub const B_E: i32 = 1 << 29;
/// Restarts before the prover gives up (each succeeds with probability
/// about 0.95 at `N = 65536`: failing 64 in a row is below `2^-270`).
const MAX_ATTEMPTS: usize = 64;

/// Repetitions for ring dimension `n`: each passes a cheater with
/// probability `1/(2n)`; the same target as `vdec`.
pub fn repetitions(n: usize) -> usize {
    crate::vdec::check_count(n)
}

/// The prover's secret: the raw plaintext polynomial and the randomness.
/// Zeroed on drop.
pub struct Witness {
    pub m: Vec<u64>,
    pub u: Vec<i32>,
    pub e0: Vec<i32>,
    pub e1: Vec<i32>,
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.m.zeroize();
        self.u.zeroize();
        self.e0.zeroize();
        self.e1.zeroize();
    }
}

/// One repetition's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub zm: Vec<u32>,
    pub zu: Vec<i32>,
    pub ze0: Vec<i32>,
    pub ze1: Vec<i32>,
}

/// A proof: the hash of the commitments, from which the challenges are
/// expanded, and one response per repetition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub commitments: [u8; 32],
    pub responses: Vec<Response>,
}

/// `X^k v` in `Z[X]/(X^N + 1)` for `k < 2N`.
fn monomial_mul<T: Copy + std::ops::Neg<Output = T>>(v: &[T], k: usize) -> Vec<T> {
    let n = v.len();
    let (neg, s) = (k >= n, k % n);
    (0..n)
        .map(|j| {
            let (x, wrapped) = if j >= s { (v[j - s], false) } else { (v[j + n - s], true) };
            if neg ^ wrapped { -x } else { x }
        })
        .collect()
}

fn ct_hash(ct: &Ciphertext) -> Result<[u8; 32]> {
    let meta = ct.meta()?;
    let mut h = Sha256::new();
    h.update(postcard::to_allocvec(&(meta.num_elements, meta.num_towers, meta.level, meta.noise_scale_deg, meta.scaling_factor_int)).expect("serializable"));
    for r in ct.export_residues()? {
        h.update(r.to_le_bytes());
    }
    Ok(h.finalize().into())
}

fn commitments_hash(context: &[u8], statement: &[u8; 32], commitments: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((WFE_DOMAIN.len() as u32).to_le_bytes());
    h.update(WFE_DOMAIN);
    h.update((context.len() as u64).to_le_bytes());
    h.update(context);
    h.update(statement);
    h.update((commitments.len() as u32).to_le_bytes());
    for c in commitments {
        h.update(c);
    }
    h.finalize().into()
}

/// The challenge exponents in `[0, 2n)` expanded from the commitment hash.
fn challenges(hash: &[u8; 32], reps: usize, n: usize) -> Vec<usize> {
    debug_assert!(n.is_power_of_two());
    (0..reps)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"challenge");
            h.update(hash);
            h.update((i as u32).to_le_bytes());
            let d: [u8; 32] = h.finalize().into();
            (u64::from_le_bytes(d[..8].try_into().expect("8 bytes")) as usize) & (2 * n - 1)
        })
        .collect()
}

/// The deterministic encryption `Enc(m; u, e0, e1)` on `reference`'s shape.
fn enc(ctx: &Context, pk: &PublicKey, reference: &Ciphertext, m: &[u64], u: &[i32], e0: &[i32], e1: &[i32]) -> Result<Ciphertext> {
    Ok(ctx.encryption_with(pk, reference, Some(m), u, e0, e1)?)
}

/// Encrypts the raw plaintext polynomial `m` (coefficients in `[0, t)`)
/// with fresh short randomness (ternary `u`, centered-binomial `e0, e1`)
/// and returns the ciphertext with its witness, for a caller that proves it
/// later ([`prove`]) under a context that depends on the ciphertext itself
/// (a client binds its proofs to the report id, a hash over every chunk).
/// `reference` is a fresh encryption (its metadata is the statement's).
pub fn encrypt_with_witness(ctx: &Context, pk: &PublicKey, reference: &Ciphertext, m: &[u64], rng: &mut impl rand::RngCore) -> Result<(Ciphertext, Witness)> {
    let mut rng = StdRng::from_rng(rng).map_err(|e| Error::Protocol(format!("seeding the encryption sampler: {e}")))?;
    sample_and_encrypt(ctx, pk, reference, m, &mut rng)
}

/// Draws the witness from `rng` (in the order `u`, `e0`, `e1`) and encrypts.
fn sample_and_encrypt(ctx: &Context, pk: &PublicKey, reference: &Ciphertext, m: &[u64], rng: &mut StdRng) -> Result<(Ciphertext, Witness)> {
    let n = ctx.ring_dim() as usize;
    let t = ctx.plain_mod();
    if m.len() != n || m.iter().any(|&x| x >= t) {
        return Err(Error::Protocol("wfe: plaintext must have the ring dimension and coefficients below t".into()));
    }
    let cbd = |rng: &mut StdRng| -> i32 {
        const MASK: u64 = (1 << crate::vdec::ETA) - 1;
        let w: u64 = rng.r#gen();
        (w & MASK).count_ones() as i32 - ((w >> crate::vdec::ETA) & MASK).count_ones() as i32
    };
    let w = Witness {
        m: m.to_vec(),
        u: (0..n).map(|_| rng.gen_range(-BETA_U..=BETA_U)).collect(),
        e0: (0..n).map(|_| cbd(rng)).collect(),
        e1: (0..n).map(|_| cbd(rng)).collect(),
    };
    let c = enc(ctx, pk, reference, &w.m, &w.u, &w.e0, &w.e1)?;
    Ok((c, w))
}

/// Encrypts the raw plaintext polynomial `m` (coefficients in `[0, t)`)
/// with fresh short randomness and proves it well formed. `reference` is a
/// fresh encryption (its metadata is the statement's); `context` binds the
/// proof to its use (task, batch, party, role), so it cannot be replayed
/// as another party's or another value's. For a given `rng` state the
/// output is the one earlier builds produced (share-upload contributions
/// are reproduced from a seed after a restart).
pub fn encrypt_proven(
    ctx: &Context,
    pk: &PublicKey,
    reference: &Ciphertext,
    m: &[u64],
    context: &[u8],
    rng: &mut impl rand::RngCore,
) -> Result<(Ciphertext, Proof)> {
    let mut rng = StdRng::from_rng(rng).map_err(|e| Error::Protocol(format!("seeding the proof sampler: {e}")))?;
    let (c, w) = sample_and_encrypt(ctx, pk, reference, m, &mut rng)?;
    let proof = prove(ctx, pk, reference, &c, &w, context, &mut rng)?;
    Ok((c, proof))
}

/// An upper bound on the postcard encoding of a [`Proof`] at ring
/// dimension `n` with plaintext modulus below `2^32`: the 32-byte
/// commitment hash, a length prefix (at most 5 bytes), and per repetition
/// four length prefixes (5 bytes each) and `n` coefficients of each of the
/// four vectors, each a varint of at most 5 bytes (`zm < t < 2^32`; the
/// others zig-zag encoded, magnitudes below `B_E < 2^30`).
pub fn proof_size_bound(n: usize) -> usize {
    32 + 5 + repetitions(n) * (4 * 5 + 4 * 5 * n)
}

/// Proves `c = Enc(w)`. Exposed for tests (a prover with a malformed
/// witness must fail verification).
pub fn prove(ctx: &Context, pk: &PublicKey, reference: &Ciphertext, c: &Ciphertext, w: &Witness, context: &[u8], rng: &mut impl Rng) -> Result<Proof> {
    let n = ctx.ring_dim() as usize;
    let t = ctx.plain_mod();
    let reps = repetitions(n);
    let statement = ct_hash(c)?;
    // the raw plaintext lifted to integers, for the carry
    let m_lift: Vec<i64> = w.m.iter().map(|&x| x as i64).collect();
    for _ in 0..MAX_ATTEMPTS {
        let mut masks = Vec::with_capacity(reps);
        let mut hashes = Vec::with_capacity(reps);
        for _ in 0..reps {
            let mm: Vec<u64> = (0..n).map(|_| rng.gen_range(0..t)).collect();
            let mu: Vec<i32> = (0..n).map(|_| rng.gen_range(-B_U..=B_U)).collect();
            let me0: Vec<i32> = (0..n).map(|_| rng.gen_range(-B_E..=B_E)).collect();
            let me1: Vec<i32> = (0..n).map(|_| rng.gen_range(-B_E..=B_E)).collect();
            hashes.push(ct_hash(&enc(ctx, pk, reference, &mm, &mu, &me0, &me1)?)?);
            masks.push((mm, mu, me0, me1));
        }
        let commitments = commitments_hash(context, &statement, &hashes);
        let ks = challenges(&commitments, reps, n);
        let mut responses = Vec::with_capacity(reps);
        let mut rejected = false;
        for ((mm, mu, me0, me1), &k) in masks.iter().zip(&ks) {
            let cm = monomial_mul(&m_lift, k);
            let cu = monomial_mul(&w.u, k);
            let ce0 = monomial_mul(&w.e0, k);
            let ce1 = monomial_mul(&w.e1, k);
            let mut zm = Vec::with_capacity(n);
            let mut ze0 = Vec::with_capacity(n);
            for j in 0..n {
                // m' + (X^k m)_j lies in (-t, 2t): reduce, carry into e0
                let s = mm[j] as i64 + cm[j];
                let kappa = s.div_euclid(t as i64);
                zm.push(s.rem_euclid(t as i64) as u32);
                ze0.push(me0[j] as i64 + ce0[j] as i64 + kappa);
            }
            let zu: Vec<i64> = mu.iter().zip(&cu).map(|(&a, &b)| a as i64 + b as i64).collect();
            let ze1: Vec<i64> = me1.iter().zip(&ce1).map(|(&a, &b)| a as i64 + b as i64).collect();
            let ok_u = zu.iter().all(|&x| x.abs() <= (B_U - BETA_U) as i64);
            let ok_e0 = ze0.iter().all(|&x| x.abs() <= (B_E - BETA_E - 1) as i64);
            let ok_e1 = ze1.iter().all(|&x| x.abs() <= (B_E - BETA_E) as i64);
            if !(ok_u && ok_e0 && ok_e1) {
                rejected = true;
                break;
            }
            responses.push(Response {
                zm,
                zu: zu.into_iter().map(|x| x as i32).collect(),
                ze0: ze0.into_iter().map(|x| x as i32).collect(),
                ze1: ze1.into_iter().map(|x| x as i32).collect(),
            });
        }
        if !rejected {
            return Ok(Proof { commitments, responses });
        }
    }
    Err(Error::Protocol(
        "wfe: every attempt was rejected: the witness is not short (or the sampler is broken)".into(),
    ))
}

/// Verifies that `c` (already decoded with the fresh-ciphertext metadata of
/// `reference`) is a well-formed encryption, for `context`.
pub fn verify(ctx: &Context, pk: &PublicKey, reference: &Ciphertext, c: &Ciphertext, proof: &Proof, context: &[u8]) -> Result<()> {
    let n = ctx.ring_dim() as usize;
    let t = ctx.plain_mod();
    let reps = repetitions(n);
    if c.meta()? != reference.meta()? {
        return Err(Error::Protocol("wfe: contribution is not shaped like a fresh encryption".into()));
    }
    if proof.responses.len() != reps {
        return Err(Error::Protocol(format!("wfe: {} responses, expected {reps}", proof.responses.len())));
    }
    let statement = ct_hash(c)?;
    let ks = challenges(&proof.commitments, reps, n);
    let mut hashes = Vec::with_capacity(reps);
    for (i, (r, &k)) in proof.responses.iter().zip(&ks).enumerate() {
        if r.zm.len() != n || r.zu.len() != n || r.ze0.len() != n || r.ze1.len() != n {
            return Err(Error::Protocol(format!("wfe: response {i} has the wrong length")));
        }
        if r.zm.iter().any(|&x| x as u64 >= t)
            || r.zu.iter().any(|&x| x.unsigned_abs() > (B_U - BETA_U) as u32)
            || r.ze0.iter().any(|&x| x.unsigned_abs() > (B_E - BETA_E - 1) as u32)
            || r.ze1.iter().any(|&x| x.unsigned_abs() > (B_E - BETA_E) as u32)
        {
            return Err(Error::Protocol(format!("wfe: response {i} is out of range")));
        }
        let zm: Vec<u64> = r.zm.iter().map(|&x| x as u64).collect();
        let ez = enc(ctx, pk, reference, &zm, &r.zu, &r.ze0, &r.ze1)?;
        let a = ctx.sub(&ez, &ctx.mult_monomial(c, k as u32)?)?;
        hashes.push(ct_hash(&a)?);
    }
    if commitments_hash(context, &statement, &hashes) != proof.commitments {
        return Err(Error::Protocol(
            "wfe: proof does not verify: the contribution is not a well-formed encryption (or the proof is for another context)".into(),
        ));
    }
    Ok(())
}

/// The contribution the protocol uses: `2C`, whose randomness the proof
/// bounds (see the module documentation).
pub fn effective(ctx: &Context, c: &Ciphertext) -> Result<Ciphertext> {
    Ok(ctx.add(c, c)?)
}

/// Conversion between slot vectors and raw plaintext polynomials mod `t`
/// (negacyclic number-theoretic transform), with OpenFHE's slot order read
/// from the slot values of `X` ([`Context::monomial_slots`]).
pub struct SlotCodec {
    t: u64,
    n: usize,
    /// `psi^i`, `psi = w_0` (a primitive `2N`-th root of unity mod `t`).
    psi_pow: Vec<u64>,
    psi_inv_pow: Vec<u64>,
    /// Slot of the evaluation at `psi^(2j+1)`, for each `j`.
    slot_of: Vec<usize>,
    n_inv: u64,
}

fn mulmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

fn powmod(mut b: u64, mut e: u64, m: u64) -> u64 {
    let mut r = 1u64;
    b %= m;
    while e > 0 {
        if e & 1 == 1 {
            r = mulmod(r, b, m);
        }
        b = mulmod(b, b, m);
        e >>= 1;
    }
    r
}

impl SlotCodec {
    pub fn new(ctx: &Context) -> Result<Self> {
        let t = ctx.plain_mod();
        let w = ctx.monomial_slots()?;
        let n = w.len();
        let psi = w[0];
        if powmod(psi, n as u64, t) != t - 1 {
            return Err(Error::Protocol("slot codec: slot value of X is not a primitive 2N-th root of unity".into()));
        }
        let mut psi_pow = Vec::with_capacity(n);
        let mut x = 1u64;
        for _ in 0..n {
            psi_pow.push(x);
            x = mulmod(x, psi, t);
        }
        let psi_inv = powmod(psi, t - 2, t);
        let mut psi_inv_pow = Vec::with_capacity(n);
        let mut x = 1u64;
        for _ in 0..n {
            psi_inv_pow.push(x);
            x = mulmod(x, psi_inv, t);
        }
        // index of each odd power psi^(2j+1) among the slots
        let mut root_index = std::collections::HashMap::with_capacity(n);
        let psi2 = mulmod(psi, psi, t);
        let mut r = psi;
        for j in 0..n {
            root_index.insert(r, j);
            r = mulmod(r, psi2, t);
        }
        let mut slot_of = vec![usize::MAX; n];
        for (s, v) in w.iter().enumerate() {
            let j = *root_index
                .get(v)
                .ok_or_else(|| Error::Protocol("slot codec: a slot value of X is not an odd power of the first".into()))?;
            if slot_of[j] != usize::MAX {
                return Err(Error::Protocol("slot codec: two slots share a root".into()));
            }
            slot_of[j] = s;
        }
        Ok(Self {
            t,
            n,
            psi_pow,
            psi_inv_pow,
            slot_of,
            n_inv: powmod(n as u64, t - 2, t),
        })
    }

    /// In-place cyclic NTT of length `n` with root `omega` (natural order).
    fn ntt(&self, a: &mut [u64], omega: u64) {
        let n = a.len();
        let t = self.t;
        let mut j = 0usize;
        for i in 1..n {
            let mut bit = n >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j |= bit;
            if i < j {
                a.swap(i, j);
            }
        }
        let mut len = 2;
        while len <= n {
            let wl = powmod(omega, (n / len) as u64, t);
            for start in (0..n).step_by(len) {
                let mut w = 1u64;
                for k in 0..len / 2 {
                    let u = a[start + k];
                    let v = mulmod(a[start + k + len / 2], w, t);
                    a[start + k] = if u + v >= t { u + v - t } else { u + v };
                    a[start + k + len / 2] = if u >= v { u - v } else { u + t - v };
                    w = mulmod(w, wl, t);
                }
            }
            len <<= 1;
        }
    }

    /// Slot values of the raw plaintext polynomial `m`.
    pub fn slots(&self, m: &[u64]) -> Vec<u64> {
        let mut a: Vec<u64> = m.iter().zip(&self.psi_pow).map(|(&x, &p)| mulmod(x, p, self.t)).collect();
        self.ntt(&mut a, mulmod(self.psi_pow[1], self.psi_pow[1], self.t));
        let mut out = vec![0u64; self.n];
        for (j, v) in a.into_iter().enumerate() {
            out[self.slot_of[j]] = v;
        }
        out
    }

    /// The raw plaintext polynomial whose slots are `v`.
    pub fn coefficients(&self, v: &[u64]) -> Vec<u64> {
        let mut a: Vec<u64> = (0..self.n).map(|j| v[self.slot_of[j]] % self.t).collect();
        let omega_inv = mulmod(self.psi_inv_pow[1], self.psi_inv_pow[1], self.t);
        self.ntt(&mut a, omega_inv);
        a.iter()
            .zip(&self.psi_inv_pow)
            .map(|(&x, &p)| mulmod(mulmod(x, self.n_inv, self.t), p, self.t))
            .collect()
    }

    /// Raw plaintext for a contribution whose **effective** ciphertext
    /// ([`effective`], `2C`) on a ciphertext of scaling factor `sf` decodes
    /// to the slot vector `v`: the coefficients of `v * sf / 2`.
    pub fn contribution_plaintext(&self, v: &[u64], sf: u64) -> Vec<u64> {
        let half = self.t.div_ceil(2); // 2^-1 mod t (t odd)
        let k = mulmod(sf % self.t, half, self.t);
        let scaled: Vec<u64> = v.iter().map(|&x| mulmod(x, k, self.t)).collect();
        self.coefficients(&scaled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monomial_multiplication_is_negacyclic() {
        let v = vec![1i64, 2, 3, 4];
        assert_eq!(monomial_mul(&v, 0), v);
        assert_eq!(monomial_mul(&v, 1), vec![-4, 1, 2, 3]);
        assert_eq!(monomial_mul(&v, 4), vec![-1, -2, -3, -4]);
        assert_eq!(monomial_mul(&v, 5), vec![4, -1, -2, -3]);
        assert_eq!(monomial_mul(&monomial_mul(&v, 3), 5), v); // X^8 = 1
    }
}
