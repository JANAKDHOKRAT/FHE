//! PINE (private inexpensive norm enforcement, `draft-chen-cfrg-vdaf-pine`)
//! in the one-aggregator protocol of [`crate::single`]: clients send
//! encrypted real-valued vectors (gradients) with a proof that the L2 norm
//! is at most a bound; the collector learns the sum of the valid ones.
//!
//! Trust: as in [`crate::single`]. The evaluator and the collector do not
//! collude and follow the protocol; clients may be malicious.
//!
//! ```text
//! client    -> evaluator : report = nonce || G || W || P || identity || signature;
//!                          G, W and P are each one or more ciphertexts:
//!                          G = gradient || norm bits
//!                          W = wraparound test results and success bits
//!                          P = norm-equality proofs || main proofs (prio's unchanged FLP)
//! evaluator -> collector : check request, at batch end: per report and verifier element,
//!                          sum over ciphertexts of ct x row + mask, flooded, one tower
//! collector -> evaluator : verdicts, one bit per report (prio's decide on every proof)
//! evaluator -> collector : aggregate request: the sum of the accepted G ciphertexts,
//!                          masked outside the gradient coordinates, flooded, one tower
//! collector              : decrypts the gradient coordinates, PINE's decode
//! ```
//!
//! Challenges. PINE fixes its randomness in two steps, each after the
//! client is committed to what the step tests. The reference commits
//! through hashes of the aggregators' shares, checked between them. Here
//! the derivation hashes ciphertext bytes instead, as [`crate::single`]
//! does for Prio3's joint randomness:
//! * the wraparound test vectors come from the nonce and the bytes of `G`;
//! * the main circuit's joint randomness comes from the nonce and the bytes
//!   of `G` and `W`;
//! * the query points come from the evaluator's secret key and the whole
//!   report.
//!
//! What this implements is a binding of bytes: changing any byte of `G`
//! changes the test vectors, changing any byte of `G` or `W` changes the
//! joint randomness, and every verifier row reads each part only from that
//! part's ciphertexts. **It is not proved that this derivation inherits
//! PINE's (or Prio3's) security**: there is no composition proof for
//! deriving the challenges from ciphertexts under the collector's key
//! (`PINE.md`, "Not proved").
//!
//! The dot products of the wraparound tests are not sent: they are linear
//! in the gradient, so the evaluator folds the test vectors into the
//! verifier rows. Every verifier element is the constant coefficient of one
//! product sum, which depends on a plaintext's coefficients inside the
//! report's layout only: what a malicious client puts elsewhere is
//! multiplied by 0, and the aggregate reads the gradient coordinates only.
//!
//! What a cheating client can hope for (per report unless stated; an
//! accounting of known bounds, see `PINE.md`):
//! * an FLP query that misses: [`PineTask::log2_query_soundness`];
//! * joint randomness under which an invalid measurement evaluates to 0 in
//!   every main proof: [`PineTask::log2_joint_rand_per_attempt`] per
//!   offline attempt (a new nonce or re-encryption is an attempt);
//! * a wraparound of the squared norm that all tests miss: each test
//!   detects one with probability at least 1/2 ([ROCT23], as cited by the
//!   draft), so `2^-100` per offline attempt at the reference's 100 tests.
//!
//! Admission. A client may send any two ring elements as a ciphertext.
//! With a large phase (noise), a plaintext product wraps modulo `Q` and
//! the decrypted verifier element is no longer a linear query of a fixed
//! vector, which is what the FLP's soundness is stated for
//! (`tests/pine.rs`, `a_ciphertext_with_large_noise_is_not_evaluated_linearly`).
//! So the evaluator sends, per report ciphertext, a copy with a uniform
//! plaintext on every coefficient and `p` times a uniform
//! `ADMIT_MASK_BITS`-bit value added, at the full modulus; the collector
//! measures its phase exactly and rejects the report, without decrypting
//! its verifier, unless every copy is below `2^ADMIT_BITS`. Then every
//! decrypted value is exactly the linear function of the plaintexts
//! `phase mod p`, honest reports are always admitted, and a copy is within
//! `2^-65` of a distribution independent of its plaintext:
//! `PINE-SECURITY-ARGUMENT.md`, part 1, whose numeric conditions
//! [`PineTask::new`] checks for the task. That argument is not reviewed.
//!
//! The task ([`descriptor::TaskDescriptor`]) lists the clients authorized
//! to report. A client signs its report's commitment: the task, the
//! collector's key, the nonce and the digest of each part. The evaluator
//! forwards, per report, the identity, nonce, digests and signature, never
//! a ciphertext of the report; the collector verifies them before it
//! decrypts anything. So the reports of a check request are reports that
//! authorized clients made for this task and key, each client at most once.
//! Nothing ties the ciphertexts the collector decrypts to those reports.
//!
//! Single use, kept in a ledger directory that must survive restarts and
//! must not be rolled back ([`Ledger`]):
//! * the evaluator accepts an identity and a nonce once per task;
//! * the collector accepts a batch identifier, an identity and a nonce
//!   once, reserving them before it decrypts anything; while a checked
//!   batch awaits release it checks nothing else; it releases the sum of a
//!   batch once, reserving the release before it decrypts it, and only
//!   with at least the task's threshold of accepted reports.
//!
//! Every ciphertext of a request is decoded and checked before the first
//! one is decrypted.
//!
//! Outside what this module provides, all of which a deployment has to
//! weigh (`PINE-THREAT-MODEL.md`, `PINE-REPAIR-STATUS.md`):
//! * the evaluator learns the verdicts, the collector the verdict of each
//!   identity;
//! * the collector cannot tell whether the ciphertexts it is asked to
//!   decrypt were computed from the signed reports as prescribed: an
//!   evaluator that deviates can have other linear functions decrypted,
//!   and can replace the sum by a ciphertext of its choice;
//! * the evaluator can leave reports out;
//! * the noise flooding has a measured margin, not a worst-case proof, and
//!   the collector does not check the noise of what it decrypts.
pub mod circuit;
pub mod descriptor;

use crate::codec::ResidueCodec;
use crate::protocol::{MAX_BATCH, MAX_PROOFS, NONCE_LEN, from_u64, to_u64};
use crate::single::finish;
use crate::{Error, FheField, Field, PLAIN_MOD, Result};
use circuit::{ALPHA, Main, NUM_WR_CHECKS, NUM_WR_SUCCESSES, NormEquality, Shape, check_linear_map};
use descriptor::TaskDescriptor;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use openfhe_tbgv_rs::{Ciphertext, CiphertextMeta, Context, PublicKey, SecretShare, keygen_first, verify_single_rebuild_once};
use prio::field::{FieldElement, FieldElementWithInteger};
use prio::flp::Flp;
use prio::vdaf::xof::{IntoFieldVec, Xof, XofTurboShake128};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::ops::Range;
use std::path::{Path, PathBuf};

const DST_TASK: &[u8] = b"fhe-flp/1 pine task";
const DST_KEY: &[u8] = b"fhe-flp/1 pine task and key";
const DST_REPORT: &[u8] = b"fhe-flp/1 pine report commitment";
const DST_VERDICTS: &[u8] = b"fhe-flp/1 pine verdicts";
const DST_WR_SEED: &[u8] = b"fhe-flp/1 pine wraparound seed";
const DST_WR: &[u8] = b"fhe-flp/1 pine wraparound vectors";
const DST_JOINT_RAND_SEED: &[u8] = b"fhe-flp/1 pine joint randomness seed";
const DST_JOINT_RAND: &[u8] = b"fhe-flp/1 pine joint randomness";
const DST_QUERY: &[u8] = b"fhe-flp/1 pine query randomness";
const DST_PROVE: &[u8] = b"fhe-flp/1 pine prove randomness";
const DST_MASK: &[u8] = b"fhe-flp/1 pine mask";
const DST_SELF_CHECK: &[u8] = b"fhe-flp/1 pine self check";

/// A client retries with a fresh nonce when a wraparound test fails on an
/// honest gradient; each retry fails with negligible probability.
const SHARD_ATTEMPTS: usize = 8;

/// A batch identifier: 32 random bytes chosen by the evaluator.
pub const BATCH_LEN: usize = 32;
/// Check request: report count, batch identifier, then one entry per report.
const CHECK_HEADER: usize = 4 + BATCH_LEN;
/// A report's entry in a check request: identity index, nonce, the digests
/// of its three parts, the client's signature.
const ENTRY_LEN: usize = 4 + NONCE_LEN + 3 * 32 + 64;
/// Aggregate request: batch identifier, verdict hash, accepted count.
const AGGREGATE_HEADER: usize = BATCH_LEN + 32 + 8;
/// Admission: the collector refuses a report unless the phase of the masked
/// copy of each of its ciphertexts has fewer than this many bits. The mask
/// is a uniform plaintext plus `p` times a uniform value of
/// `ADMIT_MASK_BITS` bits, so the phase of an admitted report ciphertext is
/// below `2^(ADMIT_BITS + 1)`, and a copy differs from one that is
/// independent of the plaintext with probability at most
/// `2^-ADMIT_MASK_BITS` per coefficient (`PINE-SECURITY-ARGUMENT.md`).
pub const ADMIT_BITS: u32 = 112;
pub const ADMIT_MASK_BITS: u32 = 78;
/// What a client appends to a report's body: its identity and signature.
const SEAL_LEN: usize = 32 + 64;

/// The three parts of a report, in order.
pub const PART_GRADIENT: usize = 0;
pub const PART_WRAPAROUND: usize = 1;
pub const PART_PROOFS: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PineParams {
    pub dimension: usize,
    /// Bound on the L2 norm of the encoded gradient: a real bound times
    /// `2^num_frac_bits`.
    pub l2_norm_bound: u64,
    pub num_frac_bits: u32,
    /// Chunk length of the main circuit's gadget: `2 * chunk + 2` verifier
    /// elements per proof against a proof of about `2 * chunk + 4 * calls`.
    pub chunk_length: usize,
    pub chunk_length_norm_equality: usize,
    pub num_proofs: usize,
    pub num_proofs_norm_equality: usize,
}

/// Everything the client, the evaluator and the collector agree on.
pub struct PineTask {
    descriptor: TaskDescriptor,
    norm_eq: NormEquality,
    main: Main,
    /// Hash of the task identifier and every parameter: part of every
    /// derivation.
    binding: [u8; 32],
    ctx: Context,
    fresh_codec: ResidueCodec,
    reduced_codec: ResidueCodec,
    reduced_meta: CiphertextMeta,
    ring: usize,
    /// Coefficients of each part of a report.
    lens: [usize; 3],
}

impl PineTask {
    /// Refused: parameters outside the reference's guards, proofs the field
    /// has no roots of unity for, more than `MAX_PROOFS` proofs of a kind,
    /// and a closed-form verifier map that disagrees with prio's `query`.
    pub fn new(descriptor: TaskDescriptor) -> Result<Self> {
        let encoded = descriptor.encode()?;
        let params = descriptor.params.clone();
        let shape = Shape::new(params.dimension, params.l2_norm_bound, params.num_frac_bits)?;
        let norm_eq = NormEquality::new(shape.clone(), params.chunk_length_norm_equality)?;
        let main = Main::new(shape.clone(), params.chunk_length)?;
        if !(1..=MAX_PROOFS).contains(&params.num_proofs) || !(1..=MAX_PROOFS).contains(&params.num_proofs_norm_equality) {
            return Err(Error::Protocol(format!("between 1 and {MAX_PROOFS} proofs of each kind are supported")));
        }
        let ctx = Context::new_single(
            PLAIN_MOD,
            128,
            <Field as FheField>::SINGLE_FIRST_MOD_BITS,
            <Field as FheField>::SINGLE_SCALING_MOD_BITS,
            <Field as FheField>::SINGLE_NUM_TOWERS,
        )?;
        if ctx.plain_mod() != PLAIN_MOD {
            return Err(Error::Protocol("context has another plaintext modulus".into()));
        }
        let ring = ctx.ring_dim() as usize;
        let moduli = ctx.moduli()?;
        let lens = [
            shape.gradient_and_norm_len(),
            shape.meas_len() - shape.gradient_and_norm_len(),
            params.num_proofs_norm_equality * norm_eq.proof_len() + params.num_proofs * main.proof_len(),
        ];

        // The numeric conditions of `PINE-SECURITY-ARGUMENT.md`, part 1, for
        // this context and this task; a task that fails one is refused.
        let (p, n) = (PLAIN_MOD as u128, ring as u128);
        let cts: usize = lens.iter().map(|l| l.div_ceil(ring)).sum();
        let log_q = moduli.iter().map(|&q| (q as f64).log2()).sum::<f64>().floor() as u32;
        let refuse = |m: &str| Err(Error::Protocol(format!("admission bound: {m}")));
        // (a) A modulus switch keeps the plaintext: every modulus is 1 modulo p.
        if moduli.iter().any(|q| q % PLAIN_MOD != 1) {
            return refuse("a ciphertext modulus is not 1 modulo p");
        }
        // (b) Completeness: an honest ciphertext has |phase| <= p + p (2 N + 1) E
        // (ternary secrets, sampler support E), its copy's mask is below
        // p + p 2^(ADMIT_MASK_BITS - 1), and their sum is below 2^ADMIT_BITS.
        let honest = p + p * (2 * n + 1) * u128::from(ctx.gaussian_bound()?);
        let mask = p + (p << (ADMIT_MASK_BITS - 1));
        if honest + mask >= 1 << ADMIT_BITS {
            return refuse("an honest report would not be admitted");
        }
        // (c) Exactness: an admitted ciphertext has |phase| < 2^ADMIT_BITS +
        // mask < 2^(ADMIT_BITS + 1). A verifier element sums, over at most `cts`
        // ciphertexts, `ring` products of a plaintext coefficient below p < 2^32
        // with a phase coefficient; the aggregate sums at most MAX_BATCH = 2^24
        // phases. Either sum must be below Q / 4: with the mask (below 2^32) and
        // the flooding (below Q / 8) the phase then stays below Q / 2.
        let terms = (cts.next_power_of_two().ilog2() + ring.next_power_of_two().ilog2() + 32).max(MAX_BATCH.next_power_of_two().ilog2());
        if mask >= 1 << ADMIT_BITS || ADMIT_BITS + 1 + terms + 2 > log_q {
            return refuse(&format!("a report of {cts} ciphertexts is too large at this modulus"));
        }
        // (d) Each modulus switch adds at most p (N + 1) / 2 to the phase, which
        // must fit in the eighth of the remaining modulus left by (c).
        if p * (n + 1) >= u128::from(moduli[0]) / 8 {
            return refuse("the modulus switch rounding does not fit");
        }

        // The descriptor, then everything else the code fixes: the circuits'
        // constants, the field and the BGV parameters.
        let mut h = Sha256::new();
        h.update(DST_TASK);
        h.update((encoded.len() as u64).to_le_bytes());
        h.update(&encoded);
        for v in [
            NUM_WR_CHECKS as u64,
            NUM_WR_SUCCESSES as u64,
            ALPHA.to_bits(),
            PLAIN_MOD,
            ring as u64,
            u64::from(ADMIT_BITS),
            u64::from(ADMIT_MASK_BITS),
            moduli.len() as u64,
        ] {
            h.update(v.to_le_bytes());
        }
        for q in &moduli {
            h.update(q.to_le_bytes());
        }

        // The metadata of what the collector receives, read off real objects
        // under a throwaway key, as `SingleTask::new` does.
        let (pk, _sk) = keygen_first(&ctx)?;
        let fresh = ctx.encrypt(&pk, &ctx.coef_plaintext(&[0])?)?;
        let check = finish::<Field>(&ctx, &ctx.mult_plain(&fresh, &ctx.coef_plaintext(&[1])?)?)?;
        let sum = finish::<Field>(&ctx, &ctx.add(&fresh, &fresh)?)?;
        let reduced_meta = check.meta()?;
        if sum.meta()? != reduced_meta || reduced_meta.num_towers != 1 || reduced_meta.num_elements != 2 {
            return Err(Error::Fhe(format!("unexpected reduced metadata {reduced_meta:?} / {:?}", sum.meta()?)));
        }
        let task = Self {
            descriptor,
            norm_eq,
            main,
            binding: h.finalize().into(),
            fresh_codec: ResidueCodec::new(&moduli)?,
            reduced_codec: ResidueCodec::new(&moduli[..1])?,
            reduced_meta,
            ctx,
            ring,
            lens,
        };
        task.self_check()?;
        Ok(task)
    }

    /// Both closed-form verifier maps against prio's `query` at a random
    /// point: equal affine maps agree, different ones agree with probability
    /// at most `1 / p`.
    fn self_check(&self) -> Result<()> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let (ne, main) = (&self.norm_eq, &self.main);
        let total = ne.input_len() + ne.proof_len() + main.input_len() + main.proof_len();
        let (t_ne, t_main) = self.sample_query_points(XofTurboShake128::seed_stream(&seed, &[DST_SELF_CHECK, b"points"], &[]), 1, 1)?;
        let r: Vec<Field> = XofTurboShake128::seed_stream(&seed, &[DST_SELF_CHECK], &[]).into_field_vec(3 + total);
        let (jr, z) = r.split_at(3);
        let (z_ne, z_main) = z.split_at(ne.input_len() + ne.proof_len());
        check_linear_map(ne, &ne.linear_map(t_ne[0])?, z_ne, t_ne[0], &[])?;
        check_linear_map(main, &main.linear_map(t_main[0], jr)?, z_main, t_main[0], jr)
    }

    pub fn descriptor(&self) -> &TaskDescriptor {
        &self.descriptor
    }
    pub fn params(&self) -> &PineParams {
        &self.descriptor.params
    }
    /// What every derivation and signature of a report is bound to: this
    /// task and this public key (the key's identity enters separately from
    /// the parameters).
    pub fn key_context(&self, pk: &PublicKey) -> Result<[u8; 32]> {
        // A key's serialization changes at its first deserialization and is
        // stable afterwards: hash the stable form.
        let stable = self.ctx.deserialize_public_key(&pk.serialize()?)?.serialize()?;
        let mut h = Sha256::new();
        h.update(DST_KEY);
        h.update(self.binding);
        h.update(Sha256::digest(&stable));
        Ok(h.finalize().into())
    }
    pub fn shape(&self) -> &Shape {
        self.main.shape()
    }
    pub fn context(&self) -> &Context {
        &self.ctx
    }
    /// Reports per batch: the sum of `n` gradients of norm at most `B` has
    /// coordinates of magnitude at most `n B`, which must stay below `p / 2`
    /// for the centered lift to be the integer sum.
    pub fn max_batch(&self) -> u64 {
        MAX_BATCH.min((PLAIN_MOD - 1) / (2 * self.descriptor.params.l2_norm_bound))
    }

    fn blocks(&self, part: usize) -> usize {
        self.lens[part].div_ceil(self.ring)
    }
    /// The first ciphertext of `part` among a report's ciphertexts.
    fn first_block(&self, part: usize) -> usize {
        (0..part).map(|p| self.blocks(p)).sum()
    }
    /// Ciphertexts per report.
    pub fn ciphertexts_per_report(&self) -> usize {
        self.first_block(3)
    }
    fn fresh_len(&self) -> usize {
        self.fresh_codec.len(2, self.ring)
    }
    fn reduced_len(&self) -> usize {
        self.reduced_codec.len(2, self.ring)
    }
    /// Nonce and ciphertexts.
    fn body_len(&self) -> usize {
        NONCE_LEN + self.ciphertexts_per_report() * self.fresh_len()
    }
    pub fn report_len(&self) -> usize {
        self.body_len() + SEAL_LEN
    }
    /// The bytes of `part` (`PART_*`) in a report.
    pub fn part_range(&self, part: usize) -> Range<usize> {
        let fl = self.fresh_len();
        NONCE_LEN + self.first_block(part) * fl..NONCE_LEN + self.first_block(part + 1) * fl
    }
    /// Verifier elements per report: one ciphertext each in a check request.
    pub fn verifier_len(&self) -> usize {
        self.descriptor.params.num_proofs_norm_equality * self.norm_eq.verifier_len() + self.descriptor.params.num_proofs * self.main.verifier_len()
    }
    pub fn check_request_len(&self, reports: usize) -> usize {
        CHECK_HEADER + reports * (ENTRY_LEN + self.check_len())
    }
    /// Ciphertexts of the aggregate: those holding gradient coordinates.
    fn output_blocks(&self) -> usize {
        self.descriptor.params.dimension.div_ceil(self.ring)
    }
    pub fn aggregate_request_len(&self) -> usize {
        AGGREGATE_HEADER + self.output_blocks() * self.reduced_len()
    }

    /// Bytes of one report's ciphertexts in a check request: the masked
    /// copies of its ciphertexts (all towers), then its verifier elements.
    fn check_len(&self) -> usize {
        self.ciphertexts_per_report() * self.fresh_len() + self.verifier_len() * self.reduced_len()
    }
    /// One report's masked copies and its verifier elements.
    fn split_check<'b>(&self, report: &'b [u8]) -> (&'b [u8], &'b [u8]) {
        report.split_at(self.ciphertexts_per_report() * self.fresh_len())
    }

    /// Decodes every ciphertext of a request without decrypting any:
    /// lengths, canonical residues, padding.
    fn preflight(&self, ciphertexts: &[u8]) -> Result<()> {
        for bytes in ciphertexts.chunks(self.reduced_len()) {
            self.reduced_codec.unpack(bytes, 2, self.ring)?;
        }
        Ok(())
    }

    /// log2 of the probability that the queries of one report miss an
    /// invalid proof of either circuit, for inputs on which the circuit is
    /// nonzero: per proof `2 (P - 1) / (p - 2 P)` (a gadget of degree 2 with
    /// wire polynomials of length `P`; query points avoid the `2 P`-th roots
    /// of unity), to the power of the number of proofs; the larger of the
    /// two circuits.
    pub fn log2_query_soundness(&self) -> f64 {
        let per = |w: usize| (2.0 * (w as f64 - 1.0) / (PLAIN_MOD as f64 - 2.0 * w as f64)).log2();
        (per(wire_len(&self.norm_eq)) * self.descriptor.params.num_proofs_norm_equality as f64)
            .max(per(wire_len(&self.main)) * self.descriptor.params.num_proofs as f64)
    }
    /// Concrete bounds on the probability that a report whose gradient has
    /// an integer L2 norm above the bound is accepted, against clients that
    /// make `2^log2_queries` hash queries and submit `2^log2_reports`
    /// reports, in the model and under the hypotheses of
    /// `PINE-SECURITY-ARGUMENT.md`, part 2 (random oracle; the wraparound
    /// lemma of [ROCT23]). log2 of each term and of their sum, at most 0.
    pub fn soundness_bound(&self, log2_queries: f64, log2_reports: f64) -> SoundnessBound {
        let p = PLAIN_MOD as f64;
        let per = |w: usize| (2.0 * (w as f64 - 1.0) / (p - 2.0 * w as f64)).log2();
        let (k_ne, k) = (self.descriptor.params.num_proofs_norm_equality as f64, self.descriptor.params.num_proofs);
        // The norm equality has no joint randomness: one query miss per proof.
        let norm_equality = (log2_reports + k_ne * per(wire_len(&self.norm_eq))).min(0.0);
        // Main circuit: some queried input has j proofs whose joint randomness
        // hides the violation (at most q C(k, j) delta^j), and the queries
        // miss on the other k - j proofs of some report (at most n eps^(k - j)).
        let (delta, eps) = ((self.main.joint_rand_degree() as f64 / p).log2(), per(wire_len(&self.main)));
        let mut main = 0.0f64;
        let mut choose = 1.0f64;
        for j in 0..=k {
            let found = (log2_queries + choose.log2() + j as f64 * delta).min(0.0);
            let missed = (log2_reports + (k - j) as f64 * eps).min(0.0);
            main += (found + missed).exp2();
            choose = choose * (k - j) as f64 / (j + 1) as f64;
        }
        let main = main.log2().min(0.0);
        // Wraparound: 100 tests, each passed with probability at most 1/2, per
        // queried choice of test vectors.
        let wraparound = (log2_queries - NUM_WR_CHECKS as f64).min(0.0);
        SoundnessBound {
            log2_norm_equality: norm_equality,
            log2_main: main,
            log2_wraparound: wraparound,
            log2_total: (norm_equality.exp2() + main.exp2() + wraparound.exp2()).log2().min(0.0),
        }
    }

    /// log2 of the probability that one choice of joint randomness makes
    /// the main circuit 0 on an invalid measurement in every proof (see
    /// [`Main::joint_rand_degree`]). A client can try choices offline.
    pub fn log2_joint_rand_per_attempt(&self) -> f64 {
        (self.main.joint_rand_degree() as f64 / PLAIN_MOD as f64).log2() * self.descriptor.params.num_proofs as f64
    }

    fn digest(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// The digests of the three parts of a report's body.
    fn part_digests(&self, body: &[u8]) -> [[u8; 32]; 3] {
        [PART_GRADIENT, PART_WRAPAROUND, PART_PROOFS].map(|part| Self::digest(&body[self.part_range(part)]))
    }

    /// What a client signs and what identifies a report: the task and key,
    /// the nonce, and each part's digest (fixed lengths: no two inputs
    /// encode alike).
    fn commitment(&self, key: &[u8; 32], nonce: &[u8], digests: &[[u8; 32]; 3]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DST_REPORT);
        h.update(key);
        h.update(nonce);
        for d in digests {
            h.update(d);
        }
        h.finalize().into()
    }

    /// What ties an aggregate request to a check: the batch, the reports'
    /// commitments in order, and the verdicts.
    fn verdict_hash<'c>(&self, key: &[u8; 32], batch: &[u8], commitments: impl Iterator<Item = &'c [u8; 32]>, verdicts: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DST_VERDICTS);
        h.update(key);
        h.update(batch);
        for c in commitments {
            h.update(c);
        }
        h.update(verdicts);
        h.finalize().into()
    }

    /// The seed of a report's wraparound test vectors: from its nonce and
    /// the digest of its gradient part.
    fn wr_seed(&self, key: &[u8; 32], nonce: &[u8], gradient: &[u8; 32]) -> [u8; 32] {
        let mut xof = XofTurboShake128::init(&[0u8; 32], &[DST_WR_SEED, key]);
        xof.update(nonce);
        xof.update(gradient);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(xof.into_seed().as_ref());
        seed
    }

    /// The wraparound test vectors of a seed ([`Challenges::wr_seed`]):
    /// `NUM_WR_CHECKS` vectors of `dimension` entries in `{-1, 0, 1}`.
    pub fn wr_vectors(&self, wr_seed: &[u8; 32]) -> Vec<i8> {
        self.shape()
            .wr_vectors(&mut XofTurboShake128::seed_stream(wr_seed, &[DST_WR, &self.binding], &[]))
    }

    /// The joint randomness of every main proof: from the nonce and the
    /// digests of the gradient and wraparound parts.
    fn joint_rands(&self, key: &[u8; 32], nonce: &[u8], gradient: &[u8; 32], wraparound: &[u8; 32]) -> Vec<Field> {
        let mut xof = XofTurboShake128::init(&[0u8; 32], &[DST_JOINT_RAND_SEED, key]);
        xof.update(nonce);
        xof.update(gradient);
        xof.update(wraparound);
        let seed = xof.into_seed();
        XofTurboShake128::seed_stream(seed.as_ref(), &[DST_JOINT_RAND, key], &[]).into_field_vec(3 * self.descriptor.params.num_proofs)
    }

    /// `ne` query points for the norm-equality circuit and `main` for the
    /// main circuit, none a root of unity of its proof's domain (each is one
    /// with probability below 2^-11; 64 spare elements).
    fn sample_query_points(&self, stream: impl IntoFieldVec, ne: usize, main: usize) -> Result<(Vec<Field>, Vec<Field>)> {
        let orders = [2 * wire_len(&self.norm_eq) as u32, 2 * wire_len(&self.main) as u32];
        let mut pool = stream.into_field_vec::<Field>(ne + main + 64).into_iter();
        let mut out = [Vec::with_capacity(ne), Vec::with_capacity(main)];
        for (which, count) in [ne, main].into_iter().enumerate() {
            while out[which].len() < count {
                let t = pool.next().ok_or_else(|| Error::Protocol("query randomness exhausted".into()))?;
                if t.pow(orders[which]) != Field::one() {
                    out[which].push(t);
                }
            }
        }
        let [a, b] = out;
        Ok((a, b))
    }

    /// Every challenge of a report, as the evaluator derives them: the
    /// wraparound seed from the nonce and the gradient part, the joint
    /// randomness from the nonce and the gradient and wraparound parts, the
    /// query points from the evaluator's secret key and the report's
    /// commitment (nonce and all three parts). `key`: [`Self::key_context`].
    pub fn challenges(&self, key: &[u8; 32], verify_key: &[u8; 32], report: &[u8]) -> Result<Challenges> {
        if report.len() != self.report_len() {
            return Err(Error::Codec(format!("report has {} bytes, expected {}", report.len(), self.report_len())));
        }
        let digests = self.part_digests(report);
        self.challenges_of(
            key,
            verify_key,
            &report[..NONCE_LEN],
            &digests,
            &self.commitment(key, &report[..NONCE_LEN], &digests),
        )
    }

    fn challenges_of(&self, key: &[u8; 32], verify_key: &[u8; 32], nonce: &[u8], digests: &[[u8; 32]; 3], commitment: &[u8; 32]) -> Result<Challenges> {
        let stream = XofTurboShake128::seed_stream(verify_key, &[DST_QUERY, key], &[commitment]);
        let (t_norm_equality, t_main) = self.sample_query_points(stream, self.descriptor.params.num_proofs_norm_equality, self.descriptor.params.num_proofs)?;
        Ok(Challenges {
            wr_seed: self.wr_seed(key, nonce, &digests[PART_GRADIENT]),
            joint_rands: self.joint_rands(key, nonce, &digests[PART_GRADIENT], &digests[PART_WRAPAROUND]),
            t_norm_equality,
            t_main,
        })
    }

    /// The two circuits (tests: comparison with prio's `query`).
    pub fn circuits(&self) -> (&NormEquality, &Main) {
        (&self.norm_eq, &self.main)
    }

    /// The verifier of a report (all norm-equality proofs, then all main
    /// proofs) as rows over the report's plaintext coefficients, ciphertext
    /// after ciphertext, and constants. The dot products of the wraparound
    /// tests are folded into the gradient coordinates.
    fn verifier_rows(&self, ch: &Challenges, mut emit: impl FnMut(&[Field], Field) -> Result<()>) -> Result<()> {
        let vectors = self.wr_vectors(&ch.wr_seed);
        let (joint_rands, t_ne, t_main) = (&ch.joint_rands, &ch.t_norm_equality, &ch.t_main);
        let shape = self.shape();
        let (d, il) = (shape.dimension(), shape.input_len());
        let (g_len, m_len) = (self.lens[PART_GRADIENT], shape.meas_len());
        let w_at = self.first_block(PART_WRAPAROUND) * self.ring;
        let mut p_at = self.first_block(PART_PROOFS) * self.ring;
        let mut row = vec![Field::zero(); self.ciphertexts_per_report() * self.ring];
        let maps = t_ne
            .iter()
            .map(|&t| self.norm_eq.linear_map(t))
            .chain(t_main.iter().zip(joint_rands.chunks(3)).map(|(&t, jr)| self.main.linear_map(t, jr)));
        for map in maps {
            let map = map?;
            let proof_len = map.rows[0].len() - il;
            for (r, &constant) in map.rows.iter().zip(&map.constants) {
                row.fill(Field::zero());
                row[..g_len].copy_from_slice(&r[..g_len]);
                row[w_at..w_at + m_len - g_len].copy_from_slice(&r[g_len..m_len]);
                for (i, &c) in r[m_len..il].iter().enumerate() {
                    if c == Field::zero() {
                        continue;
                    }
                    for (x, &v) in row[..d].iter_mut().zip(&vectors[i * d..(i + 1) * d]) {
                        match v {
                            1 => *x += c,
                            -1 => *x -= c,
                            _ => {}
                        }
                    }
                }
                row[p_at..p_at + proof_len].copy_from_slice(&r[il..]);
                emit(&row, constant)?;
            }
            p_at += proof_len;
        }
        Ok(())
    }

    /// Prio's `decide` on every proof's verifier.
    fn decide(&self, verifier: &[Field]) -> Result<bool> {
        let (v_ne, v_main) = verifier.split_at(self.descriptor.params.num_proofs_norm_equality * self.norm_eq.verifier_len());
        let mut ok = true;
        for v in v_ne.chunks(self.norm_eq.verifier_len()) {
            ok &= self.norm_eq.decide(v)?;
        }
        for v in v_main.chunks(self.main.verifier_len()) {
            ok &= self.main.decide(v)?;
        }
        Ok(ok)
    }

    fn pack_reduced(&self, ct: &Ciphertext) -> Result<Vec<u8>> {
        if ct.meta()? != self.reduced_meta {
            return Err(Error::Fhe(format!("unexpected reduced metadata {:?}", ct.meta()?)));
        }
        self.reduced_codec.pack(&ct.export_residues()?, 2, self.ring)
    }

    /// Uniform field elements on every coefficient.
    fn mask(&self) -> Vec<u64> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let r: Vec<Field> = XofTurboShake128::seed_stream(&seed, &[DST_MASK], &[]).into_field_vec(self.ring);
        r.into_iter().map(to_u64).collect()
    }
}

/// Length `P` of the wire polynomials of a circuit's gadget.
fn wire_len<T: Flp<Field = Field>>(typ: &T) -> usize {
    (1 + typ.gadget()[0].calls()).next_power_of_two()
}

/// [`PineTask::soundness_bound`].
#[derive(Clone, Debug, PartialEq)]
pub struct SoundnessBound {
    pub log2_norm_equality: f64,
    pub log2_main: f64,
    pub log2_wraparound: f64,
    pub log2_total: f64,
}

/// The challenges of one report ([`PineTask::challenges`]).
pub struct Challenges {
    /// Seed of the wraparound test vectors ([`PineTask::wr_vectors`]).
    pub wr_seed: [u8; 32],
    /// Three elements per main proof.
    pub joint_rands: Vec<Field>,
    pub t_norm_equality: Vec<Field>,
    pub t_main: Vec<Field>,
}

pub struct PineClient<'a> {
    task: &'a PineTask,
    pk: &'a PublicKey,
    key: [u8; 32],
    signing: &'a SigningKey,
}

impl<'a> PineClient<'a> {
    /// Refused unless `signing`'s verification key is one of the task's
    /// authorized identities.
    pub fn new(task: &'a PineTask, pk: &'a PublicKey, signing: &'a SigningKey) -> Result<Self> {
        if task.descriptor.identity_index(signing.verifying_key().as_bytes()).is_none() {
            return Err(Error::Protocol("the signing key is not an authorized identity of the task".into()));
        }
        Ok(Self {
            task,
            pk,
            key: task.key_context(pk)?,
            signing,
        })
    }

    /// Encodes, proves, encrypts and signs a gradient. Refused: a gradient
    /// whose encoded norm exceeds the bound (clip first), NaN, infinities
    /// and subnormals.
    pub fn shard(&self, gradient: &[f64]) -> Result<Vec<u8>> {
        Ok(self.shard_with_witness(gradient)?.0)
    }

    /// [`Self::shard`], also returning the circuits' input (measurement and
    /// dot products) and the proofs (tests: comparison with prio).
    pub fn shard_with_witness(&self, gradient: &[f64]) -> Result<(Vec<u8>, Vec<Field>, Vec<Field>)> {
        let shape = self.task.shape();
        let g = shape.encode_gradient_and_norm(gradient)?;
        for _ in 0..SHARD_ATTEMPTS {
            let (nonce, g_bytes, vectors) = self.commit(&g, &|_, _| {})?;
            if let Some((wr_bits, results)) = shape.encode_wr_checks(&g[..shape.dimension()], &vectors) {
                return self.complete(nonce, &g, g_bytes, &wr_bits, &results, &|_, _| {});
            }
        }
        Err(Error::Protocol("the wraparound tests failed on every attempt".into()))
    }

    /// A signed report for arbitrary coefficients, valid or not, built in
    /// the honest order: `gradient_part` is encrypted (the gradient and
    /// norm bits, then anything up to the end of its last ciphertext),
    /// `claim` receives the true dot products of the test vectors that
    /// fixes and returns the wraparound part to send, and the proofs are
    /// prio's for that input (malicious-client tests).
    pub fn shard_encoded(&self, gradient_part: &[Field], claim: impl FnOnce(&[Field]) -> Vec<Field>) -> Result<Vec<u8>> {
        self.shard_tampered(gradient_part, claim, &|_, _| {})
    }

    /// [`Self::shard_encoded`] for a client that also alters its
    /// ciphertexts: `tamper` receives each part (`PART_*`) right after it
    /// is encrypted and before anything is derived from its bytes, so the
    /// report stays consistent with its challenges and is validly signed
    /// (tests: ciphertexts that are not honest encryptions).
    pub fn shard_tampered(&self, gradient_part: &[Field], claim: impl FnOnce(&[Field]) -> Vec<Field>, tamper: &dyn Fn(usize, &mut Vec<u8>)) -> Result<Vec<u8>> {
        let task = self.task;
        let shape = task.shape();
        let g_len = task.lens[PART_GRADIENT];
        if gradient_part.len() < g_len || gradient_part.len() > task.blocks(PART_GRADIENT) * task.ring {
            return Err(Error::Protocol("unexpected gradient part length".into()));
        }
        let (nonce, g_bytes, vectors) = self.commit(gradient_part, tamper)?;
        let results = shape.wr_results(&gradient_part[..shape.dimension()], &vectors);
        let wr_bits = claim(&results);
        if wr_bits.len() != task.lens[PART_WRAPAROUND] {
            return Err(Error::Protocol("unexpected wraparound part length".into()));
        }
        Ok(self.complete(nonce, &gradient_part[..g_len], g_bytes, &wr_bits, &results, tamper)?.0)
    }

    /// A fresh nonce, the encrypted gradient part and the wraparound test
    /// vectors they fix.
    fn commit(&self, g: &[Field], tamper: &dyn Fn(usize, &mut Vec<u8>)) -> Result<([u8; NONCE_LEN], Vec<u8>, Vec<i8>)> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut g_bytes = self.encrypt(g)?;
        tamper(PART_GRADIENT, &mut g_bytes);
        let vectors = self.task.wr_vectors(&self.task.wr_seed(&self.key, &nonce, &PineTask::digest(&g_bytes)));
        Ok((nonce, g_bytes, vectors))
    }

    /// The report, the circuits' input and the proofs.
    fn complete(
        &self,
        nonce: [u8; NONCE_LEN],
        g: &[Field],
        g_bytes: Vec<u8>,
        wr_bits: &[Field],
        results: &[Field],
        tamper: &dyn Fn(usize, &mut Vec<u8>),
    ) -> Result<(Vec<u8>, Vec<Field>, Vec<Field>)> {
        let task = self.task;
        let (ne, main) = (&task.norm_eq, &task.main);
        let mut w_bytes = self.encrypt(wr_bits)?;
        tamper(PART_WRAPAROUND, &mut w_bytes);
        let joint_rands = task.joint_rands(&self.key, &nonce, &PineTask::digest(&g_bytes), &PineTask::digest(&w_bytes));
        let input = [g, wr_bits, results].concat();

        let (k_ne, k) = (task.descriptor.params.num_proofs_norm_equality, task.descriptor.params.num_proofs);
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let prove_rands: Vec<Field> =
            XofTurboShake128::seed_stream(&seed, &[DST_PROVE, &task.binding], &[]).into_field_vec(k_ne * ne.prove_rand_len() + k * main.prove_rand_len());
        let (pr_ne, pr_main) = prove_rands.split_at(k_ne * ne.prove_rand_len());
        let mut proofs = Vec::with_capacity(task.lens[PART_PROOFS]);
        for pr in pr_ne.chunks(ne.prove_rand_len()) {
            proofs.extend(ne.prove(&input, pr, &[])?);
        }
        for (pr, jr) in pr_main.chunks(main.prove_rand_len()).zip(joint_rands.chunks(3)) {
            proofs.extend(main.prove(&input, pr, jr)?);
        }

        let mut body = nonce.to_vec();
        body.extend(g_bytes);
        body.extend(w_bytes);
        let mut p_bytes = self.encrypt(&proofs)?;
        tamper(PART_PROOFS, &mut p_bytes);
        body.extend(p_bytes);
        Ok((self.seal(&body)?, input, proofs))
    }

    /// Signs a report body (nonce and ciphertexts): appends this client's
    /// identity and its signature of the report's commitment. Tests use it
    /// to sign bodies assembled from parts, as a malicious client could.
    pub fn seal(&self, body: &[u8]) -> Result<Vec<u8>> {
        let task = self.task;
        if body.len() != task.body_len() {
            return Err(Error::Codec("report body has the wrong length".into()));
        }
        let commitment = task.commitment(&self.key, &body[..NONCE_LEN], &task.part_digests(body));
        let mut report = body.to_vec();
        report.extend(self.signing.verifying_key().as_bytes());
        report.extend(self.signing.sign(&commitment).to_bytes());
        Ok(report)
    }

    /// The ciphertexts of one part of a report: `ring` coefficients each
    /// (tests also assemble reports part by part with it).
    pub fn encrypt(&self, coeffs: &[Field]) -> Result<Vec<u8>> {
        let task = self.task;
        let mut out = Vec::with_capacity(coeffs.len().div_ceil(task.ring) * task.fresh_len());
        for block in coeffs.chunks(task.ring) {
            let vals: Vec<u64> = block.iter().map(|&x| to_u64(x)).collect();
            let ct = task.ctx.encrypt(self.pk, &task.ctx.coef_plaintext(&vals)?)?;
            let meta = ct.meta()?;
            if meta.level != 0 || meta.num_elements != 2 || meta.num_towers != <Field as FheField>::SINGLE_NUM_TOWERS {
                return Err(Error::Fhe(format!("unexpected fresh ciphertext metadata {meta:?}")));
            }
            out.extend(task.fresh_codec.pack(&ct.export_residues()?, 2, task.ring)?);
        }
        Ok(out)
    }
}

/// Checks a client's signature of a report commitment.
fn verify_signature(identity: &[u8; 32], commitment: &[u8; 32], signature: &[u8]) -> Result<()> {
    let refused = || Error::Protocol("a report's signature does not verify".into());
    let key = VerifyingKey::from_bytes(identity).map_err(|_| refused())?;
    let signature = Signature::from_slice(signature).map_err(|_| refused())?;
    key.verify_strict(commitment, &signature).map_err(|_| refused())
}

/// Single-use markers that survive restarts: one empty file per marker in
/// a directory of the operator's choice, created exclusively and synced
/// (file and directory) before the caller goes on.
///
/// The directory must be on a local file system that honours exclusive
/// creation and `fsync`, writable only by the party that owns it, and must
/// never be rolled back or emptied while the task's keys are in use:
/// deleting it removes the protection. Markers are never removed.
pub struct Ledger {
    dir: PathBuf,
}

impl Ledger {
    /// `root` must exist and be a directory (not a symbolic link). The
    /// markers of a task and role go to their own subdirectory.
    fn open(root: &Path, task: &PineTask, role: &str) -> Result<Self> {
        let io = |e: std::io::Error| Error::Protocol(format!("ledger: {e}"));
        let meta = fs::symlink_metadata(root).map_err(io)?;
        if !meta.is_dir() {
            return Err(Error::Protocol("the ledger root must be an existing directory".into()));
        }
        let dir = root.join(format!("pine-{}-{role}", hex(&task.binding)));
        match fs::create_dir(&dir) {
            Ok(()) => fs::File::open(root).and_then(|f| f.sync_all()).map_err(io)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io(e)),
        }
        if !fs::symlink_metadata(&dir).map_err(io)?.is_dir() {
            return Err(Error::Protocol("the ledger directory is not a directory".into()));
        }
        Ok(Self { dir })
    }

    /// Records `kind`/`id`, or fails when it was recorded before.
    fn reserve(&self, kind: &str, id: &[u8]) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.dir.join(format!("{kind}-{}", hex(id))))
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::Protocol(format!("{kind} was used before"))
                } else {
                    Error::Protocol(format!("ledger: {e}"))
                }
            })?;
        file.sync_all()
            .and_then(|()| fs::File::open(&self.dir)?.sync_all())
            .map_err(|e| Error::Protocol(format!("ledger: {e}")))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Stored {
    /// Index of the client's identity in the task descriptor.
    identity: u32,
    /// The report's entry in the check request.
    entry: [u8; ENTRY_LEN],
    commitment: [u8; 32],
    cts: Vec<Ciphertext>,
    challenges: Challenges,
}

/// The single aggregator. One instance per batch: reports are ingested,
/// then the check request is built once, then the aggregate request once.
pub struct PineEvaluator<'a> {
    task: &'a PineTask,
    key: [u8; 32],
    verify_key: [u8; 32],
    reference: Ciphertext,
    ledger: Ledger,
    batch: [u8; BATCH_LEN],
    reports: Vec<Stored>,
    sealed: bool,
    released: bool,
}

impl<'a> PineEvaluator<'a> {
    /// `verify_key` is the evaluator's secret: clients must not predict the
    /// query points. `ledger_root`: see [`Ledger`]; it holds the identities
    /// and nonces of every report this evaluator accepted for the task.
    pub fn new(task: &'a PineTask, pk: &PublicKey, verify_key: [u8; 32], ledger_root: &Path) -> Result<Self> {
        verify_single_rebuild_once(&task.ctx)?;
        let reference = task.ctx.encrypt(pk, &task.ctx.coef_plaintext(&[0])?)?;
        let mut batch = [0u8; BATCH_LEN];
        OsRng.fill_bytes(&mut batch);
        Ok(Self {
            task,
            key: task.key_context(pk)?,
            verify_key,
            reference,
            ledger: Ledger::open(ledger_root, task, "evaluator")?,
            batch,
            reports: Vec::new(),
            sealed: false,
            released: false,
        })
    }

    pub fn len(&self) -> usize {
        self.reports.len()
    }
    pub fn is_empty(&self) -> bool {
        self.reports.is_empty()
    }
    /// The identifier of this batch.
    pub fn batch(&self) -> &[u8; BATCH_LEN] {
        &self.batch
    }

    /// Stores a report and derives its challenges. Refused: malformed
    /// bytes, a full or sealed batch, an identity the task does not
    /// authorize, a signature that does not verify for this task, key,
    /// nonce and these exact ciphertext bytes, and an identity or a nonce
    /// this evaluator accepted before for the task, in this batch or any
    /// earlier one.
    pub fn ingest(&mut self, report: &[u8]) -> Result<()> {
        let task = self.task;
        if self.sealed {
            return Err(Error::Protocol("the batch is sealed".into()));
        }
        if report.len() != task.report_len() {
            return Err(Error::Codec(format!("report has {} bytes, expected {}", report.len(), task.report_len())));
        }
        if self.reports.len() as u64 >= task.max_batch() {
            return Err(Error::Protocol("batch is full".into()));
        }
        let (body, seal) = report.split_at(task.body_len());
        let nonce = &body[..NONCE_LEN];
        let identity: [u8; 32] = seal[..32].try_into().expect("length checked");
        let index = task
            .descriptor
            .identity_index(&identity)
            .ok_or_else(|| Error::Protocol("the report's identity is not authorized".into()))?;
        let digests = task.part_digests(body);
        let commitment = task.commitment(&self.key, nonce, &digests);
        verify_signature(&identity, &commitment, &seal[32..])?;

        let meta = self.reference.meta()?;
        let mut cts = Vec::with_capacity(task.ciphertexts_per_report());
        for bytes in body[NONCE_LEN..].chunks(task.fresh_len()) {
            let residues = task.fresh_codec.unpack(bytes, 2, task.ring)?;
            cts.push(task.ctx.build_ciphertext(&self.reference, &meta, &residues)?);
        }
        self.ledger.reserve("identity", &identity)?;
        self.ledger.reserve("nonce", nonce)?;

        let mut entry = [0u8; ENTRY_LEN];
        entry[..4].copy_from_slice(&index.to_le_bytes());
        entry[4..4 + NONCE_LEN].copy_from_slice(nonce);
        for (i, d) in digests.iter().enumerate() {
            entry[4 + NONCE_LEN + 32 * i..4 + NONCE_LEN + 32 * (i + 1)].copy_from_slice(d);
        }
        entry[ENTRY_LEN - 64..].copy_from_slice(&seal[32..]);
        self.reports.push(Stored {
            identity: index,
            entry,
            commitment,
            cts,
            challenges: task.challenges_of(&self.key, &self.verify_key, nonce, &digests, &commitment)?,
        });
        Ok(())
    }

    /// Seals the batch and builds its check request: the batch identifier,
    /// one entry per report in increasing order of identity (identity
    /// index, nonce, digests of the three parts, the client's signature),
    /// and for every report and verifier element the sum over the report's
    /// ciphertexts of `ct x row`, the element at coefficient 0 (with the
    /// verifier's constant added) and a fresh uniform mask on every other
    /// coefficient, flooded and switched to one tower. The verdicts come
    /// back in the same order.
    pub fn check_request(&mut self) -> Result<Vec<u8>> {
        let task = self.task;
        if self.sealed {
            return Err(Error::Protocol("the batch is sealed".into()));
        }
        if self.reports.is_empty() {
            return Err(Error::Protocol("the batch is empty".into()));
        }
        self.sealed = true;
        self.reports.sort_by_key(|r| r.identity);
        let n = task.ring;
        let mut out = Vec::with_capacity(task.check_request_len(self.reports.len()));
        out.extend((self.reports.len() as u32).to_le_bytes());
        out.extend(self.batch);
        for r in &self.reports {
            out.extend(r.entry);
        }
        for r in &self.reports {
            // Admission copies: each ciphertext with a uniform plaintext on
            // every coefficient and p times a uniform ADMIT_MASK_BITS-bit
            // value added, at the full modulus: the collector measures the
            // phase and learns nothing of the plaintext.
            for ct in &r.cts {
                let copy = task
                    .ctx
                    .flood(&task.ctx.add_plain(ct, &task.ctx.coef_plaintext(&task.mask())?)?, ADMIT_MASK_BITS)?;
                out.extend(task.fresh_codec.pack(&copy.export_residues()?, 2, task.ring)?);
            }
            task.verifier_rows(&r.challenges, |row, constant| {
                let mut sum: Option<Ciphertext> = None;
                for (ct, block) in r.cts.iter().zip(row.chunks(n)) {
                    if block.iter().all(|&x| x == Field::zero()) {
                        continue;
                    }
                    // Coefficient 0 of ct x q is <block, plaintext>: X^(n-i) X^i = -1.
                    let mut q = vec![0u64; n];
                    q[0] = to_u64(block[0]);
                    for i in 1..n {
                        q[n - i] = to_u64(-block[i]);
                    }
                    let prod = task.ctx.mult_plain(ct, &task.ctx.coef_plaintext(&q)?)?;
                    sum = Some(match sum {
                        None => prod,
                        Some(s) => task.ctx.add(&s, &prod)?,
                    });
                }
                let sum = sum.ok_or_else(|| Error::Protocol("a verifier row is zero".into()))?;
                let mut mask = task.mask();
                mask[0] = to_u64(constant);
                out.extend(task.pack_reduced(&finish::<Field>(&task.ctx, &task.ctx.add_plain(&sum, &task.ctx.coef_plaintext(&mask)?)?)?)?);
                Ok(())
            })?;
        }
        Ok(out)
    }

    /// The aggregate request, once per batch: the batch identifier, the
    /// hash of the batch's commitments and verdicts, the accepted count,
    /// and the sum of the gradient ciphertexts the verdicts accept, with a
    /// fresh uniform mask on every coefficient that is not a gradient
    /// coordinate, flooded and switched to one tower.
    pub fn aggregate_request(&mut self, verdicts: &[u8]) -> Result<Vec<u8>> {
        let task = self.task;
        if !self.sealed || self.released {
            return Err(Error::Protocol("the aggregate request follows the check request, once".into()));
        }
        if verdicts.len() != self.reports.len().div_ceil(8) {
            return Err(Error::Codec("verdicts have the wrong length".into()));
        }
        let accepted: Vec<&Stored> = self
            .reports
            .iter()
            .enumerate()
            .filter(|(i, _)| verdicts[i / 8] >> (i % 8) & 1 == 1)
            .map(|(_, r)| r)
            .collect();
        if accepted.is_empty() {
            return Err(Error::Protocol("no accepted reports".into()));
        }
        self.released = true;
        let mut msg = self.batch.to_vec();
        msg.extend(task.verdict_hash(&self.key, &self.batch, self.reports.iter().map(|r| &r.commitment), verdicts));
        msg.extend((accepted.len() as u64).to_le_bytes());
        for b in 0..task.output_blocks() {
            let mut sum = accepted[0].cts[b].try_clone()?;
            for r in &accepted[1..] {
                sum = task.ctx.add(&sum, &r.cts[b])?;
            }
            let mut mask = task.mask();
            let coordinates = (task.descriptor.params.dimension - b * task.ring).min(task.ring);
            mask[..coordinates].fill(0);
            msg.extend(task.pack_reduced(&finish::<Field>(&task.ctx, &task.ctx.add_plain(&sum, &task.ctx.coef_plaintext(&mask)?)?)?)?);
        }
        Ok(msg)
    }
}

/// Where the collector is: nothing pending, or a checked batch whose sum
/// may be released once.
enum State {
    Idle,
    Checked {
        batch: [u8; BATCH_LEN],
        accepted: u64,
        verdicts: [u8; 32],
    },
}

/// The collector: holds the whole secret key.
///
/// It authenticates the cohort of a check request (authorized identities,
/// each at most once, each with its signed commitment) and enforces single
/// use. It decrypts what it is sent: nothing here lets it verify that a
/// ciphertext was computed from the committed reports as prescribed.
pub struct PineCollector<'a> {
    task: &'a PineTask,
    sk: SecretShare,
    reference: Ciphertext,
    key: [u8; 32],
    ledger: Ledger,
    state: State,
    accepted: Option<u64>,
    decryptions: Cell<u64>,
}

impl<'a> PineCollector<'a> {
    /// Generates the key pair; the public key goes to clients and the
    /// evaluator. `ledger_root`: see [`Ledger`]; it holds the batch
    /// identifiers, identities, nonces and releases this collector
    /// processed.
    pub fn new(task: &'a PineTask, ledger_root: &Path) -> Result<(Self, PublicKey)> {
        let (pk, sk) = keygen_first(&task.ctx)?;
        Ok((Self::with_keys(task, &pk, sk, ledger_root)?, pk))
    }

    /// The collector of an existing key pair, after a restart: with the
    /// ledger it used before. A batch that was checked but not released
    /// before the restart cannot be released any more.
    pub fn with_keys(task: &'a PineTask, pk: &PublicKey, sk: SecretShare, ledger_root: &Path) -> Result<Self> {
        verify_single_rebuild_once(&task.ctx)?;
        let probe = [1, 2, 3, 4];
        if sk.decrypt_coeffs(&task.ctx.encrypt(pk, &task.ctx.coef_plaintext(&probe)?)?, &[0, 1, 2, 3])? != probe {
            return Err(Error::Protocol("the secret key does not match the public key".into()));
        }
        let reference = task.ctx.encrypt(pk, &task.ctx.coef_plaintext(&[0])?)?;
        Ok(Self {
            task,
            sk,
            reference,
            key: task.key_context(pk)?,
            ledger: Ledger::open(ledger_root, task, "collector")?,
            state: State::Idle,
            accepted: None,
            decryptions: Cell::new(0),
        })
    }

    /// The secret key, to be stored by the operator for [`Self::with_keys`].
    /// Whoever reads these bytes can decrypt every report of the task.
    pub fn serialize_secret_key(&self) -> Result<Vec<u8>> {
        Ok(self.sk.serialize()?)
    }

    /// Ciphertexts this collector has decrypted so far (tests establish
    /// with it that a refusal came before any decryption).
    pub fn decryptions(&self) -> u64 {
        self.decryptions.get()
    }

    fn open(&self, bytes: &[u8], idx: &[u32]) -> Result<Vec<Field>> {
        let res = self.task.reduced_codec.unpack(bytes, 2, self.task.ring)?;
        let ct = self.task.ctx.build_ciphertext(&self.reference, &self.task.reduced_meta, &res)?;
        self.decryptions.set(self.decryptions.get() + 1);
        Ok(self.sk.decrypt_coeffs(&ct, idx)?.into_iter().map(from_u64).collect())
    }

    /// Decrypts every report's verifier, runs prio's `decide` on each proof
    /// and returns one bit per report (bit `i % 8` of byte `i / 8`).
    pub fn check(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        Ok(self.check_with_verifiers(request)?.0)
    }

    /// [`Self::check`], also returning each report's verifier message,
    /// which the collector learns in any case.
    ///
    /// Refused while a checked batch awaits release ([`Self::abandon`]
    /// gives it up). Before anything is decrypted:
    /// * the whole request is decoded;
    /// * the cohort is authenticated: identities authorized by the task, in
    ///   increasing order (so each at most once), each entry's signature
    ///   valid for this task, key, nonce and part digests;
    /// * the batch identifier, every identity and every nonce are recorded
    ///   as used; a request that repeats one is refused, and what it
    ///   recorded until then stays recorded.
    ///
    /// With fewer accepted reports than the task's release threshold the
    /// batch is closed: nothing can be released for it.
    pub fn check_with_verifiers(&mut self, request: &[u8]) -> Result<(Vec<u8>, Vec<Vec<Field>>)> {
        let task = self.task;
        if !matches!(self.state, State::Idle) {
            return Err(Error::Protocol("a checked batch awaits release: release or abandon it first".into()));
        }
        if request.len() < CHECK_HEADER {
            return Err(Error::Codec("check request too short".into()));
        }
        let n = u32::from_le_bytes(request[..4].try_into().expect("length checked")) as usize;
        if n == 0 || n as u64 > task.max_batch() || request.len() != task.check_request_len(n) {
            return Err(Error::Codec("check request has the wrong length".into()));
        }
        let batch: [u8; BATCH_LEN] = request[4..CHECK_HEADER].try_into().expect("length checked");
        let (entries, ciphertexts) = request[CHECK_HEADER..].split_at(n * ENTRY_LEN);

        let mut cohort = Vec::with_capacity(n);
        let mut commitments = Vec::with_capacity(n);
        let mut previous = None;
        for entry in entries.chunks(ENTRY_LEN) {
            let index = u32::from_le_bytes(entry[..4].try_into().expect("length checked"));
            if previous.is_some_and(|p| index <= p) {
                return Err(Error::Protocol("identities must be distinct and in increasing order".into()));
            }
            previous = Some(index);
            let identity = task
                .descriptor
                .identities
                .get(index as usize)
                .ok_or_else(|| Error::Protocol("an identity is not authorized".into()))?;
            let nonce = &entry[4..4 + NONCE_LEN];
            let digest = |i: usize| -> [u8; 32] { entry[4 + NONCE_LEN + 32 * i..4 + NONCE_LEN + 32 * (i + 1)].try_into().expect("length checked") };
            let commitment = task.commitment(&self.key, nonce, &[digest(0), digest(1), digest(2)]);
            verify_signature(identity, &commitment, &entry[ENTRY_LEN - 64..])?;
            cohort.push((identity, nonce));
            commitments.push(commitment);
        }
        if cohort.iter().map(|(_, nonce)| nonce).collect::<HashSet<_>>().len() != n {
            return Err(Error::Protocol("a nonce appears twice in the request".into()));
        }
        let fresh = self.reference.meta()?;
        for report in ciphertexts.chunks(task.check_len()) {
            let (copies, elements) = task.split_check(report);
            for bytes in copies.chunks(task.fresh_len()) {
                task.fresh_codec.unpack(bytes, 2, task.ring)?;
            }
            task.preflight(elements)?;
        }

        self.ledger.reserve("batch", &batch)?;
        for (identity, nonce) in &cohort {
            self.ledger.reserve("identity", *identity)?;
            self.ledger.reserve("nonce", nonce)?;
        }
        self.accepted = None;

        let mut verdicts = vec![0u8; n.div_ceil(8)];
        let mut verifiers = Vec::with_capacity(n);
        let mut accepted = 0u64;
        for (i, report) in ciphertexts.chunks(task.check_len()).enumerate() {
            let (copies, elements) = task.split_check(report);
            // Admission first: a report with a ciphertext whose phase is
            // beyond the bound is rejected and none of its verifier
            // elements is decrypted.
            let mut admitted = true;
            for bytes in copies.chunks(task.fresh_len()) {
                let copy = task
                    .ctx
                    .build_ciphertext(&self.reference, &fresh, &task.fresh_codec.unpack(bytes, 2, task.ring)?)?;
                admitted &= self.sk.phase_bits(&copy)? < ADMIT_BITS;
            }
            let mut verifier = Vec::with_capacity(task.verifier_len());
            if admitted {
                for bytes in elements.chunks(task.reduced_len()) {
                    verifier.extend(self.open(bytes, &[0])?);
                }
            }
            if admitted && task.decide(&verifier)? {
                verdicts[i / 8] |= 1 << (i % 8);
                accepted += 1;
            }
            verifiers.push(verifier);
        }
        self.accepted = Some(accepted);
        if accepted >= u64::from(task.descriptor.min_accepted) {
            self.state = State::Checked {
                batch,
                accepted,
                verdicts: task.verdict_hash(&self.key, &batch, commitments.iter(), &verdicts),
            };
        }
        Ok((verdicts, verifiers))
    }

    /// The reports the last check accepted.
    pub fn accepted(&self) -> Option<u64> {
        self.accepted
    }

    /// Gives up the checked batch without releasing its sum (the operator's
    /// decision, for instance when the evaluator is gone). Recorded; the
    /// batch can never be released.
    pub fn abandon(&mut self) -> Result<()> {
        let State::Checked { batch, .. } = &self.state else {
            return Err(Error::Protocol("no checked batch to abandon".into()));
        };
        self.ledger.reserve("release", batch)?;
        self.state = State::Idle;
        Ok(())
    }

    /// Decrypts the gradient coordinates of the aggregate and decodes them,
    /// once per checked batch. Refused unless the request names the batch
    /// just checked, the hash of its commitments and of the verdicts this
    /// collector gave, and the count it accepted; the release is recorded
    /// as used before anything is decrypted.
    ///
    /// These are the evaluator's statements about which batch it means,
    /// not a proof: the collector cannot tell whether the ciphertext is the
    /// sum of the reports it accepted.
    pub fn unshard(&mut self, request: &[u8]) -> Result<Vec<f64>> {
        let task = self.task;
        if request.len() != task.aggregate_request_len() {
            return Err(Error::Codec("aggregate request has the wrong length".into()));
        }
        let (header, ciphertexts) = request.split_at(AGGREGATE_HEADER);
        let count = u64::from_le_bytes(header[BATCH_LEN + 32..].try_into().expect("length checked"));
        match &self.state {
            State::Checked { batch, accepted, verdicts }
                if batch[..] == header[..BATCH_LEN] && verdicts[..] == header[BATCH_LEN..BATCH_LEN + 32] && *accepted == count => {}
            _ => {
                return Err(Error::Protocol(
                    "the aggregate does not cover the batch, the verdicts and the reports just accepted".into(),
                ));
            }
        }
        task.preflight(ciphertexts)?;
        self.ledger.reserve("release", &header[..BATCH_LEN])?;
        self.state = State::Idle;
        let mut sum = Vec::with_capacity(task.descriptor.params.dimension);
        for (b, bytes) in ciphertexts.chunks(task.reduced_len()).enumerate() {
            let coordinates = (task.descriptor.params.dimension - b * task.ring).min(task.ring) as u32;
            sum.extend(self.open(bytes, &(0..coordinates).collect::<Vec<u32>>())?);
        }
        Ok(task.shape().decode(&sum))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The noise a verifier element carries before flooding, in the worst
    /// case of the layout: a dense row over every ciphertext of a report of
    /// dense plaintexts. `finish` floods with `width` bits; the margin is
    /// measured here, on real ciphertexts, as
    /// `openfhe-tbgv-rs/tests/single_key.rs` measures it for one product.
    /// It is a measurement of this instance, not a worst-case proof: each
    /// doubling of the ciphertexts a row reads can cost one more bit.
    #[test]
    fn flooding_margin_of_a_dense_row_over_every_ciphertext() {
        let task = PineTask::new(TaskDescriptor {
            application: [0; 32],
            model_hash: [0; 32],
            round: 0,
            params: PineParams {
                dimension: 9000,
                l2_norm_bound: 128,
                num_frac_bits: 7,
                chunk_length: 4,
                chunk_length_norm_equality: 64,
                num_proofs: 2,
                num_proofs_norm_equality: 1,
            },
            min_accepted: 1,
            identities: vec![SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes()],
        })
        .unwrap();
        let ctx = &task.ctx;
        let (pk, sk) = keygen_first(ctx).unwrap();
        let dense = || task.mask();
        let mut sum: Option<Ciphertext> = None;
        for _ in 0..task.ciphertexts_per_report() {
            let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&dense()).unwrap()).unwrap();
            let prod = ctx.mult_plain(&ct, &ctx.coef_plaintext(&dense()).unwrap()).unwrap();
            sum = Some(match sum {
                None => prod,
                Some(s) => ctx.add(&s, &prod).unwrap(),
            });
        }
        let sum = sum.unwrap();
        let towers = sum.meta().unwrap().num_towers as usize;
        let log_q: f64 = ctx.moduli().unwrap()[..towers].iter().map(|&q| (q as f64).log2()).sum();
        let log_p = (PLAIN_MOD as f64).log2();
        let width = log_q.floor() - log_p.ceil() - 2.0;
        let (_, log2_phase, _) = ctx.raw_decrypt_for_tests(&sum, &[&sk]).unwrap();
        let margin = width - 1.0 - (log2_phase - log_p);
        eprintln!(
            "{} ciphertexts, flood width {width}, log2 max|phase| {log2_phase:.1}, margin {margin:.1} bits",
            task.ciphertexts_per_report()
        );
        assert!(margin >= 64.0, "flooding margin {margin:.1} below 64 bits");
    }
}
