//! PINE (private inexpensive norm enforcement, `draft-chen-cfrg-vdaf-pine`)
//! in the one-aggregator protocol of [`crate::single`]: clients send
//! encrypted real-valued vectors (gradients) with a proof that the L2 norm
//! is at most a bound; the collector learns the sum of the valid ones.
//!
//! Trust: as in [`crate::single`]. The evaluator and the collector do not
//! collude and follow the protocol; clients may be malicious.
//!
//! ```text
//! client    -> evaluator : report = nonce || G || W || P, each one or more ciphertexts:
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
//! Challenges. PINE fixes its randomness in two steps, each bound to a
//! commitment to what the client already sent. Here the commitment is the
//! ciphertext bytes (decryption is a function of them), as [`crate::single`]
//! does for Prio3's joint randomness:
//! * the wraparound test vectors come from the nonce and the bytes of `G`;
//! * the main circuit's joint randomness comes from the nonce and the bytes
//!   of `G` and `W`;
//! * the query points come from the evaluator's secret key and the whole
//!   report.
//!
//! So `W` cannot depend on test vectors other than those `G` fixes, and the
//! proofs cannot change `G` or `W`.
//!
//! The dot products of the wraparound tests are not sent: they are linear
//! in the gradient, so the evaluator folds the test vectors into the
//! verifier rows. Every verifier element is the constant coefficient of one
//! product sum, which depends on a plaintext's coefficients inside the
//! report's layout only: what a malicious client puts elsewhere is
//! multiplied by 0, and the aggregate reads the gradient coordinates only.
//!
//! What a cheating client can hope for (per report unless stated):
//! * an FLP query that misses: [`PineTask::log2_query_soundness`];
//! * joint randomness under which an invalid measurement evaluates to 0 in
//!   every main proof: [`PineTask::log2_joint_rand_per_attempt`] per
//!   offline attempt (a new nonce or re-encryption is an attempt);
//! * a wraparound of the squared norm that all tests miss: each test
//!   detects one with probability at least 1/2 ([ROCT23], as cited by the
//!   draft), so `2^-100` per offline attempt at the reference's 100 tests.
//!
//! Not provided here: hiding the verdicts from the evaluator, binding of
//! the requests to a batch, a noise bound checked by the collector, and
//! protection against an evaluator that deviates (`HARDENING-PLAN.md`,
//! `OBLIVIOUS-AGGREGATION-PLAN.md`).
pub mod circuit;

use crate::codec::ResidueCodec;
use crate::protocol::{MAX_BATCH, MAX_PROOFS, NONCE_LEN, from_u64, to_u64};
use crate::single::finish;
use crate::{Error, FheField, Field, PLAIN_MOD, Result};
use circuit::{Main, NUM_WR_CHECKS, NormEquality, Shape, check_linear_map};
use openfhe_tbgv_rs::{Ciphertext, CiphertextMeta, Context, PublicKey, SecretShare, keygen_first, verify_single_rebuild_once};
use prio::field::{FieldElement, FieldElementWithInteger};
use prio::flp::Flp;
use prio::vdaf::xof::{IntoFieldVec, Xof, XofTurboShake128};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ops::Range;

const DST_TASK: &[u8] = b"fhe-flp/1 pine task";
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
    params: PineParams,
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
    pub fn new(params: PineParams, task_id: [u8; 32]) -> Result<Self> {
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

        let mut h = Sha256::new();
        h.update(DST_TASK);
        h.update(task_id);
        for v in [
            params.dimension as u64,
            params.l2_norm_bound,
            params.num_frac_bits as u64,
            params.chunk_length as u64,
            params.chunk_length_norm_equality as u64,
            params.num_proofs as u64,
            params.num_proofs_norm_equality as u64,
            NUM_WR_CHECKS as u64,
            PLAIN_MOD,
            ring as u64,
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
            params,
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

    pub fn params(&self) -> &PineParams {
        &self.params
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
        MAX_BATCH.min((PLAIN_MOD - 1) / (2 * self.params.l2_norm_bound))
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
    pub fn report_len(&self) -> usize {
        NONCE_LEN + self.ciphertexts_per_report() * self.fresh_len()
    }
    /// The bytes of `part` (`PART_*`) in a report.
    pub fn part_range(&self, part: usize) -> Range<usize> {
        let fl = self.fresh_len();
        NONCE_LEN + self.first_block(part) * fl..NONCE_LEN + self.first_block(part + 1) * fl
    }
    /// Verifier elements per report: one ciphertext each in a check request.
    pub fn verifier_len(&self) -> usize {
        self.params.num_proofs_norm_equality * self.norm_eq.verifier_len() + self.params.num_proofs * self.main.verifier_len()
    }
    pub fn check_request_len(&self, reports: usize) -> usize {
        4 + reports * self.verifier_len() * self.reduced_len()
    }
    /// Ciphertexts of the aggregate: those holding gradient coordinates.
    fn output_blocks(&self) -> usize {
        self.params.dimension.div_ceil(self.ring)
    }
    pub fn aggregate_request_len(&self) -> usize {
        8 + self.output_blocks() * self.reduced_len()
    }

    /// log2 of the probability that the queries of one report miss an
    /// invalid proof of either circuit, for inputs on which the circuit is
    /// nonzero: per proof `2 (P - 1) / (p - 2 P)` (a gadget of degree 2 with
    /// wire polynomials of length `P`; query points avoid the `2 P`-th roots
    /// of unity), to the power of the number of proofs; the larger of the
    /// two circuits.
    pub fn log2_query_soundness(&self) -> f64 {
        let per = |w: usize| (2.0 * (w as f64 - 1.0) / (PLAIN_MOD as f64 - 2.0 * w as f64)).log2();
        (per(wire_len(&self.norm_eq)) * self.params.num_proofs_norm_equality as f64).max(per(wire_len(&self.main)) * self.params.num_proofs as f64)
    }
    /// log2 of the probability that one choice of joint randomness makes
    /// the main circuit 0 on an invalid measurement in every proof (see
    /// [`Main::joint_rand_degree`]). A client can try choices offline.
    pub fn log2_joint_rand_per_attempt(&self) -> f64 {
        (self.main.joint_rand_degree() as f64 / PLAIN_MOD as f64).log2() * self.params.num_proofs as f64
    }

    fn digest(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// The wraparound test vectors of a report: from its nonce and the
    /// bytes of its gradient part.
    fn wr_vectors(&self, nonce: &[u8], gradient_part: &[u8]) -> Vec<i8> {
        let mut xof = XofTurboShake128::init(&[0u8; 32], &[DST_WR_SEED, &self.binding]);
        xof.update(nonce);
        xof.update(&Self::digest(gradient_part));
        let seed = xof.into_seed();
        self.shape()
            .wr_vectors(&mut XofTurboShake128::seed_stream(seed.as_ref(), &[DST_WR, &self.binding], &[]))
    }

    /// The joint randomness of every main proof: from the nonce and the
    /// bytes of the gradient and wraparound parts.
    fn joint_rands(&self, nonce: &[u8], gradient_part: &[u8], wraparound_part: &[u8]) -> Vec<Field> {
        let mut xof = XofTurboShake128::init(&[0u8; 32], &[DST_JOINT_RAND_SEED, &self.binding]);
        xof.update(nonce);
        xof.update(&Self::digest(gradient_part));
        xof.update(&Self::digest(wraparound_part));
        let seed = xof.into_seed();
        XofTurboShake128::seed_stream(seed.as_ref(), &[DST_JOINT_RAND, &self.binding], &[]).into_field_vec(3 * self.params.num_proofs)
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

    /// The query points of a report: from the evaluator's secret key and
    /// the whole report.
    fn query_points(&self, verify_key: &[u8; 32], report: &[u8]) -> Result<(Vec<Field>, Vec<Field>)> {
        let stream = XofTurboShake128::seed_stream(verify_key, &[DST_QUERY, &self.binding], &[&report[..NONCE_LEN], &Self::digest(report)]);
        self.sample_query_points(stream, self.params.num_proofs_norm_equality, self.params.num_proofs)
    }

    /// Every challenge of a report, as the evaluator derives them: the
    /// wraparound test vectors, the joint randomness of the main proofs and
    /// the query points of the norm-equality and of the main proofs.
    pub fn challenges(&self, verify_key: &[u8; 32], report: &[u8]) -> Result<Challenges> {
        if report.len() != self.report_len() {
            return Err(Error::Codec(format!("report has {} bytes, expected {}", report.len(), self.report_len())));
        }
        let (g, w) = (&report[self.part_range(PART_GRADIENT)], &report[self.part_range(PART_WRAPAROUND)]);
        let (t_norm_equality, t_main) = self.query_points(verify_key, report)?;
        Ok(Challenges {
            wr_vectors: self.wr_vectors(&report[..NONCE_LEN], g),
            joint_rands: self.joint_rands(&report[..NONCE_LEN], g, w),
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
        let (vectors, joint_rands, t_ne, t_main) = (&ch.wr_vectors, &ch.joint_rands, &ch.t_norm_equality, &ch.t_main);
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
        let (v_ne, v_main) = verifier.split_at(self.params.num_proofs_norm_equality * self.norm_eq.verifier_len());
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

/// The challenges of one report ([`PineTask::challenges`]).
pub struct Challenges {
    /// `NUM_WR_CHECKS` vectors of `dimension` entries in `{-1, 0, 1}`.
    pub wr_vectors: Vec<i8>,
    /// Three elements per main proof.
    pub joint_rands: Vec<Field>,
    pub t_norm_equality: Vec<Field>,
    pub t_main: Vec<Field>,
}

pub struct PineClient<'a> {
    task: &'a PineTask,
    pk: &'a PublicKey,
}

impl<'a> PineClient<'a> {
    pub fn new(task: &'a PineTask, pk: &'a PublicKey) -> Self {
        Self { task, pk }
    }

    /// Encodes, proves and encrypts a gradient. Refused: a gradient whose
    /// encoded norm exceeds the bound (clip first), NaN, infinities and
    /// subnormals.
    pub fn shard(&self, gradient: &[f64]) -> Result<Vec<u8>> {
        Ok(self.shard_with_witness(gradient)?.0)
    }

    /// [`Self::shard`], also returning the circuits' input (measurement and
    /// dot products) and the proofs (tests: comparison with prio).
    pub fn shard_with_witness(&self, gradient: &[f64]) -> Result<(Vec<u8>, Vec<Field>, Vec<Field>)> {
        let shape = self.task.shape();
        let g = shape.encode_gradient_and_norm(gradient)?;
        for _ in 0..SHARD_ATTEMPTS {
            let (nonce, g_bytes, vectors) = self.commit(&g)?;
            if let Some((wr_bits, results)) = shape.encode_wr_checks(&g[..shape.dimension()], &vectors) {
                return self.complete(nonce, &g, g_bytes, &wr_bits, &results);
            }
        }
        Err(Error::Protocol("the wraparound tests failed on every attempt".into()))
    }

    /// A report for arbitrary coefficients, valid or not, built in the
    /// honest order: `gradient_part` is encrypted (the gradient and norm
    /// bits, then anything up to the end of its last ciphertext), `claim`
    /// receives the true dot products of the test vectors that fixes and
    /// returns the wraparound part to send, and the proofs are prio's for
    /// that input (malicious-client tests).
    pub fn shard_encoded(&self, gradient_part: &[Field], claim: impl FnOnce(&[Field]) -> Vec<Field>) -> Result<Vec<u8>> {
        let task = self.task;
        let shape = task.shape();
        let g_len = task.lens[PART_GRADIENT];
        if gradient_part.len() < g_len || gradient_part.len() > task.blocks(PART_GRADIENT) * task.ring {
            return Err(Error::Protocol("unexpected gradient part length".into()));
        }
        let (nonce, g_bytes, vectors) = self.commit(gradient_part)?;
        let results = shape.wr_results(&gradient_part[..shape.dimension()], &vectors);
        let wr_bits = claim(&results);
        if wr_bits.len() != task.lens[PART_WRAPAROUND] {
            return Err(Error::Protocol("unexpected wraparound part length".into()));
        }
        Ok(self.complete(nonce, &gradient_part[..g_len], g_bytes, &wr_bits, &results)?.0)
    }

    /// A fresh nonce, the encrypted gradient part and the wraparound test
    /// vectors they fix.
    fn commit(&self, g: &[Field]) -> Result<([u8; NONCE_LEN], Vec<u8>, Vec<i8>)> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let g_bytes = self.encrypt(g)?;
        let vectors = self.task.wr_vectors(&nonce, &g_bytes);
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
    ) -> Result<(Vec<u8>, Vec<Field>, Vec<Field>)> {
        let task = self.task;
        let (ne, main) = (&task.norm_eq, &task.main);
        let w_bytes = self.encrypt(wr_bits)?;
        let joint_rands = task.joint_rands(&nonce, &g_bytes, &w_bytes);
        let input = [g, wr_bits, results].concat();

        let (k_ne, k) = (task.params.num_proofs_norm_equality, task.params.num_proofs);
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

        let mut report = nonce.to_vec();
        report.extend(g_bytes);
        report.extend(w_bytes);
        report.extend(self.encrypt(&proofs)?);
        Ok((report, input, proofs))
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

struct Stored {
    cts: Vec<Ciphertext>,
    challenges: Challenges,
}

/// The single aggregator. One instance per batch.
pub struct PineEvaluator<'a> {
    task: &'a PineTask,
    verify_key: [u8; 32],
    reference: Ciphertext,
    seen: HashSet<[u8; NONCE_LEN]>,
    reports: Vec<Stored>,
}

impl<'a> PineEvaluator<'a> {
    /// `verify_key` is the evaluator's secret: clients must not predict the
    /// query points.
    pub fn new(task: &'a PineTask, pk: &PublicKey, verify_key: [u8; 32]) -> Result<Self> {
        verify_single_rebuild_once(&task.ctx)?;
        let reference = task.ctx.encrypt(pk, &task.ctx.coef_plaintext(&[0])?)?;
        Ok(Self {
            task,
            verify_key,
            reference,
            seen: HashSet::new(),
            reports: Vec::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.reports.len()
    }
    pub fn is_empty(&self) -> bool {
        self.reports.is_empty()
    }

    /// Stores a report and derives its challenges. Refuses malformed bytes,
    /// a replayed nonce and a full batch.
    pub fn ingest(&mut self, report: &[u8]) -> Result<()> {
        let task = self.task;
        if report.len() != task.report_len() {
            return Err(Error::Codec(format!("report has {} bytes, expected {}", report.len(), task.report_len())));
        }
        if self.reports.len() as u64 >= task.max_batch() {
            return Err(Error::Protocol("batch is full".into()));
        }
        let nonce: [u8; NONCE_LEN] = report[..NONCE_LEN].try_into().expect("length checked");
        let meta = self.reference.meta()?;
        let mut cts = Vec::with_capacity(task.ciphertexts_per_report());
        for bytes in report[NONCE_LEN..].chunks(task.fresh_len()) {
            let residues = task.fresh_codec.unpack(bytes, 2, task.ring)?;
            cts.push(task.ctx.build_ciphertext(&self.reference, &meta, &residues)?);
        }
        if !self.seen.insert(nonce) {
            return Err(Error::Protocol("duplicate report nonce".into()));
        }
        self.reports.push(Stored {
            cts,
            challenges: task.challenges(&self.verify_key, report)?,
        });
        Ok(())
    }

    /// The batch's check request: for every report and verifier element,
    /// the sum over the report's ciphertexts of `ct x row`, the element at
    /// coefficient 0 (with the verifier's constant added) and a fresh
    /// uniform mask on every other coefficient, flooded and switched to one
    /// tower.
    pub fn check_request(&self) -> Result<Vec<u8>> {
        let task = self.task;
        let n = task.ring;
        let mut out = Vec::with_capacity(task.check_request_len(self.reports.len()));
        out.extend((self.reports.len() as u32).to_le_bytes());
        for r in &self.reports {
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

    /// The aggregate request: the sum of the gradient ciphertexts the
    /// verdicts accept, a fresh uniform mask on every coefficient that is
    /// not a gradient coordinate, flooded and switched to one tower.
    pub fn aggregate_request(&self, verdicts: &[u8]) -> Result<Vec<u8>> {
        let task = self.task;
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
        let mut msg = (accepted.len() as u64).to_le_bytes().to_vec();
        for b in 0..task.output_blocks() {
            let mut sum = accepted[0].cts[b].try_clone()?;
            for r in &accepted[1..] {
                sum = task.ctx.add(&sum, &r.cts[b])?;
            }
            let mut mask = task.mask();
            let coordinates = (task.params.dimension - b * task.ring).min(task.ring);
            mask[..coordinates].fill(0);
            msg.extend(task.pack_reduced(&finish::<Field>(&task.ctx, &task.ctx.add_plain(&sum, &task.ctx.coef_plaintext(&mask)?)?)?)?);
        }
        Ok(msg)
    }
}

/// The collector: holds the whole secret key.
pub struct PineCollector<'a> {
    task: &'a PineTask,
    sk: SecretShare,
    reference: Ciphertext,
    accepted: Option<u64>,
}

impl<'a> PineCollector<'a> {
    /// Generates the key pair; the public key goes to clients and the
    /// evaluator.
    pub fn new(task: &'a PineTask) -> Result<(Self, PublicKey)> {
        verify_single_rebuild_once(&task.ctx)?;
        let (pk, sk) = keygen_first(&task.ctx)?;
        let reference = task.ctx.encrypt(&pk, &task.ctx.coef_plaintext(&[0])?)?;
        Ok((
            Self {
                task,
                sk,
                reference,
                accepted: None,
            },
            pk,
        ))
    }

    fn open(&self, bytes: &[u8], idx: &[u32]) -> Result<Vec<Field>> {
        let res = self.task.reduced_codec.unpack(bytes, 2, self.task.ring)?;
        let ct = self.task.ctx.build_ciphertext(&self.reference, &self.task.reduced_meta, &res)?;
        Ok(self.sk.decrypt_coeffs(&ct, idx)?.into_iter().map(from_u64).collect())
    }

    /// Decrypts every report's verifier, runs prio's `decide` on each proof
    /// and returns one bit per report (bit `i % 8` of byte `i / 8`).
    pub fn check(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        Ok(self.check_with_verifiers(request)?.0)
    }

    /// [`Self::check`], also returning each report's verifier message,
    /// which the collector learns in any case.
    pub fn check_with_verifiers(&mut self, request: &[u8]) -> Result<(Vec<u8>, Vec<Vec<Field>>)> {
        let task = self.task;
        if request.len() < 4 {
            return Err(Error::Codec("check request too short".into()));
        }
        let n = u32::from_le_bytes(request[..4].try_into().expect("length checked")) as usize;
        if n as u64 > task.max_batch() || request.len() != task.check_request_len(n) {
            return Err(Error::Codec("check request has the wrong length".into()));
        }
        let mut verdicts = vec![0u8; n.div_ceil(8)];
        let mut verifiers = Vec::with_capacity(n);
        let mut accepted = 0u64;
        for (i, report) in request[4..].chunks(task.verifier_len() * task.reduced_len()).enumerate() {
            let mut verifier = Vec::with_capacity(task.verifier_len());
            for bytes in report.chunks(task.reduced_len()) {
                verifier.extend(self.open(bytes, &[0])?);
            }
            if task.decide(&verifier)? {
                verdicts[i / 8] |= 1 << (i % 8);
                accepted += 1;
            }
            verifiers.push(verifier);
        }
        self.accepted = Some(accepted);
        Ok((verdicts, verifiers))
    }

    /// The reports the last check accepted.
    pub fn accepted(&self) -> Option<u64> {
        self.accepted
    }

    /// Decrypts the gradient coordinates of the aggregate and decodes them:
    /// the sum of the accepted gradients. Refused unless the count matches
    /// the reports this collector accepted.
    pub fn unshard(&self, request: &[u8]) -> Result<Vec<f64>> {
        let task = self.task;
        if request.len() != task.aggregate_request_len() {
            return Err(Error::Codec("aggregate request has the wrong length".into()));
        }
        let count = u64::from_le_bytes(request[..8].try_into().expect("length checked"));
        if Some(count) != self.accepted || count == 0 {
            return Err(Error::Protocol("the aggregate does not cover the accepted reports".into()));
        }
        let mut sum = Vec::with_capacity(task.params.dimension);
        for (b, bytes) in request[8..].chunks(task.reduced_len()).enumerate() {
            let coordinates = (task.params.dimension - b * task.ring).min(task.ring) as u32;
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
        let task = PineTask::new(
            PineParams {
                dimension: 9000,
                l2_norm_bound: 128,
                num_frac_bits: 7,
                chunk_length: 4,
                chunk_length_norm_equality: 64,
                num_proofs: 2,
                num_proofs_norm_equality: 1,
            },
            [0; 32],
        )
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
