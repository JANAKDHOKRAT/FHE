//! One aggregator (the evaluator) and a collector that holds the whole BGV
//! key.
//!
//! Trust: the evaluator and the collector do not collude and follow the
//! protocol (the model of this repository's single-evaluator packages).
//! Clients may be malicious.
//!
//! ```text
//! client    -> evaluator : report = nonce || ciphertext(s) of z = input || proof_1 || .. || proof_k
//!                          (Prio3 encoding, prio's unchanged FLP)
//!                          * types without joint randomness (Count, Sum, BitVec): one
//!                            ciphertext holding z;
//!                          * types with joint randomness (SumVec, Histogram,
//!                            MultihotCountVec): first a ciphertext of the input, then one of
//!                            the proofs, made with joint randomness derived from the bytes of
//!                            the first, as Prio3 derives it from a commitment to the input
//! evaluator -> collector : check request, at batch end: per report and group of
//!                          verifier rows, ct x Q~ + mask, flooded, switched to one tower
//! collector -> evaluator : verdicts, one bit per report (Prio3's decide)
//! evaluator -> collector : aggregate request: the sum of accepted inputs, mapped to the
//!                          aggregate by prio's (linear) truncate under encryption, masked,
//!                          flooded, switched to one tower: one ciphertext
//! collector              : decrypts the output coefficients only, Prio3's decode_result
//! ```
//!
//! What each party learns:
//! * evaluator: ciphertexts (RLWE under the collector's key) and the verdicts;
//! * collector: per report exactly the FLP verifier message, which is what
//!   Prio3's aggregators learn and is covered by the FLP's zero knowledge,
//!   then the aggregate (for Sum and SumVec the weighted totals, never the
//!   per-bit counts). Every other coefficient of what it decrypts carries a
//!   fresh uniform mask; the noise is flooded (statistical distance at most
//!   2^-64 per coefficient in the worst case, `openfhe-tbgv-rs/tests/single_key.rs`).
//!
//! The collector participates once per batch (two messages), never per
//! report, and never sees a report ciphertext.
use crate::codec::ResidueCodec;
use crate::protocol::{FlpPlan, Layout, NONCE_LEN, OutputMap, VerifierMap};
use crate::{Error, FheField, Result};
use openfhe_tbgv_rs::{Ciphertext, CiphertextMeta, Context, PublicKey, SecretShare, keygen_first, verify_single_rebuild_once};
use prio::vdaf::xof::{IntoFieldVec, Xof, XofTurboShake128};
use rand::RngCore;
use rand::rngs::OsRng;
use std::collections::HashSet;
use std::ops::Range;

/// The modulus chain comes from the field ([`FheField`]): measured so that
/// the worst-case flooding margin is at least 64 bits at ring 8192.
const DST_MASK: &[u8] = b"fhe-flp/1 single mask";
const DST_PAD: &[u8] = b"fhe-flp/1 single support pad";

/// Everything the client, the evaluator and the collector agree on.
pub struct SingleTask<F: FheField, T: VerifierMap<F>> {
    plan: FlpPlan<F, T>,
    ctx: Context,
    /// Fresh reports: all towers.
    fresh_codec: ResidueCodec,
    /// What the collector receives: one tower.
    reduced_codec: ResidueCodec,
    /// Metadata of every object the collector receives, read off a real one.
    reduced_meta: CiphertextMeta,
    /// Ciphertexts per report: 2 when the circuit uses joint randomness.
    parts: usize,
    /// How the aggregate is read off the sum of the input ciphertexts.
    agg: AggMap,
}

/// The aggregate under encryption. Each output coefficient depends on the
/// input coefficients `[0, |input|)` only, whatever else a client's
/// plaintext holds: values a malicious client puts outside its input (where
/// no FLP row reads them) cannot reach the aggregate.
enum AggMap {
    /// Output `j` is input coefficient `idx[j]`: decrypted directly.
    Select(Vec<u32>),
    /// Output `j` is `sum_t pattern[t] * input[offset + stride * j + t]`
    /// (Sum, SumVec: bits weighted by powers of two): the sum times the one
    /// plaintext `W = sum_t pattern[t] * X^-t`, whose coefficient
    /// `offset + stride * j` is exactly that, then read at those
    /// coefficients.
    Convolution { coeffs: Vec<u32>, poly: Vec<u64> },
}

impl AggMap {
    fn coeffs(&self) -> &[u32] {
        match self {
            AggMap::Select(idx) => idx,
            AggMap::Convolution { coeffs, .. } => coeffs,
        }
    }
}

/// prio's truncate as one plaintext product. Refuses weights that are not
/// one pattern shifted by a fixed stride per output (every Prio3 type
/// fits), or that leave the input coefficients.
fn agg_map<F: FheField>(map: &OutputMap<F>, input_len: usize, ring: usize) -> Result<AggMap> {
    let rows = match map {
        OutputMap::Select(idx) => return Ok(AggMap::Select(idx.clone())),
        OutputMap::Linear(rows) => rows,
    };
    let refuse = || Error::Protocol("truncate is not one weight pattern shifted per output".into());
    let support = |row: &[F]| -> Option<(usize, usize)> {
        let first = row.iter().position(|&c| c != F::zero())?;
        let last = row.iter().rposition(|&c| c != F::zero())?;
        Some((first, last))
    };
    let (offset, last) = support(rows.first().ok_or_else(refuse)?).ok_or_else(refuse)?;
    let pattern = rows[0][offset..=last].to_vec();
    let stride = match rows.get(1) {
        Some(r) => support(r).ok_or_else(refuse)?.0.checked_sub(offset).filter(|&s| s > 0).ok_or_else(refuse)?,
        None => 0,
    };
    let mut coeffs = Vec::with_capacity(rows.len());
    for (j, row) in rows.iter().enumerate() {
        let start = offset + stride * j;
        if row.len() != input_len || start + pattern.len() > input_len {
            return Err(refuse());
        }
        let mut expected = vec![F::zero(); input_len];
        expected[start..start + pattern.len()].copy_from_slice(&pattern);
        if *row != expected {
            return Err(refuse());
        }
        coeffs.push(start as u32);
    }
    // W = sum_t pattern[t] X^-t, with X^-t = -X^(N-t) in Z_p[X]/(X^N + 1).
    let mut poly = vec![0u64; ring];
    for (t, &w) in pattern.iter().enumerate() {
        let w = w.to_u64();
        if t == 0 {
            poly[0] = w;
        } else {
            poly[ring - t] = (F::PLAIN_MOD - w) % F::PLAIN_MOD;
        }
    }
    Ok(AggMap::Convolution { coeffs, poly })
}

impl<F: FheField, T: VerifierMap<F>> SingleTask<F, T> {
    pub fn new(typ: T, task_id: [u8; 32], num_proofs: usize) -> Result<Self> {
        let ctx = Context::new_single(F::PLAIN_MOD, 128, F::SINGLE_FIRST_MOD_BITS, F::SINGLE_SCALING_MOD_BITS, F::SINGLE_NUM_TOWERS)?;
        if ctx.plain_mod() != F::PLAIN_MOD {
            return Err(Error::Protocol("context has another plaintext modulus".into()));
        }
        let parts = if typ.joint_rand_len() > 0 { 2 } else { 1 };
        let plan = FlpPlan::new(typ, task_id, num_proofs, ctx.ring_dim() as usize)?;
        let agg = agg_map(plan.output_map(), plan.layout().input_len, plan.layout().ring)?;
        let moduli = ctx.moduli()?;
        // Both kinds of object the collector receives, under a throwaway key:
        // their metadata must agree and is then fixed by the task.
        let (pk, _sk) = keygen_first(&ctx)?;
        let fresh = ctx.encrypt(&pk, &ctx.coef_plaintext(&[0])?)?;
        let check = finish::<F>(&ctx, &ctx.mult_plain(&fresh, &ctx.coef_plaintext(&[1])?)?)?;
        let sum = finish::<F>(&ctx, &ctx.add(&fresh, &fresh)?)?;
        let reduced_meta = check.meta()?;
        if sum.meta()? != reduced_meta || reduced_meta.num_towers != 1 || reduced_meta.num_elements != 2 {
            return Err(Error::Fhe(format!("unexpected reduced metadata {reduced_meta:?} / {:?}", sum.meta()?)));
        }
        Ok(Self {
            plan,
            fresh_codec: ResidueCodec::new(&moduli)?,
            reduced_codec: ResidueCodec::new(&moduli[..1])?,
            reduced_meta,
            ctx,
            parts,
            agg,
        })
    }

    pub fn typ(&self) -> &T {
        self.plan.typ()
    }
    pub fn layout(&self) -> &Layout {
        self.plan.layout()
    }
    /// See [`FlpPlan::max_batch`].
    pub fn max_batch(&self) -> u64 {
        self.plan.max_batch()
    }
    /// See [`FlpPlan::log2_soundness`].
    pub fn log2_soundness(&self) -> f64 {
        self.plan.log2_soundness()
    }
    /// Ciphertexts per report: 1, or 2 for circuits with joint randomness.
    pub fn ciphertexts_per_report(&self) -> usize {
        self.parts
    }
    /// The query randomness the evaluator derives for a report.
    pub fn query_rands(&self, verify_key: &[u8; 32], report: &[u8]) -> Result<Vec<Vec<F>>> {
        self.plan.query_rands(verify_key, report)
    }
    /// The joint randomness of a report's proofs (empty without joint
    /// randomness): from its nonce and its first ciphertext.
    pub fn joint_rands(&self, report: &[u8]) -> Result<Vec<Vec<F>>> {
        if report.len() != self.report_len() {
            return Err(Error::Codec("report has the wrong length".into()));
        }
        Ok(self.plan.joint_rands(&report[..NONCE_LEN], &report[NONCE_LEN..NONCE_LEN + self.fresh_len()]))
    }
    pub fn context(&self) -> &Context {
        &self.ctx
    }
    fn fresh_len(&self) -> usize {
        self.fresh_codec.len(2, self.layout().ring)
    }
    pub fn report_len(&self) -> usize {
        NONCE_LEN + self.parts * self.fresh_len()
    }
    fn reduced_len(&self) -> usize {
        self.reduced_codec.len(2, self.layout().ring)
    }
    /// Bytes of a check request for `reports` reports: per report, the
    /// verifier groups and one support check per ciphertext.
    pub fn check_request_len(&self, reports: usize) -> usize {
        4 + reports * (self.layout().groups().len() + self.parts) * self.reduced_len()
    }

    /// The coefficients ciphertext `part` of an honest report may hold:
    /// `z`; with joint randomness, the input in the first and the proofs in
    /// the second. Every other coefficient of an honest plaintext is 0.
    fn support(&self, part: usize) -> Range<usize> {
        let l = self.layout();
        match (self.parts, part) {
            (1, _) => 0..l.z_len,
            (_, 0) => 0..l.input_len,
            _ => l.input_len..l.z_len,
        }
    }

    /// Fresh uniform field elements on `support`, 0 elsewhere.
    fn pad(&self, support: Range<usize>) -> Vec<u64> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let r: Vec<F> = XofTurboShake128::seed_stream(&seed, &[DST_PAD], &[]).into_field_vec(support.len());
        let mut m = vec![0u64; self.layout().ring];
        for (i, v) in support.zip(r) {
            m[i] = v.to_u64();
        }
        m
    }
    pub fn aggregate_request_len(&self) -> usize {
        8 + self.reduced_len()
    }

    fn pack_reduced(&self, ct: &Ciphertext) -> Result<Vec<u8>> {
        if ct.meta()? != self.reduced_meta {
            return Err(Error::Fhe(format!("unexpected reduced metadata {:?}", ct.meta()?)));
        }
        self.reduced_codec.pack(&ct.export_residues()?, 2, self.layout().ring)
    }

    /// Uniform field elements everywhere except `keep`, where `values` go.
    fn mask(&self, keep: &[u32], values: &[F]) -> Vec<u64> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let n = self.layout().ring;
        let r: Vec<F> = XofTurboShake128::seed_stream(&seed, &[DST_MASK], &[]).into_field_vec(n);
        let mut m: Vec<u64> = r.into_iter().map(F::to_u64).collect();
        for (&i, &v) in keep.iter().zip(values) {
            m[i as usize] = v.to_u64();
        }
        m
    }
}

/// Flood with the widest width the ciphertext's modulus allows, then switch
/// to one tower. Flooding first: switching only post-processes it.
fn finish<F: FheField>(ctx: &Context, ct: &Ciphertext) -> Result<Ciphertext> {
    let towers = ct.meta()?.num_towers as usize;
    let log_q: f64 = ctx.moduli()?[..towers].iter().map(|&q| (q as f64).log2()).sum();
    let width = log_q.floor() as u32 - (F::PLAIN_MOD as f64).log2().ceil() as u32 - 2;
    let flooded = ctx.flood(ct, width)?;
    Ok(ctx.mod_reduce(&flooded, towers as u32 - 1)?)
}

pub struct SingleClient<'a, F: FheField, T: VerifierMap<F>> {
    task: &'a SingleTask<F, T>,
    pk: &'a PublicKey,
}

impl<'a, F: FheField, T: VerifierMap<F>> SingleClient<'a, F, T> {
    pub fn new(task: &'a SingleTask<F, T>, pk: &'a PublicKey) -> Self {
        Self { task, pk }
    }

    pub fn shard(&self, measurement: &T::Measurement) -> Result<Vec<u8>> {
        let input = self.task.typ().encode_measurement(measurement)?;
        Ok(self.shard_with_witness(&input)?.0)
    }

    /// Proves and encrypts an already-encoded input, valid or not, and
    /// returns `z = input || proofs` too (tests: malicious clients,
    /// comparison with prio). With joint randomness the input ciphertext is
    /// made first and the proofs use the joint randomness derived from it.
    pub fn shard_with_witness(&self, input: &[F]) -> Result<(Vec<u8>, Vec<F>)> {
        let task = self.task;
        let mut out = vec![0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut out);
        if task.parts == 1 {
            let z = task.plan.prove(input, &vec![Vec::new(); task.plan.num_proofs()])?;
            out.extend(self.encrypt(&z)?);
            return Ok((out, z));
        }
        let input_ct = self.encrypt(input)?;
        let joint_rands = task.plan.joint_rands(&out[..NONCE_LEN], &input_ct);
        let z = task.plan.prove(input, &joint_rands)?;
        out.extend(input_ct);
        out.extend(self.encrypt_proofs(&z)?);
        Ok((out, z))
    }

    /// Encrypts arbitrary coefficients `z = input || proofs` as a report,
    /// without proving (malicious-client tests).
    pub fn report_from_coefficients(&self, z: &[F]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut out);
        if self.task.parts == 1 {
            out.extend(self.encrypt(z)?);
        } else {
            let il = self.task.layout().input_len.min(z.len());
            out.extend(self.encrypt(&z[..il])?);
            out.extend(self.encrypt_proofs(z)?);
        }
        Ok(out)
    }

    /// The proofs of `z` at their coefficients `|input| ..`, zeros below.
    fn encrypt_proofs(&self, z: &[F]) -> Result<Vec<u8>> {
        let il = self.task.layout().input_len;
        let mut v = vec![F::zero(); z.len().max(il)];
        if z.len() > il {
            v[il..].copy_from_slice(&z[il..]);
        }
        self.encrypt(&v)
    }

    /// One fresh ciphertext of arbitrary coefficients, as a report carries
    /// it (malicious-client tests build reports part by part with it).
    pub fn encrypt_coefficients(&self, coeffs: &[F]) -> Result<Vec<u8>> {
        self.encrypt(coeffs)
    }

    fn encrypt(&self, coeffs: &[F]) -> Result<Vec<u8>> {
        let ctx = &self.task.ctx;
        if coeffs.len() > self.task.layout().ring {
            return Err(Error::Protocol("too many coefficients".into()));
        }
        let vals: Vec<u64> = coeffs.iter().map(|&x| x.to_u64()).collect();
        let ct = ctx.encrypt(self.pk, &ctx.coef_plaintext(&vals)?)?;
        let meta = ct.meta()?;
        if meta.level != 0 || meta.num_elements != 2 || meta.num_towers != F::SINGLE_NUM_TOWERS {
            return Err(Error::Fhe(format!("unexpected fresh ciphertext metadata {meta:?}")));
        }
        self.task.fresh_codec.pack(&ct.export_residues()?, 2, self.task.layout().ring)
    }
}

struct Stored<F> {
    /// The ciphertext of `z`, or with joint randomness of the input.
    ct: Ciphertext,
    /// With joint randomness: the ciphertext of the proofs.
    proofs: Option<Ciphertext>,
    query_rands: Vec<Vec<F>>,
    joint_rands: Vec<Vec<F>>,
}

/// The single aggregator. One instance per batch.
pub struct Evaluator<'a, F: FheField, T: VerifierMap<F>> {
    task: &'a SingleTask<F, T>,
    verify_key: [u8; 32],
    reference: Ciphertext,
    seen: HashSet<[u8; NONCE_LEN]>,
    reports: Vec<Stored<F>>,
}

impl<'a, F: FheField, T: VerifierMap<F>> Evaluator<'a, F, T> {
    /// `verify_key` is the evaluator's secret: clients must not predict the
    /// FLP query randomness. The ciphertext-rebuild self-test runs here.
    pub fn new(task: &'a SingleTask<F, T>, pk: &PublicKey, verify_key: [u8; 32]) -> Result<Self> {
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

    /// Stores a report. Refuses malformed bytes, a replayed nonce and a full
    /// batch.
    pub fn ingest(&mut self, report: &[u8]) -> Result<()> {
        let task = self.task;
        if report.len() != task.report_len() {
            return Err(Error::Codec(format!("report has {} bytes, expected {}", report.len(), task.report_len())));
        }
        if self.reports.len() as u64 >= task.plan.max_batch() {
            return Err(Error::Protocol("batch is full".into()));
        }
        let nonce: [u8; NONCE_LEN] = report[..NONCE_LEN].try_into().expect("length checked");
        let fl = task.fresh_len();
        let meta = self.reference.meta()?;
        let mut cts = Vec::with_capacity(task.parts);
        for part in 0..task.parts {
            let bytes = &report[NONCE_LEN + part * fl..NONCE_LEN + (part + 1) * fl];
            let residues = task.fresh_codec.unpack(bytes, 2, task.layout().ring)?;
            cts.push(task.ctx.build_ciphertext(&self.reference, &meta, &residues)?);
        }
        if !self.seen.insert(nonce) {
            return Err(Error::Protocol("duplicate report nonce".into()));
        }
        let query_rands = task.plan.query_rands(&self.verify_key, report)?;
        let joint_rands = task.joint_rands(report)?;
        let proofs = if task.parts == 2 { cts.pop() } else { None };
        self.reports.push(Stored {
            ct: cts.pop().expect("one ciphertext per part"),
            proofs,
            query_rands,
            joint_rands,
        });
        Ok(())
    }

    /// The batch's check request: for every report and group of verifier
    /// rows, `ct x Q~` with the verifier constants added at the verifier
    /// coefficients and a fresh uniform mask everywhere else, flooded and
    /// switched to one tower.
    pub fn check_request(&self) -> Result<Vec<u8>> {
        let task = self.task;
        let layout = task.layout();
        let mut out = Vec::with_capacity(task.check_request_len(self.reports.len()));
        out.extend((self.reports.len() as u32).to_le_bytes());
        for r in &self.reports {
            let (rows, constants) = task.plan.linear_map(&r.query_rands, &r.joint_rands)?;
            for g in layout.groups() {
                let prod = match &r.proofs {
                    None => task.ctx.mult_plain(&r.ct, &task.ctx.coef_plaintext(&task.plan.query_poly(&rows[g.clone()]))?)?,
                    // Each row's input part reads only the input ciphertext and its
                    // proof part only the proof ciphertext: the proofs cannot alter
                    // the input that fixed the joint randomness.
                    Some(proofs) => {
                        let il = layout.input_len;
                        let (ins, pfs): (Vec<Vec<F>>, Vec<Vec<F>>) = rows[g.clone()]
                            .iter()
                            .map(|row| {
                                let mut a = row.clone();
                                let mut b = row.clone();
                                a[il..].fill(F::zero());
                                b[..il].fill(F::zero());
                                (a, b)
                            })
                            .unzip();
                        let a = task.ctx.mult_plain(&r.ct, &task.ctx.coef_plaintext(&task.plan.query_poly(&ins))?)?;
                        let b = task.ctx.mult_plain(proofs, &task.ctx.coef_plaintext(&task.plan.query_poly(&pfs))?)?;
                        task.ctx.add(&a, &b)?
                    }
                };
                let idx = layout.group_coeffs(g.len());
                let mask = task.ctx.coef_plaintext(&task.mask(&idx, &constants[g.clone()]))?;
                out.extend(task.pack_reduced(&finish::<F>(&task.ctx, &task.ctx.add_plain(&prod, &mask)?)?)?);
            }
            // Support checks: each ciphertext with its support one-time padded.
            // The collector decrypts every other coefficient and requires 0.
            for (part, ct) in std::iter::once(&r.ct).chain(r.proofs.as_ref()).enumerate() {
                let pad = task.ctx.coef_plaintext(&task.pad(task.support(part)))?;
                out.extend(task.pack_reduced(&finish::<F>(&task.ctx, &task.ctx.add_plain(ct, &pad)?)?)?);
            }
        }
        Ok(out)
    }

    /// The aggregate request: the sum of the input ciphertexts the verdicts
    /// accept, mapped to the aggregate by prio's truncate (one plaintext
    /// product when the outputs are weighted sums of input bits), masked
    /// outside the output coefficients, flooded, switched to one tower.
    pub fn aggregate_request(&self, verdicts: &[u8]) -> Result<Vec<u8>> {
        let task = self.task;
        if verdicts.len() != self.reports.len().div_ceil(8) {
            return Err(Error::Codec("verdicts have the wrong length".into()));
        }
        let mut sum: Option<Ciphertext> = None;
        let mut count = 0u64;
        for (i, r) in self.reports.iter().enumerate() {
            if verdicts[i / 8] >> (i % 8) & 1 == 1 {
                sum = Some(match sum {
                    None => r.ct.try_clone()?,
                    Some(s) => task.ctx.add(&s, &r.ct)?,
                });
                count += 1;
            }
        }
        let sum = sum.ok_or_else(|| Error::Protocol("no accepted reports".into()))?;
        let mapped = match &task.agg {
            AggMap::Select(_) => sum,
            AggMap::Convolution { poly, .. } => task.ctx.mult_plain(&sum, &task.ctx.coef_plaintext(poly)?)?,
        };
        let idx = task.agg.coeffs();
        let mask = task.ctx.coef_plaintext(&task.mask(idx, &vec![F::zero(); idx.len()]))?;
        let mut msg = count.to_le_bytes().to_vec();
        msg.extend(task.pack_reduced(&finish::<F>(&task.ctx, &task.ctx.add_plain(&mapped, &mask)?)?)?);
        Ok(msg)
    }
}

/// The collector: holds the whole secret key.
pub struct SingleCollector<'a, F: FheField, T: VerifierMap<F>> {
    task: &'a SingleTask<F, T>,
    sk: SecretShare,
    reference: Ciphertext,
    accepted: Option<u64>,
}

impl<'a, F: FheField, T: VerifierMap<F>> SingleCollector<'a, F, T> {
    /// Generates the key pair; the public key goes to clients and the
    /// evaluator.
    pub fn new(task: &'a SingleTask<F, T>) -> Result<(Self, PublicKey)> {
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

    fn open(&self, bytes: &[u8], idx: &[u32]) -> Result<Vec<F>> {
        let res = self.task.reduced_codec.unpack(bytes, 2, self.task.layout().ring)?;
        let ct = self.task.ctx.build_ciphertext(&self.reference, &self.task.reduced_meta, &res)?;
        Ok(self.sk.decrypt_coeffs(&ct, idx)?.into_iter().map(F::from_u64).collect())
    }

    /// Decrypts the verifier coefficients of every report, runs Prio3's
    /// `decide` and returns one bit per report (bit `i % 8` of byte `i / 8`).
    pub fn check(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        Ok(self.check_with_verifiers(request)?.0)
    }

    /// [`Self::check`], also returning each report's verifier message (all
    /// proofs), which the collector learns in any case.
    pub fn check_with_verifiers(&mut self, request: &[u8]) -> Result<(Vec<u8>, Vec<Vec<F>>)> {
        let task = self.task;
        let layout = task.layout();
        if request.len() < 4 {
            return Err(Error::Codec("check request too short".into()));
        }
        let n = u32::from_le_bytes(request[..4].try_into().expect("length checked")) as usize;
        if n as u64 > task.plan.max_batch() || request.len() != task.check_request_len(n) {
            return Err(Error::Codec("check request has the wrong length".into()));
        }
        let len = task.reduced_len();
        let mut off = 4;
        let mut verdicts = vec![0u8; n.div_ceil(8)];
        let mut verifiers = Vec::with_capacity(n);
        let mut accepted = 0u64;
        for i in 0..n {
            let mut verifier = Vec::with_capacity(layout.num_rows());
            for g in layout.groups() {
                verifier.extend(self.open(&request[off..off + len], &layout.group_coeffs(g.len()))?);
                off += len;
            }
            let mut supported = true;
            for part in 0..task.parts {
                let support = task.support(part);
                let outside: Vec<u32> = (0..layout.ring as u32).filter(|&c| !support.contains(&(c as usize))).collect();
                supported &= self.open(&request[off..off + len], &outside)?.iter().all(|&x| x == F::zero());
                off += len;
            }
            if supported && task.plan.decide(&verifier)? {
                verdicts[i / 8] |= 1 << (i % 8);
                accepted += 1;
            }
            verifiers.push(verifier);
        }
        self.accepted = Some(accepted);
        Ok((verdicts, verifiers))
    }

    /// Decrypts the output coefficients of the aggregate and decodes them
    /// with Prio3's `decode_result`. Refused unless the count matches the
    /// reports this collector accepted.
    pub fn unshard(&self, request: &[u8]) -> Result<T::AggregateResult> {
        let task = self.task;
        if request.len() != task.aggregate_request_len() {
            return Err(Error::Codec("aggregate request has the wrong length".into()));
        }
        let count = u64::from_le_bytes(request[..8].try_into().expect("length checked"));
        if Some(count) != self.accepted || count == 0 {
            return Err(Error::Protocol("the aggregate does not cover the accepted reports".into()));
        }
        let data = self.open(&request[8..], task.agg.coeffs())?;
        Ok(task.typ().decode_result(&data, count as usize)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f65537::Field65537;
    use prio::field::FieldPrio2;
    use prio::flp::Flp;
    use prio::flp::gadgets::{Mul, ParallelSum};
    use prio::flp::types::{Count, Histogram, Sum, SumVec};

    /// `a * b` in Z_p[X]/(X^N + 1), schoolbook.
    fn negacyclic<F: FheField>(a: &[F], b: &[u64]) -> Vec<F> {
        let n = b.len();
        let mut c = vec![F::zero(); n];
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                let t = x * F::from_u64(y);
                if i + j < n {
                    c[i + j] += t;
                } else {
                    c[i + j - n] -= t;
                }
            }
        }
        c
    }

    /// The aggregate map equals prio's truncate on the input, whatever the
    /// plaintext holds outside it.
    fn agg_map_is_truncate_and_ignores_the_rest<F: FheField, T: VerifierMap<F>>(typ: &T, ring: usize) {
        let (map, _) = crate::protocol::output_map(typ).unwrap();
        let agg = agg_map(&map, typ.input_len(), ring).unwrap();
        for trial in 0..4 {
            let mut plain: Vec<F> = F::random_vector(ring);
            let input: Vec<F> = plain[..typ.input_len()].to_vec();
            if trial == 0 {
                plain[typ.input_len()..].fill(F::zero());
            }
            let got: Vec<F> = match &agg {
                AggMap::Select(idx) => idx.iter().map(|&i| plain[i as usize]).collect(),
                AggMap::Convolution { coeffs, poly } => {
                    let prod = negacyclic(&plain, poly);
                    coeffs.iter().map(|&i| prod[i as usize]).collect()
                }
            };
            assert_eq!(got, typ.truncate(input).unwrap());
        }
    }

    #[test]
    fn aggregate_maps_of_prio3_types() {
        let ring = 256;
        agg_map_is_truncate_and_ignores_the_rest(&Count::<Field65537>::new(), ring);
        agg_map_is_truncate_and_ignores_the_rest(&Sum::<Field65537>::new(100).unwrap(), ring);
        agg_map_is_truncate_and_ignores_the_rest(&Sum::<FieldPrio2>::new(1 << 20).unwrap(), ring);
        agg_map_is_truncate_and_ignores_the_rest(&SumVec::<Field65537, ParallelSum<Field65537, Mul>>::new(5, 7, 4).unwrap(), ring);
        agg_map_is_truncate_and_ignores_the_rest(&SumVec::<FieldPrio2, ParallelSum<FieldPrio2, Mul>>::new(1000, 4, 3).unwrap(), ring);
        agg_map_is_truncate_and_ignores_the_rest(&Histogram::<Field65537, ParallelSum<Field65537, Mul>>::new(9, 3).unwrap(), ring);
        let sv = SumVec::<Field65537, ParallelSum<Field65537, Mul>>::new(5, 7, 4).unwrap();
        let (map, _) = crate::protocol::output_map(&sv).unwrap();
        assert!(matches!(agg_map(&map, sv.input_len(), ring).unwrap(), AggMap::Convolution { .. }));
    }

    #[test]
    fn weights_that_are_not_one_shifted_pattern_are_refused() {
        let w = |v: &[u32]| v.iter().map(|&x| Field65537::from_u64(x as u64)).collect::<Vec<_>>();
        let bad: [Vec<Vec<Field65537>>; 4] = [
            vec![w(&[1, 2, 0, 0]), w(&[0, 0, 1, 3])],          // another pattern
            vec![w(&[0, 0, 1, 2]), w(&[1, 2, 0, 0])],          // backwards
            vec![w(&[0, 0, 0, 0])],                            // empty
            vec![w(&[1, 2, 0]), w(&[0, 1, 2]), w(&[0, 0, 1])], // runs past the input
        ];
        for (i, rows) in bad.iter().enumerate() {
            let il = rows[0].len();
            assert!(agg_map(&OutputMap::Linear(rows.clone()), il, 16).is_err(), "case {i}");
        }
        // interleaved outputs (stride 1, pattern longer than the stride) are exact
        let rows = vec![w(&[1, 0, 2, 0]), w(&[0, 1, 0, 2])];
        assert!(agg_map(&OutputMap::Linear(rows), 4, 16).is_ok());
    }
}
