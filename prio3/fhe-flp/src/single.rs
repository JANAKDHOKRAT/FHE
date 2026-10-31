//! One aggregator (the evaluator) and a collector that holds the whole BGV
//! key.
//!
//! Trust: the evaluator and the collector do not collude and follow the
//! protocol (the model of this repository's single-evaluator packages).
//! Clients may be malicious.
//!
//! ```text
//! client    -> evaluator : report = nonce || fresh coefficient ciphertext of
//!                          z = input || proof_1 || .. || proof_k   (Prio3 encoding, prio's FLP)
//! evaluator -> collector : check request, at batch end: per report and group of
//!                          verifier rows, ct x Q~ + mask, flooded, switched to one tower
//! collector -> evaluator : verdicts, one bit per report (Prio3's decide)
//! evaluator -> collector : aggregate request: sum of accepted reports + mask,
//!                          flooded, switched to one tower
//! collector              : decrypts the output coefficients only
//! ```
//!
//! What each party learns:
//! * evaluator: ciphertexts (RLWE under the collector's key) and the verdicts;
//! * collector: per report exactly the FLP verifier message, which is what
//!   Prio3's aggregators learn and is covered by the FLP's zero knowledge,
//!   then the aggregate. Every other coefficient of what it decrypts carries
//!   a fresh uniform mask; the noise is flooded (statistical distance at most
//!   2^-86 per coefficient in the worst case, `openfhe-tbgv-rs/tests/single_key.rs`).
//!
//! The collector participates once per batch (two messages), never per
//! report, and never sees a report ciphertext.
use crate::codec::ResidueCodec;
use crate::protocol::{FlpPlan, Layout, NONCE_LEN, VerifierMap};
use crate::{Error, FheField, Result};
use openfhe_tbgv_rs::{Ciphertext, CiphertextMeta, Context, PublicKey, SecretShare, keygen_first, verify_single_rebuild_once};
use prio::vdaf::xof::{IntoFieldVec, Xof, XofTurboShake128};
use rand::RngCore;
use rand::rngs::OsRng;
use std::collections::HashSet;

/// The modulus chain comes from the field ([`FheField`]): measured so that
/// the worst-case flooding margin is at least 64 bits at ring 8192.
const DST_MASK: &[u8] = b"fhe-flp/1 single mask";

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
}

impl<F: FheField, T: VerifierMap<F>> SingleTask<F, T> {
    pub fn new(typ: T, task_id: [u8; 32], num_proofs: usize) -> Result<Self> {
        let ctx = Context::new_single(F::PLAIN_MOD, 128, F::SINGLE_FIRST_MOD_BITS, F::SINGLE_SCALING_MOD_BITS, F::SINGLE_NUM_TOWERS)?;
        if ctx.plain_mod() != F::PLAIN_MOD {
            return Err(Error::Protocol("context has another plaintext modulus".into()));
        }
        let plan = FlpPlan::new(typ, task_id, num_proofs, ctx.ring_dim() as usize)?;
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
    /// The query randomness the evaluator derives for a report.
    pub fn query_rands(&self, verify_key: &[u8; 32], report: &[u8]) -> Result<Vec<Vec<F>>> {
        self.plan.query_rands(verify_key, report)
    }
    pub fn context(&self) -> &Context {
        &self.ctx
    }
    pub fn report_len(&self) -> usize {
        NONCE_LEN + self.fresh_codec.len(2, self.layout().ring)
    }
    fn reduced_len(&self) -> usize {
        self.reduced_codec.len(2, self.layout().ring)
    }
    /// Bytes of a check request for `reports` reports.
    pub fn check_request_len(&self, reports: usize) -> usize {
        4 + reports * self.layout().groups().len() * self.reduced_len()
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
    /// returns `z` too (tests: malicious clients, comparison with prio).
    pub fn shard_with_witness(&self, input: &[F]) -> Result<(Vec<u8>, Vec<F>)> {
        let z = self.task.plan.prove(input)?;
        Ok((self.report_from_coefficients(&z)?, z))
    }

    /// Encrypts arbitrary coefficients as a report (malicious-client tests).
    pub fn report_from_coefficients(&self, z: &[F]) -> Result<Vec<u8>> {
        let ctx = &self.task.ctx;
        if z.len() > self.task.layout().ring {
            return Err(Error::Protocol("too many coefficients".into()));
        }
        let vals: Vec<u64> = z.iter().map(|&x| x.to_u64()).collect();
        let ct = ctx.encrypt(self.pk, &ctx.coef_plaintext(&vals)?)?;
        let meta = ct.meta()?;
        if meta.level != 0 || meta.num_elements != 2 || meta.num_towers != F::SINGLE_NUM_TOWERS {
            return Err(Error::Fhe(format!("unexpected fresh ciphertext metadata {meta:?}")));
        }
        let mut out = vec![0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut out);
        out.extend(self.task.fresh_codec.pack(&ct.export_residues()?, 2, self.task.layout().ring)?);
        Ok(out)
    }
}

struct Stored<F> {
    ct: Ciphertext,
    query_rands: Vec<Vec<F>>,
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
        let residues = task.fresh_codec.unpack(&report[NONCE_LEN..], 2, task.layout().ring)?;
        let ct = task.ctx.build_ciphertext(&self.reference, &self.reference.meta()?, &residues)?;
        if !self.seen.insert(nonce) {
            return Err(Error::Protocol("duplicate report nonce".into()));
        }
        let query_rands = task.plan.query_rands(&self.verify_key, report)?;
        self.reports.push(Stored { ct, query_rands });
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
            let (rows, constants) = task.plan.linear_map(&r.query_rands)?;
            for g in layout.groups() {
                let q = task.ctx.coef_plaintext(&task.plan.query_poly(&rows[g.clone()]))?;
                let prod = task.ctx.mult_plain(&r.ct, &q)?;
                let idx = layout.group_coeffs(g.len());
                let mask = task.ctx.coef_plaintext(&task.mask(&idx, &constants[g.clone()]))?;
                out.extend(task.pack_reduced(&finish::<F>(&task.ctx, &task.ctx.add_plain(&prod, &mask)?)?)?);
            }
        }
        Ok(out)
    }

    /// The aggregate request: the sum of the reports the verdicts accept,
    /// masked outside the output coefficients, flooded, switched to one tower.
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
        let out_idx = task.layout().output_coeffs();
        let zeros = vec![F::zero(); out_idx.len()];
        let mask = task.ctx.coef_plaintext(&task.mask(&out_idx, &zeros))?;
        let mut msg = count.to_le_bytes().to_vec();
        msg.extend(task.pack_reduced(&finish::<F>(&task.ctx, &task.ctx.add_plain(&sum, &mask)?)?)?);
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
            if task.plan.decide(&verifier)? {
                verdicts[i / 8] |= 1 << (i % 8);
                accepted += 1;
            }
            verifiers.push(verifier);
        }
        self.accepted = Some(accepted);
        Ok((verdicts, verifiers))
    }

    /// Decrypts the output coefficients of the aggregate. Refused unless the
    /// count matches the reports this collector accepted.
    pub fn unshard(&self, request: &[u8]) -> Result<T::AggregateResult> {
        let task = self.task;
        if request.len() != task.aggregate_request_len() {
            return Err(Error::Codec("aggregate request has the wrong length".into()));
        }
        let count = u64::from_le_bytes(request[..8].try_into().expect("length checked"));
        if Some(count) != self.accepted || count == 0 {
            return Err(Error::Protocol("the aggregate does not cover the accepted reports".into()));
        }
        let data = self.open(&request[8..], &task.layout().output_coeffs())?;
        Ok(task.typ().decode_result(&data, count as usize)?)
    }
}
