//! Aggregator state machine.
//!
//! Admission (both modes), in `prepare_init` / `process_silent`, before any
//! ciphertext is parsed and in this order: batch open; size cap; task id;
//! signature and registry and per-client quota (when the policy requires
//! it); report id recomputation; replay; chunk count; then each chunk is
//! parsed in the packed wire format (`packed.rs`: fingerprint, exactly the
//! metadata of a fresh encryption, exact length, every residue below its
//! modulus) and rebuilt inside this aggregator's own context. Bytes from
//! another party never reach OpenFHE's deserializer. Every one of these
//! decisions is deterministic, so honest aggregators agree.
//!
//! Verdict mode, per report:
//!   1. `prepare_init`   — compute the check ciphertext `S`, broadcast a mask;
//!   2. `prepare_masks`  — `u = S * mask`, broadcast a partial decryption;
//!   3. `prepare_finish` — fuse and accept or reject.
//! Silent mode, per report: `process_silent` computes the validity bit
//! homomorphically and adds `x * valid` to the sums. No messages, no
//! decryption.
//! Per batch, `aggregate_share` releases partial decryptions of the sums and
//! closes the batch.
//!
//! Privacy invariant: an aggregator only ever partially decrypts ciphertexts
//! it computed itself from (a) the report bytes, (b) the deterministic
//! challenge, and (c) in verdict mode the received masks, whose content
//! cannot affect what the decryption reveals as long as this aggregator's own
//! mask is uniform.

use crate::auth::{self, ClientRegistry};
use crate::config::{AuthPolicy, TaskConfig, VerificationMode};
use crate::error::{Error, RejectReason, Result};
use crate::field::Field;
use crate::keys;
use crate::layout::Layout;
use crate::messages::{AggregateShare, CountShare, MaskMessage, PublicMaterial, Report, ReportId, VerifierMessage, batch_digest};
use crate::packed::{check_stored, Codec, Expect, WireError};
use crate::verify::{Challenge, Circuit};
use openfhe_tbgv_rs::{Ciphertext, CiphertextMeta, Context, PartialDecryption, PublicKey, SecretShare};
use rand::rngs::OsRng;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Rejected(RejectReason),
}

/// Everything an aggregator must persist to resume after a restart:
/// serialized ciphertext accumulators and the bookkeeping. Verdict-mode
/// reports that are mid-preparation are not included; they are re-run from
/// the report by the coordinator.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregatorState {
    pub sums: Option<Vec<Vec<u8>>>,
    pub valid_count_sum: Option<Vec<u8>>,
    pub moment_sums: Option<Vec<Vec<u8>>>,
    pub silent_terms: Option<Vec<u8>>,
    /// Reports whose terms are in `silent_terms` but whose validity-masked
    /// chunks have not been folded into the sums yet: (group, report id).
    /// Their ciphertexts are recomputed from the stored reports on restore.
    pub silent_pending: Vec<(usize, ReportId)>,
    pub accepted_ids: Vec<ReportId>,
    pub seen: Vec<ReportId>,
    pub client_reports: Vec<([u8; 32], u32)>,
    pub admitted: u64,
    pub valid_count: Option<u64>,
    pub closed: bool,
    /// The count share released for this batch, if any. Released once:
    /// a repeated close returns these same bytes rather than a fresh
    /// partial decryption of the same ciphertext.
    pub released_count_share: Option<CountShare>,
    /// The aggregate shares released for this batch, by collector (same rule).
    pub released_aggregate_shares: BTreeMap<u32, AggregateShare>,
}

struct Pending {
    chunks: Vec<Ciphertext>,
    s: Ciphertext,
    masks: BTreeMap<usize, Ciphertext>,
    partials: BTreeMap<usize, PartialDecryption>,
    u: Option<Ciphertext>,
}

/// Silent mode: the reports whose check terms share the current
/// verification ciphertext. Flushed when every group is used, when a group
/// is reused, or at batch close.
struct SilentBatch {
    terms: Option<Ciphertext>,
    /// (group, report id, per-chunk ciphertexts masked to that group's slots, level 1)
    reports: Vec<(usize, ReportId, Vec<Ciphertext>)>,
    used_groups: HashSet<usize>,
}

impl SilentBatch {
    fn new() -> Self {
        Self { terms: None, reports: Vec::new(), used_groups: HashSet::new() }
    }
}

pub struct Aggregator {
    cfg: TaskConfig,
    field: Field,
    layout: Layout,
    ctx: Context,
    pk: PublicKey,
    /// Keeps the joint evaluation keys installed while this aggregator lives.
    _keys: keys::KeyLease,
    index: usize,
    share: SecretShare,
    circuit: Circuit,
    /// Packed wire format bound to this task's parameters and joint key:
    /// every ciphertext received from another party is parsed and rebuilt
    /// through it, never through OpenFHE's deserializer.
    codec: Codec,
    registry: Option<Arc<dyn ClientRegistry>>,
    client_reports: HashMap<[u8; 32], u32>,
    seen: HashSet<ReportId>,
    admitted: u64,
    pending: HashMap<ReportId, Pending>,
    accepted_ids: Vec<ReportId>,
    sums: Option<Vec<Ciphertext>>,
    /// Silent mode: encrypted number of valid reports (slot 0).
    valid_count_sum: Option<Ciphertext>,
    /// Post-validation moments: one accumulator per `Layout::moment_terms`
    /// entry, digit products at group 0's element slots `i*D`.
    moment_sums: Option<Vec<Ciphertext>>,
    silent_batch: SilentBatch,
    /// Silent mode: decrypted valid count, once the count round has run.
    valid_count: Option<u64>,
    closed: bool,
    released_count_share: Option<CountShare>,
    released_aggregate_shares: BTreeMap<u32, AggregateShare>,
    rng: OsRng,
}

impl Aggregator {
    /// `registry` is required when the task's `AuthPolicy` is `Required`.
    pub fn new(
        cfg: TaskConfig,
        material: &PublicMaterial,
        index: usize,
        share: &[u8],
        registry: Option<Arc<dyn ClientRegistry>>,
    ) -> Result<Self> {
        let field = cfg.validate()?;
        if index >= cfg.num_aggregators {
            return Err(Error::Config("aggregator index out of range".into()));
        }
        if matches!(cfg.auth, AuthPolicy::Required { .. }) && registry.is_none() {
            return Err(Error::Config("task requires client authentication but no registry was given".into()));
        }
        let ctx = Context::deserialize(&material.context)?;
        if ctx.plain_mod() != cfg.plain_mod || ctx.mult_depth() < cfg.mult_depth() {
            return Err(Error::Config("context parameters do not match the task".into()));
        }
        // Every ciphertext this aggregator receives is rebuilt from residues
        // and metadata; refuse to run if the loaded OpenFHE does not rebuild
        // exactly at every level the task reaches (once per process).
        openfhe_tbgv_rs::verify_rebuild_once(&ctx, cfg.mult_depth())?;
        let key_lease = keys::install(&ctx, material)?;
        let pk = ctx.deserialize_public_key(&material.public_key)?;
        let joint_tag = pk.tag()?;
        if joint_tag != material.joint_tag {
            return Err(Error::Config("joint key tag does not match public key".into()));
        }
        let layout = cfg.layout(ctx.row_slots())?;
        let need = layout.rotation_indices();
        if need.iter().any(|i| !material.rotation_indices.contains(i)) {
            return Err(Error::Config("rotation keys do not cover the task layout".into()));
        }
        let share = ctx.deserialize_secret_share(share)?;
        let circuit = Circuit::new(&ctx, &layout)?;
        let codec = Codec::new(&ctx, &pk, &material.public_key)?;
        Ok(Self {
            cfg,
            field,
            layout,
            ctx,
            pk,
            _keys: key_lease,
            index,
            share,
            circuit,
            codec,
            registry,
            client_reports: HashMap::new(),
            seen: HashSet::new(),
            admitted: 0,
            pending: HashMap::new(),
            accepted_ids: Vec::new(),
            sums: None,
            valid_count_sum: None,
            moment_sums: None,
            silent_batch: SilentBatch::new(),
            valid_count: None,
            closed: false,
            released_count_share: None,
            released_aggregate_shares: BTreeMap::new(),
            rng: OsRng,
        })
    }

    fn add_to_moments(&mut self, products: Vec<Ciphertext>) -> Result<()> {
        match &mut self.moment_sums {
            None => self.moment_sums = Some(products),
            Some(acc) => {
                for (a, p) in acc.iter_mut().zip(&products) {
                    *a = self.ctx.add(a, p)?;
                }
            }
        }
        Ok(())
    }

    pub fn index(&self) -> usize {
        self.index
    }
    pub fn layout(&self) -> &Layout {
        &self.layout
    }
    pub fn accepted_count(&self) -> usize {
        self.accepted_ids.len()
    }
    pub fn is_lead(&self) -> bool {
        self.index == 0
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Largest ciphertext payload a report may carry: exactly one packed
    /// fresh ciphertext per chunk.
    pub fn max_report_bytes(&self) -> usize {
        let derived = self.layout.num_chunks * self.codec.fresh_len();
        if self.cfg.max_report_bytes == 0 { derived } else { self.cfg.max_report_bytes.min(derived) }
    }

    /// Largest ciphertext payload of any message between aggregators: a
    /// report forwarded to a helper, or the masks of the other `n - 1`
    /// aggregators sent in one request (each a packed fresh ciphertext).
    /// Partial decryptions have one element, so the `n - 1` verifier
    /// messages or the `n` count shares of one request are smaller still.
    pub fn max_message_bytes(&self) -> usize {
        let masks = (self.cfg.num_aggregators - 1) * self.codec.fresh_len();
        self.max_report_bytes().max(masks)
    }

    /// The packed-ciphertext codec of this aggregator.
    pub fn codec(&self) -> &Codec {
        &self.codec
    }

    /// A client chunk or a peer's mask: must be a packed fresh encryption
    /// under this task's joint key.
    fn load_fresh(&self, bytes: &[u8]) -> std::result::Result<Ciphertext, RejectReason> {
        self.codec.decode(bytes, Expect::Exactly(self.codec.fresh_meta())).map_err(|e| match e {
            WireError::WrongParameters => RejectReason::WrongParameters,
            other => RejectReason::MalformedCiphertext(other.to_string()),
        })
    }

    /// Metadata of a partial decryption of `ct`: the same as `ct`'s, with
    /// one element.
    fn partial_meta(ct: &Ciphertext) -> Result<CiphertextMeta> {
        Ok(CiphertextMeta { num_elements: 1, ..ct.meta()? })
    }

    /// A peer's partial decryption of a ciphertext this aggregator computed
    /// too: must have exactly the shape of this aggregator's own.
    fn load_partial(&self, bytes: &[u8], expected: CiphertextMeta, lead: bool) -> Result<PartialDecryption> {
        let ct = self.codec.decode(bytes, Expect::Exactly(expected))?;
        Ok(PartialDecryption::from_ciphertext(ct, lead))
    }

    /// Cheap checks first, FHE work last. On success the report id and the
    /// client's quota are consumed even if verification later fails.
    fn admit(&mut self, report: &Report) -> std::result::Result<Vec<Ciphertext>, RejectReason> {
        if self.closed {
            return Err(RejectReason::BatchClosed);
        }
        let limit = self.max_report_bytes();
        let got = report.ciphertext_bytes();
        if got > limit {
            return Err(RejectReason::TooLarge { limit, got });
        }
        if report.task_id != self.cfg.task_id {
            return Err(RejectReason::WrongTask);
        }
        if let AuthPolicy::Required { max_reports_per_client_per_batch } = self.cfg.auth {
            let a = report.auth.as_ref().ok_or_else(|| RejectReason::Unauthenticated("report carries no signature".into()))?;
            auth::verify(a, &report.task_id, &report.report_id).map_err(|e| RejectReason::Unauthenticated(e.to_string()))?;
            let registry = self.registry.as_ref().expect("checked in new");
            if !registry.is_registered(&a.client_key) {
                return Err(RejectReason::UnknownClient);
            }
            let used = self.client_reports.entry(a.client_key).or_insert(0);
            if *used >= max_reports_per_client_per_batch {
                return Err(RejectReason::QuotaExceeded);
            }
            // The attempt is charged now, whatever happens next.
            *used += 1;
        }
        if Report::compute_id(&report.task_id, report.group, &report.chunks) != report.report_id {
            return Err(RejectReason::ReportIdMismatch);
        }
        if report.group as usize >= self.layout.groups {
            return Err(RejectReason::BadGroup);
        }
        if self.seen.contains(&report.report_id) {
            return Err(RejectReason::Replay);
        }
        if report.chunks.len() != self.layout.num_chunks {
            return Err(RejectReason::WrongChunkCount { expected: self.layout.num_chunks, got: report.chunks.len() });
        }
        if self.admitted >= self.cfg.max_batch_size {
            return Err(RejectReason::BatchFull);
        }
        let mut chunks = Vec::with_capacity(report.chunks.len());
        for bytes in &report.chunks {
            chunks.push(self.load_fresh(bytes)?);
        }
        self.seen.insert(report.report_id);
        self.admitted += 1;
        Ok(chunks)
    }

    fn add_to_sums(&mut self, chunks: Vec<Ciphertext>) -> Result<()> {
        match &mut self.sums {
            None => self.sums = Some(chunks),
            Some(sums) => {
                for (acc, ct) in sums.iter_mut().zip(&chunks) {
                    *acc = self.ctx.add(acc, ct)?;
                }
            }
        }
        Ok(())
    }

    /// Verdict mode, step 1. Returns this aggregator's mask message for the
    /// report, or the deterministic reason the report is refused.
    pub fn prepare_init(&mut self, report: &Report) -> Result<MaskMessage> {
        if self.cfg.mode != VerificationMode::Verdict {
            return Err(Error::Protocol("prepare_init is only valid in verdict mode".into()));
        }
        let chunks = self.admit(report).map_err(Error::Reject)?;
        let challenge = Challenge::derive(&self.cfg, &self.field, &self.layout, &report.report_id, 0);
        let s = self.circuit.check_sum(&chunks, &challenge)?;
        let mask = self.circuit.make_mask(&self.pk, &self.field, &mut self.rng)?;
        let mask_bytes = self.codec.encode(&mask)?;
        let mut masks = BTreeMap::new();
        masks.insert(self.index, mask);
        self.pending.insert(report.report_id, Pending { chunks, s, masks, partials: BTreeMap::new(), u: None });
        Ok(MaskMessage { report_id: report.report_id, aggregator: self.index, mask: mask_bytes })
    }

    /// Verdict mode, step 2. Takes the other aggregators' masks and returns
    /// this aggregator's partial decryption of the masked check value.
    pub fn prepare_masks(&mut self, report_id: &ReportId, masks: &[MaskMessage]) -> Result<VerifierMessage> {
        let n = self.cfg.num_aggregators;
        let my_index = self.index;
        let mut loaded = Vec::new();
        for m in masks {
            if m.report_id != *report_id {
                return Err(Error::Protocol("mask for a different report".into()));
            }
            if m.aggregator >= n || m.aggregator == my_index {
                return Err(Error::Protocol("mask from an unexpected aggregator".into()));
            }
            let ct = self.load_fresh(&m.mask).map_err(|r| Error::Protocol(format!("mask ciphertext rejected: {r}")))?;
            loaded.push((m.aggregator, ct));
        }
        let pending = self.pending.get_mut(report_id).ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
        for (i, ct) in loaded {
            if pending.masks.insert(i, ct).is_some() {
                return Err(Error::Protocol("duplicate mask".into()));
            }
        }
        if pending.masks.len() != n {
            return Err(Error::Protocol(format!("expected {n} masks, have {}", pending.masks.len())));
        }
        let mask_refs: Vec<&Ciphertext> = pending.masks.values().collect();
        let u = self.circuit.apply_masks(&pending.s, &mask_refs)?;
        let partial = self.share.partial_decrypt(&u, my_index == 0)?;
        let bytes = self.codec.encode(partial.ciphertext())?;
        pending.partials.insert(my_index, partial);
        pending.u = Some(u);
        Ok(VerifierMessage { report_id: *report_id, aggregator: my_index, partial: bytes })
    }

    /// Verdict mode, step 3. Fuses all partial decryptions and decides.
    /// Accepted reports are added to the running sums.
    pub fn prepare_finish(&mut self, report_id: &ReportId, verifiers: &[VerifierMessage]) -> Result<Verdict> {
        let n = self.cfg.num_aggregators;
        let expected = {
            let pending = self.pending.get(report_id).ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
            let u = pending.u.as_ref().ok_or_else(|| Error::Protocol("prepare_masks has not run for this report".into()))?;
            Self::partial_meta(u)?
        };
        let mut loaded = Vec::new();
        for v in verifiers {
            if v.report_id != *report_id {
                return Err(Error::Protocol("verifier message for a different report".into()));
            }
            if v.aggregator >= n || v.aggregator == self.index {
                return Err(Error::Protocol("verifier message from an unexpected aggregator".into()));
            }
            loaded.push((v.aggregator, self.load_partial(&v.partial, expected, v.aggregator == 0)?));
        }
        let mut pending = self.pending.remove(report_id).ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
        for (i, p) in loaded {
            if pending.partials.insert(i, p).is_some() {
                return Err(Error::Protocol("duplicate verifier message".into()));
            }
        }
        if pending.partials.len() != n {
            return Err(Error::Protocol(format!("expected {n} verifier messages, have {}", pending.partials.len())));
        }
        let refs: Vec<&PartialDecryption> = pending.partials.values().collect();
        let fused = self.ctx.fuse(&refs, self.layout.result_span())?;
        if !self.circuit.verdict(&fused) {
            return Ok(Verdict::Rejected(RejectReason::ValidityCheckFailed));
        }
        if self.layout.moments.is_some() {
            let products = self.circuit.moment_products(&pending.chunks, 0)?;
            self.add_to_moments(products)?;
        }
        self.add_to_sums(pending.chunks)?;
        self.accepted_ids.push(*report_id);
        Ok(Verdict::Accepted)
    }

    /// Silent mode. Admits the report and adds its check terms to the current
    /// verification ciphertext. Nothing is decrypted and no message is
    /// exchanged. When every group of the layout is in use (or the report's
    /// group is already taken) the shared chain runs first. Returns the
    /// structural rejection reason if the report was not admitted.
    pub fn process_silent(&mut self, report: &Report) -> Result<()> {
        if self.cfg.mode != VerificationMode::Silent {
            return Err(Error::Protocol("process_silent is only valid in silent mode".into()));
        }
        let chunks = self.admit(report).map_err(Error::Reject)?;
        let group = report.group as usize;
        if self.silent_batch.used_groups.contains(&group) {
            self.flush_silent_batch()?;
        }
        let challenge = Challenge::derive(&self.cfg, &self.field, &self.layout, &report.report_id, group);
        let terms = self.circuit.report_terms(&chunks, &challenge)?;
        self.silent_batch.terms = Some(match self.silent_batch.terms.take() {
            None => terms,
            Some(t) => self.ctx.add(&t, &terms)?,
        });
        let mut masked = Vec::with_capacity(chunks.len());
        for (c, ct) in chunks.iter().enumerate() {
            masked.push(self.circuit.mask_to_group(ct, c, group)?);
        }
        self.silent_batch.reports.push((group, report.report_id, masked));
        self.silent_batch.used_groups.insert(group);
        self.accepted_ids.push(report.report_id);
        if self.silent_batch.used_groups.len() == self.layout.groups {
            self.flush_silent_batch()?;
        }
        Ok(())
    }

    /// Runs the shared chain for the current verification ciphertext and
    /// folds every report's validity-masked chunks and count into the sums.
    fn flush_silent_batch(&mut self) -> Result<()> {
        let batch = std::mem::replace(&mut self.silent_batch, SilentBatch::new());
        let Some(terms) = batch.terms else { return Ok(()) };
        let s = self.circuit.class_sums(&terms)?;
        let g = self.circuit.silent_validity(&s)?;
        for (group, _id, masked) in batch.reports {
            let mut y = Vec::with_capacity(masked.len());
            for ct in &masked {
                let prod = self.ctx.mult(ct, &g)?;
                y.push(self.circuit.fold_to_group0(&prod, group)?);
            }
            if self.layout.moments.is_some() {
                // Products are non-zero only at the group's element slots
                // `i*D` (class 0), where G holds this report's validity bit.
                let mut folded = Vec::new();
                for p in self.circuit.moment_products(&masked, group)? {
                    let gated = self.ctx.mult(&p, &g)?;
                    folded.push(self.circuit.fold_to_group0(&gated, group)?);
                }
                self.add_to_moments(folded)?;
            }
            self.add_to_sums(y)?;
            let cnt = self.circuit.fold_to_group0(&self.circuit.count_of_group(&g, group)?, group)?;
            self.valid_count_sum = Some(match self.valid_count_sum.take() {
                None => cnt,
                Some(acc) => self.ctx.add(&acc, &cnt)?,
            });
        }
        Ok(())
    }

    /// Number of reports admitted into the current, not yet flushed,
    /// verification ciphertext.
    pub fn pending_silent_reports(&self) -> usize {
        self.silent_batch.reports.len()
    }

    /// Serializes the resumable state (see [`AggregatorState`]).
    /// The accumulators are this aggregator's own objects, written to and
    /// read back from its own database, so they keep OpenFHE's format;
    /// nothing in the snapshot comes from another party except the stored
    /// client reports, which `restore` decodes through the packed codec.
    pub fn snapshot(&self) -> Result<AggregatorState> {
        let ser = |v: &Vec<Ciphertext>| -> Result<Vec<Vec<u8>>> { v.iter().map(|c| c.serialize().map_err(Into::into)).collect() };
        Ok(AggregatorState {
            sums: match &self.sums {
                Some(v) => Some(ser(v)?),
                None => None,
            },
            valid_count_sum: match &self.valid_count_sum {
                Some(c) => Some(c.serialize()?),
                None => None,
            },
            moment_sums: match &self.moment_sums {
                Some(v) => Some(ser(v)?),
                None => None,
            },
            silent_terms: match &self.silent_batch.terms {
                Some(c) => Some(c.serialize()?),
                None => None,
            },
            silent_pending: self.silent_batch.reports.iter().map(|(g, id, _)| (*g, *id)).collect(),
            accepted_ids: self.accepted_ids.clone(),
            seen: self.seen.iter().copied().collect(),
            client_reports: self.client_reports.iter().map(|(k, n)| (*k, *n)).collect(),
            admitted: self.admitted,
            valid_count: self.valid_count,
            closed: self.closed,
            released_count_share: self.released_count_share.clone(),
            released_aggregate_shares: self.released_aggregate_shares.clone(),
        })
    }

    /// Restores a state produced by [`Aggregator::snapshot`] on a freshly
    /// constructed aggregator with the same task, keys and index.
    /// `pending_reports` must contain every report listed in
    /// `st.silent_pending`; their validity-masked chunks are recomputed.
    pub fn restore(&mut self, st: AggregatorState, pending_reports: &[Report]) -> Result<()> {
        // Stored partial decryptions this aggregator released are returned
        // unchanged on a retried close, so they must be in the packed
        // format; a state from before it cannot be resumed.
        let f = self.codec.format();
        if let Some(c) = &st.released_count_share {
            check_stored(f, &c.partial, Expect::Partial, "released count share")?;
        }
        for (c, share) in &st.released_aggregate_shares {
            let what = format!("aggregate share released to collector {c}");
            for p in share.partials.iter().chain(&share.moment_partials).chain(share.valid_count_partial.as_ref()) {
                check_stored(f, p, Expect::Partial, &what)?;
            }
        }
        for (_, id) in &st.silent_pending {
            let report = pending_reports
                .iter()
                .find(|r| r.report_id == *id)
                .ok_or_else(|| Error::Protocol(format!("restore: pending report {} not supplied", hex::encode(id))))?;
            for bytes in &report.chunks {
                check_stored(f, bytes, Expect::Exactly(self.codec.fresh_meta()), &format!("pending report {}", hex::encode(id)))?;
            }
        }
        let de = |v: &Vec<Vec<u8>>| -> Result<Vec<Ciphertext>> { v.iter().map(|b| self.ctx.deserialize_ciphertext(b).map_err(Into::into)).collect() };
        self.sums = match &st.sums {
            Some(v) => Some(de(v)?),
            None => None,
        };
        self.valid_count_sum = match &st.valid_count_sum {
            Some(b) => Some(self.ctx.deserialize_ciphertext(b)?),
            None => None,
        };
        self.moment_sums = match &st.moment_sums {
            // the accumulator count follows the task's digit width; a state
            // written under another decomposition cannot be continued
            Some(v) if v.len() != self.layout.moment_terms().len() => {
                return Err(Error::Protocol(format!(
                    "restore: {} moment accumulators stored, this task has {}",
                    v.len(),
                    self.layout.moment_terms().len()
                )))
            }
            Some(v) => Some(de(v)?),
            None => None,
        };
        let mut batch = SilentBatch::new();
        batch.terms = match &st.silent_terms {
            Some(b) => Some(self.ctx.deserialize_ciphertext(b)?),
            None => None,
        };
        for (g, id) in &st.silent_pending {
            let report = pending_reports
                .iter()
                .find(|r| r.report_id == *id)
                .ok_or_else(|| Error::Protocol(format!("restore: pending report {} not supplied", hex::encode(id))))?;
            if report.group as usize != *g {
                return Err(Error::Protocol("restore: pending report group mismatch".into()));
            }
            let mut masked = Vec::with_capacity(report.chunks.len());
            for (c, bytes) in report.chunks.iter().enumerate() {
                // stored client bytes: decoded like any client chunk
                let ct = self.load_fresh(bytes).map_err(Error::Reject)?;
                masked.push(self.circuit.mask_to_group(&ct, c, *g)?);
            }
            batch.reports.push((*g, *id, masked));
            batch.used_groups.insert(*g);
        }
        self.silent_batch = batch;
        self.accepted_ids = st.accepted_ids;
        self.seen = st.seen.into_iter().collect();
        self.client_reports = st.client_reports.into_iter().collect();
        self.admitted = st.admitted;
        self.valid_count = st.valid_count;
        self.closed = st.closed;
        self.released_count_share = st.released_count_share;
        self.released_aggregate_shares = st.released_aggregate_shares;
        self.pending.clear();
        Ok(())
    }

    /// Silent mode, batch close step 1: partial decryption of the encrypted
    /// valid-report counter. Requires at least `min_batch_size` admitted
    /// reports; reveals only the count.
    ///
    /// Released once per batch: a second call returns the share released
    /// the first time. Each partial decryption carries fresh flooding noise,
    /// and every extra noisy partial decryption of the same ciphertext is
    /// an extra sample an adversary could average, so the aggregator never
    /// produces two of them for one ciphertext. This also makes a retried
    /// close (network failure, leader restart) idempotent.
    pub fn count_share(&mut self) -> Result<CountShare> {
        if self.cfg.mode != VerificationMode::Silent {
            return Err(Error::Protocol("count_share is only used in silent mode".into()));
        }
        if let Some(s) = &self.released_count_share {
            return Ok(s.clone());
        }
        let count = self.accepted_ids.len();
        if count < self.cfg.min_batch_size {
            return Err(Error::Protocol(format!("batch has {count} admitted reports, minimum is {}", self.cfg.min_batch_size)));
        }
        self.flush_silent_batch()?;
        self.closed = true;
        let ct = self.valid_count_sum.as_ref().expect("count >= 1");
        let share = CountShare {
            task_id: self.cfg.task_id,
            aggregator: self.index,
            batch_digest: batch_digest(self.accepted_ids.clone()),
            report_count: count as u64,
            partial: self.codec.encode(self.share.partial_decrypt(ct, self.index == 0)?.ciphertext())?,
        };
        self.released_count_share = Some(share.clone());
        Ok(share)
    }

    /// Silent mode, batch close step 2: fuses every aggregator's count share
    /// (including this one's) and records the valid count.
    pub fn count_finish(&mut self, shares: &[CountShare]) -> Result<u64> {
        let n = self.cfg.num_aggregators;
        if shares.len() != n {
            return Err(Error::Protocol(format!("expected {n} count shares, got {}", shares.len())));
        }
        let digest = batch_digest(self.accepted_ids.clone());
        let expected = Self::partial_meta(self.valid_count_sum.as_ref().ok_or_else(|| Error::Protocol("count_finish before count_share".into()))?)?;
        let mut seen = vec![false; n];
        let mut partials = Vec::with_capacity(n);
        for s in shares {
            if s.task_id != self.cfg.task_id || s.batch_digest != digest || s.report_count != self.accepted_ids.len() as u64 {
                return Err(Error::Protocol("count share for a different batch".into()));
            }
            if s.aggregator >= n || std::mem::replace(&mut seen[s.aggregator], true) {
                return Err(Error::Protocol("duplicate or out-of-range aggregator in count shares".into()));
            }
            partials.push(self.load_partial(&s.partial, expected, s.aggregator == 0)?);
        }
        let refs: Vec<&PartialDecryption> = partials.iter().collect();
        let fused = self.ctx.fuse(&refs, 1)?;
        let valid = fused[0];
        if valid > self.accepted_ids.len() as u64 {
            return Err(Error::Protocol("valid count exceeds admitted count: batch corrupted".into()));
        }
        self.valid_count = Some(valid);
        Ok(valid)
    }

    /// Releases this aggregator's partial decryptions of the batch sums to
    /// the single collector of a task without release policies (id 0) and
    /// closes the batch. Tasks with policies use [`Self::aggregate_share_for`].
    pub fn aggregate_share(&mut self) -> Result<AggregateShare> {
        if !self.cfg.collectors.is_empty() {
            return Err(Error::Protocol("task has release policies: use aggregate_share_for(collector)".into()));
        }
        self.aggregate_share_for(0)
    }

    /// Releases to collector `collector` exactly what its policy allows:
    /// partial decryptions of the chunks it may see (whole chunks, cut at
    /// visibility boundaries, so nothing outside its elements is ever
    /// partially decrypted) and of the second-moment accumulators of pairs
    /// within its elements. Closes the batch on first release. Refuses
    /// batches with fewer than `min_batch_size` valid reports (in silent
    /// mode this requires the count round to have run).
    ///
    /// Released once per (batch, collector), for the reason given at
    /// [`Self::count_share`]; the number of releases per batch is therefore
    /// bounded by the number of collectors declared in the task.
    pub fn aggregate_share_for(&mut self, collector: usize) -> Result<AggregateShare> {
        let elements = self.cfg.collector_elements(collector)?; // rejects unknown collectors
        if let Some(s) = self.released_aggregate_shares.get(&(collector as u32)) {
            return Ok(s.clone());
        }
        let count = self.accepted_ids.len();
        let valid = match self.cfg.mode {
            VerificationMode::Verdict => count as u64,
            VerificationMode::Silent => self.valid_count.ok_or_else(|| Error::Protocol("silent mode: run count_share/count_finish before aggregate_share".into()))?,
        };
        if valid < self.cfg.min_batch_size as u64 {
            return Err(Error::Protocol(format!("batch has {valid} valid reports, minimum is {}", self.cfg.min_batch_size)));
        }
        self.closed = true;
        self.pending.clear();
        let sums = self.sums.as_ref().expect("count >= 1");
        let chunks = self.cfg.collector_chunks(&self.layout, collector);
        let mut partials = Vec::with_capacity(chunks.len());
        for &k in &chunks {
            partials.push(self.codec.encode(self.share.partial_decrypt(&sums[k], self.index == 0)?.ciphertext())?);
        }
        let valid_count_partial = match &self.valid_count_sum {
            Some(ct) => Some(self.codec.encode(self.share.partial_decrypt(ct, self.index == 0)?.ciphertext())?),
            None => None,
        };
        let mut moment_partials = Vec::new();
        let pairs = self.cfg.collector_moment_pairs(collector)?;
        if !pairs.is_empty() {
            let sums = self.moment_sums.as_ref().ok_or_else(|| Error::Protocol("moments enabled but no products accumulated".into()))?;
            // accumulators of the collector's pairs, in accumulator order
            for (idx, t) in self.layout.moment_terms().into_iter().enumerate() {
                if pairs.contains(&(t.a, t.b)) {
                    moment_partials.push(self.codec.encode(self.share.partial_decrypt(&sums[idx], self.index == 0)?.ciphertext())?);
                }
            }
        }
        let _ = elements;
        let share = AggregateShare {
            task_id: self.cfg.task_id,
            collector: collector as u32,
            aggregator: self.index,
            batch_digest: batch_digest(self.accepted_ids.clone()),
            report_count: count as u64,
            partials,
            valid_count_partial,
            moment_partials,
        };
        self.released_aggregate_shares.insert(collector as u32, share.clone());
        Ok(share)
    }

    /// [`Self::aggregate_share_for`], sealed to the collector's key from the
    /// task. Tasks without policies have no key and cannot seal.
    pub fn sealed_share_for(&mut self, collector: usize) -> Result<crate::seal::SealedShare> {
        let key = self.cfg.collectors.get(collector).map(|p| p.seal_key).ok_or_else(|| Error::Config(format!("no sealing key for collector {collector}")))?;
        let share = self.aggregate_share_for(collector)?;
        crate::seal::seal(&share, &key)
    }
}
