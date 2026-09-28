//! Aggregator state machine.
//!
//! Admission (both modes), in `prepare_init` / `process_silent`, before any
//! ciphertext is deserialized and in this order: batch open; size cap; task
//! id; signature and registry and per-client quota (when the policy requires
//! it); report id recomputation; replay; chunk count; then structural
//! validation of each ciphertext against a reference fresh encryption.
//! Every one of these decisions is deterministic, so honest aggregators agree.
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
use crate::verify::{Challenge, Circuit};
use openfhe_tbgv_rs::{Ciphertext, CiphertextInfo, Context, PartialDecryption, PublicKey, SecretShare};
use rand::rngs::OsRng;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Rejected(RejectReason),
}

struct Pending {
    chunks: Vec<Ciphertext>,
    s: Ciphertext,
    masks: BTreeMap<usize, Ciphertext>,
    partials: BTreeMap<usize, PartialDecryption>,
    u: Option<Ciphertext>,
}

pub struct Aggregator {
    cfg: TaskConfig,
    field: Field,
    layout: Layout,
    ctx: Context,
    pk: PublicKey,
    joint_tag: String,
    index: usize,
    share: SecretShare,
    circuit: Circuit,
    /// Structure of a fresh encryption under the joint key; every incoming
    /// ciphertext must match it exactly.
    fresh: CiphertextInfo,
    /// Serialized size of a fresh encryption, for the report size cap.
    fresh_bytes: usize,
    registry: Option<Arc<dyn ClientRegistry>>,
    client_reports: HashMap<[u8; 32], u32>,
    seen: HashSet<ReportId>,
    admitted: u64,
    pending: HashMap<ReportId, Pending>,
    accepted_ids: Vec<ReportId>,
    sums: Option<Vec<Ciphertext>>,
    /// Silent mode: encrypted number of valid reports (every slot).
    valid_count_sum: Option<Ciphertext>,
    /// Silent mode: decrypted valid count, once the count round has run.
    valid_count: Option<u64>,
    closed: bool,
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
        keys::install(&ctx, material)?;
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
        let reference = ctx.encrypt(&pk, &ctx.plaintext(&[0])?)?;
        let fresh = reference.info()?;
        let fresh_bytes = reference.serialize()?.len();
        Ok(Self {
            cfg,
            field,
            layout,
            ctx,
            pk,
            joint_tag,
            index,
            share,
            circuit,
            fresh,
            fresh_bytes,
            registry,
            client_reports: HashMap::new(),
            seen: HashSet::new(),
            admitted: 0,
            pending: HashMap::new(),
            accepted_ids: Vec::new(),
            sums: None,
            valid_count_sum: None,
            valid_count: None,
            closed: false,
            rng: OsRng,
        })
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

    /// Largest serialized ciphertext payload a report may carry.
    pub fn max_report_bytes(&self) -> usize {
        let derived = self.layout.num_chunks * (self.fresh_bytes + 1024);
        if self.cfg.max_report_bytes == 0 { derived } else { self.cfg.max_report_bytes.min(derived) }
    }

    fn check_fresh(&self, info: &CiphertextInfo) -> std::result::Result<(), RejectReason> {
        if info.key_tag != self.joint_tag {
            return Err(RejectReason::MalformedCiphertext("not encrypted under the joint key".into()));
        }
        if *info != self.fresh {
            return Err(RejectReason::MalformedCiphertext(format!(
                "not a fresh ciphertext: expected {} elements, level {}, degree {}, {} limbs, packed={}; got {} elements, level {}, degree {}, {} limbs, packed={}",
                self.fresh.num_elements, self.fresh.level, self.fresh.noise_scale_deg, self.fresh.num_limbs, self.fresh.packed_encoding,
                info.num_elements, info.level, info.noise_scale_deg, info.num_limbs, info.packed_encoding
            )));
        }
        Ok(())
    }

    fn load_fresh(&self, bytes: &[u8]) -> std::result::Result<Ciphertext, RejectReason> {
        let ct = self.ctx.deserialize_ciphertext(bytes).map_err(|e| RejectReason::MalformedCiphertext(e.0))?;
        let info = ct.info().map_err(|e| RejectReason::MalformedCiphertext(e.0))?;
        self.check_fresh(&info)?;
        Ok(ct)
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
        if Report::compute_id(&report.task_id, &report.chunks) != report.report_id {
            return Err(RejectReason::ReportIdMismatch);
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
        let challenge = Challenge::derive(&self.cfg, &self.field, &self.layout, &report.report_id);
        let s = self.circuit.check_sum(&chunks, &challenge)?;
        let mask = self.circuit.make_mask(&self.pk, &self.field, &mut self.rng)?;
        let mask_bytes = mask.serialize()?;
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
            if m.mask.len() > self.fresh_bytes + 1024 {
                return Err(Error::Protocol("mask ciphertext too large".into()));
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
        let bytes = partial.serialize()?;
        pending.partials.insert(my_index, partial);
        pending.u = Some(u);
        Ok(VerifierMessage { report_id: *report_id, aggregator: my_index, partial: bytes })
    }

    /// Verdict mode, step 3. Fuses all partial decryptions and decides.
    /// Accepted reports are added to the running sums.
    pub fn prepare_finish(&mut self, report_id: &ReportId, verifiers: &[VerifierMessage]) -> Result<Verdict> {
        let n = self.cfg.num_aggregators;
        let mut loaded = Vec::new();
        for v in verifiers {
            if v.report_id != *report_id {
                return Err(Error::Protocol("verifier message for a different report".into()));
            }
            if v.aggregator >= n || v.aggregator == self.index {
                return Err(Error::Protocol("verifier message from an unexpected aggregator".into()));
            }
            loaded.push((v.aggregator, PartialDecryption::deserialize(&self.ctx, &v.partial, v.aggregator == 0)?));
        }
        let mut pending = self.pending.remove(report_id).ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
        if pending.u.is_none() {
            return Err(Error::Protocol("prepare_masks has not run for this report".into()));
        }
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
        self.add_to_sums(pending.chunks)?;
        self.accepted_ids.push(*report_id);
        Ok(Verdict::Accepted)
    }

    /// Silent mode. Admits the report, computes `valid` homomorphically and
    /// adds `x * valid` to the sums. Nothing is decrypted and no message is
    /// exchanged; an invalid report contributes exactly zero. Returns the
    /// structural rejection reason if the report was not admitted.
    pub fn process_silent(&mut self, report: &Report) -> Result<()> {
        if self.cfg.mode != VerificationMode::Silent {
            return Err(Error::Protocol("process_silent is only valid in silent mode".into()));
        }
        let chunks = self.admit(report).map_err(Error::Reject)?;
        let challenge = Challenge::derive(&self.cfg, &self.field, &self.layout, &report.report_id);
        let s = self.circuit.check_sum(&chunks, &challenge)?;
        let valid = self.circuit.silent_validity(&s)?;
        let mut masked = Vec::with_capacity(chunks.len());
        for ct in &chunks {
            masked.push(self.ctx.mult(ct, &valid)?);
        }
        self.add_to_sums(masked)?;
        self.valid_count_sum = Some(match self.valid_count_sum.take() {
            None => valid,
            Some(acc) => self.ctx.add(&acc, &valid)?,
        });
        self.accepted_ids.push(report.report_id);
        Ok(())
    }

    /// Silent mode, batch close step 1: partial decryption of the encrypted
    /// valid-report counter. Requires at least `min_batch_size` admitted
    /// reports; reveals only the count.
    pub fn count_share(&mut self) -> Result<CountShare> {
        if self.cfg.mode != VerificationMode::Silent {
            return Err(Error::Protocol("count_share is only used in silent mode".into()));
        }
        let count = self.accepted_ids.len();
        if count < self.cfg.min_batch_size {
            return Err(Error::Protocol(format!("batch has {count} admitted reports, minimum is {}", self.cfg.min_batch_size)));
        }
        self.closed = true;
        let ct = self.valid_count_sum.as_ref().expect("count >= 1");
        Ok(CountShare {
            task_id: self.cfg.task_id,
            aggregator: self.index,
            batch_digest: batch_digest(self.accepted_ids.clone()),
            report_count: count as u64,
            partial: self.share.partial_decrypt(ct, self.index == 0)?.serialize()?,
        })
    }

    /// Silent mode, batch close step 2: fuses every aggregator's count share
    /// (including this one's) and records the valid count.
    pub fn count_finish(&mut self, shares: &[CountShare]) -> Result<u64> {
        let n = self.cfg.num_aggregators;
        if shares.len() != n {
            return Err(Error::Protocol(format!("expected {n} count shares, got {}", shares.len())));
        }
        let digest = batch_digest(self.accepted_ids.clone());
        let mut seen = vec![false; n];
        let mut partials = Vec::with_capacity(n);
        for s in shares {
            if s.task_id != self.cfg.task_id || s.batch_digest != digest || s.report_count != self.accepted_ids.len() as u64 {
                return Err(Error::Protocol("count share for a different batch".into()));
            }
            if s.aggregator >= n || std::mem::replace(&mut seen[s.aggregator], true) {
                return Err(Error::Protocol("duplicate or out-of-range aggregator in count shares".into()));
            }
            partials.push(PartialDecryption::deserialize(&self.ctx, &s.partial, s.aggregator == 0)?);
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

    /// Releases this aggregator's partial decryptions of the batch sums and
    /// closes the batch: no further reports are admitted under this key.
    /// Refuses batches with fewer than `min_batch_size` valid reports (in
    /// silent mode this requires the count round to have run).
    pub fn aggregate_share(&mut self) -> Result<AggregateShare> {
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
        let mut partials = Vec::with_capacity(sums.len());
        for s in sums {
            partials.push(self.share.partial_decrypt(s, self.index == 0)?.serialize()?);
        }
        let valid_count_partial = match &self.valid_count_sum {
            Some(ct) => Some(self.share.partial_decrypt(ct, self.index == 0)?.serialize()?),
            None => None,
        };
        Ok(AggregateShare {
            task_id: self.cfg.task_id,
            aggregator: self.index,
            batch_digest: batch_digest(self.accepted_ids.clone()),
            report_count: count as u64,
            partials,
            valid_count_partial,
        })
    }
}
