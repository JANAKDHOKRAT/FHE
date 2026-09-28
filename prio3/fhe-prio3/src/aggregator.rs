//! Aggregator state machine.
//!
//! Per report, the aggregators run:
//!   1. `prepare_init`   — validate the report, compute the check ciphertext
//!                         `S`, broadcast a fresh encrypted mask;
//!   2. `prepare_masks`  — combine all masks into `u = S * mask`, broadcast a
//!                         partial decryption of `u`;
//!   3. `prepare_finish` — fuse the partial decryptions and accept or reject.
//! Per batch, `aggregate_share` releases partial decryptions of the sums over
//! accepted reports.
//!
//! Privacy invariant: an aggregator only ever partially decrypts ciphertexts
//! it computed itself from (a) the report bytes, (b) the deterministic
//! challenge, and (c) the received masks, whose content cannot affect what
//! the decryption reveals as long as this aggregator's own mask is uniform.

use crate::config::TaskConfig;
use crate::error::{Error, RejectReason, Result};
use crate::field::Field;
use crate::keys;
use crate::layout::Layout;
use crate::messages::{AggregateShare, MaskMessage, PublicMaterial, Report, ReportId, VerifierMessage, batch_digest};
use crate::verify::{Challenge, Circuit};
use openfhe_tbgv_rs::{Ciphertext, CiphertextInfo, Context, PartialDecryption, PublicKey, SecretShare};
use rand::rngs::OsRng;
use std::collections::{BTreeMap, HashMap, HashSet};

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
    seen: HashSet<ReportId>,
    pending: HashMap<ReportId, Pending>,
    accepted_ids: Vec<ReportId>,
    sums: Option<Vec<Ciphertext>>,
    rng: OsRng,
}

impl Aggregator {
    pub fn new(cfg: TaskConfig, material: &PublicMaterial, index: usize, share: &[u8]) -> Result<Self> {
        let field = cfg.validate()?;
        if index >= cfg.num_aggregators {
            return Err(Error::Config("aggregator index out of range".into()));
        }
        let ctx = Context::deserialize(&material.context)?;
        if ctx.plain_mod() != cfg.plain_mod {
            return Err(Error::Config("context plaintext modulus does not match task".into()));
        }
        keys::install(&ctx, material)?;
        let pk = ctx.deserialize_public_key(&material.public_key)?;
        let joint_tag = pk.tag()?;
        if joint_tag != material.joint_tag {
            return Err(Error::Config("joint key tag does not match public key".into()));
        }
        let layout = cfg.layout(ctx.row_slots())?;
        let mut need = layout.rotation_indices();
        need.sort_unstable();
        let mut have = material.rotation_indices.clone();
        have.sort_unstable();
        if need.iter().any(|i| !have.contains(i)) {
            return Err(Error::Config("rotation keys do not cover the task layout".into()));
        }
        let share = ctx.deserialize_secret_share(share)?;
        let circuit = Circuit::new(&ctx, &layout)?;
        let fresh = ctx.encrypt(&pk, &ctx.plaintext(&[0])?)?.info()?;
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
            seen: HashSet::new(),
            pending: HashMap::new(),
            accepted_ids: Vec::new(),
            sums: None,
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

    /// Step 1. Returns this aggregator's mask message for the report, or the
    /// deterministic reason the report is refused.
    pub fn prepare_init(&mut self, report: &Report) -> Result<MaskMessage> {
        if report.task_id != self.cfg.task_id {
            return Err(Error::Reject(RejectReason::WrongTask));
        }
        if Report::compute_id(&report.task_id, &report.chunks) != report.report_id {
            return Err(Error::Reject(RejectReason::ReportIdMismatch));
        }
        if self.seen.contains(&report.report_id) {
            return Err(Error::Reject(RejectReason::Replay));
        }
        if report.chunks.len() != self.layout.num_chunks {
            return Err(Error::Reject(RejectReason::WrongChunkCount { expected: self.layout.num_chunks, got: report.chunks.len() }));
        }
        if (self.accepted_ids.len() + self.pending.len()) as u64 >= self.cfg.max_batch_size {
            return Err(Error::Reject(RejectReason::BatchFull));
        }
        let mut chunks = Vec::with_capacity(report.chunks.len());
        for bytes in &report.chunks {
            chunks.push(self.load_fresh(bytes).map_err(Error::Reject)?);
        }
        // From here on the report id is consumed even if verification fails.
        self.seen.insert(report.report_id);

        let challenge = Challenge::derive(&self.cfg, &self.field, &self.layout, &report.report_id);
        let s = self.circuit.check_sum(&chunks, &challenge)?;
        let mask = self.circuit.make_mask(&self.pk, &self.field, &mut self.rng)?;
        let mask_bytes = mask.serialize()?;
        let mut masks = BTreeMap::new();
        masks.insert(self.index, mask);
        self.pending.insert(report.report_id, Pending { chunks, s, masks, partials: BTreeMap::new(), u: None });
        Ok(MaskMessage { report_id: report.report_id, aggregator: self.index, mask: mask_bytes })
    }

    /// Step 2. Takes the other aggregators' masks and returns this
    /// aggregator's partial decryption of the masked check value.
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
        let bytes = partial.serialize()?;
        pending.partials.insert(my_index, partial);
        pending.u = Some(u);
        Ok(VerifierMessage { report_id: *report_id, aggregator: my_index, partial: bytes })
    }

    /// Step 3. Fuses all partial decryptions and decides. Accepted reports
    /// are added to the running sums.
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
        match &mut self.sums {
            None => self.sums = Some(pending.chunks),
            Some(sums) => {
                for (acc, ct) in sums.iter_mut().zip(&pending.chunks) {
                    *acc = self.ctx.add(acc, ct)?;
                }
            }
        }
        self.accepted_ids.push(*report_id);
        Ok(Verdict::Accepted)
    }

    /// Releases this aggregator's partial decryptions of the batch sums.
    /// Refuses batches below `min_batch_size`.
    pub fn aggregate_share(&self) -> Result<AggregateShare> {
        let count = self.accepted_ids.len();
        if count < self.cfg.min_batch_size {
            return Err(Error::Protocol(format!("batch has {count} accepted reports, minimum is {}", self.cfg.min_batch_size)));
        }
        let sums = self.sums.as_ref().expect("count >= 1");
        let mut partials = Vec::with_capacity(sums.len());
        for s in sums {
            partials.push(self.share.partial_decrypt(s, self.index == 0)?.serialize()?);
        }
        Ok(AggregateShare {
            task_id: self.cfg.task_id,
            aggregator: self.index,
            batch_digest: batch_digest(self.accepted_ids.clone()),
            report_count: count as u64,
            partials,
        })
    }
}
