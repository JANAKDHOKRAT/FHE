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
//!   1. `prepare_init`        — compute the check ciphertext `S`, commit to a mask;
//!   2. `prepare_mask_reveal` — with every mask commitment in, reveal the mask;
//!   3. `prepare_masks`       — `u = S * masks`, commit to a partial decryption;
//!   4. `prepare_reveal`      — with every commitment in, reveal the partial;
//!   5. `prepare_finish`      — fuse and accept or reject.
//! Each "commit, then reveal" stops a rushing aggregator from choosing its
//! value after seeing the others' (cancelling the honest mask, or forcing
//! the fused check to zero).
//! Silent mode, per report: `process_silent` computes the validity bit
//! homomorphically and adds `x * valid` to the sums. No messages, no
//! decryption.
//! Per batch, `aggregate_share` releases partial decryptions of the sums and
//! closes the batch.
//!
//! Privacy invariant: an aggregator only ever partially decrypts ciphertexts
//! it computed itself from (a) the report bytes, (b) the challenge (a
//! deterministic function of the task, the report id and the verify key all
//! aggregators share), and (c) in verdict mode the received masks, whose content
//! cannot affect what the decryption reveals as long as this aggregator's own
//! mask is uniform and the others were committed before it was revealed.

use crate::auth::{self, ClientRegistry};
use crate::config::{AuthPolicy, TaskConfig, VerificationMode};
use crate::error::{Error, RejectReason, Result};
use crate::field::Field;
use crate::keys;
use crate::layout::Layout;
use crate::messages::{
    AggregateShare, CountCommit, CountOpening, CountReveal, CountShare, MaskCommit, MaskMessage, PublicMaterial, ReleaseChallenge, ReleaseCommit, ReleaseOpening,
    ReleaseReveal, Report, ReportId, VerifierCommit, VerifierMessage, batch_digest,
};
use crate::vdec;
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
    /// Verifiable-decryption state of the count round and the releases.
    #[serde(default)]
    pub verification: VerificationState,
}

/// What an aggregator keeps between the rounds of verifiable decryption
/// (`vdec`), persisted so that a restarted aggregator answers a repeated
/// round with the same bytes and never decrypts a second set of checks.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct VerificationState {
    /// Silent mode: this aggregator's count checks, secret until round 3.
    pub count_opening: Option<vdec::Opening>,
    /// Every aggregator's count share, as received in round 2.
    pub count_shares: Vec<CountShare>,
    /// This aggregator's partial decryptions of the others' count checks, by verifier.
    pub count_partials: Vec<(usize, Vec<Vec<u8>>)>,
    /// The others' commitments to their partials of this aggregator's checks.
    pub count_commits: Vec<CountCommit>,
    /// Per collector: the challenge answered and this aggregator's partial
    /// decryptions of its checks (one challenge per release, ever).
    pub releases: BTreeMap<u32, (ReleaseChallenge, Vec<Vec<u8>>)>,
}

struct Pending {
    chunks: Vec<Ciphertext>,
    s: Ciphertext,
    masks: BTreeMap<usize, Ciphertext>,
    /// This aggregator's encoded mask, revealed after every mask commitment is in.
    my_mask: Vec<u8>,
    /// The other aggregators' commitments to their masks.
    mask_commits: BTreeMap<usize, [u8; 32]>,
    partials: BTreeMap<usize, PartialDecryption>,
    u: Option<Ciphertext>,
    /// This aggregator's encoded partial, revealed after every commitment is in.
    mine: Option<Vec<u8>>,
    /// The other aggregators' commitments to their partials.
    commits: BTreeMap<usize, [u8; 32]>,
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
    /// The task's secret verify key: every report's challenge is expanded
    /// from it (see `verify.rs`). Never leaves this aggregator.
    verify_key: keys::VerifyKey,
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
    verification: VerificationState,
    rng: OsRng,
}

impl Aggregator {
    /// `secret` is this aggregator's encoded [`keys::AggregatorSecret`] (its
    /// key share and the task's verify key) as the ceremony returned it.
    /// `registry` is required when the task's `AuthPolicy` is `Required`.
    pub fn new(
        cfg: TaskConfig,
        material: &PublicMaterial,
        index: usize,
        secret: &[u8],
        registry: Option<Arc<dyn ClientRegistry>>,
    ) -> Result<Self> {
        let secret = keys::AggregatorSecret::decode(secret)?;
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
        let share = ctx.deserialize_secret_share(&secret.share)?;
        let verify_key = secret.verify_key.clone();
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
            verify_key,
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
            verification: VerificationState::default(),
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
    pub fn is_silent(&self) -> bool {
        self.cfg.mode == VerificationMode::Silent
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

    /// Verdict mode, step 1. Returns this aggregator's commitment to its mask
    /// for the report, or the deterministic reason the report is refused.
    pub fn prepare_init(&mut self, report: &Report) -> Result<MaskCommit> {
        if self.cfg.mode != VerificationMode::Verdict {
            return Err(Error::Protocol("prepare_init is only valid in verdict mode".into()));
        }
        let chunks = self.admit(report).map_err(Error::Reject)?;
        let challenge = Challenge::derive(&self.cfg, &self.field, &self.layout, &self.verify_key, &report.report_id, 0);
        let s = self.circuit.check_sum(&chunks, &challenge)?;
        let mask = self.circuit.make_mask(&self.pk, &self.field, &mut self.rng)?;
        let mask_bytes = self.codec.encode(&mask)?;
        let digest = vdec::commit(&Self::mask_context(&self.cfg.task_id, &report.report_id, self.index), &mask_bytes);
        let mut masks = BTreeMap::new();
        masks.insert(self.index, mask);
        self.pending.insert(
            report.report_id,
            Pending { chunks, s, masks, my_mask: mask_bytes, mask_commits: BTreeMap::new(), partials: BTreeMap::new(), u: None, mine: None, commits: BTreeMap::new() },
        );
        Ok(MaskCommit { report_id: report.report_id, aggregator: self.index, digest })
    }

    fn mask_context(task_id: &[u8; 32], report_id: &ReportId, aggregator: usize) -> Vec<u8> {
        let mut c = b"mask".to_vec();
        c.extend_from_slice(task_id);
        c.extend_from_slice(report_id);
        c.extend_from_slice(&(aggregator as u64).to_le_bytes());
        c
    }

    /// Verdict mode, step 2. Records every other aggregator's mask
    /// commitment and only then reveals this aggregator's mask, so no mask
    /// can depend on another.
    pub fn prepare_mask_reveal(&mut self, report_id: &ReportId, commits: &[MaskCommit]) -> Result<MaskMessage> {
        let n = self.cfg.num_aggregators;
        let pending = self.pending.get_mut(report_id).ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
        for c in commits {
            if c.report_id != *report_id {
                return Err(Error::Protocol("mask commitment for a different report".into()));
            }
            if c.aggregator >= n || c.aggregator == self.index {
                return Err(Error::Protocol("mask commitment from an unexpected aggregator".into()));
            }
            match pending.mask_commits.get(&c.aggregator) {
                Some(d) if *d != c.digest => return Err(Error::Protocol(format!("aggregator {} changed its mask commitment", c.aggregator))),
                _ => {
                    pending.mask_commits.insert(c.aggregator, c.digest);
                }
            }
        }
        if pending.mask_commits.len() != n - 1 {
            return Err(Error::Protocol(format!("expected {} mask commitments, have {}", n - 1, pending.mask_commits.len())));
        }
        Ok(MaskMessage { report_id: *report_id, aggregator: self.index, mask: pending.my_mask.clone() })
    }

    /// Verdict mode, step 3. Takes the other aggregators' masks (each must
    /// match its commitment) and returns this aggregator's commitment to its
    /// partial decryption of the masked check value; the partial itself is
    /// revealed by [`Self::prepare_reveal`] once every other aggregator has
    /// committed.
    pub fn prepare_masks(&mut self, report_id: &ReportId, masks: &[MaskMessage]) -> Result<VerifierCommit> {
        let n = self.cfg.num_aggregators;
        let my_index = self.index;
        {
            let pending = self.pending.get(report_id).ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
            if pending.mask_commits.len() != n - 1 {
                return Err(Error::Protocol("masks before every mask commitment: run prepare_mask_reveal first".into()));
            }
            for m in masks {
                if let Some(d) = pending.mask_commits.get(&m.aggregator) {
                    if vdec::commit(&Self::mask_context(&self.cfg.task_id, report_id, m.aggregator), &m.mask) != *d {
                        return Err(Error::Protocol(format!("aggregator {}'s mask is not the one it committed to", m.aggregator)));
                    }
                }
            }
        }
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
        let digest = vdec::commit(&Self::verdict_context(&self.cfg.task_id, report_id, my_index), &bytes);
        pending.partials.insert(my_index, partial);
        pending.mine = Some(bytes);
        pending.u = Some(u);
        Ok(VerifierCommit { report_id: *report_id, aggregator: my_index, digest })
    }

    /// Tests only: the masked check value of a verdict-mode report this
    /// aggregator holds (after [`Self::prepare_masks`]), to measure its noise.
    #[doc(hidden)]
    pub fn check_value_for_tests(&self, report_id: &ReportId) -> Option<&Ciphertext> {
        self.pending.get(report_id).and_then(|p| p.u.as_ref())
    }

    fn verdict_context(task_id: &[u8; 32], report_id: &ReportId, aggregator: usize) -> Vec<u8> {
        let mut c = b"verdict".to_vec();
        c.extend_from_slice(task_id);
        c.extend_from_slice(report_id);
        c.extend_from_slice(&(aggregator as u64).to_le_bytes());
        c
    }

    /// Verdict mode, step 3: records every other aggregator's commitment and
    /// only then reveals this aggregator's partial decryption.
    pub fn prepare_reveal(&mut self, report_id: &ReportId, commits: &[VerifierCommit]) -> Result<VerifierMessage> {
        let n = self.cfg.num_aggregators;
        let pending = self.pending.get_mut(report_id).ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
        let mine = pending.mine.clone().ok_or_else(|| Error::Protocol("prepare_masks has not run for this report".into()))?;
        for c in commits {
            if c.report_id != *report_id {
                return Err(Error::Protocol("commitment for a different report".into()));
            }
            if c.aggregator >= n || c.aggregator == self.index {
                return Err(Error::Protocol("commitment from an unexpected aggregator".into()));
            }
            match pending.commits.get(&c.aggregator) {
                Some(d) if *d != c.digest => return Err(Error::Protocol(format!("aggregator {} changed its commitment", c.aggregator))),
                _ => {
                    pending.commits.insert(c.aggregator, c.digest);
                }
            }
        }
        if pending.commits.len() != n - 1 {
            return Err(Error::Protocol(format!("expected {} commitments, have {}", n - 1, pending.commits.len())));
        }
        Ok(VerifierMessage { report_id: *report_id, aggregator: self.index, partial: mine })
    }

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
            let pending = self.pending.get(report_id).ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
            let committed = pending.commits.get(&v.aggregator).ok_or_else(|| Error::Protocol(format!("no commitment from aggregator {}: run prepare_reveal first", v.aggregator)))?;
            if vdec::commit(&Self::verdict_context(&self.cfg.task_id, report_id, v.aggregator), &v.partial) != *committed {
                return Err(Error::Protocol(format!("aggregator {}'s partial decryption is not the one it committed to", v.aggregator)));
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
        // Noise beyond the flooding range (vdec::check_flooding) comes from a
        // malformed client ciphertext or from a malformed key or partial, and
        // the two cannot be told apart here: the report is rejected, like any
        // other check value that is not a decryption of zero. Every honest
        // aggregator fuses the same partials, so they agree. Keys are bounded
        // before any report by the ceremony's deep key check (SECURITY.md §6.2).
        if !self.ctx.fuse_flooding_check(&refs, vdec::FLOODING_SLACK_BITS)?.0 {
            return Ok(Verdict::Rejected(RejectReason::ValidityCheckFailed));
        }
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
        let challenge = Challenge::derive(&self.cfg, &self.field, &self.layout, &self.verify_key, &report.report_id, group);
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
            verification: self.verification.clone(),
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
        self.verification = st.verification;
        self.pending.clear();
        Ok(())
    }

    /// Silent mode, count round 1: partial decryption of the encrypted
    /// valid-report counter, and this aggregator's blinded checks of it
    /// (`vdec`). Requires at least `min_batch_size` admitted reports.
    ///
    /// The decrypted count decides whether any aggregate is released
    /// (`min_batch_size` applies to *valid* reports), so every aggregator
    /// verifies it itself before trusting it: rounds 2 to 4
    /// ([`Self::count_commit`], [`Self::count_open`], [`Self::count_reveal`],
    /// [`Self::count_finish`]). Unverified, a malicious aggregator could
    /// shift its partial so that a batch with one valid report reads as
    /// full, and the honest aggregators would release that report.
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
        let opening = vdec::draw(&self.ctx, &[ct], &mut self.rng)?;
        let checks = vdec::build(&self.ctx, &self.pk, &[ct], &opening)?.iter().map(|c| self.codec.encode(c)).collect::<Result<Vec<_>>>()?;
        let share = CountShare {
            task_id: self.cfg.task_id,
            aggregator: self.index,
            batch_digest: batch_digest(self.accepted_ids.clone()),
            report_count: count as u64,
            partial: self.codec.encode(self.share.partial_decrypt(ct, self.index == 0)?.ciphertext())?,
            checks,
        };
        self.verification.count_opening = Some(opening);
        self.released_count_share = Some(share.clone());
        Ok(share)
    }

    fn count_context(&self, verifier: usize, check: usize, committer: usize) -> Vec<u8> {
        let mut c = b"count".to_vec();
        c.extend_from_slice(&self.cfg.task_id);
        c.extend_from_slice(&batch_digest(self.accepted_ids.clone()));
        for x in [verifier, check, committer] {
            c.extend_from_slice(&(x as u64).to_le_bytes());
        }
        c
    }

    fn count_ct(&self) -> Result<&Ciphertext> {
        self.valid_count_sum.as_ref().ok_or_else(|| Error::Protocol("count round before count_share".into()))
    }

    /// The count checks aggregator `j` published, rebuilt through the codec.
    fn count_checks_of(&self, j: usize) -> Result<Vec<Ciphertext>> {
        let meta = self.count_ct()?.meta()?;
        let share = self.verification.count_shares.iter().find(|s| s.aggregator == j).ok_or_else(|| Error::Protocol(format!("no count share from aggregator {j}")))?;
        share.checks.iter().map(|b| self.codec.decode(b, Expect::Exactly(meta)).map_err(|e| Error::Protocol(format!("aggregator {j}'s count check: {e}")))).collect()
    }

    /// Silent mode, count round 2: takes every aggregator's count share,
    /// partially decrypts every other aggregator's checks and returns
    /// commitments to those partials (revealed in round 4, after the checks
    /// are opened and verified).
    pub fn count_commit(&mut self, shares: &[CountShare]) -> Result<CountCommit> {
        let n = self.cfg.num_aggregators;
        let digest = batch_digest(self.accepted_ids.clone());
        let my_checks = self.released_count_share.as_ref().ok_or_else(|| Error::Protocol("count_commit before count_share".into()))?.checks.len();
        if !self.verification.count_partials.is_empty() {
            let same = shares.len() == self.verification.count_shares.len()
                && shares.iter().all(|s| self.verification.count_shares.iter().any(|t| t.aggregator == s.aggregator && t.partial == s.partial && t.checks == s.checks));
            if !same {
                return Err(Error::Protocol("different count shares than those this aggregator already committed on".into()));
            }
        } else {
            if shares.len() != n {
                return Err(Error::Protocol(format!("expected {n} count shares, got {}", shares.len())));
            }
            let mut seen = vec![false; n];
            for s in shares {
                if s.task_id != self.cfg.task_id || s.batch_digest != digest || s.report_count != self.accepted_ids.len() as u64 {
                    return Err(Error::Protocol("count share for a different batch".into()));
                }
                if s.aggregator >= n || std::mem::replace(&mut seen[s.aggregator], true) {
                    return Err(Error::Protocol("duplicate or out-of-range aggregator in count shares".into()));
                }
                if s.checks.len() != my_checks {
                    return Err(Error::Protocol(format!("aggregator {} published {} count checks, expected {my_checks}", s.aggregator, s.checks.len())));
                }
            }
            if shares.iter().find(|s| s.aggregator == self.index).map(|s| s.partial.as_slice()) != self.released_count_share.as_ref().map(|s| s.partial.as_slice()) {
                return Err(Error::Protocol("the count shares do not carry this aggregator's own share".into()));
            }
            // every share must parse to the shapes this aggregator computed,
            // before anything is stored or committed to
            let ct_meta = self.count_ct()?.meta()?;
            let partial_meta = Self::partial_meta(self.count_ct()?)?;
            for s in shares {
                self.load_partial(&s.partial, partial_meta, s.aggregator == 0).map_err(|e| Error::Protocol(format!("aggregator {}'s count share: {e}", s.aggregator)))?;
                for b in &s.checks {
                    self.codec.decode(b, Expect::Exactly(ct_meta)).map_err(|e| Error::Protocol(format!("aggregator {}'s count check: {e}", s.aggregator)))?;
                }
            }
            self.verification.count_shares = shares.to_vec();
            let mut partials = Vec::new();
            for j in (0..n).filter(|&j| j != self.index) {
                let mut mine = Vec::with_capacity(my_checks);
                for c in self.count_checks_of(j)? {
                    mine.push(self.codec.encode(self.share.partial_decrypt(&c, self.index == 0)?.ciphertext())?);
                }
                partials.push((j, mine));
            }
            self.verification.count_partials = partials;
        }
        let digests = self
            .verification
            .count_partials
            .iter()
            .map(|(j, ps)| (*j, ps.iter().enumerate().map(|(l, p)| vdec::commit(&self.count_context(*j, l, self.index), p)).collect()))
            .collect();
        Ok(CountCommit { task_id: self.cfg.task_id, aggregator: self.index, batch_digest: digest, digests })
    }

    /// Silent mode, count round 3: once every other aggregator has committed
    /// to its partials of this aggregator's checks, reveals the checks.
    pub fn count_open(&mut self, commits: &[CountCommit]) -> Result<CountOpening> {
        let n = self.cfg.num_aggregators;
        let digest = batch_digest(self.accepted_ids.clone());
        let opening = self.verification.count_opening.clone().ok_or_else(|| Error::Protocol("count_open before count_share".into()))?;
        if self.verification.count_partials.is_empty() {
            return Err(Error::Protocol("count_open before count_commit".into()));
        }
        let others: Vec<&CountCommit> = commits.iter().filter(|c| c.aggregator != self.index).collect();
        let mut seen = vec![false; n];
        for c in &others {
            if c.task_id != self.cfg.task_id || c.batch_digest != digest {
                return Err(Error::Protocol("count commitment for a different batch".into()));
            }
            if c.aggregator >= n || std::mem::replace(&mut seen[c.aggregator], true) {
                return Err(Error::Protocol("duplicate or out-of-range aggregator in count commitments".into()));
            }
            let mine = c.digests.iter().find(|(v, _)| *v == self.index).ok_or_else(|| Error::Protocol(format!("aggregator {} did not commit to this aggregator's checks", c.aggregator)))?;
            if mine.1.len() != opening.checks.len() {
                return Err(Error::Protocol(format!("aggregator {} committed to {} checks, expected {}", c.aggregator, mine.1.len(), opening.checks.len())));
            }
        }
        if others.len() != n - 1 {
            return Err(Error::Protocol(format!("expected {} count commitments, got {}", n - 1, others.len())));
        }
        if self.verification.count_commits.is_empty() {
            self.verification.count_commits = others.into_iter().cloned().collect();
        } else {
            for c in &self.verification.count_commits {
                let again = commits.iter().find(|x| x.aggregator == c.aggregator).expect("checked above");
                if again.digests != c.digests {
                    return Err(Error::Protocol(format!("aggregator {} changed its count commitments", c.aggregator)));
                }
            }
        }
        Ok(CountOpening { task_id: self.cfg.task_id, aggregator: self.index, batch_digest: digest, opening })
    }

    /// Silent mode, count round 4: rebuilds every other aggregator's checks
    /// from this aggregator's own count ciphertext and their openings, and
    /// reveals its partials only if each is exactly what was published (so
    /// no aggregator can have anything else decrypted through a "check").
    pub fn count_reveal(&mut self, openings: &[CountOpening]) -> Result<CountReveal> {
        let n = self.cfg.num_aggregators;
        let digest = batch_digest(self.accepted_ids.clone());
        if self.verification.count_commits.len() != n - 1 {
            return Err(Error::Protocol("count_reveal before count_open".into()));
        }
        let ct = self.count_ct()?.try_clone()?;
        for j in (0..n).filter(|&j| j != self.index) {
            let o = openings.iter().find(|o| o.aggregator == j).ok_or_else(|| Error::Protocol(format!("no count opening from aggregator {j}")))?;
            if o.task_id != self.cfg.task_id || o.batch_digest != digest {
                return Err(Error::Protocol("count opening for a different batch".into()));
            }
            let rebuilt = vdec::build(&self.ctx, &self.pk, &[&ct], &o.opening)?;
            let published = self.count_checks_of(j)?;
            if rebuilt.len() != published.len() || rebuilt.iter().zip(&published).any(|(a, b)| !vdec::same(a, b).unwrap_or(false)) {
                return Err(Error::Protocol(format!("aggregator {j}'s count checks are not what it opened: refusing to decrypt them")));
            }
        }
        Ok(CountReveal { task_id: self.cfg.task_id, aggregator: self.index, batch_digest: digest, partials: self.verification.count_partials.clone() })
    }

    /// Silent mode, count round 5 (local): verifies this aggregator's checks
    /// with every other aggregator's revealed partials (each against its
    /// commitment), fuses the count and records it. Only a verified count
    /// lets [`Self::aggregate_share_for`] release anything.
    pub fn count_finish(&mut self, reveals: &[CountReveal]) -> Result<u64> {
        let n = self.cfg.num_aggregators;
        let digest = batch_digest(self.accepted_ids.clone());
        let opening = self.verification.count_opening.clone().ok_or_else(|| Error::Protocol("count_finish before count_share".into()))?;
        if self.verification.count_commits.len() != n - 1 {
            return Err(Error::Protocol("count_finish before count_open".into()));
        }
        let ct = self.count_ct()?.try_clone()?;
        let my_checks = vdec::build(&self.ctx, &self.pk, &[&ct], &opening)?;
        let check_meta = CiphertextMeta { num_elements: 1, ..my_checks[0].meta()? };
        let count_meta = Self::partial_meta(&ct)?;
        // per check, every aggregator's partial, in aggregator order
        let mut check_partials: Vec<Vec<PartialDecryption>> = (0..my_checks.len()).map(|_| Vec::with_capacity(n)).collect();
        let mut count_partials = Vec::with_capacity(n);
        for j in 0..n {
            let share = self.verification.count_shares.iter().find(|s| s.aggregator == j).ok_or_else(|| Error::Protocol(format!("no count share from aggregator {j}")))?;
            count_partials.push(self.load_partial(&share.partial, count_meta, j == 0)?);
            if j == self.index {
                for (l, c) in my_checks.iter().enumerate() {
                    check_partials[l].push(self.share.partial_decrypt(c, self.index == 0)?);
                }
                continue;
            }
            let r = reveals.iter().find(|r| r.aggregator == j).ok_or_else(|| Error::Protocol(format!("no count reveal from aggregator {j}")))?;
            if r.task_id != self.cfg.task_id || r.batch_digest != digest {
                return Err(Error::Protocol("count reveal for a different batch".into()));
            }
            let ps = &r.partials.iter().find(|(v, _)| *v == self.index).ok_or_else(|| Error::Protocol(format!("aggregator {j} revealed nothing for this aggregator's checks")))?.1;
            let committed = &self.verification.count_commits.iter().find(|c| c.aggregator == j).expect("n - 1 commitments").digests;
            let committed = &committed.iter().find(|(v, _)| *v == self.index).expect("checked in count_open").1;
            if ps.len() != my_checks.len() {
                return Err(Error::Protocol(format!("aggregator {j} revealed {} partials, expected {}", ps.len(), my_checks.len())));
            }
            for (l, p) in ps.iter().enumerate() {
                if vdec::commit(&self.count_context(self.index, l, j), p) != committed[l] {
                    return Err(Error::Protocol(format!("aggregator {j}'s partial of count check {l} is not the one it committed to")));
                }
                check_partials[l].push(self.load_partial(p, check_meta, j == 0)?);
            }
        }
        let fused_count = vdec::fuse_checked(&self.ctx, &count_partials.iter().collect::<Vec<_>>(), "valid count")?;
        let fused_checks = check_partials
            .iter()
            .enumerate()
            .map(|(l, ps)| vdec::fuse_checked(&self.ctx, &ps.iter().collect::<Vec<_>>(), &format!("count check {l}")))
            .collect::<Result<Vec<_>>>()?;
        let powers = vdec::SlotPowers::new(&self.ctx)?;
        vdec::verify(&powers, &[vec![0]], &[fused_count.clone()], &fused_checks, &opening)?;
        let valid = fused_count[0];
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
        let accs = self.release_accumulators(collector)?;
        let chunks = self.cfg.collector_chunks(&self.layout, collector).len();
        let has_count = self.valid_count_sum.is_some();
        let mut partials = Vec::with_capacity(accs.len());
        for c in &accs {
            partials.push(self.codec.encode(self.share.partial_decrypt(c, self.index == 0)?.ciphertext())?);
        }
        let accumulators = accs.iter().map(|c| self.codec.encode(c)).collect::<Result<Vec<_>>>()?;
        let moment_partials = partials.split_off(chunks + has_count as usize);
        let valid_count_partial = if has_count { partials.pop() } else { None };
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
            accumulators,
        };
        self.released_aggregate_shares.insert(collector as u32, share.clone());
        Ok(share)
    }

    /// The ciphertexts released to `collector`, in the order chunks, valid
    /// count (silent mode), second-moment accumulators of its pairs.
    fn release_accumulators(&self, collector: usize) -> Result<Vec<Ciphertext>> {
        let sums = self.sums.as_ref().ok_or_else(|| Error::Protocol("no report in the batch".into()))?;
        let mut out = Vec::new();
        for k in self.cfg.collector_chunks(&self.layout, collector) {
            out.push(sums[k].try_clone()?);
        }
        if let Some(ct) = &self.valid_count_sum {
            out.push(ct.try_clone()?);
        }
        let pairs = self.cfg.collector_moment_pairs(collector)?;
        if !pairs.is_empty() {
            let m = self.moment_sums.as_ref().ok_or_else(|| Error::Protocol("moments enabled but no products accumulated".into()))?;
            for (idx, t) in self.layout.moment_terms().into_iter().enumerate() {
                if pairs.contains(&(t.a, t.b)) {
                    out.push(m[idx].try_clone()?);
                }
            }
        }
        Ok(out)
    }

    fn release_context(&self, collector: u32, check: usize, aggregator: usize) -> Vec<u8> {
        let mut c = b"release".to_vec();
        c.extend_from_slice(&self.cfg.task_id);
        c.extend_from_slice(&batch_digest(self.accepted_ids.clone()));
        c.extend_from_slice(&collector.to_le_bytes());
        for x in [check, aggregator] {
            c.extend_from_slice(&(x as u64).to_le_bytes());
        }
        c
    }

    /// Release verification, step 1 (after [`Self::aggregate_share_for`]):
    /// partially decrypts the collector's checks and returns commitments to
    /// those partials. One challenge per (batch, collector), ever: the same
    /// challenge again returns the same commitments, another is refused.
    pub fn release_commit(&mut self, ch: &ReleaseChallenge) -> Result<ReleaseCommit> {
        let collector = ch.collector;
        if ch.task_id != self.cfg.task_id || !self.released_aggregate_shares.contains_key(&collector) || ch.batch_digest != batch_digest(self.accepted_ids.clone()) {
            return Err(Error::Protocol("release challenge for a share this aggregator has not released".into()));
        }
        let digest = ch.digest();
        if let Some((done, _)) = self.verification.releases.get(&collector) {
            if done.digest() != digest {
                return Err(Error::Protocol(format!("collector {collector} already has its checks answered for this batch: refusing a second set")));
            }
        } else {
            let accs = self.release_accumulators(collector as usize)?;
            let refs: Vec<&Ciphertext> = accs.iter().collect();
            let groups = vdec::groups(&refs)?;
            let per = vdec::check_count(self.ctx.ring_dim() as usize);
            if ch.checks.len() != groups.len() * per {
                return Err(Error::Protocol(format!("{} release checks, expected {}", ch.checks.len(), groups.len() * per)));
            }
            let mut partials = Vec::with_capacity(ch.checks.len());
            for (l, b) in ch.checks.iter().enumerate() {
                let meta = accs[groups[l / per][0]].meta()?;
                let c = self.codec.decode(b, Expect::Exactly(meta)).map_err(|e| Error::Protocol(format!("release check {l}: {e}")))?;
                partials.push(self.codec.encode(self.share.partial_decrypt(&c, self.index == 0)?.ciphertext())?);
            }
            self.verification.releases.insert(collector, (ch.clone(), partials));
        }
        let partials = &self.verification.releases[&collector].1;
        let digests = partials.iter().enumerate().map(|(l, p)| vdec::commit(&self.release_context(collector, l, self.index), p)).collect();
        Ok(ReleaseCommit { task_id: self.cfg.task_id, collector, aggregator: self.index, challenge: digest, digests })
    }

    /// Release verification, step 2: rebuilds the collector's checks from
    /// this aggregator's own accumulators and the opening, and reveals its
    /// partials only if each check is exactly what it decrypted (so a
    /// collector cannot have anything else decrypted through a "check").
    pub fn release_reveal(&mut self, op: &ReleaseOpening) -> Result<ReleaseReveal> {
        let (ch, partials) = self
            .verification
            .releases
            .get(&op.collector)
            .ok_or_else(|| Error::Protocol("release opening before this aggregator committed".into()))?;
        if op.task_id != self.cfg.task_id || op.challenge != ch.digest() {
            return Err(Error::Protocol("release opening for another challenge".into()));
        }
        let accs = self.release_accumulators(op.collector as usize)?;
        let refs: Vec<&Ciphertext> = accs.iter().collect();
        let rebuilt = vdec::build(&self.ctx, &self.pk, &refs, &op.opening)?;
        let groups = vdec::groups(&refs)?;
        let per = vdec::check_count(self.ctx.ring_dim() as usize);
        for (l, (b, r)) in ch.checks.iter().zip(&rebuilt).enumerate() {
            let c = self.codec.decode(b, Expect::Exactly(accs[groups[l / per][0]].meta()?))?;
            if !vdec::same(&c, r)? {
                return Err(Error::Protocol(format!("release check {l} is not what the collector opened: refusing to reveal")));
            }
        }
        Ok(ReleaseReveal { task_id: self.cfg.task_id, collector: op.collector, aggregator: self.index, challenge: op.challenge, partials: partials.clone() })
    }

    /// [`Self::release_reveal`] sealed to the collector's key (tasks with
    /// release policies: the leader relays it and must not read it).
    pub fn sealed_release_reveal(&mut self, op: &ReleaseOpening) -> Result<crate::seal::SealedShare> {
        let key = self.cfg.collectors.get(op.collector as usize).map(|p| p.seal_key).ok_or_else(|| Error::Config(format!("no sealing key for collector {}", op.collector)))?;
        let r = self.release_reveal(op)?;
        crate::seal::seal_reveal(&r, &key)
    }

    /// [`Self::aggregate_share_for`], sealed to the collector's key from the
    /// task. Tasks without policies have no key and cannot seal.
    pub fn sealed_share_for(&mut self, collector: usize) -> Result<crate::seal::SealedShare> {
        let key = self.cfg.collectors.get(collector).map(|p| p.seal_key).ok_or_else(|| Error::Config(format!("no sealing key for collector {collector}")))?;
        let share = self.aggregate_share_for(collector)?;
        crate::seal::seal(&share, &key)
    }
}
