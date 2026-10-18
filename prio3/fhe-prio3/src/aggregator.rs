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
//!
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
    AggregateShare, CountCommit, CountOpening, CountReveal, CountShare, GateCheckCommit, GateCommit, GateContribution, GateOpening, GateReveal, GateShare,
    MaskCommit, MaskMessage, ProvenReport, PublicMaterial, ReleaseChallenge, ReleaseCommit, ReleaseOpening, ReleaseReveal, Report, ReportId, ShareContribution,
    ShareFlushRequest, ShareReport, VerifierCommit, VerifierMessage, batch_digest,
};
use crate::packed::{Codec, Expect, WireError, check_stored};
use crate::vdec;
use crate::verify::{Challenge, Circuit};
use crate::wfe;
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
    /// Reports admitted into the current silent-mode batch, not yet
    /// verified: (group, report id). The batch accumulator is rebuilt from
    /// the stored reports on restore.
    pub silent_pending: Vec<(usize, ReportId)>,
    /// Batched silent mode: the accumulators have been folded into group 0
    /// and masked (`finalize_silent`), which happens once, at the close.
    #[serde(default)]
    pub silent_finalized: bool,
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
    /// Split-key tasks: the valid count at every element slot (the input of
    /// the batch-size gate, `gate.rs`).
    #[serde(default)]
    pub valid_spread_sum: Option<Vec<u8>>,
    /// Gated release state (`gate.rs`).
    #[serde(default)]
    pub gate: crate::gate::GateState,
    /// Secret-shared upload state (`shares.rs`).
    #[serde(default)]
    pub share_round: ShareRoundState,
}

/// [`AggregatorState`] as builds before the secret-shared upload wrote it
/// (postcard, field by field: every field of today's but `share_round`).
#[derive(serde::Deserialize)]
struct AggregatorStateV3 {
    sums: Option<Vec<Vec<u8>>>,
    valid_count_sum: Option<Vec<u8>>,
    moment_sums: Option<Vec<Vec<u8>>>,
    silent_pending: Vec<(usize, ReportId)>,
    silent_finalized: bool,
    accepted_ids: Vec<ReportId>,
    seen: Vec<ReportId>,
    client_reports: Vec<([u8; 32], u32)>,
    admitted: u64,
    valid_count: Option<u64>,
    closed: bool,
    released_count_share: Option<CountShare>,
    released_aggregate_shares: BTreeMap<u32, AggregateShare>,
    verification: VerificationState,
    valid_spread_sum: Option<Vec<u8>>,
    gate: crate::gate::GateState,
}

impl AggregatorState {
    /// Decodes a stored state: today's encoding, or one written before the
    /// secret-shared upload existed (read with an empty `share_round`).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if let Ok(st) = crate::messages::decode::<AggregatorState>(bytes) {
            return Ok(st);
        }
        let v: AggregatorStateV3 = crate::messages::decode(bytes)?;
        Ok(Self {
            sums: v.sums,
            valid_count_sum: v.valid_count_sum,
            moment_sums: v.moment_sums,
            silent_pending: v.silent_pending,
            silent_finalized: v.silent_finalized,
            accepted_ids: v.accepted_ids,
            seen: v.seen,
            client_reports: v.client_reports,
            admitted: v.admitted,
            valid_count: v.valid_count,
            closed: v.closed,
            released_count_share: v.released_count_share,
            released_aggregate_shares: v.released_aggregate_shares,
            verification: v.verification,
            valid_spread_sum: v.valid_spread_sum,
            gate: v.gate,
            share_round: ShareRoundState::default(),
        })
    }
}

/// What a key party keeps of the secret-shared upload (`shares.rs`)
/// between requests, persisted with the bookkeeping. Contributions are
/// deterministic, so a party recomputes rather than stores them.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShareRoundState {
    /// Flushes this party has finished: the next flush's sequence number.
    pub next_seq: u64,
    /// Leader: the reports admitted into the open flush, report `k` in group `k`.
    pub pending: Vec<ShareReport>,
    /// The flush this party has contributed to and not finished:
    /// (sequence number, flush digest, digest of its own contribution).
    pub contributed: Option<(u64, [u8; 32], [u8; 32])>,
    /// The last flush finished: (sequence number, flush digest), so a
    /// repeated finish is acknowledged without being applied twice.
    pub finished: Option<(u64, [u8; 32])>,
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

/// The reports admitted into the current, not yet verified, silent-mode
/// batch. Flushed when every group is used, when a group is reused, or at
/// batch close. Each report is restricted to its own group's element slots
/// on admission (`Circuit::mask_to_group`), so the batch is one ciphertext
/// per chunk, the sum of the masked reports, and the validity circuit runs
/// once on it at the flush with each report's own challenge in its slots
/// (`Challenge::derive_batch`). Per report the aggregator does one
/// plaintext multiplication and one ciphertext addition per chunk. The mask
/// is what keeps a client from writing into another report's slots: a raw
/// sum would let it shift an honest report's value, or a colluding
/// report's, before either is checked or counted.
struct SilentBatch {
    /// Per chunk: sum of the admitted reports' ciphertexts (level 0).
    acc: Option<Vec<Ciphertext>>,
    /// (group, report id), in admission order.
    reports: Vec<(usize, ReportId)>,
    used_groups: HashSet<usize>,
}

impl SilentBatch {
    fn new() -> Self {
        Self {
            acc: None,
            reports: Vec::new(),
            used_groups: HashSet::new(),
        }
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
    /// `seen` in insertion order: what a node appends to its store, so it
    /// writes each id once instead of the whole set with every step.
    seen_log: Vec<ReportId>,
    admitted: u64,
    pending: HashMap<ReportId, Pending>,
    accepted_ids: Vec<ReportId>,
    sums: Tracked<Option<Vec<Ciphertext>>>,
    /// Silent mode: encrypted number of valid reports (slot 0).
    valid_count_sum: Tracked<Option<Ciphertext>>,
    /// Post-validation moments: one accumulator per `Layout::moment_terms`
    /// entry, digit products at group 0's element slots `i*D`.
    moment_sums: Tracked<Option<Vec<Ciphertext>>>,
    silent_batch: SilentBatch,
    /// See `AggregatorState::silent_finalized`.
    silent_finalized: bool,
    /// Silent mode: decrypted valid count, once the count round has run.
    valid_count: Option<u64>,
    closed: bool,
    released_count_share: Option<CountShare>,
    released_aggregate_shares: BTreeMap<u32, AggregateShare>,
    verification: VerificationState,
    /// See `AggregatorState::valid_spread_sum`.
    valid_spread_sum: Tracked<Option<Ciphertext>>,
    gate: crate::gate::GateState,
    /// [`crate::config::Upload::Shares`]: this party's upload key (opens its
    /// sealed input shares; [`Self::with_upload_key`]).
    upload_key: Option<crate::shares::UploadKey>,
    share_round: ShareRoundState,
    rng: OsRng,
}

/// An accumulator field: every mutable access counts as a change (bumps
/// `generation`), so [`Aggregator::accumulator_generation`] moves whenever
/// an accumulator may have changed and a caller persisting them can skip
/// the write otherwise. Conservative by construction: the compiler routes
/// every mutation through `DerefMut`.
struct Tracked<T> {
    value: T,
    generation: u64,
}

impl<T> Tracked<T> {
    fn new(value: T) -> Self {
        Self { value, generation: 0 }
    }
}

impl<T> std::ops::Deref for Tracked<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> std::ops::DerefMut for Tracked<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.generation += 1;
        &mut self.value
    }
}

/// The encrypted accumulators of an [`AggregatorState`], which change only
/// when a verification ciphertext is folded in (silent mode: once per
/// `silent_batch_groups` reports) or a report is accepted (verdict mode). A
/// node persists them apart from the rest of the state and only when
/// [`Aggregator::accumulator_generation`] moved: they are tens of MiB,
/// the rest is bookkeeping.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AccumulatorState {
    pub sums: Option<Vec<Vec<u8>>>,
    pub valid_count_sum: Option<Vec<u8>>,
    pub moment_sums: Option<Vec<Vec<u8>>>,
    pub valid_spread_sum: Option<Vec<u8>>,
}

impl AggregatorState {
    /// Moves the accumulators out: the bookkeeping (accumulators `None`) and
    /// the accumulators.
    pub fn split(mut self) -> (AggregatorState, AccumulatorState) {
        let acc = AccumulatorState {
            sums: self.sums.take(),
            valid_count_sum: self.valid_count_sum.take(),
            moment_sums: self.moment_sums.take(),
            valid_spread_sum: self.valid_spread_sum.take(),
        };
        (self, acc)
    }

    /// Puts accumulators stored apart back (the inverse of [`Self::split`]).
    pub fn with_accumulators(mut self, acc: AccumulatorState) -> Self {
        self.sums = acc.sums;
        self.valid_count_sum = acc.valid_count_sum;
        self.moment_sums = acc.moment_sums;
        self.valid_spread_sum = acc.valid_spread_sum;
        self
    }
}

impl Aggregator {
    /// `secret` is this aggregator's encoded [`keys::AggregatorSecret`] (its
    /// key share and the task's verify key) as the ceremony returned it.
    /// `registry` is required when the task's `AuthPolicy` is `Required`.
    pub fn new(cfg: TaskConfig, material: &PublicMaterial, index: usize, secret: &[u8], registry: Option<Arc<dyn ClientRegistry>>) -> Result<Self> {
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
            seen_log: Vec::new(),
            admitted: 0,
            pending: HashMap::new(),
            accepted_ids: Vec::new(),
            sums: Tracked::new(None),
            valid_count_sum: Tracked::new(None),
            moment_sums: Tracked::new(None),
            silent_batch: SilentBatch::new(),
            silent_finalized: false,
            valid_count: None,
            closed: false,
            released_count_share: None,
            released_aggregate_shares: BTreeMap::new(),
            verification: VerificationState::default(),
            valid_spread_sum: Tracked::new(None),
            gate: crate::gate::GateState::default(),
            upload_key: None,
            share_round: ShareRoundState::default(),
            rng: OsRng,
        })
    }

    /// Installs this aggregator's upload key (required when clients upload
    /// shares): its public half must be the task's `upload_keys[index]`.
    pub fn with_upload_key(mut self, key: crate::shares::UploadKey) -> Result<Self> {
        if !self.cfg.shares_upload() {
            return Err(Error::Config("the task's clients upload ciphertexts: no upload key is used".into()));
        }
        if self.cfg.upload_keys[self.index] != key.public_key() {
            return Err(Error::Config(format!("this upload key is not the task's upload key of party {}", self.index)));
        }
        self.upload_key = Some(key);
        Ok(self)
    }

    fn add_to_moments(&mut self, products: Vec<Ciphertext>) -> Result<()> {
        match &mut *self.moment_sums {
            None => *self.moment_sums = Some(products),
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
    pub fn config(&self) -> &TaskConfig {
        &self.cfg
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
        if self.cfg.shares_upload() {
            // the sealed inputs of every key party, exactly
            let m = self.cfg.measurement_type.input_len();
            return (0..self.cfg.num_key_parties()).map(|p| 32 + 12 + crate::shares::sealed_len(p, m)).sum();
        }
        let derived = self.layout.num_chunks * self.codec.fresh_len();
        if self.cfg.max_report_bytes == 0 {
            derived
        } else {
            self.cfg.max_report_bytes.min(derived)
        }
    }

    /// Largest ciphertext payload of any message between aggregators: a
    /// report forwarded to a helper, or the masks of the other `n - 1`
    /// aggregators sent in one request (each a packed fresh ciphertext).
    /// Partial decryptions have one element, so the `n - 1` verifier
    /// messages or the `n` count shares of one request are smaller still.
    pub fn max_message_bytes(&self) -> usize {
        let masks = (self.cfg.num_aggregators - 1) * self.codec.fresh_len();
        self.max_submission_bytes().max(masks)
    }

    /// Largest encoded submission: the report, plus with
    /// [`TaskConfig::client_proofs`] one proof per chunk
    /// ([`wfe::proof_size_bound`]) and the proof list's length prefix.
    pub fn max_submission_bytes(&self) -> usize {
        let proofs = if self.cfg.client_proofs {
            5 + self.layout.num_chunks * wfe::proof_size_bound(self.ctx.ring_dim() as usize)
        } else {
            0
        };
        self.max_report_bytes() + proofs
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
    ///
    /// With [`TaskConfig::client_proofs`] every chunk must come with its
    /// proof of well-formed encryption (`proofs`), verified after the cheap
    /// checks and the quota (the most expensive step before the FHE work);
    /// the returned chunks are then the effective ciphertexts `2C`, whose
    /// randomness the proofs bound.
    fn admit(&mut self, report: &Report, proofs: Option<&[wfe::Proof]>) -> std::result::Result<Vec<Ciphertext>, RejectReason> {
        if self.cfg.shares_upload() {
            return Err(RejectReason::WrongUpload);
        }
        match (self.cfg.client_proofs, proofs.is_some()) {
            (true, false) => return Err(RejectReason::MissingProof),
            (false, true) => return Err(RejectReason::UnexpectedProof),
            _ => {}
        }
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
        if let AuthPolicy::Required {
            max_reports_per_client_per_batch,
        } = self.cfg.auth
        {
            let a = report
                .auth
                .as_ref()
                .ok_or_else(|| RejectReason::Unauthenticated("report carries no signature".into()))?;
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
            return Err(RejectReason::WrongChunkCount {
                expected: self.layout.num_chunks,
                got: report.chunks.len(),
            });
        }
        if self.admitted >= self.cfg.max_batch_size {
            return Err(RejectReason::BatchFull);
        }
        if let Some(proofs) = proofs
            && proofs.len() != report.chunks.len()
        {
            return Err(RejectReason::WrongProofCount {
                expected: report.chunks.len(),
                got: proofs.len(),
            });
        }
        let mut chunks = Vec::with_capacity(report.chunks.len());
        for bytes in &report.chunks {
            chunks.push(self.load_fresh(bytes)?);
        }
        if let Some(proofs) = proofs {
            let digest = self.cfg.digest();
            let n = chunks.len();
            for (i, (ct, proof)) in chunks.iter_mut().zip(proofs).enumerate() {
                let context = ProvenReport::proof_context(&digest, &report.report_id, i, n);
                wfe::verify(&self.ctx, &self.pk, self.codec.reference(), ct, proof, &context).map_err(|_| RejectReason::InvalidProof { chunk: i })?;
                *ct = wfe::effective(&self.ctx, ct).map_err(|e| RejectReason::MalformedCiphertext(format!("effective ciphertext of chunk {i}: {e}")))?;
            }
        }
        self.mark_seen(report.report_id);
        self.admitted += 1;
        Ok(chunks)
    }

    fn mark_seen(&mut self, id: ReportId) {
        if self.seen.insert(id) {
            self.seen_log.push(id);
        }
    }

    /// The report ids seen (in insertion order) and accepted, which grow by
    /// at most one each per report. A node stores them append-only (only the
    /// ids past what it already stored) and the rest of the state with
    /// [`Self::snapshot_bookkeeping_without_ids`]; restore takes them back
    /// in `AggregatorState::seen` and `accepted_ids`.
    pub fn id_logs(&self) -> (&[ReportId], &[ReportId]) {
        (&self.seen_log, &self.accepted_ids)
    }

    fn add_to_sums(&mut self, chunks: Vec<Ciphertext>) -> Result<()> {
        match &mut *self.sums {
            None => *self.sums = Some(chunks),
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
    /// Refused with [`RejectReason::MissingProof`] when the task requires
    /// client proofs ([`Self::prepare_init_proven`]).
    pub fn prepare_init(&mut self, report: &Report) -> Result<MaskCommit> {
        self.prepare_init_with(report, None)
    }

    /// [`Self::prepare_init`] for a task with [`TaskConfig::client_proofs`]:
    /// every chunk's proof is verified, and the check runs on the proven
    /// effective ciphertexts `2C`.
    pub fn prepare_init_proven(&mut self, report: &ProvenReport) -> Result<MaskCommit> {
        self.prepare_init_with(&report.report, Some(&report.proofs))
    }

    /// [`Self::prepare_init`] with the report's proofs, if it carries any
    /// (`None` is a plain [`Report`]; a node that received the report and
    /// its proofs apart, as a leader forwarding them, calls this).
    pub fn prepare_init_with(&mut self, report: &Report, proofs: Option<&[wfe::Proof]>) -> Result<MaskCommit> {
        if self.cfg.mode != VerificationMode::Verdict {
            return Err(Error::Protocol("prepare_init is only valid in verdict mode".into()));
        }
        let chunks = self.admit(report, proofs).map_err(Error::Reject)?;
        let challenge = Challenge::derive(&self.cfg, &self.field, &self.layout, &self.verify_key, &report.report_id, 0);
        let s = self.circuit.check_sum(&chunks, &challenge)?;
        let mask = self.circuit.make_mask(&self.pk, &self.field, &mut self.rng)?;
        let mask_bytes = self.codec.encode(&mask)?;
        let digest = vdec::commit(&Self::mask_context(&self.cfg.task_id, &report.report_id, self.index), &mask_bytes);
        let mut masks = BTreeMap::new();
        masks.insert(self.index, mask);
        self.pending.insert(
            report.report_id,
            Pending {
                chunks,
                s,
                masks,
                my_mask: mask_bytes,
                mask_commits: BTreeMap::new(),
                partials: BTreeMap::new(),
                u: None,
                mine: None,
                commits: BTreeMap::new(),
            },
        );
        Ok(MaskCommit {
            report_id: report.report_id,
            aggregator: self.index,
            digest,
        })
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
        let pending = self
            .pending
            .get_mut(report_id)
            .ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
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
            return Err(Error::Protocol(format!(
                "expected {} mask commitments, have {}",
                n - 1,
                pending.mask_commits.len()
            )));
        }
        Ok(MaskMessage {
            report_id: *report_id,
            aggregator: self.index,
            mask: pending.my_mask.clone(),
        })
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
            let pending = self
                .pending
                .get(report_id)
                .ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
            if pending.mask_commits.len() != n - 1 {
                return Err(Error::Protocol("masks before every mask commitment: run prepare_mask_reveal first".into()));
            }
            for m in masks {
                if let Some(d) = pending.mask_commits.get(&m.aggregator)
                    && vdec::commit(&Self::mask_context(&self.cfg.task_id, report_id, m.aggregator), &m.mask) != *d
                {
                    return Err(Error::Protocol(format!("aggregator {}'s mask is not the one it committed to", m.aggregator)));
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
            let ct = self
                .load_fresh(&m.mask)
                .map_err(|r| Error::Protocol(format!("mask ciphertext rejected: {r}")))?;
            loaded.push((m.aggregator, ct));
        }
        let pending = self
            .pending
            .get_mut(report_id)
            .ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
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
        Ok(VerifierCommit {
            report_id: *report_id,
            aggregator: my_index,
            digest,
        })
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
        let pending = self
            .pending
            .get_mut(report_id)
            .ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
        let mine = pending
            .mine
            .clone()
            .ok_or_else(|| Error::Protocol("prepare_masks has not run for this report".into()))?;
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
        Ok(VerifierMessage {
            report_id: *report_id,
            aggregator: self.index,
            partial: mine,
        })
    }

    pub fn prepare_finish(&mut self, report_id: &ReportId, verifiers: &[VerifierMessage]) -> Result<Verdict> {
        let n = self.cfg.num_aggregators;
        let expected = {
            let pending = self
                .pending
                .get(report_id)
                .ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
            let u = pending
                .u
                .as_ref()
                .ok_or_else(|| Error::Protocol("prepare_masks has not run for this report".into()))?;
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
            let pending = self
                .pending
                .get(report_id)
                .ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
            let committed = pending
                .commits
                .get(&v.aggregator)
                .ok_or_else(|| Error::Protocol(format!("no commitment from aggregator {}: run prepare_reveal first", v.aggregator)))?;
            if vdec::commit(&Self::verdict_context(&self.cfg.task_id, report_id, v.aggregator), &v.partial) != *committed {
                return Err(Error::Protocol(format!(
                    "aggregator {}'s partial decryption is not the one it committed to",
                    v.aggregator
                )));
            }
            loaded.push((v.aggregator, self.load_partial(&v.partial, expected, v.aggregator == 0)?));
        }
        let mut pending = self
            .pending
            .remove(report_id)
            .ok_or_else(|| Error::Protocol("unknown or finished report".into()))?;
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
        let chunks = self.admit(report, None).map_err(Error::Reject)?;
        let group = report.group as usize;
        if self.silent_batch.used_groups.contains(&group) {
            self.flush_silent_batch()?;
        }
        let chunks = self.mask_report(group, chunks)?;
        self.accumulate_silent(group, report.report_id, chunks)?;
        self.accepted_ids.push(report.report_id);
        if self.silent_batch.used_groups.len() == self.layout.groups {
            self.flush_silent_batch()?;
        }
        Ok(())
    }

    // ----- secret-shared upload (`shares.rs`) -------------------------

    fn upload_key(&self) -> Result<&crate::shares::UploadKey> {
        self.upload_key
            .as_ref()
            .ok_or_else(|| Error::Config("the task's clients upload shares: install this aggregator's upload key (with_upload_key)".into()))
    }

    fn share_env(&self) -> Result<crate::shares::ShareEnv<'_>> {
        Ok(crate::shares::ShareEnv {
            cfg: &self.cfg,
            field: &self.field,
            layout: &self.layout,
            ctx: &self.ctx,
            pk: &self.pk,
            codec: &self.codec,
            key: self.upload_key()?,
            party: self.index,
        })
    }

    /// Every check of a share report except the quota charge, in the order
    /// of [`Self::admit`]; `quota_used` is the count of the report's signer
    /// to compare against the quota, `in_flush` the ids already listed in
    /// the same flush.
    fn share_report_problem(&self, r: &ShareReport, quota_used: u32, in_flush: &HashSet<ReportId>) -> Option<RejectReason> {
        if !self.cfg.shares_upload() {
            return Some(RejectReason::WrongUpload);
        }
        if self.closed {
            return Some(RejectReason::BatchClosed);
        }
        let limit = self.max_report_bytes();
        let got = r.sealed_bytes();
        if got > limit {
            return Some(RejectReason::TooLarge { limit, got });
        }
        if r.task_id != self.cfg.task_id {
            return Some(RejectReason::WrongTask);
        }
        if let AuthPolicy::Required {
            max_reports_per_client_per_batch,
        } = self.cfg.auth
        {
            let Some(a) = r.auth.as_ref() else {
                return Some(RejectReason::Unauthenticated("report carries no signature".into()));
            };
            if let Err(e) = auth::verify(a, &r.task_id, &r.report_id) {
                return Some(RejectReason::Unauthenticated(e.to_string()));
            }
            let registry = self.registry.as_ref().expect("checked in new");
            if !registry.is_registered(&a.client_key) {
                return Some(RejectReason::UnknownClient);
            }
            if quota_used >= max_reports_per_client_per_batch {
                return Some(RejectReason::QuotaExceeded);
            }
        }
        if let Err(reason) = crate::shares::check_structure(&self.cfg, r) {
            return Some(reason);
        }
        if self.seen.contains(&r.report_id) || in_flush.contains(&r.report_id) {
            return Some(RejectReason::Replay);
        }
        if self.admitted + in_flush.len() as u64 >= self.cfg.max_batch_size {
            return Some(RejectReason::BatchFull);
        }
        None
    }

    fn quota_used(&self, r: &ShareReport, extra: &HashMap<[u8; 32], u32>) -> u32 {
        match &r.auth {
            Some(a) => self.client_reports.get(&a.client_key).copied().unwrap_or(0) + extra.get(&a.client_key).copied().unwrap_or(0),
            None => 0,
        }
    }

    /// Leader, [`crate::config::Upload::Shares`]: admits a client's share
    /// report into the open flush (report `k` of a flush occupies group
    /// `k`). Only deterministic checks that need no secret; the report's
    /// own input is opened when the flush is contributed. The client's
    /// quota is charged for the attempt whatever happens next. When
    /// [`Self::share_flush_ready`] turns true the caller runs the flush
    /// before admitting more.
    pub fn admit_share_report(&mut self, r: &ShareReport) -> Result<()> {
        if !self.cfg.shares_upload() {
            return Err(Error::Reject(RejectReason::WrongUpload));
        }
        if self.index != 0 {
            return Err(Error::Protocol("only the leader admits share reports".into()));
        }
        if self.share_round.contributed.is_some() || self.share_round.pending.len() >= self.layout.groups {
            return Err(Error::Protocol("the open share flush is full or being contributed: finish it first".into()));
        }
        let used = self.quota_used(r, &HashMap::new());
        let in_flush: HashSet<ReportId> = self.share_round.pending.iter().map(|p| p.report_id).collect();
        let problem = self.share_report_problem(r, used, &in_flush);
        // the attempt is charged once the signature and the registry have
        // passed, as in `admit`
        if let (AuthPolicy::Required { .. }, Some(a)) = (&self.cfg.auth, &r.auth) {
            let charged = !matches!(
                problem,
                Some(
                    RejectReason::WrongUpload
                        | RejectReason::BatchClosed
                        | RejectReason::TooLarge { .. }
                        | RejectReason::WrongTask
                        | RejectReason::Unauthenticated(_)
                        | RejectReason::UnknownClient
                        | RejectReason::QuotaExceeded
                )
            );
            if charged {
                *self.client_reports.entry(a.client_key).or_insert(0) += 1;
            }
        }
        if let Some(reason) = problem {
            return Err(Error::Reject(reason));
        }
        self.mark_seen(r.report_id);
        self.admitted += 1;
        self.share_round.pending.push(r.clone());
        Ok(())
    }

    /// Leader: reports admitted into the open flush.
    pub fn share_pending(&self) -> usize {
        self.share_round.pending.len()
    }

    /// Leader: whether the open flush has a report in every group.
    pub fn share_flush_ready(&self) -> bool {
        self.share_round.pending.len() >= self.layout.groups
    }

    /// The secret-shared upload state (persisted with the bookkeeping).
    pub fn share_round(&self) -> &ShareRoundState {
        &self.share_round
    }

    /// Leader: the request for the open flush, if it holds any report.
    pub fn share_flush_request(&self) -> Option<ShareFlushRequest> {
        (!self.share_round.pending.is_empty()).then(|| ShareFlushRequest {
            task_id: self.cfg.task_id,
            seq: self.share_round.next_seq,
            reports: self.share_round.pending.clone(),
        })
    }

    /// Every key party: this party's contribution to flush `req`. The
    /// leader's request must be its own open flush; another aggregator
    /// admits the listed reports here (every check of the leader's
    /// admission, all or nothing). Contributing again to the same flush
    /// returns the same bytes; a party contributes to each sequence number
    /// once.
    pub fn share_contribute(&mut self, req: &ShareFlushRequest) -> Result<ShareContribution> {
        if !self.cfg.shares_upload() {
            return Err(Error::Protocol("the task's clients upload ciphertexts".into()));
        }
        crate::shares::check_request(&self.cfg, &self.layout, req)?;
        let digest = req.digest();
        if self.share_round.contributed.is_none() && self.share_round.finished == Some((req.seq, digest)) {
            // the leader lost the round after this party finished it (a
            // restart between the helpers' finish and its own): the same
            // contribution again, nothing admitted twice
            return crate::shares::contribution(&self.share_env()?, req);
        }
        if let Some((seq, d, own)) = self.share_round.contributed {
            if seq != req.seq || d != digest {
                return Err(Error::Protocol(format!(
                    "already contributed to share flush {seq}, not finished; refusing another flush {}",
                    req.seq
                )));
            }
            let c = crate::shares::contribution(&self.share_env()?, req)?;
            if c.digest() != own {
                return Err(Error::Protocol("this party's contribution to the flush is not reproducible".into()));
            }
            return Ok(c);
        }
        if req.seq != self.share_round.next_seq {
            return Err(Error::Protocol(format!(
                "share flush {} requested, the next is {}",
                req.seq, self.share_round.next_seq
            )));
        }
        if self.index == 0 {
            let open = self.share_flush_request().ok_or_else(|| Error::Protocol("no open share flush".into()))?;
            if open.digest() != digest {
                return Err(Error::Protocol("the share flush request is not the leader's open flush".into()));
            }
        } else {
            let mut in_flush = HashSet::with_capacity(req.reports.len());
            let mut extra: HashMap<[u8; 32], u32> = HashMap::new();
            for (k, r) in req.reports.iter().enumerate() {
                if let Some(reason) = self.share_report_problem(r, self.quota_used(r, &extra), &in_flush) {
                    return Err(Error::Protocol(format!("share flush {}: report {k} is not admissible: {reason}", req.seq)));
                }
                in_flush.insert(r.report_id);
                if let Some(a) = &r.auth {
                    *extra.entry(a.client_key).or_insert(0) += 1;
                }
            }
        }
        let c = crate::shares::contribution(&self.share_env()?, req)?;
        if self.index != 0 {
            for r in &req.reports {
                self.mark_seen(r.report_id);
                if let (AuthPolicy::Required { .. }, Some(a)) = (&self.cfg.auth, &r.auth) {
                    *self.client_reports.entry(a.client_key).or_insert(0) += 1;
                }
            }
            self.admitted += req.reports.len() as u64;
        }
        self.share_round.contributed = Some((req.seq, digest, c.digest()));
        Ok(c)
    }

    /// Aggregators: with every key party's contribution to the flush this
    /// party contributed to, checks them (this party's own against its
    /// recorded digest, every other party's proofs), adds them, restricts
    /// the sum to the element slots of the occupied groups and runs the
    /// validity circuit on it. A repeated finish of the last finished flush
    /// is acknowledged without effect.
    pub fn share_finish(&mut self, req: &ShareFlushRequest, contributions: &[ShareContribution]) -> Result<()> {
        if !self.cfg.shares_upload() {
            return Err(Error::Protocol("the task's clients upload ciphertexts".into()));
        }
        let digest = req.digest();
        if self.share_round.finished == Some((req.seq, digest)) && self.share_round.contributed.is_none() {
            return Ok(());
        }
        let Some((seq, d, own)) = self.share_round.contributed else {
            return Err(Error::Protocol("share finish before contributing to the flush".into()));
        };
        if seq != req.seq || d != digest {
            return Err(Error::Protocol(format!("share finish for flush {}, this party contributed to {seq}", req.seq)));
        }
        let acc = crate::shares::combine(&self.share_env()?, req, contributions, &own)?;
        let reports = crate::shares::flush_reports(req);
        let groups: Vec<usize> = reports.iter().map(|(g, _)| *g).collect();
        let mut masked = Vec::with_capacity(acc.len());
        for (c, ct) in acc.iter().enumerate() {
            masked.push(self.circuit.mask_to_groups(ct, c, &groups)?);
        }
        self.verify_and_fold(masked, &reports)?;
        self.accepted_ids.extend(reports.iter().map(|(_, id)| *id));
        if self.index == 0 {
            self.share_round.pending.clear();
        }
        self.share_round.contributed = None;
        self.share_round.finished = Some((req.seq, digest));
        self.share_round.next_seq += 1;
        Ok(())
    }

    /// Refuses to close while a share flush is open (its reports would be
    /// silently dropped) or contributed and not finished.
    fn require_no_open_share_flush(&self) -> Result<()> {
        if self.cfg.shares_upload() && (!self.share_round.pending.is_empty() || self.share_round.contributed.is_some()) {
            return Err(Error::Protocol("a share flush is open: run and finish it before closing the batch".into()));
        }
        Ok(())
    }

    /// Batched layout: restricts an admitted report's fresh chunks to its
    /// own group's element slots. Everything the client wrote elsewhere,
    /// including into other groups' slots, is zeroed before the report
    /// meets any other report. A single-group layout holds one report per
    /// batch and is masked as a whole at the flush instead.
    fn mask_report(&self, group: usize, chunks: Vec<Ciphertext>) -> Result<Vec<Ciphertext>> {
        if self.layout.groups == 1 {
            return Ok(chunks);
        }
        chunks.iter().enumerate().map(|(c, ct)| self.circuit.mask_to_group(ct, c, group)).collect()
    }

    /// Adds an admitted report's chunks, already restricted to its group by
    /// [`Self::mask_report`], into the current batch.
    fn accumulate_silent(&mut self, group: usize, id: ReportId, chunks: Vec<Ciphertext>) -> Result<()> {
        match &mut self.silent_batch.acc {
            None => self.silent_batch.acc = Some(chunks),
            Some(acc) => {
                for (a, c) in acc.iter_mut().zip(&chunks) {
                    *a = self.ctx.add(a, c)?;
                }
            }
        }
        self.silent_batch.reports.push((group, id));
        self.silent_batch.used_groups.insert(group);
        Ok(())
    }

    /// TEST HOOK: admits already-decoded chunks into the current silent
    /// batch without the wire checks and without the per-report group mask,
    /// for tests that build accumulators the client path cannot (for
    /// example the noise of a full batch). The caller is responsible for
    /// what the mask would guarantee.
    pub fn accumulate_silent_for_tests(&mut self, group: usize, id: ReportId, chunks: Vec<Ciphertext>) -> Result<()> {
        if self.silent_batch.used_groups.contains(&group) {
            self.flush_silent_batch()?;
        }
        self.accumulate_silent(group, id, chunks)?;
        self.accepted_ids.push(id);
        self.mark_seen(id);
        self.admitted += 1;
        if self.silent_batch.used_groups.len() == self.layout.groups {
            self.flush_silent_batch()?;
        }
        Ok(())
    }

    /// Runs the validity circuit once over the batch accumulator, with
    /// every report's challenge in its own group's slots, and adds the
    /// validity-gated chunks, count and moment products of all groups to the
    /// running sums. Group `r`'s contribution stays at group `r`'s slots
    /// until the close, where `finalize_silent` folds the groups into group
    /// 0 and zeroes the rest.
    fn flush_silent_batch(&mut self) -> Result<()> {
        let batch = std::mem::replace(&mut self.silent_batch, SilentBatch::new());
        let Some(acc) = batch.acc else { return Ok(()) };
        self.verify_and_fold(acc, &batch.reports)
    }

    /// The validity circuit over one verification ciphertext per chunk,
    /// with every report's challenge in its own group's slots; adds the
    /// validity-gated chunks, count and moment products to the running sums.
    fn verify_and_fold(&mut self, acc: Vec<Ciphertext>, reports: &[(usize, ReportId)]) -> Result<()> {
        let challenge = Challenge::derive_batch(&self.cfg, &self.field, &self.layout, &self.verify_key, reports);
        let terms = self.circuit.report_terms(&acc, &challenge)?;
        let s = self.circuit.class_sums(&terms)?;
        let g = self.circuit.silent_validity(&s)?;
        let groups: Vec<usize> = reports.iter().map(|(g, _)| *g).collect();
        // Batched: every report was masked to its group on admission (with
        // shares: the combined batch input was masked to its reports'
        // groups), so the accumulator is already zero outside the groups'
        // element slots. Single group: the one report is masked here, after
        // its validity terms, which keeps the circuit's input at the first
        // level (`TaskConfig::mult_depth` counts no mask for one group).
        let masked = if self.layout.groups == 1 {
            let mut m = Vec::with_capacity(acc.len());
            for (c, ct) in acc.iter().enumerate() {
                m.push(self.circuit.mask_all_groups(ct, c)?);
            }
            m
        } else {
            acc
        };
        let mut y = Vec::with_capacity(masked.len());
        for ct in &masked {
            y.push(self.ctx.mult(ct, &g)?);
        }
        if self.layout.moments.is_some() {
            // Products are non-zero only at each group's element slots
            // `i*D` (class 0), where G holds that report's validity bit.
            let mut gated = Vec::new();
            for p in self.circuit.moment_products_of_groups(&masked, &groups)? {
                gated.push(self.ctx.mult(&p, &g)?);
            }
            self.add_to_moments(gated)?;
        }
        self.add_to_sums(y)?;
        if self.cfg.collector_holds_key() {
            let spread = self.circuit.spread_of_groups(&g, &groups)?;
            *self.valid_spread_sum = Some(match self.valid_spread_sum.take() {
                None => spread,
                Some(acc) => self.ctx.add(&acc, &spread)?,
            });
        }
        let cnt = self.circuit.count_of_groups(&g, &groups)?;
        *self.valid_count_sum = Some(match self.valid_count_sum.take() {
            None => cnt,
            Some(acc) => self.ctx.add(&acc, &cnt)?,
        });
        Ok(())
    }

    /// Batched silent mode, once per batch at the close: folds every
    /// accumulator's groups into group 0 and zeroes the other slots, which
    /// would otherwise reveal partial sums over subsets of the reports when
    /// decrypted. Idempotent; a no-op for a single-group layout.
    fn finalize_silent(&mut self) -> Result<()> {
        if self.silent_finalized || self.layout.groups == 1 {
            self.silent_finalized = true;
            return Ok(());
        }
        if let Some(sums) = &mut *self.sums {
            for (c, ct) in sums.iter_mut().enumerate() {
                *ct = self.circuit.finalize_chunk(ct, c)?;
            }
        }
        if let Some(ct) = &*self.valid_count_sum {
            let f = self.circuit.finalize_count(ct)?;
            *self.valid_count_sum = Some(f);
        }
        if let Some(ct) = &*self.valid_spread_sum {
            let f = self.circuit.finalize_spread(ct)?;
            *self.valid_spread_sum = Some(f);
        }
        if let Some(m) = &mut *self.moment_sums {
            for (ct, t) in m.iter_mut().zip(self.layout.moment_terms()) {
                *ct = self.circuit.finalize_moment(ct, t)?;
            }
        }
        self.silent_finalized = true;
        Ok(())
    }

    /// Number of reports admitted into the current, not yet flushed,
    /// verification ciphertext.
    pub fn pending_silent_reports(&self) -> usize {
        self.silent_batch.reports.len() + self.share_round.pending.len()
    }

    /// Ids of the reports in the current, not yet flushed, verification
    /// ciphertext: the only client reports a restart needs
    /// ([`AggregatorState::silent_pending`]). Once flushed, a report lives
    /// on only inside the accumulators and its bytes can be discarded.
    pub fn silent_pending_ids(&self) -> impl Iterator<Item = &ReportId> {
        self.silent_batch.reports.iter().map(|(_, id)| id)
    }

    /// Serializes the resumable state (see [`AggregatorState`]).
    /// The accumulators are this aggregator's own objects, written to and
    /// read back from its own database, so they keep OpenFHE's format;
    /// nothing in the snapshot comes from another party except the stored
    /// client reports, which `restore` decodes through the packed codec.
    pub fn snapshot(&self) -> Result<AggregatorState> {
        Ok(self.snapshot_bookkeeping()?.with_accumulators(self.snapshot_accumulators()?))
    }

    /// Changes whenever an accumulator may have changed (every mutable
    /// access counts). A node that persisted the accumulators at generation
    /// `g` need not write them again while this returns `g`.
    pub fn accumulator_generation(&self) -> u64 {
        self.sums.generation + self.valid_count_sum.generation + self.moment_sums.generation + self.valid_spread_sum.generation
    }

    /// The accumulators of [`Self::snapshot`] alone.
    pub fn snapshot_accumulators(&self) -> Result<AccumulatorState> {
        let ser = |v: &Vec<Ciphertext>| -> Result<Vec<Vec<u8>>> { v.iter().map(|c| c.serialize().map_err(Into::into)).collect() };
        Ok(AccumulatorState {
            sums: match &*self.sums {
                Some(v) => Some(ser(v)?),
                None => None,
            },
            valid_count_sum: match &*self.valid_count_sum {
                Some(c) => Some(c.serialize()?),
                None => None,
            },
            moment_sums: match &*self.moment_sums {
                Some(v) => Some(ser(v)?),
                None => None,
            },
            valid_spread_sum: match &*self.valid_spread_sum {
                Some(c) => Some(c.serialize()?),
                None => None,
            },
        })
    }

    /// [`Self::snapshot`] without the accumulators (`None`): what changes
    /// with every report. Restore it with the accumulators stored apart
    /// ([`AggregatorState::with_accumulators`]).
    pub fn snapshot_bookkeeping(&self) -> Result<AggregatorState> {
        let mut st = self.snapshot_bookkeeping_without_ids()?;
        st.seen = self.seen_log.clone();
        st.accepted_ids = self.accepted_ids.clone();
        Ok(st)
    }

    /// [`Self::snapshot_bookkeeping`] without the report ids (`seen` and
    /// `accepted_ids` empty), which a node stores append-only from
    /// [`Self::id_logs`]: tens of bytes per report instead of the whole
    /// lists (megabytes in a large batch) with every step.
    pub fn snapshot_bookkeeping_without_ids(&self) -> Result<AggregatorState> {
        Ok(AggregatorState {
            sums: None,
            valid_count_sum: None,
            moment_sums: None,
            silent_pending: self.silent_batch.reports.clone(),
            silent_finalized: self.silent_finalized,
            accepted_ids: Vec::new(),
            seen: Vec::new(),
            client_reports: self.client_reports.iter().map(|(k, n)| (*k, *n)).collect(),
            admitted: self.admitted,
            valid_count: self.valid_count,
            closed: self.closed,
            released_count_share: self.released_count_share.clone(),
            released_aggregate_shares: self.released_aggregate_shares.clone(),
            verification: self.verification.clone(),
            valid_spread_sum: None,
            gate: self.gate.clone(),
            share_round: self.share_round.clone(),
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
                check_stored(
                    f,
                    bytes,
                    Expect::Exactly(self.codec.fresh_meta()),
                    &format!("pending report {}", hex::encode(id)),
                )?;
            }
        }
        let de = |v: &Vec<Vec<u8>>| -> Result<Vec<Ciphertext>> { v.iter().map(|b| self.ctx.deserialize_ciphertext(b).map_err(Into::into)).collect() };
        *self.sums = match &st.sums {
            Some(v) => Some(de(v)?),
            None => None,
        };
        *self.valid_count_sum = match &st.valid_count_sum {
            Some(b) => Some(self.ctx.deserialize_ciphertext(b)?),
            None => None,
        };
        *self.moment_sums = match &st.moment_sums {
            // the accumulator count follows the task's digit width; a state
            // written under another decomposition cannot be continued
            Some(v) if v.len() != self.layout.moment_terms().len() => {
                return Err(Error::Protocol(format!(
                    "restore: {} moment accumulators stored, this task has {}",
                    v.len(),
                    self.layout.moment_terms().len()
                )));
            }
            Some(v) => Some(de(v)?),
            None => None,
        };
        self.silent_batch = SilentBatch::new();
        for (g, id) in &st.silent_pending {
            let report = pending_reports
                .iter()
                .find(|r| r.report_id == *id)
                .ok_or_else(|| Error::Protocol(format!("restore: pending report {} not supplied", hex::encode(id))))?;
            if report.group as usize != *g {
                return Err(Error::Protocol("restore: pending report group mismatch".into()));
            }
            if self.silent_batch.used_groups.contains(g) {
                return Err(Error::Protocol("restore: two pending reports in one group".into()));
            }
            let mut chunks = Vec::with_capacity(report.chunks.len());
            for bytes in &report.chunks {
                // stored client bytes: decoded like any client chunk
                chunks.push(self.load_fresh(bytes).map_err(Error::Reject)?);
            }
            let chunks = self.mask_report(*g, chunks)?;
            self.accumulate_silent(*g, *id, chunks)?;
        }
        self.silent_finalized = st.silent_finalized;
        self.accepted_ids = st.accepted_ids;
        self.seen = st.seen.iter().copied().collect();
        self.seen_log = st.seen;
        self.client_reports = st.client_reports.into_iter().collect();
        self.admitted = st.admitted;
        self.valid_count = st.valid_count;
        self.closed = st.closed;
        self.released_count_share = st.released_count_share;
        self.released_aggregate_shares = st.released_aggregate_shares;
        self.verification = st.verification;
        *self.valid_spread_sum = match &st.valid_spread_sum {
            Some(b) => Some(self.ctx.deserialize_ciphertext(b)?),
            None => None,
        };
        self.gate = st.gate;
        if !self.cfg.shares_upload() && st.share_round != ShareRoundState::default() {
            return Err(Error::Protocol(
                "restore: secret-shared upload state in a task whose clients upload ciphertexts".into(),
            ));
        }
        for r in &st.share_round.pending {
            if crate::shares::check_structure(&self.cfg, r).is_err() || !self.seen.contains(&r.report_id) {
                return Err(Error::Protocol("restore: a pending share report is malformed or was never admitted".into()));
            }
        }
        self.share_round = st.share_round;
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
        if self.cfg.collector_holds_key() {
            return Err(Error::Protocol(
                "split-key task: the batch size is gated under encryption (gate_commit), there is no count round".into(),
            ));
        }
        if let Some(s) = &self.released_count_share {
            return Ok(s.clone());
        }
        self.require_no_open_share_flush()?;
        let count = self.accepted_ids.len();
        if count < self.cfg.min_batch_size {
            return Err(Error::Protocol(format!(
                "batch has {count} admitted reports, minimum is {}",
                self.cfg.min_batch_size
            )));
        }
        self.flush_silent_batch()?;
        self.finalize_silent()?;
        self.closed = true;
        let ct = self.valid_count_sum.as_ref().expect("count >= 1");
        let opening = vdec::draw(&self.ctx, &[ct], &mut self.rng)?;
        let checks = vdec::build(&self.ctx, &self.pk, &[ct], &opening)?
            .iter()
            .map(|c| self.codec.encode(c))
            .collect::<Result<Vec<_>>>()?;
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
        self.valid_count_sum
            .as_ref()
            .ok_or_else(|| Error::Protocol("count round before count_share".into()))
    }

    /// The count checks aggregator `j` published, rebuilt through the codec.
    fn count_checks_of(&self, j: usize) -> Result<Vec<Ciphertext>> {
        let meta = self.count_ct()?.meta()?;
        let share = self
            .verification
            .count_shares
            .iter()
            .find(|s| s.aggregator == j)
            .ok_or_else(|| Error::Protocol(format!("no count share from aggregator {j}")))?;
        share
            .checks
            .iter()
            .map(|b| {
                self.codec
                    .decode(b, Expect::Exactly(meta))
                    .map_err(|e| Error::Protocol(format!("aggregator {j}'s count check: {e}")))
            })
            .collect()
    }

    /// Silent mode, count round 2: takes every aggregator's count share,
    /// partially decrypts every other aggregator's checks and returns
    /// commitments to those partials (revealed in round 4, after the checks
    /// are opened and verified).
    pub fn count_commit(&mut self, shares: &[CountShare]) -> Result<CountCommit> {
        let n = self.cfg.num_aggregators;
        let digest = batch_digest(self.accepted_ids.clone());
        let my_checks = self
            .released_count_share
            .as_ref()
            .ok_or_else(|| Error::Protocol("count_commit before count_share".into()))?
            .checks
            .len();
        if !self.verification.count_partials.is_empty() {
            let same = shares.len() == self.verification.count_shares.len()
                && shares.iter().all(|s| {
                    self.verification
                        .count_shares
                        .iter()
                        .any(|t| t.aggregator == s.aggregator && t.partial == s.partial && t.checks == s.checks)
                });
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
                    return Err(Error::Protocol(format!(
                        "aggregator {} published {} count checks, expected {my_checks}",
                        s.aggregator,
                        s.checks.len()
                    )));
                }
            }
            if shares.iter().find(|s| s.aggregator == self.index).map(|s| s.partial.as_slice())
                != self.released_count_share.as_ref().map(|s| s.partial.as_slice())
            {
                return Err(Error::Protocol("the count shares do not carry this aggregator's own share".into()));
            }
            // every share must parse to the shapes this aggregator computed,
            // before anything is stored or committed to
            let ct_meta = self.count_ct()?.meta()?;
            let partial_meta = Self::partial_meta(self.count_ct()?)?;
            for s in shares {
                self.load_partial(&s.partial, partial_meta, s.aggregator == 0)
                    .map_err(|e| Error::Protocol(format!("aggregator {}'s count share: {e}", s.aggregator)))?;
                for b in &s.checks {
                    self.codec
                        .decode(b, Expect::Exactly(ct_meta))
                        .map_err(|e| Error::Protocol(format!("aggregator {}'s count check: {e}", s.aggregator)))?;
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
            .map(|(j, ps)| {
                (
                    *j,
                    ps.iter()
                        .enumerate()
                        .map(|(l, p)| vdec::commit(&self.count_context(*j, l, self.index), p))
                        .collect(),
                )
            })
            .collect();
        Ok(CountCommit {
            task_id: self.cfg.task_id,
            aggregator: self.index,
            batch_digest: digest,
            digests,
        })
    }

    /// Silent mode, count round 3: once every other aggregator has committed
    /// to its partials of this aggregator's checks, reveals the checks.
    pub fn count_open(&mut self, commits: &[CountCommit]) -> Result<CountOpening> {
        let n = self.cfg.num_aggregators;
        let digest = batch_digest(self.accepted_ids.clone());
        let opening = self
            .verification
            .count_opening
            .clone()
            .ok_or_else(|| Error::Protocol("count_open before count_share".into()))?;
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
            let mine = c
                .digests
                .iter()
                .find(|(v, _)| *v == self.index)
                .ok_or_else(|| Error::Protocol(format!("aggregator {} did not commit to this aggregator's checks", c.aggregator)))?;
            if mine.1.len() != opening.checks.len() {
                return Err(Error::Protocol(format!(
                    "aggregator {} committed to {} checks, expected {}",
                    c.aggregator,
                    mine.1.len(),
                    opening.checks.len()
                )));
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
        Ok(CountOpening {
            task_id: self.cfg.task_id,
            aggregator: self.index,
            batch_digest: digest,
            opening,
        })
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
            let o = openings
                .iter()
                .find(|o| o.aggregator == j)
                .ok_or_else(|| Error::Protocol(format!("no count opening from aggregator {j}")))?;
            if o.task_id != self.cfg.task_id || o.batch_digest != digest {
                return Err(Error::Protocol("count opening for a different batch".into()));
            }
            let rebuilt = vdec::build(&self.ctx, &self.pk, &[&ct], &o.opening)?;
            let published = self.count_checks_of(j)?;
            if rebuilt.len() != published.len() || rebuilt.iter().zip(&published).any(|(a, b)| !vdec::same(a, b).unwrap_or(false)) {
                return Err(Error::Protocol(format!(
                    "aggregator {j}'s count checks are not what it opened: refusing to decrypt them"
                )));
            }
        }
        Ok(CountReveal {
            task_id: self.cfg.task_id,
            aggregator: self.index,
            batch_digest: digest,
            partials: self.verification.count_partials.clone(),
        })
    }

    /// Silent mode, count round 5 (local): verifies this aggregator's checks
    /// with every other aggregator's revealed partials (each against its
    /// commitment), fuses the count and records it. Only a verified count
    /// lets [`Self::aggregate_share_for`] release anything.
    pub fn count_finish(&mut self, reveals: &[CountReveal]) -> Result<u64> {
        let n = self.cfg.num_aggregators;
        let digest = batch_digest(self.accepted_ids.clone());
        let opening = self
            .verification
            .count_opening
            .clone()
            .ok_or_else(|| Error::Protocol("count_finish before count_share".into()))?;
        if self.verification.count_commits.len() != n - 1 {
            return Err(Error::Protocol("count_finish before count_open".into()));
        }
        let ct = self.count_ct()?.try_clone()?;
        let my_checks = vdec::build(&self.ctx, &self.pk, &[&ct], &opening)?;
        let check_meta = CiphertextMeta {
            num_elements: 1,
            ..my_checks[0].meta()?
        };
        let count_meta = Self::partial_meta(&ct)?;
        // per check, every aggregator's partial, in aggregator order
        let mut check_partials: Vec<Vec<PartialDecryption>> = (0..my_checks.len()).map(|_| Vec::with_capacity(n)).collect();
        let mut count_partials = Vec::with_capacity(n);
        for j in 0..n {
            let share = self
                .verification
                .count_shares
                .iter()
                .find(|s| s.aggregator == j)
                .ok_or_else(|| Error::Protocol(format!("no count share from aggregator {j}")))?;
            count_partials.push(self.load_partial(&share.partial, count_meta, j == 0)?);
            if j == self.index {
                for (l, c) in my_checks.iter().enumerate() {
                    check_partials[l].push(self.share.partial_decrypt(c, self.index == 0)?);
                }
                continue;
            }
            let r = reveals
                .iter()
                .find(|r| r.aggregator == j)
                .ok_or_else(|| Error::Protocol(format!("no count reveal from aggregator {j}")))?;
            if r.task_id != self.cfg.task_id || r.batch_digest != digest {
                return Err(Error::Protocol("count reveal for a different batch".into()));
            }
            let ps = &r
                .partials
                .iter()
                .find(|(v, _)| *v == self.index)
                .ok_or_else(|| Error::Protocol(format!("aggregator {j} revealed nothing for this aggregator's checks")))?
                .1;
            let committed = &self
                .verification
                .count_commits
                .iter()
                .find(|c| c.aggregator == j)
                .expect("n - 1 commitments")
                .digests;
            let committed = &committed.iter().find(|(v, _)| *v == self.index).expect("checked in count_open").1;
            if ps.len() != my_checks.len() {
                return Err(Error::Protocol(format!(
                    "aggregator {j} revealed {} partials, expected {}",
                    ps.len(),
                    my_checks.len()
                )));
            }
            for (l, p) in ps.iter().enumerate() {
                if vdec::commit(&self.count_context(self.index, l, j), p) != committed[l] {
                    return Err(Error::Protocol(format!(
                        "aggregator {j}'s partial of count check {l} is not the one it committed to"
                    )));
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
        vdec::verify(&powers, &[vec![0]], std::slice::from_ref(&fused_count), &fused_checks, &opening)?;
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
        self.require_no_open_share_flush()?;
        let count = self.accepted_ids.len();
        if self.cfg.gated() {
            return self.gated_share(collector);
        }
        let valid = match self.cfg.mode {
            VerificationMode::Verdict => count as u64,
            VerificationMode::Silent => self
                .valid_count
                .ok_or_else(|| Error::Protocol("silent mode: run count_share/count_finish before aggregate_share".into()))?,
        };
        if valid < self.cfg.min_batch_size as u64 {
            return Err(Error::Protocol(format!(
                "batch has {valid} valid reports, minimum is {}",
                self.cfg.min_batch_size
            )));
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
    /// count (silent mode), second-moment accumulators of its pairs; in a
    /// gated task, the gated release's outputs.
    fn release_accumulators(&self, collector: usize) -> Result<Vec<Ciphertext>> {
        if self.cfg.gated() {
            let out = self.gate.outputs.as_ref().ok_or_else(|| Error::Protocol("gated release not finished".into()))?;
            return out.iter().map(|b| self.codec.decode(b, Expect::Any).map_err(Into::into)).collect();
        }
        let sums = self.sums.as_ref().ok_or_else(|| Error::Protocol("no report in the batch".into()))?;
        let mut out = Vec::new();
        for k in self.cfg.collector_chunks(&self.layout, collector) {
            out.push(sums[k].try_clone()?);
        }
        if let Some(ct) = &*self.valid_count_sum {
            out.push(ct.try_clone()?);
        }
        let pairs = self.cfg.collector_moment_pairs(collector)?;
        if !pairs.is_empty() {
            let m = self
                .moment_sums
                .as_ref()
                .ok_or_else(|| Error::Protocol("moments enabled but no products accumulated".into()))?;
            // terms are over pieces; a collector's pairs are over elements
            let el = |i: usize| self.layout.moment_pieces[i].0;
            for (idx, t) in self.layout.moment_terms().into_iter().enumerate() {
                if pairs.contains(&(el(t.a), el(t.b))) {
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
        if ch.task_id != self.cfg.task_id
            || !self.released_aggregate_shares.contains_key(&collector)
            || ch.batch_digest != batch_digest(self.accepted_ids.clone())
        {
            return Err(Error::Protocol("release challenge for a share this aggregator has not released".into()));
        }
        let digest = ch.digest();
        if let Some((done, _)) = self.verification.releases.get(&collector) {
            if done.digest() != digest {
                return Err(Error::Protocol(format!(
                    "collector {collector} already has its checks answered for this batch: refusing a second set"
                )));
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
                let c = self
                    .codec
                    .decode(b, Expect::Exactly(meta))
                    .map_err(|e| Error::Protocol(format!("release check {l}: {e}")))?;
                partials.push(self.codec.encode(self.share.partial_decrypt(&c, self.index == 0)?.ciphertext())?);
            }
            self.verification.releases.insert(collector, (ch.clone(), partials));
        }
        let partials = &self.verification.releases[&collector].1;
        let digests = partials
            .iter()
            .enumerate()
            .map(|(l, p)| vdec::commit(&self.release_context(collector, l, self.index), p))
            .collect();
        Ok(ReleaseCommit {
            task_id: self.cfg.task_id,
            collector,
            aggregator: self.index,
            challenge: digest,
            digests,
        })
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
                return Err(Error::Protocol(format!(
                    "release check {l} is not what the collector opened: refusing to reveal"
                )));
            }
        }
        Ok(ReleaseReveal {
            task_id: self.cfg.task_id,
            collector: op.collector,
            aggregator: self.index,
            challenge: op.challenge,
            partials: partials.clone(),
        })
    }

    /// [`Self::release_reveal`] sealed to the collector's key (tasks with
    /// release policies: the leader relays it and must not read it).
    pub fn sealed_release_reveal(&mut self, op: &ReleaseOpening) -> Result<crate::seal::SealedShare> {
        let key = self
            .cfg
            .collectors
            .get(op.collector as usize)
            .map(|p| p.seal_key)
            .ok_or_else(|| Error::Config(format!("no sealing key for collector {}", op.collector)))?;
        let r = self.release_reveal(op)?;
        crate::seal::seal_reveal(&r, &key)
    }

    /// [`Self::aggregate_share_for`], sealed to the collector's key from the
    /// task. Tasks without policies have no key and cannot seal.
    pub fn sealed_share_for(&mut self, collector: usize) -> Result<crate::seal::SealedShare> {
        let key = self
            .cfg
            .collectors
            .get(collector)
            .map(|p| p.seal_key)
            .ok_or_else(|| Error::Config(format!("no sealing key for collector {collector}")))?;
        let share = self.aggregate_share_for(collector)?;
        crate::seal::seal(&share, &key)
    }

    // ---- gated release (`gate.rs`) ----------------------------------------

    fn gate_env(&self) -> crate::gate::GateEnv<'_> {
        crate::gate::GateEnv {
            cfg: &self.cfg,
            layout: &self.layout,
            ctx: &self.ctx,
            pk: &self.pk,
            codec: &self.codec,
            share: &self.share,
            party: self.index,
        }
    }

    /// The values the gated release refreshes ([`crate::gate::GatePlan`]).
    fn gate_values(&self) -> Result<Vec<Ciphertext>> {
        let plan = crate::gate::GatePlan::new(&self.cfg, &self.layout)?;
        let sums = self.sums.as_ref().ok_or_else(|| Error::Protocol("no report in the batch".into()))?;
        plan.refreshed
            .iter()
            .map(|r| match *r {
                crate::gate::Refreshed::Chunk(c) => Ok(sums[c].try_clone()?),
                crate::gate::Refreshed::SpreadCount => Ok(self
                    .valid_spread_sum
                    .as_ref()
                    .ok_or_else(|| Error::Protocol("no spread count accumulated".into()))?
                    .try_clone()?),
                crate::gate::Refreshed::Moment(i) => Ok(self
                    .moment_sums
                    .as_ref()
                    .ok_or_else(|| Error::Protocol("moments enabled but no products accumulated".into()))?[i]
                    .try_clone()?),
            })
            .collect()
    }

    /// Gated release, round 0: closes the batch and commits to this
    /// aggregator's contribution (masks, random factors, and in a split-key
    /// task the accumulators to refresh). Tasks with a count round
    /// (aggregators only, suppression) require a verified count of at
    /// least `min_batch_size`; split-key tasks gate the batch size under
    /// encryption and only require that many admitted reports.
    pub fn gate_commit(&mut self) -> Result<GateCommit> {
        if !self.cfg.gated() {
            return Err(Error::Protocol("task does not use the gated release".into()));
        }
        self.require_no_open_share_flush()?;
        let admitted = self.accepted_ids.len();
        if admitted < self.cfg.min_batch_size {
            return Err(Error::Protocol(format!(
                "batch has {admitted} admitted reports, minimum is {}",
                self.cfg.min_batch_size
            )));
        }
        if !self.cfg.collector_holds_key() {
            let valid = self
                .valid_count
                .ok_or_else(|| Error::Protocol("run the count round before the gated release".into()))?;
            if valid < self.cfg.min_batch_size as u64 {
                return Err(Error::Protocol(format!(
                    "batch has {valid} valid reports, minimum is {}",
                    self.cfg.min_batch_size
                )));
            }
        }
        self.flush_silent_batch()?;
        self.finalize_silent()?;
        self.closed = true;
        self.pending.clear();
        let xs = if self.cfg.collector_holds_key() { self.gate_values()? } else { Vec::new() };
        let digest = batch_digest(self.accepted_ids.clone());
        let mut gate = std::mem::take(&mut self.gate);
        let r = crate::gate::commit(&self.gate_env(), &mut gate, digest, &xs, &mut OsRng);
        self.gate = gate;
        r
    }

    /// Gated release, round 1: reveals the contribution once every key
    /// party's commitment is in.
    pub fn gate_contribute(&mut self, commits: &[GateCommit]) -> Result<GateContribution> {
        let mut gate = std::mem::take(&mut self.gate);
        let r = crate::gate::contribute(&self.gate_env(), &mut gate, commits);
        self.gate = gate;
        r
    }

    /// Gated release, round 2: checks every contribution (proofs of well
    /// formedness included), partially decrypts the masked accumulators and
    /// publishes this aggregator's checks of them.
    pub fn gate_share(&mut self, contributions: &[GateContribution]) -> Result<GateShare> {
        let xs = self.gate_own_values()?;
        let mut gate = std::mem::take(&mut self.gate);
        let r = crate::gate::share(&self.gate_env(), &mut gate, contributions, xs.as_deref(), &mut OsRng);
        self.gate = gate;
        r
    }

    /// The accumulators this aggregator refreshes: its own; in a split-key
    /// task, exactly those it committed to and sent the collector (`None`:
    /// taken from its contribution), so both key parties form the same `Y`.
    fn gate_own_values(&self) -> Result<Option<Vec<Ciphertext>>> {
        Ok(if self.cfg.collector_holds_key() { None } else { Some(self.gate_values()?) })
    }

    fn gate_ys(&self) -> Result<Vec<Ciphertext>> {
        crate::gate::masked_values(&self.gate_env(), &self.gate, self.gate_own_values()?.as_deref())
    }

    /// Gated release, round 3.
    pub fn gate_check_commit(&mut self, shares: &[GateShare]) -> Result<GateCheckCommit> {
        let ys = self.gate_ys()?;
        let mut gate = std::mem::take(&mut self.gate);
        let r = crate::gate::check_commit(&self.gate_env(), &mut gate, shares, &ys);
        self.gate = gate;
        r
    }

    /// Gated release, round 4.
    pub fn gate_open(&mut self, commits: &[GateCheckCommit]) -> Result<GateOpening> {
        let mut gate = std::mem::take(&mut self.gate);
        let r = crate::gate::open(&self.gate_env(), &mut gate, commits);
        self.gate = gate;
        r
    }

    /// Gated release, round 5.
    pub fn gate_reveal(&mut self, openings: &[GateOpening]) -> Result<GateReveal> {
        let ys = self.gate_ys()?;
        let mut gate = std::mem::take(&mut self.gate);
        let r = crate::gate::reveal(&self.gate_env(), &mut gate, openings, &ys);
        self.gate = gate;
        r
    }

    /// Gated release, round 6: verifies and fuses the masked accumulators,
    /// re-encrypts them at the top of the chain and computes the gates and
    /// the released ciphertexts. Nothing is decrypted here.
    pub fn gate_finish(&mut self, reveals: &[GateReveal]) -> Result<()> {
        if self.gate.outputs.is_some() {
            return Ok(());
        }
        let ys = self.gate_ys()?;
        let mut gate = std::mem::take(&mut self.gate);
        let r = crate::gate::finish(&self.gate_env(), &mut gate, reveals, &ys).and_then(|_| crate::gate::outputs(&self.gate_env(), &gate));
        let out = match r {
            Ok(o) => o,
            Err(e) => {
                self.gate = gate;
                return Err(e);
            }
        };
        gate.outputs = Some(out.iter().map(|c| self.codec.encode(c)).collect::<Result<_>>()?);
        self.gate = gate;
        Ok(())
    }

    /// The release of a gated task: partial decryptions of the gated
    /// outputs (once). With suppression the counts are withheld.
    fn gated_share(&mut self, collector: usize) -> Result<AggregateShare> {
        if collector != 0 {
            return Err(Error::Protocol("gated tasks have one collector".into()));
        }
        let accs = self.release_accumulators(0)?;
        let mut partials = Vec::with_capacity(accs.len());
        for c in &accs {
            partials.push(self.codec.encode(self.share.partial_decrypt(c, self.index == 0)?.ciphertext())?);
        }
        let share = AggregateShare {
            task_id: self.cfg.task_id,
            collector: 0,
            aggregator: self.index,
            batch_digest: batch_digest(self.accepted_ids.clone()),
            report_count: if self.cfg.min_cell_count > 0 { 0 } else { self.accepted_ids.len() as u64 },
            partials,
            valid_count_partial: None,
            moment_partials: Vec::new(),
            accumulators: self.gate.outputs.clone().expect("checked by release_accumulators"),
        };
        self.released_aggregate_shares.insert(0, share.clone());
        Ok(share)
    }

    /// TEST HOOK: the accumulators a split-key aggregator sends to be
    /// refreshed, for tests that substitute them (a malicious aggregator).
    pub fn gate_values_for_tests(&self) -> Result<Vec<Ciphertext>> {
        self.gate_values()
    }

    /// TEST HOOK: commits like [`Self::gate_commit`] but with `xs` as the
    /// accumulators to refresh (what a malicious split-key aggregator does).
    pub fn gate_commit_substituted_for_tests(&mut self, xs: &[Ciphertext]) -> Result<GateCommit> {
        self.flush_silent_batch()?;
        self.finalize_silent()?;
        self.closed = true;
        let digest = batch_digest(self.accepted_ids.clone());
        let mut gate = std::mem::take(&mut self.gate);
        let r = crate::gate::commit(&self.gate_env(), &mut gate, digest, xs, &mut OsRng);
        self.gate = gate;
        r
    }

    /// TEST HOOK: the masked values `Y` this aggregator decrypts in the refresh.
    pub fn gate_masked_values_for_tests(&self) -> Result<Vec<Ciphertext>> {
        self.gate_ys()
    }

    /// The gated release's state (tests that act as a malicious party).
    pub fn gate_state_for_tests(&mut self) -> &mut crate::gate::GateState {
        &mut self.gate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(share_round: ShareRoundState) -> AggregatorState {
        AggregatorState {
            sums: Some(vec![vec![1, 2, 3]]),
            valid_count_sum: Some(vec![4]),
            moment_sums: None,
            silent_pending: vec![(3, [7u8; 32])],
            silent_finalized: false,
            accepted_ids: vec![[1u8; 32], [2u8; 32]],
            seen: vec![[1u8; 32], [2u8; 32], [7u8; 32]],
            client_reports: vec![([9u8; 32], 2)],
            admitted: 3,
            valid_count: Some(2),
            closed: false,
            released_count_share: None,
            released_aggregate_shares: BTreeMap::new(),
            verification: VerificationState::default(),
            valid_spread_sum: None,
            gate: crate::gate::GateState::default(),
            share_round,
        }
    }

    /// A database written before the secret-shared upload holds the state
    /// without its last field; it decodes with an empty `share_round`, and
    /// today's encoding round-trips with a non-empty one.
    #[test]
    fn states_from_before_share_upload_decode() {
        let st = state(ShareRoundState::default());
        let bytes = crate::messages::encode(&st).unwrap();
        // the empty share round encodes as four bytes: 0 (next_seq), 0
        // (pending), None, None
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 0, 0, 0]);
        let old = &bytes[..bytes.len() - 4];
        assert!(crate::messages::decode::<AggregatorState>(old).is_err());
        let back = AggregatorState::decode(old).unwrap();
        assert_eq!(crate::messages::encode(&back).unwrap(), bytes);
        let busy = state(ShareRoundState {
            next_seq: 5,
            pending: Vec::new(),
            contributed: Some((5, [1u8; 32], [2u8; 32])),
            finished: Some((4, [3u8; 32])),
        });
        let bytes = crate::messages::encode(&busy).unwrap();
        assert_eq!(AggregatorState::decode(&bytes).unwrap().share_round, busy.share_round);
        // a truncated or extended encoding is refused, not misread
        assert!(AggregatorState::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(AggregatorState::decode(&longer).is_err());
    }
}
