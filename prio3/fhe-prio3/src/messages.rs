//! Wire messages. Ciphertexts travel as OpenFHE binary serializations.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type ReportId = [u8; 32];

/// A client's report: one ciphertext per chunk of the encoded measurement.
/// The same report is sent to every aggregator.
#[derive(Clone, Serialize, Deserialize)]
pub struct Report {
    pub task_id: [u8; 32],
    pub report_id: ReportId,
    /// Batched silent mode: the group the client was assigned before
    /// encrypting; 0 otherwise. Bound by `report_id` and the signature.
    pub group: u32,
    pub chunks: Vec<Vec<u8>>,
    /// Present when the task's `AuthPolicy` requires it.
    pub auth: Option<crate::auth::ReportAuth>,
}

impl Report {
    /// Deterministic identifier binding the task, the group and every
    /// ciphertext byte.
    pub fn compute_id(task_id: &[u8; 32], group: u32, chunks: &[Vec<u8>]) -> ReportId {
        let mut h = Sha256::new();
        h.update(b"fhe-prio3/2 report");
        h.update(task_id);
        h.update(group.to_le_bytes());
        h.update((chunks.len() as u32).to_le_bytes());
        for c in chunks {
            h.update((c.len() as u64).to_le_bytes());
            h.update(c);
        }
        h.finalize().into()
    }

    /// Serialized size of the ciphertexts alone.
    pub fn ciphertext_bytes(&self) -> usize {
        self.chunks.iter().map(|c| c.len()).sum()
    }
}

/// One key party's input share, sealed to its upload key (`shares.rs`):
/// ephemeral X25519 public key, AES-256-GCM nonce and ciphertext (with tag).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedInput {
    pub ephemeral: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// A client's report under [`crate::config::Upload::Shares`]: its encoded
/// measurement split into one additive share per key party, each sealed to
/// that party. No ciphertext under the joint key: a few hundred bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareReport {
    pub task_id: [u8; 32],
    pub report_id: ReportId,
    /// Fresh per report; bound into every sealed input's associated data
    /// and every seed's expansion.
    pub nonce: [u8; 16],
    /// One sealed input per key party, in party order.
    pub inputs: Vec<SealedInput>,
    /// Present when the task's `AuthPolicy` requires it.
    pub auth: Option<crate::auth::ReportAuth>,
}

impl ShareReport {
    /// Deterministic identifier binding the task, the nonce and every byte
    /// of every sealed input: once a client has sent a report, the value
    /// its shares add up to is fixed, before the validity check's
    /// coefficients (derived from this id) exist.
    pub fn compute_id(task_id: &[u8; 32], nonce: &[u8; 16], inputs: &[SealedInput]) -> ReportId {
        let mut h = Sha256::new();
        h.update(b"fhe-prio3/3 share report");
        h.update(task_id);
        h.update(nonce);
        h.update((inputs.len() as u32).to_le_bytes());
        for i in inputs {
            h.update(i.ephemeral);
            h.update(i.nonce);
            h.update((i.ciphertext.len() as u64).to_le_bytes());
            h.update(&i.ciphertext);
        }
        h.finalize().into()
    }

    /// Total size of the sealed inputs.
    pub fn sealed_bytes(&self) -> usize {
        self.inputs.iter().map(|i| 32 + 12 + i.ciphertext.len()).sum()
    }
}

/// The leader's request for one verification batch of share reports (a
/// "flush"): every report with the group it occupies, report `i` in group
/// `i`. Every key party contributes its shares of exactly these reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareFlushRequest {
    pub task_id: [u8; 32],
    /// Flushes are numbered from 0 within a batch; a party contributes to
    /// each number once.
    pub seq: u64,
    pub reports: Vec<ShareReport>,
}

impl ShareFlushRequest {
    /// Binds the task, the sequence number and every report id in group
    /// order: what every contribution and its proofs are bound to.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"fhe-prio3/3 share flush");
        h.update(self.task_id);
        h.update(self.seq.to_le_bytes());
        h.update((self.reports.len() as u32).to_le_bytes());
        for r in &self.reports {
            h.update(r.report_id);
        }
        h.finalize().into()
    }
}

/// One key party's shares of a flush, encrypted under the joint key: one
/// packed fresh-shaped ciphertext per chunk (its effective ciphertext `2C`
/// decodes to the party's shares at the reports' group slots), each with a
/// proof of well-formedness (`wfe.rs`).
#[derive(Clone, Serialize, Deserialize)]
pub struct ShareContribution {
    pub task_id: [u8; 32],
    pub party: usize,
    pub seq: u64,
    pub flush_digest: [u8; 32],
    pub chunks: Vec<Vec<u8>>,
    pub proofs: Vec<crate::wfe::Proof>,
}

impl ShareContribution {
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"fhe-prio3/3 share contribution");
        h.update(encode(self).expect("serializable"));
        h.finalize().into()
    }
}

/// Verdict mode: aggregator `aggregator`'s commitment to its mask for one
/// report, sent before any mask is revealed. Without it, an aggregator that
/// saw the others' masks first could send `Enc(r) − Σ others` and fix the
/// combined mask to `r`. That would force invalid reports through (`r = 0`)
/// and reveal each check value `E_j` itself instead of one bit.
#[derive(Clone, Serialize, Deserialize)]
pub struct MaskCommit {
    pub report_id: ReportId,
    pub aggregator: usize,
    pub digest: [u8; 32],
}

/// Aggregator `aggregator`'s fresh encrypted mask for one report.
#[derive(Clone, Serialize, Deserialize)]
pub struct MaskMessage {
    pub report_id: ReportId,
    pub aggregator: usize,
    pub mask: Vec<u8>,
}

/// Verdict mode: aggregator `aggregator`'s commitment to its partial
/// decryption of the masked check value, sent before any partial is
/// revealed, so that no aggregator can choose its partial after seeing the
/// others' (which would let it force the fused verdict to zero, i.e.
/// accept an invalid report).
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifierCommit {
    pub report_id: ReportId,
    pub aggregator: usize,
    pub digest: [u8; 32],
}

/// Aggregator `aggregator`'s partial decryption of the masked check value.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifierMessage {
    pub report_id: ReportId,
    pub aggregator: usize,
    pub partial: Vec<u8>,
}

/// Silent mode: an aggregator's partial decryption of the encrypted count
/// of valid reports in the batch. Exchanged among aggregators before any
/// sum is released, so that `min_batch_size` applies to *valid* reports.
#[derive(Clone, Serialize, Deserialize)]
pub struct CountShare {
    pub task_id: [u8; 32],
    pub aggregator: usize,
    pub batch_digest: [u8; 32],
    pub report_count: u64,
    pub partial: Vec<u8>,
    /// This aggregator's blinded checks of the count (`vdec`), which every
    /// other aggregator partially decrypts in the rounds below.
    pub checks: Vec<Vec<u8>>,
}

/// Silent mode, count round 2: an aggregator's commitments to its partial
/// decryptions of every other aggregator's count checks, by verifier.
#[derive(Clone, Serialize, Deserialize)]
pub struct CountCommit {
    pub task_id: [u8; 32],
    pub aggregator: usize,
    pub batch_digest: [u8; 32],
    pub digests: Vec<(usize, Vec<[u8; 32]>)>,
}

/// Silent mode, count round 3: an aggregator reveals what its checks were.
#[derive(Clone, Serialize, Deserialize)]
pub struct CountOpening {
    pub task_id: [u8; 32],
    pub aggregator: usize,
    pub batch_digest: [u8; 32],
    pub opening: crate::vdec::Opening,
}

/// Silent mode, count round 4: an aggregator's partial decryptions of every
/// other aggregator's count checks, after it has verified those checks.
#[derive(Clone, Serialize, Deserialize)]
pub struct CountReveal {
    pub task_id: [u8; 32],
    pub aggregator: usize,
    pub batch_digest: [u8; 32],
    pub partials: Vec<(usize, Vec<Vec<u8>>)>,
}

/// Aggregator's contribution to the collector: partial decryptions of the
/// per-chunk sums over the batch.
#[derive(Clone, Serialize, Deserialize)]
pub struct AggregateShare {
    pub task_id: [u8; 32],
    /// Collector this share is released to; `partials` covers exactly the
    /// chunks `TaskConfig::collector_chunks` lists for it and
    /// `moment_partials` the accumulators (`Layout::moment_pair_terms`) of
    /// exactly `TaskConfig::collector_moment_pairs`.
    pub collector: u32,
    pub aggregator: usize,
    /// SHA-256 over the sorted identifiers of the reports in the batch.
    pub batch_digest: [u8; 32],
    /// Reports in the batch (verdict mode: accepted; silent mode: admitted).
    pub report_count: u64,
    pub partials: Vec<Vec<u8>>,
    /// Silent mode: partial decryption of the encrypted valid-report count,
    /// so the collector can verify it rather than trust it.
    pub valid_count_partial: Option<Vec<u8>>,
    /// Post-validation moments: one partial decryption per accumulator of
    /// the collector's pairs, in `Layout::moment_terms` order.
    pub moment_partials: Vec<Vec<u8>>,
    /// The ciphertexts decrypted above, in the order chunks, valid count,
    /// moments: every aggregator computed the same ones, and the collector
    /// checks the partials against them (`vdec`).
    pub accumulators: Vec<Vec<u8>>,
}

/// Collector -> aggregators: blinded checks of the released accumulators.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReleaseChallenge {
    pub task_id: [u8; 32],
    pub collector: u32,
    pub batch_digest: [u8; 32],
    pub checks: Vec<Vec<u8>>,
}

impl ReleaseChallenge {
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"fhe-prio3/1 release challenge");
        h.update(self.task_id);
        h.update(self.collector.to_le_bytes());
        h.update(self.batch_digest);
        h.update((self.checks.len() as u64).to_le_bytes());
        for c in &self.checks {
            h.update(Sha256::digest(c));
        }
        h.finalize().into()
    }
}

/// Aggregator -> collector: commitments to its partial decryptions of the checks.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReleaseCommit {
    pub task_id: [u8; 32],
    pub collector: u32,
    pub aggregator: usize,
    pub challenge: [u8; 32],
    pub digests: Vec<[u8; 32]>,
}

/// Collector -> aggregators, once every commitment is in: what the checks were.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReleaseOpening {
    pub task_id: [u8; 32],
    pub collector: u32,
    pub challenge: [u8; 32],
    pub opening: crate::vdec::Opening,
}

/// Aggregator -> collector: its partial decryptions of the checks, released
/// after it rebuilt the checks from its own accumulators and the opening.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReleaseReveal {
    pub task_id: [u8; 32],
    pub collector: u32,
    pub aggregator: usize,
    pub challenge: [u8; 32],
    pub partials: Vec<Vec<u8>>,
}

/// Gated release, round 0: a key party's commitment to its contribution
/// (and, for the aggregator of a split-key task, to the accumulators it
/// asks the collector to refresh), sent before any contribution is
/// revealed. See `gate.rs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateCommit {
    pub task_id: [u8; 32],
    pub party: usize,
    pub batch_digest: [u8; 32],
    pub digest: [u8; 32],
}

/// Gated release, round 1: a key party's masks (one per refreshed
/// accumulator) and, for aggregators, random factors (one per gate input),
/// each a fresh encryption with a proof that it is well formed (`wfe.rs`).
/// The aggregator of a split-key task also carries the accumulators.
#[derive(Clone, Serialize, Deserialize)]
pub struct GateContribution {
    pub task_id: [u8; 32],
    pub party: usize,
    pub batch_digest: [u8; 32],
    pub accumulators: Vec<Vec<u8>>,
    pub masks: Vec<Vec<u8>>,
    pub factors: Vec<Vec<u8>>,
    /// One per mask, then one per factor.
    pub proofs: Vec<crate::wfe::Proof>,
}

impl GateContribution {
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"fhe-prio3/1 gate contribution");
        h.update(self.task_id);
        h.update((self.party as u64).to_le_bytes());
        h.update(self.batch_digest);
        for list in [&self.accumulators, &self.masks, &self.factors] {
            h.update((list.len() as u64).to_le_bytes());
            for c in list.iter() {
                h.update(Sha256::digest(c));
            }
        }
        h.update(Sha256::digest(encode(&self.proofs).expect("serializable")));
        h.finalize().into()
    }
}

/// Gated release, joint decryption round 1: a key party's partial
/// decryptions of the masked accumulators `Y` and its blinded checks of
/// them (`vdec`), which every other key party partially decrypts.
#[derive(Clone, Serialize, Deserialize)]
pub struct GateShare {
    pub task_id: [u8; 32],
    pub party: usize,
    pub batch_digest: [u8; 32],
    pub partials: Vec<Vec<u8>>,
    pub checks: Vec<Vec<u8>>,
}

/// Joint decryption round 2: commitments to partials of the others' checks, by verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateCheckCommit {
    pub task_id: [u8; 32],
    pub party: usize,
    pub batch_digest: [u8; 32],
    pub digests: Vec<(usize, Vec<[u8; 32]>)>,
}

/// Joint decryption round 3: what a party's checks were.
#[derive(Clone, Serialize, Deserialize)]
pub struct GateOpening {
    pub task_id: [u8; 32],
    pub party: usize,
    pub batch_digest: [u8; 32],
    pub opening: crate::vdec::Opening,
}

/// Joint decryption round 4: partials of the others' checks, after verifying them.
#[derive(Clone, Serialize, Deserialize)]
pub struct GateReveal {
    pub task_id: [u8; 32],
    pub party: usize,
    pub batch_digest: [u8; 32],
    pub partials: Vec<(usize, Vec<Vec<u8>>)>,
}

/// Output of the key ceremony that every party may hold.
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicMaterial {
    pub context: Vec<u8>,
    pub public_key: Vec<u8>,
    pub joint_tag: String,
    pub eval_mult_key: Vec<u8>,
    /// One serialized key map per entry of `rotation_indices`, so that a
    /// party can install them one at a time and never hold two copies of
    /// the whole set.
    pub rotation_keys: Vec<Vec<u8>>,
    pub rotation_indices: Vec<i32>,
    /// One signature per aggregator over the client-relevant part of this
    /// material and the task digest (`attest.rs`); empty until attested.
    pub attestations: Vec<crate::attest::MaterialAttestation>,
}

impl PublicMaterial {
    pub fn rotation_key_bytes(&self) -> usize {
        self.rotation_keys.iter().map(|k| k.len()).sum()
    }
}

pub fn batch_digest(mut ids: Vec<ReportId>) -> [u8; 32] {
    ids.sort_unstable();
    let mut h = Sha256::new();
    h.update(b"fhe-prio3/1 batch");
    h.update((ids.len() as u64).to_le_bytes());
    for id in ids {
        h.update(id);
    }
    h.finalize().into()
}

/// Message codec: postcard (serde, canonical, varint lengths). One value
/// has exactly one encoding, which the commitments and digests taken over
/// encoded messages rely on.
pub fn encode<T: Serialize>(t: &T) -> crate::Result<Vec<u8>> {
    postcard::to_allocvec(t).map_err(|e| crate::Error::Serialization(e.to_string()))
}
/// Decodes exactly one value: trailing bytes are an error, so a message
/// cannot carry an unparsed tail.
pub fn decode<'a, T: Deserialize<'a>>(b: &'a [u8]) -> crate::Result<T> {
    let (v, rest) = postcard::take_from_bytes::<T>(b).map_err(|e| crate::Error::Serialization(e.to_string()))?;
    if !rest.is_empty() {
        return Err(crate::Error::Serialization(format!("{} trailing byte(s) after the message", rest.len())));
    }
    Ok(v)
}
