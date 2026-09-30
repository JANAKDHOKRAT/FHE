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
