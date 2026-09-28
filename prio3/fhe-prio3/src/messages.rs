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

/// Aggregator `aggregator`'s fresh encrypted mask for one report.
#[derive(Clone, Serialize, Deserialize)]
pub struct MaskMessage {
    pub report_id: ReportId,
    pub aggregator: usize,
    pub mask: Vec<u8>,
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
}

/// Aggregator's contribution to the collector: partial decryptions of the
/// per-chunk sums over the batch.
#[derive(Clone, Serialize, Deserialize)]
pub struct AggregateShare {
    pub task_id: [u8; 32],
    pub aggregator: usize,
    /// SHA-256 over the sorted identifiers of the reports in the batch.
    pub batch_digest: [u8; 32],
    /// Reports in the batch (verdict mode: accepted; silent mode: admitted).
    pub report_count: u64,
    pub partials: Vec<Vec<u8>>,
    /// Silent mode: partial decryption of the encrypted valid-report count,
    /// so the collector can verify it rather than trust it.
    pub valid_count_partial: Option<Vec<u8>>,
    /// Post-validation moments: one partial decryption per (a <= b) pair.
    pub moment_partials: Vec<Vec<u8>>,
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

pub fn encode<T: Serialize>(t: &T) -> crate::Result<Vec<u8>> {
    bincode::serialize(t).map_err(|e| crate::Error::Serialization(e.to_string()))
}
pub fn decode<'a, T: Deserialize<'a>>(b: &'a [u8]) -> crate::Result<T> {
    bincode::deserialize(b).map_err(|e| crate::Error::Serialization(e.to_string()))
}
