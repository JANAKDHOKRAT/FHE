//! Task configuration shared by clients, aggregators and the collector.

use crate::error::{Error, Result};
use crate::field::Field;
use crate::layout::Layout;
use crate::types::MeasurementType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Prime plaintext modulus used by default: the largest 32-bit prime
/// congruent to 1 modulo 2^17, so SIMD packing works for ring dimensions up
/// to 65536.
pub const DEFAULT_PLAIN_MOD: u64 = 4_293_918_721;

/// Multiplicative depth of the verification circuit:
/// `x(x-1)` (1), multiplication by the check coefficients (2), multiplication
/// by the masked aggregator randomness (3).
pub const CIRCUIT_DEPTH: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskConfig {
    /// 32-byte task identifier chosen by the deployment.
    pub task_id: [u8; 32],
    pub measurement_type: MeasurementType,
    /// Number of aggregators holding key shares (n-of-n). At least 2.
    pub num_aggregators: usize,
    /// Independent repetitions of the random-linear-combination check.
    /// Soundness against a malicious client is `p^-repetitions` per report,
    /// and a client grinding the Fiat–Shamir challenge needs about
    /// `p^repetitions` encryptions per forged report.
    pub repetitions: usize,
    /// Aggregators refuse to release an aggregate over fewer reports.
    pub min_batch_size: usize,
    /// Upper bound on accepted reports per batch; must be below `p`.
    pub max_batch_size: u64,
    pub plain_mod: u64,
    pub security_bits: u32,
}

impl TaskConfig {
    pub fn new(task_id: [u8; 32], measurement_type: MeasurementType, num_aggregators: usize) -> Self {
        Self {
            task_id,
            measurement_type,
            num_aggregators,
            repetitions: 4,
            min_batch_size: 1,
            max_batch_size: 1 << 20,
            plain_mod: DEFAULT_PLAIN_MOD,
            security_bits: 128,
        }
    }

    pub fn validate(&self) -> Result<Field> {
        self.measurement_type.validate()?;
        if self.num_aggregators < 2 {
            return Err(Error::Config("at least two aggregators are required".into()));
        }
        if self.repetitions == 0 || self.repetitions > 64 {
            return Err(Error::Config("repetitions must be in 1..=64".into()));
        }
        let field = Field::new(self.plain_mod).ok_or_else(|| Error::Config("plain_mod must be a prime below 2^32".into()))?;
        if self.min_batch_size == 0 {
            return Err(Error::Config("min_batch_size must be >= 1".into()));
        }
        if self.max_batch_size < self.min_batch_size as u64 || self.max_batch_size >= self.plain_mod {
            return Err(Error::Config("need min_batch_size <= max_batch_size < plain_mod".into()));
        }
        if !matches!(self.security_bits, 128 | 192 | 256) {
            return Err(Error::Config("security_bits must be 128, 192 or 256".into()));
        }
        Ok(field)
    }

    pub fn field(&self) -> Field {
        Field::new(self.plain_mod).expect("validated")
    }

    pub fn layout(&self, row: usize) -> Result<Layout> {
        Layout::new(self.measurement_type.input_len(), self.repetitions, row)
    }

    /// Bits of soundness of the validity check against a malicious client.
    pub fn soundness_bits(&self) -> f64 {
        self.repetitions as f64 * self.field().log2()
    }

    /// Canonical bytes that every derived randomness commits to.
    pub fn binding(&self) -> Vec<u8> {
        bincode::serialize(self).expect("TaskConfig is serializable")
    }

    /// Hash of the configuration, for logging and for peers to compare.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.binding()).into()
    }
}
