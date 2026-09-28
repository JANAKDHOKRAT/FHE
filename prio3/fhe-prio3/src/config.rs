//! Task configuration shared by clients, aggregators and the collector.

use crate::error::{Error, Result};
use crate::field::Field;
use crate::layout::{Layout, LayoutKind};
use crate::types::MeasurementType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default plaintext modulus for verdict mode: the largest 32-bit prime
/// congruent to 1 modulo 2^17, so SIMD packing works for ring dimensions up
/// to 65536.
pub const DEFAULT_PLAIN_MOD: u64 = 4_293_918_721;

/// Default plaintext modulus for silent mode: `3 * 2^18 + 1`, the smallest
/// prime congruent to 1 modulo 2^17. Its Fermat exponent `p - 1 = 3 * 2^18`
/// costs 20 multiplicative levels.
pub const SILENT_PLAIN_MOD: u64 = 786_433;

/// Multiplicative depth of the verdict-mode verification circuit:
/// `x(x-1)` (1), multiplication by the check coefficients (2), multiplication
/// by the masked aggregator randomness (3).
pub const VERDICT_CIRCUIT_DEPTH: u32 = 3;

/// How the aggregators use the result of the validity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMode {
    /// Two message rounds per report; the aggregators learn accept/reject.
    /// Depth 3, ring dimension 32768 at 128-bit security.
    Verdict,
    /// No per-report messages and no per-report decryption. Each report is
    /// multiplied by a homomorphically computed validity bit and only the
    /// batch sums are ever decrypted. Depth `2 + fermat + log2(classes) + 1`,
    /// ring dimension 65536 at 128-bit security with the default modulus.
    Silent,
}

/// Whether reports must be signed by a registered client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthPolicy {
    /// Anyone may submit. Only appropriate when the transport authenticates
    /// clients by other means.
    Open,
    /// Every report carries an Ed25519 signature by a key the aggregator's
    /// registry accepts, and each key may submit at most this many reports
    /// per batch (attempts count, whether or not they are accepted).
    Required { max_reports_per_client_per_batch: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskConfig {
    /// 32-byte task identifier chosen by the deployment.
    pub task_id: [u8; 32],
    pub measurement_type: MeasurementType,
    pub mode: VerificationMode,
    pub auth: AuthPolicy,
    /// Number of aggregators holding key shares (n-of-n). At least 2.
    pub num_aggregators: usize,
    /// Independent repetitions of the random-linear-combination check.
    pub repetitions: usize,
    /// Aggregators refuse to release an aggregate over fewer reports.
    pub min_batch_size: usize,
    /// Upper bound on reports admitted per batch; must be below `p`.
    pub max_batch_size: u64,
    /// Upper bound on the serialized size of a report; 0 means "derive from
    /// the size of a fresh ciphertext".
    pub max_report_bytes: usize,
    pub plain_mod: u64,
    pub security_bits: u32,
    /// Silent mode: reports verified together in one ciphertext (a power of
    /// two; 1 disables batching). The Fermat chain is shared by all of them.
    pub silent_batch_groups: usize,
    /// Post-validation computation: also accumulate the second moments
    /// `sum v_a v_b` of the SumVec values over valid reports, so the
    /// collector can solve a linear regression (last value = target) without
    /// ever seeing a record. Requires `SumVec` with a power-of-two `bits`.
    pub moments: bool,
}

impl TaskConfig {
    /// Verdict mode with 128-bit soundness (`4 * 32 = 128` bits).
    pub fn new(task_id: [u8; 32], measurement_type: MeasurementType, num_aggregators: usize) -> Self {
        Self {
            task_id,
            measurement_type,
            mode: VerificationMode::Verdict,
            auth: AuthPolicy::Open,
            num_aggregators,
            repetitions: 4,
            min_batch_size: 1,
            max_batch_size: 1 << 20,
            max_report_bytes: 0,
            plain_mod: DEFAULT_PLAIN_MOD,
            security_bits: 128,
            silent_batch_groups: 1,
            moments: false,
        }
    }

    /// Largest batch for which every second-moment sum stays below `p`
    /// (each product is below `2^(2 bits)`). `None` when moments are off.
    pub fn moments_max_batch(&self) -> Option<u64> {
        if !self.moments {
            return None;
        }
        match self.measurement_type {
            MeasurementType::SumVec { bits, .. } => Some((self.plain_mod - 1) >> (2 * bits)),
            _ => None,
        }
    }

    /// Silent mode with 78-bit soundness (`4 * log2(786433)`), depth 25,
    /// ring dimension 65536. Five to seven repetitions give up to 137 bits
    /// at depth 26, for which OpenFHE selects ring dimension 131072 (about
    /// four times the cost and memory).
    pub fn new_silent(task_id: [u8; 32], measurement_type: MeasurementType, num_aggregators: usize) -> Self {
        let mut c = Self::new(task_id, measurement_type, num_aggregators);
        c.mode = VerificationMode::Silent;
        c.repetitions = 4;
        c.plain_mod = SILENT_PLAIN_MOD;
        c.max_batch_size = 1 << 16;
        c.silent_batch_groups = 64;
        c
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
        if let AuthPolicy::Required { max_reports_per_client_per_batch: 0 } = self.auth {
            return Err(Error::Config("max_reports_per_client_per_batch must be >= 1".into()));
        }
        if !self.silent_batch_groups.is_power_of_two() {
            return Err(Error::Config("silent_batch_groups must be a power of two".into()));
        }
        if self.moments {
            match self.measurement_type {
                MeasurementType::SumVec { length, bits } => {
                    if length < 2 || !bits.is_power_of_two() {
                        return Err(Error::Config("moments need SumVec with length >= 2 (features + target) and a power-of-two bits".into()));
                    }
                    if 2 * bits as u64 >= 64 - self.plain_mod.leading_zeros() as u64 {
                        return Err(Error::Config("moments: 2*bits must be below log2(plain_mod) so products are exact".into()));
                    }
                    let cap = self.moments_max_batch().expect("checked");
                    if self.max_batch_size > cap {
                        return Err(Error::Config(format!("moments: max_batch_size must be at most {cap} for {bits}-bit values under p = {}", self.plain_mod)));
                    }
                }
                _ => return Err(Error::Config("moments are only defined for SumVec".into())),
            }
        }
        if self.mode == VerificationMode::Silent && self.mult_depth() > 26 {
            return Err(Error::Config(format!(
                "silent mode circuit depth {} exceeds 26; use a plaintext modulus with a shorter Fermat chain or fewer repetitions",
                self.mult_depth()
            )));
        }
        Ok(field)
    }

    pub fn field(&self) -> Field {
        Field::new(self.plain_mod).expect("validated")
    }

    pub fn layout_kind(&self) -> LayoutKind {
        match self.mode {
            VerificationMode::Verdict => LayoutKind::Blocked,
            VerificationMode::Silent if self.silent_batch_groups > 1 => LayoutKind::Batched,
            VerificationMode::Silent => LayoutKind::Interleaved,
        }
    }

    pub fn layout(&self, row: usize) -> Result<Layout> {
        let groups = if self.layout_kind() == LayoutKind::Batched { self.silent_batch_groups } else { 1 };
        let mut l = Layout::with_groups(self.layout_kind(), self.measurement_type.input_len(), self.repetitions, row, groups)?;
        if self.moments {
            if let MeasurementType::SumVec { length, bits } = self.measurement_type {
                if l.num_chunks != 1 {
                    return Err(Error::Config("moments need the whole SumVec in one chunk".into()));
                }
                l.moments = Some((length, bits));
            }
        }
        Ok(l)
    }

    /// Multiplicative levels consumed by `E^(p-1)` with left-to-right
    /// square-and-multiply.
    pub fn fermat_depth(&self) -> u32 {
        let e = self.plain_mod - 1;
        (64 - e.leading_zeros() - 1) + (e.count_ones() - 1)
    }

    /// Multiplicative depth the crypto context must support.
    pub fn mult_depth(&self) -> u32 {
        match self.mode {
            VerificationMode::Verdict => VERDICT_CIRCUIT_DEPTH,
            VerificationMode::Silent => {
                let classes = self.repetitions.next_power_of_two();
                2 + self.fermat_depth() + classes.trailing_zeros() + 1
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn depths() {
        let v = TaskConfig::new([0; 32], MeasurementType::Count, 2);
        assert_eq!(v.mult_depth(), 3);
        let s = TaskConfig::new_silent([0; 32], MeasurementType::Count, 2);
        assert_eq!(s.fermat_depth(), 20); // 3 * 2^18: E^3 then 18 squarings
        assert_eq!(s.mult_depth(), 25); // 2 + 20 + 2 + 1
        assert!(s.validate().is_ok());
        assert!(s.soundness_bits() > 78.0);
        let mut seven = s.clone();
        seven.repetitions = 7;
        assert_eq!(seven.mult_depth(), 26);
        assert!(seven.validate().is_ok());
        let mut too_deep = s.clone();
        too_deep.repetitions = 9; // 16 classes -> depth 27
        assert!(too_deep.validate().is_err());
    }
}
