//! A bounded, fail-closed interface for one collector task.
//!
//! This limits reactions; it does not authenticate evaluator computation or
//! prove ciphertext privacy. Use only behind an authenticated evaluator channel.
//! An evaluator can still substitute ciphertexts. Never expose the underlying
//! collector as an alternate endpoint. Failure timing is NOT made constant-time.
use super::{Ledger, PineCollector, PineTask};
use crate::{Error, Result};
use openfhe_tbgv_rs::PublicKey;
use std::path::Path;

/// Deliberately one public error: do not send library diagnostics or secret
/// measurements to the evaluator. It conveys no claim about timing leakage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;
impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("collector request refused")
    }
}
impl std::error::Error for Refused {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ready,
    AwaitingAggregate,
    Closed,
}

/// Fresh full key, one check request, at most one aggregate request, per task.
/// Both reservations are durable BEFORE processing. A failed request burns its
/// opportunity, including after a process crash. Restart is fail-closed: start
/// a new round with a new descriptor and key; never delete the old ledger.
pub struct CollectorSession<'a> {
    inner: PineCollector<'a>,
    ledger: Ledger,
    phase: Phase,
    max_reports: usize,
    max_check_bytes: usize,
    aggregate_bytes: usize,
}

/// The collector's authorized output. Equal client weighting is explicit;
/// this is not a sample-weighted average. Application code still needs the
/// honest-evaluator assumption until computation authentication is implemented.
#[derive(Debug)]
pub struct ReleasedSum {
    pub task: super::descriptor::TaskDescriptor,
    pub accepted: u64,
    pub sum: Vec<f64>,
}

impl<'a> CollectorSession<'a> {
    pub fn new(task: &'a PineTask, root: &Path, max_reports: usize) -> Result<(Self, PublicKey)> {
        if max_reports < task.descriptor().min_accepted as usize || max_reports > task.descriptor().identities.len() || max_reports as u64 > task.max_batch() {
            return Err(Error::Protocol("collector report budget is invalid".into()));
        }
        let ledger = Ledger::open(root, task, "session")?;
        // Only one instance/key can ever serve this task in this ledger.
        ledger.reserve("created", b"task")?;
        let (inner, pk) = PineCollector::new(task, root)?;
        Ok((
            Self {
                inner,
                ledger,
                phase: Phase::Ready,
                max_reports,
                max_check_bytes: task.check_request_len(max_reports),
                aggregate_bytes: task.aggregate_request_len(),
            },
            pk,
        ))
    }

    /// Includes admission measurements as well as verifier/aggregate openings.
    /// For local audit only; do not expose this counter as a network response.
    pub fn secret_key_operations(&self) -> u64 {
        self.inner.secret_key_operations()
    }

    pub fn check(&mut self, bytes: &[u8]) -> std::result::Result<Vec<u8>, Refused> {
        if self.phase != Phase::Ready {
            return Err(Refused);
        }
        self.phase = Phase::Closed;
        self.ledger.reserve("check", b"once").map_err(|_| Refused)?;
        if bytes.len() < 4 || bytes.len() > self.max_check_bytes {
            return Err(Refused);
        }
        let count = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Refused)?) as usize;
        if count > self.max_reports {
            return Err(Refused);
        }
        let verdict = self.inner.check(bytes).map_err(|_| Refused)?;
        if self.inner.accepted().unwrap_or(0) < u64::from(self.inner.task.descriptor().min_accepted) {
            return Err(Refused);
        }
        self.phase = Phase::AwaitingAggregate;
        Ok(verdict)
    }

    pub fn release(&mut self, bytes: &[u8]) -> std::result::Result<ReleasedSum, Refused> {
        if self.phase != Phase::AwaitingAggregate {
            return Err(Refused);
        }
        self.phase = Phase::Closed;
        self.ledger.reserve("release", b"once").map_err(|_| Refused)?;
        if bytes.len() != self.aggregate_bytes {
            return Err(Refused);
        }
        let accepted = self.inner.accepted().ok_or(Refused)?;
        let sum = self.inner.unshard(bytes).map_err(|_| Refused)?;
        Ok(ReleasedSum {
            task: self.inner.task.descriptor().clone(),
            accepted,
            sum,
        })
    }
}
