use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("invalid measurement: {0}")]
    Measurement(String),
    #[error("report rejected: {0}")]
    Reject(RejectReason),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error(transparent)]
    Fhe(#[from] openfhe_tbgv_rs::Error),
}

/// Why an aggregator refused a report before or during verification.
/// These are all deterministic decisions, so honest aggregators agree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RejectReason {
    WrongTask,
    ReportIdMismatch,
    Replay,
    WrongChunkCount { expected: usize, got: usize },
    MalformedCiphertext(String),
    ValidityCheckFailed,
    BatchFull,
    BatchClosed,
    TooLarge { limit: usize, got: usize },
    /// Policy requires a signature and none was supplied, or it did not verify.
    Unauthenticated(String),
    /// The signing key is not in the aggregator's registry.
    UnknownClient,
    /// The signing key has used up its reports for this batch.
    QuotaExceeded,
    /// Group out of range for the layout, or non-zero outside batched silent mode.
    BadGroup,
    /// The chunk was encrypted for other parameters or another joint key
    /// (its fingerprint does not match this task's public material).
    WrongParameters,
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub type Result<T> = std::result::Result<T, Error>;
