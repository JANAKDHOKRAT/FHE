//! Prio3's fully linear proofs (FLP), verified under threshold BGV.
//!
//! A client encodes its measurement as Prio3 does, proves it with the
//! generic FLP of `prio` 0.18.1 (draft-irtf-cfrg-vdaf, BBCGGI19), and
//! encrypts `input || proof_1 || .. || proof_k` as the coefficients of ONE
//! BGV plaintext polynomial under an n-of-n threshold key. The FLP verifier
//! is affine in `(input, proof)` once its randomness is fixed, so the
//! aggregators evaluate it as one plaintext x ciphertext product per group
//! of verifier rows (depth 0: no relinearisation or rotation keys) and
//! decrypt, with flooding, only the coefficients that hold the verifier
//! message: exactly what Prio3 reveals to its aggregators. They run Prio3's
//! `decide`, add accepted ciphertexts, and finally decrypt only the output
//! coefficients of the sum for the collector.
//!
//! See `DESIGN.md` for the protocol, the security argument and its limits.
pub mod bitvec;
pub mod codec;
pub mod protocol;
pub mod single;
pub mod soundness;

pub use protocol::*;

/// The FLP field and the BGV plaintext modulus: `GF(4293918721)`, prio's
/// `FieldPrio2` (the plaintext prime `fhe-prio3` also uses).
pub type Field = prio::field::FieldPrio2;
pub const PLAIN_MOD: u64 = 4_293_918_721;

#[derive(Debug)]
pub enum Error {
    /// The FHE library refused an operation.
    Fhe(String),
    /// The FLP refused an input (malformed lengths, parameters).
    Flp(String),
    /// Bytes that do not decode.
    Codec(String),
    /// A protocol rule was violated (duplicate report, wrong share count, ..).
    Protocol(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Fhe(m) => write!(f, "fhe: {m}"),
            Error::Flp(m) => write!(f, "flp: {m}"),
            Error::Codec(m) => write!(f, "codec: {m}"),
            Error::Protocol(m) => write!(f, "protocol: {m}"),
        }
    }
}
impl std::error::Error for Error {}

impl From<openfhe_tbgv_rs::Error> for Error {
    fn from(e: openfhe_tbgv_rs::Error) -> Self {
        Error::Fhe(e.0)
    }
}
impl From<prio::flp::FlpError> for Error {
    fn from(e: prio::flp::FlpError) -> Self {
        Error::Flp(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
