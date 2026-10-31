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
pub mod f65537;
pub mod protocol;
pub mod single;
pub mod soundness;

pub use protocol::*;

/// The FLP field and the BGV plaintext modulus: `GF(4293918721)`, prio's
/// `FieldPrio2` (the plaintext prime `fhe-prio3` also uses).
pub type Field = prio::field::FieldPrio2;
pub const PLAIN_MOD: u64 = 4_293_918_721;

/// A prime field that is both the FLP field and the BGV plaintext modulus,
/// with the one-aggregator modulus chain measured for it
/// (`openfhe-tbgv-rs/tests/single_key.rs`: worst-case flooding margin at
/// least 64 bits at ring 8192).
pub trait FheField: prio::field::NttFriendlyFieldElement + prio::field::FieldElementWithInteger<Integer = u32> + Send + Sync {
    const PLAIN_MOD: u64;
    const SINGLE_FIRST_MOD_BITS: u32;
    const SINGLE_SCALING_MOD_BITS: u32;
    const SINGLE_NUM_TOWERS: u32;
    fn to_u64(self) -> u64;
    /// `v` must be below `p` (decrypted coefficients are).
    fn from_u64(v: u64) -> Self {
        Self::from(u32::try_from(v).expect("value below p < 2^32"))
    }
}

/// p = 4293918721: chain [60, 55, 55] (Q = 170 bits), lambda = 86.7.
impl FheField for Field {
    const PLAIN_MOD: u64 = PLAIN_MOD;
    const SINGLE_FIRST_MOD_BITS: u32 = 60;
    const SINGLE_SCALING_MOD_BITS: u32 = 55;
    const SINGLE_NUM_TOWERS: u32 = 3;
    fn to_u64(self) -> u64 {
        u64::from(u32::from(self))
    }
}

/// p = 65537: chain [40, 40, 40] (Q = 120 bits), lambda = 68.0.
impl FheField for f65537::Field65537 {
    const PLAIN_MOD: u64 = 65_537;
    const SINGLE_FIRST_MOD_BITS: u32 = 40;
    const SINGLE_SCALING_MOD_BITS: u32 = 40;
    const SINGLE_NUM_TOWERS: u32 = 3;
    fn to_u64(self) -> u64 {
        u64::from(u32::from(self))
    }
}

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
