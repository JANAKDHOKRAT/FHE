//! # fhe-prio3
//!
//! Prio3's measurement types with the validity check evaluated
//! homomorphically under an n-of-n threshold BGV key instead of proved with
//! an FLP over secret shares. See `FHE_PRIO3_SPEC.md` for the protocol,
//! the soundness bound and the threat model.
//!
//! Roles:
//! * [`client::Client`] encodes a measurement and encrypts it once under
//!   the joint public key.
//! * [`aggregator::Aggregator`] (one per key share) verifies each report,
//!   in two message rounds (verdict mode) or with no messages at all (silent
//!   mode), and accumulates accepted reports.
//! * [`collector::Collector`] fuses the aggregators' partial decryptions of
//!   the batch sums; it holds no key.

pub mod aggregator;
pub mod auth;
pub mod client;
pub mod collector;
pub mod config;
pub mod error;
pub mod field;
pub mod keys;
pub mod layout;
pub mod messages;
pub mod types;
pub mod verify;
pub mod xof;

pub use aggregator::{Aggregator, Verdict};
pub use client::Client;
pub use collector::Collector;
pub use auth::{ClientIdentity, ClientRegistry, StaticRegistry};
pub use config::{AuthPolicy, TaskConfig, VerificationMode};
pub use error::{Error, RejectReason, Result};
pub use messages::{AggregateShare, CountShare, MaskMessage, PublicMaterial, Report, VerifierMessage};
pub use types::{AggregateResult, BatchResult, Measurement, MeasurementType};
