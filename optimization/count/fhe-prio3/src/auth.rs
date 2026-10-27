//! Client authentication: Ed25519 signatures over the report identifier by
//! keys an aggregator-side registry accepts, plus per-client quotas.
//!
//! What this buys (see the spec): a party that is not a registered client
//! cannot get any report verified, so the verdict-round oracle of verdict
//! mode is limited to identities the adversary controls, each of which is
//! rate-limited per batch and attributable. It does not by itself stop a
//! registered-but-malicious client from probing with its own quota.

use crate::error::{Error, Result};
use crate::messages::ReportId;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

pub const AUTH_DOMAIN: &[u8] = b"fhe-prio3/1 report-auth";

/// Authentication data attached to a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportAuth {
    pub client_key: [u8; 32],
    /// 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
}

/// Message a client signs: the domain, the task and the report identifier,
/// which itself commits to every ciphertext byte.
pub fn signing_message(task_id: &[u8; 32], report_id: &ReportId) -> Vec<u8> {
    let mut m = Vec::with_capacity(AUTH_DOMAIN.len() + 64);
    m.extend_from_slice(AUTH_DOMAIN);
    m.extend_from_slice(task_id);
    m.extend_from_slice(report_id);
    m
}

/// A client's long-term signing identity.
pub struct ClientIdentity {
    key: SigningKey,
}

impl ClientIdentity {
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut rand_core::OsRng),
        }
    }
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
        }
    }
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    pub fn sign(&self, task_id: &[u8; 32], report_id: &ReportId) -> ReportAuth {
        let sig = self.key.sign(&signing_message(task_id, report_id));
        ReportAuth {
            client_key: self.public_key(),
            signature: sig.to_bytes().to_vec(),
        }
    }
}

/// Verifies a report's signature. Constant-cost and run before any
/// ciphertext is parsed.
pub fn verify(auth: &ReportAuth, task_id: &[u8; 32], report_id: &ReportId) -> Result<()> {
    let vk = VerifyingKey::from_bytes(&auth.client_key).map_err(|_| Error::Protocol("invalid client public key".into()))?;
    let sig_bytes: [u8; 64] = auth
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::Protocol("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(&signing_message(task_id, report_id), &sig)
        .map_err(|_| Error::Protocol("bad signature".into()))
}

/// The set of client keys an aggregator accepts. Production deployments
/// implement this over their enrolment database; `StaticRegistry` is the
/// in-memory version.
pub trait ClientRegistry: Send + Sync {
    fn is_registered(&self, client_key: &[u8; 32]) -> bool;
}

pub struct StaticRegistry {
    keys: HashSet<[u8; 32]>,
}

impl StaticRegistry {
    pub fn new(keys: impl IntoIterator<Item = [u8; 32]>) -> Arc<Self> {
        Arc::new(Self {
            keys: keys.into_iter().collect(),
        })
    }
}

impl ClientRegistry for StaticRegistry {
    fn is_registered(&self, client_key: &[u8; 32]) -> bool {
        self.keys.contains(client_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sign_and_verify() {
        let id = ClientIdentity::generate();
        let task = [1u8; 32];
        let rid = [2u8; 32];
        let auth = id.sign(&task, &rid);
        assert!(verify(&auth, &task, &rid).is_ok());
        assert!(verify(&auth, &task, &[3u8; 32]).is_err(), "signature is bound to the report");
        assert!(verify(&auth, &[9u8; 32], &rid).is_err(), "signature is bound to the task");
        let mut bad = auth.clone();
        bad.signature[0] ^= 1;
        assert!(verify(&bad, &task, &rid).is_err());
        let other = ClientIdentity::generate();
        let mut swapped = auth.clone();
        swapped.client_key = other.public_key();
        assert!(verify(&swapped, &task, &rid).is_err());
        let again = ClientIdentity::from_secret_bytes(&id.secret_bytes());
        assert_eq!(again.public_key(), id.public_key());
        let reg = StaticRegistry::new([id.public_key()]);
        assert!(reg.is_registered(&id.public_key()));
        assert!(!reg.is_registered(&other.public_key()));
    }
}
