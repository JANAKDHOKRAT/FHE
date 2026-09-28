//! Material attestation: every aggregator signs the public material of a
//! task with a long-term Ed25519 identity, and a client accepts material
//! only when each aggregator's signature verifies against the aggregator
//! keys it holds out of band.
//!
//! Why: a client must encrypt under the *joint* public key of the
//! aggregators. Whoever hands the client that key (a file, a router, any
//! service) could substitute a key of its own and read that client's
//! measurement. With attestation the client trusts the aggregators'
//! identities, pinned like their TLS roots, and nothing in between: a
//! substituted key would need every aggregator's signature, which is the
//! same collusion that breaks the scheme anyway. The signed message binds
//! the task (its digest), the context, the public key, the joint tag and
//! the rotation indices, so a task or parameter substitution fails too.

use crate::config::TaskConfig;
use crate::error::{Error, Result};
use crate::messages::PublicMaterial;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ATTEST_DOMAIN: &[u8] = b"fhe-prio3/1 material";

/// An aggregator's long-term signing identity.
pub struct AggregatorIdentity {
    key: SigningKey,
}

impl AggregatorIdentity {
    pub fn generate() -> Self {
        Self { key: SigningKey::generate(&mut rand_core::OsRng) }
    }
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self { key: SigningKey::from_bytes(bytes) }
    }
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterialAttestation {
    pub aggregator: usize,
    pub aggregator_key: [u8; 32],
    /// 64-byte Ed25519 signature over [`material_message`].
    pub signature: Vec<u8>,
}

/// The signed message. It covers what a client uses (context, public key,
/// joint tag, rotation indices) and the task digest; evaluation keys are
/// not part of it, since clients never receive them.
pub fn material_message(cfg: &TaskConfig, m: &PublicMaterial) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(ATTEST_DOMAIN);
    h.update(cfg.digest());
    h.update((m.context.len() as u64).to_le_bytes());
    h.update(&m.context);
    h.update((m.public_key.len() as u64).to_le_bytes());
    h.update(&m.public_key);
    h.update((m.joint_tag.len() as u64).to_le_bytes());
    h.update(m.joint_tag.as_bytes());
    h.update((m.rotation_indices.len() as u64).to_le_bytes());
    for i in &m.rotation_indices {
        h.update(i.to_le_bytes());
    }
    let mut msg = Vec::with_capacity(ATTEST_DOMAIN.len() + 32);
    msg.extend_from_slice(ATTEST_DOMAIN);
    msg.extend_from_slice(&h.finalize());
    msg
}

/// Signs the material as aggregator `index`.
pub fn attest(cfg: &TaskConfig, m: &PublicMaterial, index: usize, id: &AggregatorIdentity) -> MaterialAttestation {
    let sig = id.key.sign(&material_message(cfg, m));
    MaterialAttestation { aggregator: index, aggregator_key: id.public_key(), signature: sig.to_bytes().to_vec() }
}

/// Verifies that the material carries a valid attestation from every
/// aggregator, where `pinned[i]` is the identity key of aggregator `i`.
/// Fails on a missing, duplicated or mismatched aggregator, a key that is
/// not the pinned one, or a bad signature.
pub fn verify_material(cfg: &TaskConfig, m: &PublicMaterial, pinned: &[[u8; 32]]) -> Result<()> {
    if pinned.len() != cfg.num_aggregators {
        return Err(Error::Config(format!("{} pinned aggregator keys for a task with {} aggregators", pinned.len(), cfg.num_aggregators)));
    }
    let msg = material_message(cfg, m);
    let mut seen = vec![false; cfg.num_aggregators];
    for a in &m.attestations {
        if a.aggregator >= cfg.num_aggregators || std::mem::replace(&mut seen[a.aggregator], true) {
            return Err(Error::Protocol("attestation for an out-of-range or repeated aggregator".into()));
        }
        if a.aggregator_key != pinned[a.aggregator] {
            return Err(Error::Protocol(format!("attestation of aggregator {} is not under its pinned key", a.aggregator)));
        }
        let vk = VerifyingKey::from_bytes(&a.aggregator_key).map_err(|_| Error::Protocol("invalid aggregator public key".into()))?;
        let sig_bytes: [u8; 64] = a.signature.as_slice().try_into().map_err(|_| Error::Protocol("attestation signature must be 64 bytes".into()))?;
        vk.verify_strict(&msg, &Signature::from_bytes(&sig_bytes)).map_err(|_| Error::Protocol(format!("bad attestation from aggregator {}", a.aggregator)))?;
    }
    if let Some(i) = seen.iter().position(|s| !s) {
        return Err(Error::Protocol(format!("material is not attested by aggregator {i}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MeasurementType;

    fn material(tag: &str) -> PublicMaterial {
        PublicMaterial {
            context: vec![1, 2, 3],
            public_key: vec![4, 5, 6, 7],
            joint_tag: tag.into(),
            eval_mult_key: vec![9],
            rotation_keys: vec![vec![8]],
            rotation_indices: vec![1],
            attestations: Vec::new(),
        }
    }

    #[test]
    fn attestation_binds_task_material_and_identities() {
        let cfg = TaskConfig::new([1u8; 32], MeasurementType::Count, 2);
        let ids = [AggregatorIdentity::generate(), AggregatorIdentity::generate()];
        let pinned = [ids[0].public_key(), ids[1].public_key()];
        let mut m = material("t");
        m.attestations = ids.iter().enumerate().map(|(i, id)| attest(&cfg, &m, i, id)).collect();
        verify_material(&cfg, &m, &pinned).unwrap();

        // one attestation missing
        let mut one = m.clone();
        one.attestations.pop();
        assert!(verify_material(&cfg, &one, &pinned).is_err());
        // the same aggregator twice does not cover the other
        let mut dup = m.clone();
        dup.attestations[1] = dup.attestations[0].clone();
        assert!(verify_material(&cfg, &dup, &pinned).is_err());
        // a key that is not the pinned one, even with a valid signature
        let rogue = AggregatorIdentity::generate();
        let mut sub = m.clone();
        sub.attestations[1] = attest(&cfg, &sub, 1, &rogue);
        assert!(verify_material(&cfg, &sub, &pinned).is_err());
        // substituted public key (what a malicious router would do)
        let mut swapped = m.clone();
        swapped.public_key = vec![4, 5, 6, 8];
        assert!(verify_material(&cfg, &swapped, &pinned).is_err());
        // substituted context or joint tag
        let mut ctx = m.clone();
        ctx.context = vec![1, 2, 4];
        assert!(verify_material(&cfg, &ctx, &pinned).is_err());
        let mut tag = m.clone();
        tag.joint_tag = "u".into();
        assert!(verify_material(&cfg, &tag, &pinned).is_err());
        // attestations of one task do not carry to another task
        let other = TaskConfig::new([2u8; 32], MeasurementType::Count, 2);
        assert!(verify_material(&other, &m, &pinned).is_err());
        let mut other_min = cfg.clone();
        other_min.min_batch_size = 1000;
        assert!(verify_material(&other_min, &m, &pinned).is_err());
        // wrong number of pinned keys
        assert!(verify_material(&cfg, &m, &pinned[..1]).is_err());
        // evaluation keys are not covered: stripping them for clients keeps the attestation valid
        let mut stripped = m.clone();
        stripped.eval_mult_key.clear();
        stripped.rotation_keys.clear();
        verify_material(&cfg, &stripped, &pinned).unwrap();
    }
}
