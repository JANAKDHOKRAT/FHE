//! Sealing of aggregate shares to a collector's X25519 key.
//!
//! The leader relays every aggregator's share to the collector. Without
//! sealing it could fuse them with its own and read every released
//! aggregate. With sealing each aggregator encrypts its share to the
//! collector named in the task, so the leader carries opaque bytes and a
//! release is read by its collector only. Construction: ephemeral X25519
//! Diffie–Hellman with the collector's static key, HKDF-SHA256 over the
//! shared secret with both public keys in the info, AES-256-GCM with a
//! random nonce, and associated data binding the task, the collector and
//! the aggregator index. One fresh key per message.

use crate::error::{Error, Result};
use crate::messages::{AggregateShare, ReleaseReveal, decode, encode};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub const SEAL_DOMAIN: &[u8] = b"fhe-prio3/1 sealed-share";
/// Domain of sealed release reveals (`vdec` check partials): a sealed
/// reveal never opens as a share, nor a share as a reveal.
pub const SEAL_REVEAL_DOMAIN: &[u8] = b"fhe-prio3/1 sealed-reveal";

/// A collector's long-term sealing key pair.
pub struct CollectorSealKey {
    secret: StaticSecret,
}

impl CollectorSealKey {
    pub fn generate() -> Self {
        Self { secret: StaticSecret::random_from_rng(rand_core::OsRng) }
    }
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self { secret: StaticSecret::from(*bytes) }
    }
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SealedShare {
    pub task_id: [u8; 32],
    pub collector: u32,
    pub aggregator: usize,
    pub ephemeral: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

fn aad(domain: &[u8], task_id: &[u8; 32], collector: u32, aggregator: usize) -> Vec<u8> {
    let mut a = Vec::with_capacity(domain.len() + 44);
    a.extend_from_slice(domain);
    a.extend_from_slice(task_id);
    a.extend_from_slice(&collector.to_le_bytes());
    a.extend_from_slice(&(aggregator as u64).to_le_bytes());
    a
}

fn derive_key(domain: &[u8], shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut info = Vec::with_capacity(domain.len() + 64);
    info.extend_from_slice(domain);
    info.extend_from_slice(ephemeral);
    info.extend_from_slice(recipient);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).map_err(|_| Error::Protocol("hkdf expand".into()))?;
    Ok(key)
}

fn seal_bytes(domain: &[u8], task_id: [u8; 32], collector: u32, aggregator: usize, plain: &[u8], collector_key: &[u8; 32]) -> Result<SealedShare> {
    let recipient = PublicKey::from(*collector_key);
    let eph = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_pk = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(Error::Protocol("collector sealing key is a low-order point".into()));
    }
    let key = derive_key(domain, shared.as_bytes(), &eph_pk, collector_key)?;
    let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    let mut nonce = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: &aad(domain, &task_id, collector, aggregator) })
        .map_err(|_| Error::Protocol("seal".into()))?;
    Ok(SealedShare { task_id, collector, aggregator, ephemeral: eph_pk, nonce, ciphertext })
}

fn open_bytes(domain: &[u8], sealed: &SealedShare, key: &CollectorSealKey) -> Result<Vec<u8>> {
    let shared = key.secret.diffie_hellman(&PublicKey::from(sealed.ephemeral));
    if !shared.was_contributory() {
        return Err(Error::Protocol("ephemeral key is a low-order point".into()));
    }
    let k = derive_key(domain, shared.as_bytes(), &sealed.ephemeral, &key.public_key())?;
    let cipher = Aes256Gcm::new_from_slice(&k).expect("32-byte key");
    cipher
        .decrypt(Nonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ciphertext, aad: &aad(domain, &sealed.task_id, sealed.collector, sealed.aggregator) })
        .map_err(|_| Error::Protocol("sealed message does not open: wrong collector key, wrong kind or tampered".into()))
}

/// Seals `share` (which must carry `collector`) to the collector's public key.
pub fn seal(share: &AggregateShare, collector_key: &[u8; 32]) -> Result<SealedShare> {
    seal_bytes(SEAL_DOMAIN, share.task_id, share.collector, share.aggregator, &encode(share)?, collector_key)
}

/// Opens a sealed share with the collector's secret. Fails on any change to
/// the ciphertext, the ephemeral key, the nonce, the task, the collector id
/// or the aggregator index, and when the opened share disagrees with the
/// envelope's header.
pub fn open(sealed: &SealedShare, key: &CollectorSealKey) -> Result<AggregateShare> {
    let share: AggregateShare = decode(&open_bytes(SEAL_DOMAIN, sealed, key)?)?;
    if share.task_id != sealed.task_id || share.collector != sealed.collector || share.aggregator != sealed.aggregator {
        return Err(Error::Protocol("sealed share header does not match its content".into()));
    }
    Ok(share)
}

/// Seals a release reveal (check partials) to the collector's public key.
pub fn seal_reveal(r: &ReleaseReveal, collector_key: &[u8; 32]) -> Result<SealedShare> {
    seal_bytes(SEAL_REVEAL_DOMAIN, r.task_id, r.collector, r.aggregator, &encode(r)?, collector_key)
}

/// Opens a sealed release reveal (same checks as [`open`]).
pub fn open_reveal(sealed: &SealedShare, key: &CollectorSealKey) -> Result<ReleaseReveal> {
    let r: ReleaseReveal = decode(&open_bytes(SEAL_REVEAL_DOMAIN, sealed, key)?)?;
    if r.task_id != sealed.task_id || r.collector != sealed.collector || r.aggregator != sealed.aggregator {
        return Err(Error::Protocol("sealed reveal header does not match its content".into()));
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(collector: u32, aggregator: usize) -> AggregateShare {
        AggregateShare {
            task_id: [3u8; 32],
            collector,
            aggregator,
            batch_digest: [4u8; 32],
            report_count: 7,
            partials: vec![vec![1, 2, 3], vec![4, 5]],
            valid_count_partial: Some(vec![9]),
            moment_partials: vec![vec![6, 7]],
            accumulators: vec![vec![8]],
        }
    }

    #[test]
    fn seal_roundtrip_and_rejections() {
        let k = CollectorSealKey::generate();
        let k2 = CollectorSealKey::from_secret_bytes(&k.secret_bytes());
        assert_eq!(k.public_key(), k2.public_key());
        let s = share(1, 0);
        let sealed = seal(&s, &k.public_key()).unwrap();
        let opened = open(&sealed, &k2).unwrap();
        assert_eq!(encode(&opened).unwrap(), encode(&s).unwrap());
        // two seals of the same share differ (fresh ephemeral key and nonce)
        let sealed2 = seal(&s, &k.public_key()).unwrap();
        assert_ne!(sealed.ciphertext, sealed2.ciphertext);
        assert_ne!(sealed.ephemeral, sealed2.ephemeral);
        // another collector's key does not open it
        assert!(open(&sealed, &CollectorSealKey::generate()).is_err());
        // any header change breaks the associated data
        let mut t = sealed.clone();
        t.collector = 0;
        assert!(open(&t, &k).is_err());
        let mut t = sealed.clone();
        t.aggregator = 1;
        assert!(open(&t, &k).is_err());
        let mut t = sealed.clone();
        t.task_id[0] ^= 1;
        assert!(open(&t, &k).is_err());
        let mut t = sealed.clone();
        t.ciphertext[5] ^= 1;
        assert!(open(&t, &k).is_err());
        let mut t = sealed.clone();
        t.nonce[0] ^= 1;
        assert!(open(&t, &k).is_err());
        let mut t = sealed.clone();
        t.ephemeral[0] ^= 1;
        assert!(open(&t, &k).is_err());
        // a share whose content names another collector cannot be re-labelled
        let mut wrong = share(1, 0);
        wrong.collector = 2;
        let sealed_wrong = seal(&wrong, &k.public_key()).unwrap();
        let mut relabel = sealed_wrong.clone();
        relabel.collector = 1;
        assert!(open(&relabel, &k).is_err());
    }
}
