//! Sealing of the key share at rest: AES-256-GCM with a key supplied by the
//! environment (a KMS or HSM hands the same 32 bytes to the process in a
//! real deployment). The share is never written unsealed.

use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Nonce};

pub const ENV_KEY: &str = "FHE_PRIO3_SEAL_KEY";

fn key_from_env() -> anyhow::Result<[u8; 32]> {
    let hexkey = std::env::var(ENV_KEY).map_err(|_| anyhow::anyhow!("{ENV_KEY} (64 hex chars) must be set to seal/unseal the key share"))?;
    let bytes = hex::decode(hexkey.trim())?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("{ENV_KEY} must decode to 32 bytes"))?;
    Ok(arr)
}

/// `nonce(12) || ciphertext`. Associated data binds the blob to a label.
pub fn seal(label: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = key_from_env()?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), aes_gcm::aead::Payload { msg: plaintext, aad: label })
        .map_err(|_| anyhow::anyhow!("seal failed"))?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(out)
}

pub fn unseal(label: &[u8], blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    if blob.len() < 12 {
        anyhow::bail!("sealed blob too short");
    }
    let key = key_from_env()?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    cipher
        .decrypt(Nonce::from_slice(&blob[..12]), aes_gcm::aead::Payload { msg: &blob[12..], aad: label })
        .map_err(|_| anyhow::anyhow!("unseal failed: wrong key or corrupted blob"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_tamper() {
        unsafe { std::env::set_var(ENV_KEY, hex::encode([7u8; 32])) };
        let blob = seal(b"share:0", b"secret").unwrap();
        assert_eq!(unseal(b"share:0", &blob).unwrap(), b"secret");
        assert!(unseal(b"share:1", &blob).is_err(), "label is authenticated");
        let mut bad = blob.clone();
        bad[20] ^= 1;
        assert!(unseal(b"share:0", &bad).is_err());
    }
}
