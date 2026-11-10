//! The canonical description of a PINE task: what every party must agree on
//! before a report is made, in one versioned binary encoding. Its hash
//! (with the cryptographic parameters) is part of every derivation and of
//! every signature.
use super::PineParams;
use crate::{Error, Result};
use ed25519_dalek::VerifyingKey;

/// Version of this encoding and of the protocol it describes.
pub const VERSION: u16 = 1;
const MAGIC: &[u8; 8] = b"PINEBGV\0";
const FIXED_LEN: usize = 8 + 2 + 32 + 32 + 8 + 8 + 8 + 4 * 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskDescriptor {
    /// The application's identifier of this aggregation.
    pub application: [u8; 32],
    /// Hash of the model the gradients are for.
    pub model_hash: [u8; 32],
    /// The training round. One report per identity is accepted per task,
    /// and a task is one round.
    pub round: u64,
    pub params: PineParams,
    /// Release policy: the sum is released only when at least this many
    /// reports were accepted (at least 1).
    pub min_accepted: u32,
    /// The Ed25519 verification keys of the clients authorized to report,
    /// in strictly increasing byte order.
    pub identities: Vec<[u8; 32]>,
}

impl TaskDescriptor {
    /// Refused: no identity, identities not strictly increasing or not
    /// Ed25519 keys, a release threshold of 0 or above the cohort.
    pub fn validate(&self) -> Result<()> {
        let err = |m: &str| Error::Protocol(format!("task descriptor: {m}"));
        if self.identities.is_empty() || self.identities.len() > u32::MAX as usize {
            return Err(err("between 1 and 2^32 - 1 identities"));
        }
        if self.identities.windows(2).any(|w| w[0] >= w[1]) {
            return Err(err("identities must be distinct and in increasing order"));
        }
        if self.identities.iter().any(|k| VerifyingKey::from_bytes(k).is_err()) {
            return Err(err("an identity is not an Ed25519 verification key"));
        }
        if self.min_accepted == 0 || self.min_accepted as usize > self.identities.len() {
            return Err(err("the release threshold must be between 1 and the number of identities"));
        }
        Ok(())
    }

    /// The index of an authorized identity.
    pub fn identity_index(&self, identity: &[u8; 32]) -> Option<u32> {
        self.identities.binary_search(identity).ok().map(|i| i as u32)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let p = &self.params;
        let narrow = |v: usize| u32::try_from(v).map_err(|_| Error::Protocol("task descriptor: a parameter exceeds 32 bits".into()));
        let mut out = Vec::with_capacity(FIXED_LEN + 32 * self.identities.len());
        out.extend(MAGIC);
        out.extend(VERSION.to_le_bytes());
        out.extend(self.application);
        out.extend(self.model_hash);
        out.extend(self.round.to_le_bytes());
        out.extend((p.dimension as u64).to_le_bytes());
        out.extend(p.l2_norm_bound.to_le_bytes());
        for v in [
            p.num_frac_bits,
            narrow(p.chunk_length)?,
            narrow(p.chunk_length_norm_equality)?,
            narrow(p.num_proofs)?,
            narrow(p.num_proofs_norm_equality)?,
            self.min_accepted,
            self.identities.len() as u32,
        ] {
            out.extend(v.to_le_bytes());
        }
        for k in &self.identities {
            out.extend(k);
        }
        Ok(out)
    }

    /// The descriptor of exactly these bytes: any other length, version or
    /// ordering is refused, so equal descriptors have equal encodings.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let err = |m: &str| Error::Codec(format!("task descriptor: {m}"));
        if bytes.len() < FIXED_LEN || &bytes[..8] != MAGIC {
            return Err(err("not a task descriptor"));
        }
        if u16::from_le_bytes([bytes[8], bytes[9]]) != VERSION {
            return Err(err("unsupported version"));
        }
        let u64_at = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().expect("length checked"));
        let u32_at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().expect("length checked"));
        let count = u32_at(FIXED_LEN - 4) as usize;
        if bytes.len() != FIXED_LEN + 32 * count {
            return Err(err("wrong length"));
        }
        let descriptor = Self {
            application: bytes[10..42].try_into().expect("length checked"),
            model_hash: bytes[42..74].try_into().expect("length checked"),
            round: u64_at(74),
            params: PineParams {
                dimension: usize::try_from(u64_at(82)).map_err(|_| err("dimension"))?,
                l2_norm_bound: u64_at(90),
                num_frac_bits: u32_at(98),
                chunk_length: u32_at(102) as usize,
                chunk_length_norm_equality: u32_at(106) as usize,
                num_proofs: u32_at(110) as usize,
                num_proofs_norm_equality: u32_at(114) as usize,
            },
            min_accepted: u32_at(118),
            identities: bytes[FIXED_LEN..].chunks(32).map(|k| k.try_into().expect("length checked")).collect(),
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn descriptor() -> TaskDescriptor {
        let mut identities: Vec<[u8; 32]> = (1..=3u8).map(|i| SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes()).collect();
        identities.sort();
        TaskDescriptor {
            application: [1; 32],
            model_hash: [2; 32],
            round: 7,
            params: PineParams {
                dimension: 20,
                l2_norm_bound: 128,
                num_frac_bits: 7,
                chunk_length: 4,
                chunk_length_norm_equality: 4,
                num_proofs: 5,
                num_proofs_norm_equality: 1,
            },
            min_accepted: 2,
            identities,
        }
    }

    #[test]
    fn encoding_is_canonical_and_strict() {
        let d = descriptor();
        let bytes = d.encode().unwrap();
        assert_eq!(bytes.len(), FIXED_LEN + 96);
        assert_eq!(TaskDescriptor::decode(&bytes).unwrap(), d);
        assert_eq!(d.identity_index(&d.identities[2]), Some(2));
        assert_eq!(d.identity_index(&[0; 32]), None);
        // Every field changes the encoding.
        let variants = [
            TaskDescriptor {
                application: [9; 32],
                ..d.clone()
            },
            TaskDescriptor {
                model_hash: [9; 32],
                ..d.clone()
            },
            TaskDescriptor { round: 8, ..d.clone() },
            TaskDescriptor { min_accepted: 1, ..d.clone() },
            TaskDescriptor {
                params: PineParams {
                    num_proofs: 7,
                    ..d.params.clone()
                },
                ..d.clone()
            },
            TaskDescriptor {
                identities: d.identities[..2].to_vec(),
                ..d.clone()
            },
        ];
        for v in &variants {
            assert_ne!(v.encode().unwrap(), bytes);
        }
        // Refused: truncation, trailing bytes, another version, another magic.
        assert!(TaskDescriptor::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(TaskDescriptor::decode(&[bytes.clone(), vec![0]].concat()).is_err());
        let mut other = bytes.clone();
        other[8] = 2;
        assert!(TaskDescriptor::decode(&other).is_err());
        other = bytes.clone();
        other[0] ^= 1;
        assert!(TaskDescriptor::decode(&other).is_err());
        // Refused: identities out of order or repeated, in the struct and on the wire.
        let mut swapped = d.clone();
        swapped.identities.swap(0, 1);
        assert!(swapped.encode().is_err());
        let mut wire = bytes.clone();
        let (a, b) = (FIXED_LEN, FIXED_LEN + 32);
        let first: Vec<u8> = wire[a..b].to_vec();
        wire.copy_within(b..b + 32, a);
        wire[b..b + 32].copy_from_slice(&first);
        assert!(TaskDescriptor::decode(&wire).is_err());
        let mut repeated = d.clone();
        repeated.identities[1] = repeated.identities[0];
        assert!(repeated.validate().is_err());
        // Refused: a release threshold of 0 or above the cohort, no identity.
        assert!(TaskDescriptor { min_accepted: 0, ..d.clone() }.validate().is_err());
        assert!(TaskDescriptor { min_accepted: 4, ..d.clone() }.validate().is_err());
        assert!(TaskDescriptor { identities: vec![], ..d }.validate().is_err());
    }
}
