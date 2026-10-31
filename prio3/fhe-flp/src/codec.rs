//! Canonical bit-packing of RNS residues.
//!
//! Every message of the protocol is a sequence of blocks; a block holds
//! `per_tower` residues for each tower in order (tower-major), and each
//! residue of tower `t` takes exactly `bits[t] = ceil(log2 q_t)` bits. A
//! fresh ciphertext is two blocks of `N` (its two elements); a verifier or
//! aggregate share is one block of the decrypted coefficients. Decoding
//! refuses a wrong length, a residue at or above its modulus, and non-zero
//! padding, so every message has exactly one encoding.
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct ResidueCodec {
    moduli: Vec<u64>,
    bits: Vec<u32>,
}

impl ResidueCodec {
    pub fn new(moduli: &[u64]) -> Result<Self> {
        if moduli.is_empty() || moduli.iter().any(|&q| q < 2) {
            return Err(Error::Codec("moduli must be at least 2".into()));
        }
        let bits = moduli.iter().map(|&q| 64 - (q - 1).leading_zeros()).collect();
        Ok(Self { moduli: moduli.to_vec(), bits })
    }

    pub fn num_towers(&self) -> usize {
        self.moduli.len()
    }

    /// Bytes for `blocks` blocks of `per_tower` residues per tower.
    pub fn len(&self, blocks: usize, per_tower: usize) -> usize {
        let bits: usize = self.bits.iter().map(|&b| b as usize).sum();
        (blocks * per_tower * bits).div_ceil(8)
    }

    pub fn pack(&self, values: &[u64], blocks: usize, per_tower: usize) -> Result<Vec<u8>> {
        let towers = self.moduli.len();
        if values.len() != blocks * towers * per_tower {
            return Err(Error::Codec(format!("expected {} residues, got {}", blocks * towers * per_tower, values.len())));
        }
        let mut out = Vec::with_capacity(self.len(blocks, per_tower));
        let (mut acc, mut nacc) = (0u128, 0u32);
        for (i, &v) in values.iter().enumerate() {
            let t = (i / per_tower) % towers;
            if v >= self.moduli[t] {
                return Err(Error::Codec(format!("residue {v} not below modulus {}", self.moduli[t])));
            }
            acc |= (v as u128) << nacc;
            nacc += self.bits[t];
            while nacc >= 8 {
                out.push(acc as u8);
                acc >>= 8;
                nacc -= 8;
            }
        }
        if nacc > 0 {
            out.push(acc as u8);
        }
        debug_assert_eq!(out.len(), self.len(blocks, per_tower));
        Ok(out)
    }

    pub fn unpack(&self, bytes: &[u8], blocks: usize, per_tower: usize) -> Result<Vec<u64>> {
        let want = self.len(blocks, per_tower);
        if bytes.len() != want {
            return Err(Error::Codec(format!("expected {want} bytes, got {}", bytes.len())));
        }
        let towers = self.moduli.len();
        let count = blocks * towers * per_tower;
        let mut out = Vec::with_capacity(count);
        let (mut acc, mut nacc) = (0u128, 0u32);
        let mut it = bytes.iter();
        for i in 0..count {
            let t = (i / per_tower) % towers;
            let b = self.bits[t];
            while nacc < b {
                acc |= (*it.next().expect("length checked") as u128) << nacc;
                nacc += 8;
            }
            let v = (acc & ((1u128 << b) - 1)) as u64;
            acc >>= b;
            nacc -= b;
            if v >= self.moduli[t] {
                return Err(Error::Codec(format!("residue {v} not below modulus {}", self.moduli[t])));
            }
            out.push(v);
        }
        if acc != 0 || it.next().is_some() {
            return Err(Error::Codec("non-zero padding".into()));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_canonical() {
        let c = ResidueCodec::new(&[(1 << 47) - 115, 1 << 60 | 1, 65537]).unwrap();
        let per = 5;
        let vals: Vec<u64> = (0..2 * 3 * per as u64).map(|i| i * 7919 % 65537).collect();
        let b = c.pack(&vals, 2, per).unwrap();
        assert_eq!(b.len(), c.len(2, per));
        assert_eq!(c.unpack(&b, 2, per).unwrap(), vals);
        // wrong length
        assert!(c.unpack(&b[1..], 2, per).is_err());
        // a residue at its modulus
        let mut bad = vals.clone();
        bad[2 * per] = 65537;
        assert!(c.pack(&bad, 2, per).is_err());
        // non-zero padding: (47 + 61 + 17) * 10 = 1250 bits, 6 bits of padding
        let mut p = b.clone();
        *p.last_mut().unwrap() |= 0x80;
        assert!(c.unpack(&p, 2, per).is_err());
    }

    #[test]
    fn out_of_range_residue_in_bytes_is_refused() {
        let c = ResidueCodec::new(&[5]).unwrap();
        // 3 bits per residue; 7 >= 5
        assert!(c.unpack(&[0b0000_0111], 1, 1).is_err());
        assert_eq!(c.unpack(&[0b0000_0100], 1, 1).unwrap(), vec![4]);
    }
}
