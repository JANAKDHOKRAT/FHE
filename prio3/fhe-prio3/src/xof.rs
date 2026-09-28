//! Extendable-output function used to derive verification randomness.
//!
//! SHAKE128 with a fixed domain-separation prefix. Field elements are sampled
//! by rejection from 32-bit words, so the output is exactly uniform in
//! `[0, p)` (no modular bias).

use crate::field::Field;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};

pub const DOMAIN: &[u8] = b"fhe-prio3/1";

pub struct Xof {
    reader: Shake128Reader,
}

impl Xof {
    /// `usage` separates independent streams; `binder` fixes what the
    /// randomness commits to (task configuration and report identifier).
    pub fn new(usage: &[u8], binder: &[&[u8]]) -> Self {
        let mut h = Shake128::default();
        h.update(&(DOMAIN.len() as u32).to_le_bytes());
        h.update(DOMAIN);
        h.update(&(usage.len() as u32).to_le_bytes());
        h.update(usage);
        h.update(&(binder.len() as u32).to_le_bytes());
        for b in binder {
            h.update(&(b.len() as u64).to_le_bytes());
            h.update(b);
        }
        Self { reader: h.finalize_xof() }
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.reader.read(&mut b);
        u32::from_le_bytes(b)
    }

    /// Uniform element of `[0, p)`.
    pub fn next_field_elem(&mut self, f: &Field) -> u64 {
        let p = f.modulus();
        loop {
            let v = self.next_u32() as u64;
            if v < p {
                return v;
            }
        }
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_and_separated() {
        let f = Field::new(4_293_918_721).unwrap();
        let a: Vec<u64> = { let mut x = Xof::new(b"t", &[b"a", b"b"]); (0..8).map(|_| x.next_field_elem(&f)).collect() };
        let b: Vec<u64> = { let mut x = Xof::new(b"t", &[b"a", b"b"]); (0..8).map(|_| x.next_field_elem(&f)).collect() };
        let c: Vec<u64> = { let mut x = Xof::new(b"t", &[b"ab", b""]); (0..8).map(|_| x.next_field_elem(&f)).collect() };
        let d: Vec<u64> = { let mut x = Xof::new(b"u", &[b"a", b"b"]); (0..8).map(|_| x.next_field_elem(&f)).collect() };
        assert_eq!(a, b);
        assert_ne!(a, c, "length-prefixing must separate (a,b) from (ab,)");
        assert_ne!(a, d);
        assert!(a.iter().all(|&v| v < f.modulus()));
    }
}
