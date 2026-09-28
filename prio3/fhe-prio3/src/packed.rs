//! Packed ciphertext wire format, version 1.
//!
//! Every ciphertext that crosses from one party to another (client report
//! chunks, verdict-mode masks, partial decryptions exchanged between
//! aggregators or sent to the collector) travels in this format. The receiver
//! parses it here, in safe Rust, and rebuilds the ciphertext inside its own
//! OpenFHE context from the residues and five metadata values
//! (`Context::build_ciphertext`). Bytes from another party are never handed
//! to OpenFHE's deserializer, whose loader trusts the vector lengths and
//! moduli it reads (a seeded mutation run crashed it with arithmetic faults,
//! an abort and a segmentation fault).
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//!  0       4    magic "FPC1"
//!  4       1    version = 1
//!  5       1    num_elements (1 or 2)
//!  6       2    num_towers (1..=L)
//!  8       4    level (level + num_towers = L)
//! 12       1    noise_scale_deg (1 or 2)
//! 13       3    reserved, zero
//! 16       8    scaling_factor_int (1 <= s < p)
//! 24      32    fingerprint of the parameters and the joint public key
//! 56       *    residues, element-major, then tower, then coefficient index;
//!               the residue of tower t occupies exactly bitlen(q_t) bits,
//!               least significant bit first, packed without gaps; the last
//!               byte's unused high bits are zero
//! ```
//!
//! `L` and the tower moduli `q_t` are the receiver's own (its context's full
//! chain; an object with `k` towers uses the first `k`). Decoding is
//! canonical: the length must be exact, reserved bytes and padding bits must
//! be zero and every residue must be below its tower modulus, so one
//! ciphertext has exactly one encoding and the report identifier (a hash of
//! these bytes) cannot be varied without changing the ciphertext.
//!
//! The fingerprint is the same for every party of a task: SHA-256 over a
//! domain string, the plaintext modulus, the ring dimension, the tower moduli
//! and SHA-256 of the joint public key bytes. It carries no information about
//! any client; it replaces the key-tag check that OpenFHE's own metadata
//! provided, so a client holding the wrong parameters or a stale key is
//! refused before any work instead of contributing garbage.

use crate::error::{Error, Result};
use openfhe_tbgv_rs::{Ciphertext, CiphertextMeta, Context, PublicKey};
use sha2::{Digest, Sha256};

pub const MAGIC: [u8; 4] = *b"FPC1";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 56;
const FINGERPRINT_DOMAIN: &[u8] = b"fhe-prio3/1 packed-ciphertext";

/// Why a packed ciphertext was refused. Every variant is decided in safe
/// Rust before any OpenFHE call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Truncated { len: usize },
    BadMagic,
    BadVersion(u8),
    NonZeroReserved,
    /// Encrypted for other parameters or another joint key.
    WrongParameters,
    BadShape(String),
    /// The shape is valid but not the one this message must have.
    UnexpectedShape { expected: CiphertextMeta, got: CiphertextMeta },
    BadLength { expected: usize, got: usize },
    ResidueOutOfRange { element: usize, tower: usize, index: usize },
    NonZeroPadding,
    /// The shim refused to build the ciphertext (it re-checks everything).
    Rebuild(String),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<WireError> for Error {
    fn from(e: WireError) -> Self {
        Error::Protocol(format!("packed ciphertext refused: {e}"))
    }
}

/// What shape a received ciphertext must have.
#[derive(Debug, Clone, Copy)]
pub enum Expect {
    /// Exactly this metadata (client chunks and masks: the metadata of a
    /// fresh encryption; partial decryptions exchanged between aggregators:
    /// the metadata of the receiver's own partial decryption of the same
    /// ciphertext).
    Exactly(CiphertextMeta),
    /// A partial decryption of a ciphertext the receiver did not compute
    /// (the collector): one element and otherwise any valid shape. The
    /// collector additionally requires every aggregator's share to have the
    /// same shape.
    Partial,
}

pub fn fingerprint(plain_mod: u64, ring_dim: u32, moduli: &[u64], public_key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((FINGERPRINT_DOMAIN.len() as u32).to_le_bytes());
    h.update(FINGERPRINT_DOMAIN);
    h.update(plain_mod.to_le_bytes());
    h.update(ring_dim.to_le_bytes());
    h.update((moduli.len() as u32).to_le_bytes());
    for q in moduli {
        h.update(q.to_le_bytes());
    }
    h.update(Sha256::digest(public_key));
    h.finalize().into()
}

fn bit_length(v: u64) -> u32 {
    64 - v.leading_zeros()
}

/// Encoder and decoder bound to one context and joint public key.
pub struct Codec {
    ctx: Context,
    moduli: Vec<u64>,
    widths: Vec<u32>,
    ring_dim: usize,
    plain_mod: u64,
    fingerprint: [u8; 32],
    /// A fresh encryption of zero made by this party under the joint key:
    /// the template every received ciphertext is rebuilt from.
    reference: Ciphertext,
    fresh: CiphertextMeta,
}

impl Codec {
    /// `public_key` is the serialized joint public key every party of the
    /// task holds (the task's public material); `pk` is it deserialized.
    pub fn new(ctx: &Context, pk: &PublicKey, public_key: &[u8]) -> Result<Self> {
        let moduli = ctx.moduli()?;
        // The header stores the tower count in 16 bits.
        if moduli.is_empty() || moduli.len() > u16::MAX as usize || moduli.iter().any(|&q| q < 2) {
            return Err(Error::Config("context has an invalid modulus chain".into()));
        }
        let widths = moduli.iter().map(|&q| bit_length(q - 1).max(1)).collect();
        let ring_dim = ctx.ring_dim() as usize;
        let reference = ctx.encrypt(pk, &ctx.plaintext(&[0])?)?;
        let fresh = reference.meta()?;
        if fresh.num_towers as usize != moduli.len() || fresh.level != 0 {
            return Err(Error::Config("a fresh encryption does not use the full modulus chain".into()));
        }
        let fp = fingerprint(ctx.plain_mod(), ctx.ring_dim(), &moduli, public_key);
        Ok(Self { ctx: ctx.clone(), moduli, widths, ring_dim, plain_mod: ctx.plain_mod(), fingerprint: fp, reference, fresh })
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Metadata of a fresh encryption under the joint key.
    pub fn fresh_meta(&self) -> CiphertextMeta {
        self.fresh
    }

    fn payload_bits(&self, meta: &CiphertextMeta) -> usize {
        let per_coeff: usize = self.widths[..meta.num_towers as usize].iter().map(|&w| w as usize).sum();
        meta.num_elements as usize * self.ring_dim * per_coeff
    }

    /// Exact encoded length of an object with this metadata.
    pub fn encoded_len(&self, meta: &CiphertextMeta) -> usize {
        HEADER_LEN + self.payload_bits(meta).div_ceil(8)
    }

    /// Encoded length of a fresh ciphertext (one report chunk or one mask).
    pub fn fresh_len(&self) -> usize {
        self.encoded_len(&self.fresh)
    }

    /// Checks the metadata bounds the shim enforces, here in Rust first.
    fn check_meta(&self, m: &CiphertextMeta) -> std::result::Result<(), WireError> {
        let l = self.moduli.len() as u64;
        if !(1..=2).contains(&m.num_elements) {
            return Err(WireError::BadShape(format!("num_elements {}", m.num_elements)));
        }
        if m.num_towers == 0 || m.num_towers as u64 > l {
            return Err(WireError::BadShape(format!("num_towers {}", m.num_towers)));
        }
        if m.level as u64 + m.num_towers as u64 != l {
            return Err(WireError::BadShape(format!("level {} with {} towers of {l}", m.level, m.num_towers)));
        }
        if !(1..=2).contains(&m.noise_scale_deg) {
            return Err(WireError::BadShape(format!("noise_scale_deg {}", m.noise_scale_deg)));
        }
        if m.scaling_factor_int == 0 || m.scaling_factor_int >= self.plain_mod {
            return Err(WireError::BadShape("scaling_factor_int out of range".into()));
        }
        Ok(())
    }

    pub fn encode(&self, ct: &Ciphertext) -> Result<Vec<u8>> {
        let meta = ct.meta()?;
        self.check_meta(&meta).map_err(|e| Error::Protocol(format!("cannot encode this ciphertext: {e}")))?;
        let residues = ct.export_residues()?;
        let k = meta.num_towers as usize;
        let n = self.ring_dim;
        if residues.len() != meta.num_elements as usize * k * n {
            return Err(Error::Protocol("exported residue count does not match the metadata".into()));
        }
        let mut out = Vec::with_capacity(self.encoded_len(&meta));
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(meta.num_elements as u8);
        out.extend_from_slice(&(meta.num_towers as u16).to_le_bytes());
        out.extend_from_slice(&meta.level.to_le_bytes());
        out.push(meta.noise_scale_deg as u8);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&meta.scaling_factor_int.to_le_bytes());
        out.extend_from_slice(&self.fingerprint);
        debug_assert_eq!(out.len(), HEADER_LEN);
        let mut w = BitWriter::new(out);
        for e in 0..meta.num_elements as usize {
            for t in 0..k {
                let q = self.moduli[t];
                let width = self.widths[t];
                for &v in &residues[(e * k + t) * n..(e * k + t + 1) * n] {
                    if v >= q {
                        return Err(Error::Protocol("our own ciphertext has a residue above its modulus".into()));
                    }
                    w.put(v, width);
                }
            }
        }
        let out = w.finish();
        debug_assert_eq!(out.len(), self.encoded_len(&meta));
        Ok(out)
    }

    /// Parses and validates, in safe Rust and without any OpenFHE call,
    /// returning the metadata and residues. Cheap checks first.
    pub fn parse(&self, bytes: &[u8], expect: Expect) -> std::result::Result<(CiphertextMeta, Vec<u64>), WireError> {
        if bytes.len() < HEADER_LEN {
            return Err(WireError::Truncated { len: bytes.len() });
        }
        if bytes[0..4] != MAGIC {
            return Err(WireError::BadMagic);
        }
        if bytes[4] != VERSION {
            return Err(WireError::BadVersion(bytes[4]));
        }
        if bytes[13..16] != [0, 0, 0] {
            return Err(WireError::NonZeroReserved);
        }
        if bytes[24..56] != self.fingerprint {
            return Err(WireError::WrongParameters);
        }
        let meta = CiphertextMeta {
            num_elements: bytes[5] as u32,
            num_towers: u16::from_le_bytes([bytes[6], bytes[7]]) as u32,
            level: u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")),
            noise_scale_deg: bytes[12] as u32,
            scaling_factor_int: u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes")),
        };
        self.check_meta(&meta)?;
        match expect {
            Expect::Exactly(m) => {
                if meta != m {
                    return Err(WireError::UnexpectedShape { expected: m, got: meta });
                }
            }
            Expect::Partial => {
                if meta.num_elements != 1 {
                    return Err(WireError::BadShape(format!("a partial decryption has 1 element, got {}", meta.num_elements)));
                }
            }
        }
        let expected = self.encoded_len(&meta);
        if bytes.len() != expected {
            return Err(WireError::BadLength { expected, got: bytes.len() });
        }
        let k = meta.num_towers as usize;
        let n = self.ring_dim;
        let mut residues = Vec::with_capacity(meta.num_elements as usize * k * n);
        let mut r = BitReader::new(&bytes[HEADER_LEN..]);
        for e in 0..meta.num_elements as usize {
            for t in 0..k {
                let q = self.moduli[t];
                let width = self.widths[t];
                for i in 0..n {
                    let v = r.get(width);
                    if v >= q {
                        return Err(WireError::ResidueOutOfRange { element: e, tower: t, index: i });
                    }
                    residues.push(v);
                }
            }
        }
        if !r.rest_is_zero() {
            return Err(WireError::NonZeroPadding);
        }
        Ok((meta, residues))
    }

    /// Parses, validates and rebuilds the ciphertext inside this party's own
    /// context from its fresh reference.
    pub fn decode(&self, bytes: &[u8], expect: Expect) -> std::result::Result<Ciphertext, WireError> {
        Ok(self.decode_with_meta(bytes, expect)?.1)
    }

    /// As [`Self::decode`], also returning the validated metadata.
    pub fn decode_with_meta(&self, bytes: &[u8], expect: Expect) -> std::result::Result<(CiphertextMeta, Ciphertext), WireError> {
        let (meta, residues) = self.parse(bytes, expect)?;
        let ct = self.ctx.build_ciphertext(&self.reference, &meta, &residues).map_err(|e| WireError::Rebuild(e.0))?;
        Ok((meta, ct))
    }
}

/// Appends values of given bit widths, least significant bit first.
struct BitWriter {
    out: Vec<u8>,
    acc: u128,
    nbits: u32,
}

impl BitWriter {
    fn new(out: Vec<u8>) -> Self {
        Self { out, acc: 0, nbits: 0 }
    }
    /// `v` must be below `2^width`, `1 <= width <= 64`.
    fn put(&mut self, v: u64, width: u32) {
        debug_assert!((1..=64).contains(&width) && (width == 64 || v >> width == 0));
        self.acc |= (v as u128) << self.nbits;
        self.nbits += width;
        if self.nbits >= 64 {
            self.out.extend_from_slice(&(self.acc as u64).to_le_bytes());
            self.acc >>= 64;
            self.nbits -= 64;
        }
    }
    fn finish(mut self) -> Vec<u8> {
        while self.nbits > 0 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.nbits = self.nbits.saturating_sub(8);
        }
        self.out
    }
}

/// Reads values of given bit widths from an exactly sized buffer. The caller
/// has checked the length, so `get` never needs more bytes than exist.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u128,
    nbits: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, acc: 0, nbits: 0 }
    }
    fn get(&mut self, width: u32) -> u64 {
        while self.nbits < width {
            if self.pos + 8 <= self.data.len() {
                let w = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().expect("8 bytes"));
                self.acc |= (w as u128) << self.nbits;
                self.pos += 8;
                self.nbits += 64;
            } else if self.pos < self.data.len() {
                self.acc |= (self.data[self.pos] as u128) << self.nbits;
                self.pos += 1;
                self.nbits += 8;
            } else {
                // Unreachable for a correctly sized buffer; reading zeros
                // here keeps the reader total, and the length check has
                // already refused any buffer this short.
                self.nbits += 64;
            }
        }
        let mask: u128 = if width == 64 { u64::MAX as u128 } else { (1u128 << width) - 1 };
        let v = (self.acc & mask) as u64;
        self.acc >>= width;
        self.nbits -= width;
        v
    }
    /// True if every bit not consumed by `get` is zero.
    fn rest_is_zero(&self) -> bool {
        self.acc == 0 && self.data[self.pos..].iter().all(|&b| b == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_packing_roundtrip_all_widths() {
        let mut seed = 0x243F6A8885A308D3u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for width in 1..=64u32 {
            let vals: Vec<u64> = (0..1000).map(|_| if width == 64 { next() } else { next() & ((1u64 << width) - 1) }).collect();
            let mut w = BitWriter::new(Vec::new());
            for &v in &vals {
                w.put(v, width);
            }
            let bytes = w.finish();
            assert_eq!(bytes.len(), (1000 * width as usize).div_ceil(8), "width {width}");
            let mut r = BitReader::new(&bytes);
            for &v in &vals {
                assert_eq!(r.get(width), v, "width {width}");
            }
            assert!(r.rest_is_zero(), "width {width}");
        }
        // mixed widths, as a ciphertext has
        let widths = [48u32, 60, 60, 55, 55, 55, 17];
        let vals: Vec<(u64, u32)> = (0..7000).map(|i| {
            let w = widths[i % 7];
            (next() & ((1u64 << w) - 1), w)
        }).collect();
        let mut wr = BitWriter::new(vec![9, 9]);
        for &(v, w) in &vals {
            wr.put(v, w);
        }
        let bytes = wr.finish();
        assert_eq!(&bytes[..2], &[9, 9]);
        let mut r = BitReader::new(&bytes[2..]);
        for &(v, w) in &vals {
            assert_eq!(r.get(w), v);
        }
        assert!(r.rest_is_zero());
    }

    #[test]
    fn padding_bits_are_detected() {
        let mut w = BitWriter::new(Vec::new());
        w.put(5, 3);
        let mut bytes = w.finish();
        assert_eq!(bytes, vec![5]);
        bytes[0] |= 0x80;
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.get(3), 5);
        assert!(!r.rest_is_zero());
    }
}
