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
    /// Any shape within the bounds (stored material whose shape the reader
    /// does not know in advance, and the fuzz targets).
    Any,
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

/// Largest ring dimension the format accepts (OpenFHE's BGV uses at most
/// 2^17; the bound keeps every length computation far from overflow).
pub const MAX_RING_DIM: usize = 1 << 20;

/// The wire format itself: parameters, parser and encoder, in safe Rust and
/// without any OpenFHE object. [`Codec`] binds it to a context; the fuzz
/// targets drive it directly with small synthetic parameters, which reach
/// every path the real parameters reach and some they do not (padding bits
/// exist only when `num_elements * N * sum(widths)` is not a multiple of 8).
#[derive(Clone, Debug)]
pub struct WireFormat {
    moduli: Vec<u64>,
    widths: Vec<u32>,
    ring_dim: usize,
    plain_mod: u64,
    fingerprint: [u8; 32],
}

impl WireFormat {
    /// `public_key` is the serialized joint public key; only its hash enters
    /// the fingerprint.
    pub fn new(plain_mod: u64, ring_dim: usize, moduli: Vec<u64>, public_key: &[u8]) -> Result<Self> {
        // The header stores the tower count in 16 bits.
        if moduli.is_empty() || moduli.len() > u16::MAX as usize || moduli.iter().any(|&q| q < 2) {
            return Err(Error::Config("invalid modulus chain for the wire format".into()));
        }
        if ring_dim == 0 || ring_dim > MAX_RING_DIM || u32::try_from(ring_dim).is_err() {
            return Err(Error::Config("invalid ring dimension for the wire format".into()));
        }
        if plain_mod < 2 {
            return Err(Error::Config("invalid plaintext modulus for the wire format".into()));
        }
        let widths = moduli.iter().map(|&q| bit_length(q - 1).max(1)).collect();
        let fp = fingerprint(plain_mod, ring_dim as u32, &moduli, public_key);
        Ok(Self { moduli, widths, ring_dim, plain_mod, fingerprint: fp })
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub fn moduli(&self) -> &[u64] {
        &self.moduli
    }

    pub fn ring_dim(&self) -> usize {
        self.ring_dim
    }

    fn payload_bits(&self, meta: &CiphertextMeta) -> usize {
        let per_coeff: usize = self.widths[..meta.num_towers as usize].iter().map(|&w| w as usize).sum();
        meta.num_elements as usize * self.ring_dim * per_coeff
    }

    /// Exact encoded length of an object with this metadata (which must pass
    /// [`Self::check_meta`]).
    pub fn encoded_len(&self, meta: &CiphertextMeta) -> usize {
        HEADER_LEN + self.payload_bits(meta).div_ceil(8)
    }

    /// The metadata bounds the shim enforces, checked here in Rust first.
    pub fn check_meta(&self, m: &CiphertextMeta) -> std::result::Result<(), WireError> {
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

    /// Encodes metadata and residues (element-major, then tower, then
    /// coefficient). Refuses anything [`Self::parse`] would refuse, so every
    /// output parses back to exactly its input.
    pub fn encode_raw(&self, meta: &CiphertextMeta, residues: &[u64]) -> std::result::Result<Vec<u8>, WireError> {
        self.check_meta(meta)?;
        let k = meta.num_towers as usize;
        let n = self.ring_dim;
        let count = meta.num_elements as usize * k * n;
        if residues.len() != count {
            return Err(WireError::BadLength { expected: count, got: residues.len() });
        }
        let mut out = Vec::with_capacity(self.encoded_len(meta));
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
                for (i, &v) in residues[(e * k + t) * n..(e * k + t + 1) * n].iter().enumerate() {
                    if v >= q {
                        return Err(WireError::ResidueOutOfRange { element: e, tower: t, index: i });
                    }
                    w.put(v, width);
                }
            }
        }
        let out = w.finish();
        debug_assert_eq!(out.len(), self.encoded_len(meta));
        Ok(out)
    }

    /// Parses and validates, returning the metadata and residues. Cheap
    /// checks first; the residue vector is allocated only after the exact
    /// length has been checked.
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
            Expect::Any => {}
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
}

/// Why stored state from before the packed format cannot be used. A node
/// written by such a build stored ciphertexts from other parties (client
/// reports, released partial decryptions) in OpenFHE's own serialization,
/// which this build never feeds to OpenFHE's loader.
pub const LEGACY_STATE: &str = "stored state was written by a build that exchanged ciphertexts in OpenFHE's serialization, \
     before the packed wire format; this build cannot resume or collect that batch. \
     Finish collecting it with the build that wrote it, or discard it";

/// Checks that stored bytes of another party's ciphertext (or of a partial
/// decryption this party released) are in the packed format, telling a
/// state from before the format apart from a corrupt one.
pub fn check_stored(format: &WireFormat, bytes: &[u8], expect: Expect, what: &str) -> Result<()> {
    match format.parse(bytes, expect) {
        Ok(_) => Ok(()),
        Err(WireError::BadMagic) => Err(Error::Config(format!("{what}: {LEGACY_STATE}"))),
        Err(e) => Err(Error::Config(format!("{what}: stored ciphertext is not valid: {e}"))),
    }
}

/// Encoder and decoder bound to one context and joint public key.
pub struct Codec {
    ctx: Context,
    format: WireFormat,
    /// A fresh encryption of zero made by this party under the joint key:
    /// the template every received ciphertext is rebuilt from.
    reference: Ciphertext,
    fresh: CiphertextMeta,
}

impl Codec {
    /// `public_key` is the serialized joint public key every party of the
    /// task holds (the task's public material); `pk` is it deserialized.
    pub fn new(ctx: &Context, pk: &PublicKey, public_key: &[u8]) -> Result<Self> {
        let format = WireFormat::new(ctx.plain_mod(), ctx.ring_dim() as usize, ctx.moduli()?, public_key)?;
        let reference = ctx.encrypt(pk, &ctx.plaintext(&[0])?)?;
        let fresh = reference.meta()?;
        if fresh.num_towers as usize != format.moduli.len() || fresh.level != 0 {
            return Err(Error::Config("a fresh encryption does not use the full modulus chain".into()));
        }
        Ok(Self { ctx: ctx.clone(), format, reference, fresh })
    }

    /// The format this codec encodes and parses.
    pub fn format(&self) -> &WireFormat {
        &self.format
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.format.fingerprint
    }

    /// Metadata of a fresh encryption under the joint key.
    pub fn fresh_meta(&self) -> CiphertextMeta {
        self.fresh
    }

    /// Exact encoded length of an object with this metadata.
    pub fn encoded_len(&self, meta: &CiphertextMeta) -> usize {
        self.format.encoded_len(meta)
    }

    /// Encoded length of a fresh ciphertext (one report chunk or one mask).
    pub fn fresh_len(&self) -> usize {
        self.format.encoded_len(&self.fresh)
    }

    pub fn encode(&self, ct: &Ciphertext) -> Result<Vec<u8>> {
        let meta = ct.meta()?;
        let residues = ct.export_residues()?;
        self.format.encode_raw(&meta, &residues).map_err(|e| Error::Protocol(format!("cannot encode this ciphertext: {e}")))
    }

    /// Parses and validates, in safe Rust and without any OpenFHE call.
    pub fn parse(&self, bytes: &[u8], expect: Expect) -> std::result::Result<(CiphertextMeta, Vec<u64>), WireError> {
        self.format.parse(bytes, expect)
    }

    /// Parses, validates and rebuilds the ciphertext inside this party's own
    /// context from its fresh reference. The rebuild is refused (as
    /// [`WireError::Rebuild`]) until `openfhe_tbgv_rs::verify_rebuild_once`
    /// has passed for these parameters at the object's level in this
    /// process; [`crate::Aggregator::new`] and [`crate::Collector::new`] run
    /// it.
    pub fn decode(&self, bytes: &[u8], expect: Expect) -> std::result::Result<Ciphertext, WireError> {
        Ok(self.decode_with_meta(bytes, expect)?.1)
    }

    /// As [`Self::decode`], also returning the validated metadata.
    pub fn decode_with_meta(&self, bytes: &[u8], expect: Expect) -> std::result::Result<(CiphertextMeta, Ciphertext), WireError> {
        let (meta, residues) = self.format.parse(bytes, expect)?;
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

    fn xorshift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    /// Small synthetic formats, including towers of 2, 3 and 64 bits and
    /// ring dimensions that leave padding bits in the last byte.
    fn small_formats() -> Vec<WireFormat> {
        let chains: [&[u64]; 5] = [&[3], &[17, 3], &[65537, 2, 97], &[u64::MAX - 58, 1 << 40 | 1], &[(1 << 61) - 1, 7681, 12289, 3]];
        let mut out = Vec::new();
        for chain in chains {
            for n in [1usize, 2, 3, 5, 8] {
                out.push(WireFormat::new(65537, n, chain.to_vec(), b"test key").unwrap());
            }
        }
        out
    }

    fn all_metas(f: &WireFormat) -> Vec<CiphertextMeta> {
        let l = f.moduli().len() as u32;
        let mut v = Vec::new();
        for ne in 1..=2 {
            for k in 1..=l {
                for deg in 1..=2 {
                    for sf in [1u64, 2, 65536] {
                        v.push(CiphertextMeta { num_elements: ne, num_towers: k, level: l - k, noise_scale_deg: deg, scaling_factor_int: sf });
                    }
                }
            }
        }
        v
    }

    #[test]
    fn format_roundtrip_and_canonical_for_every_shape() {
        let mut seed = 0x9E3779B97F4A7C15u64;
        let mut padded = 0;
        for f in small_formats() {
            for m in all_metas(&f) {
                let k = m.num_towers as usize;
                let n = f.ring_dim();
                let res: Vec<u64> = (0..m.num_elements as usize * k * n).map(|j| xorshift(&mut seed) % f.moduli()[(j / n) % k]).collect();
                let bytes = f.encode_raw(&m, &res).unwrap();
                assert_eq!(bytes.len(), f.encoded_len(&m));
                let (m2, r2) = f.parse(&bytes, Expect::Any).unwrap();
                assert_eq!((m2, &r2), (m, &res));
                // any single bit flip in the payload either is refused or
                // parses to other residues that re-encode to exactly it
                for bit in 0..(bytes.len() - HEADER_LEN) * 8 {
                    let mut b = bytes.clone();
                    b[HEADER_LEN + bit / 8] ^= 1 << (bit % 8);
                    if let Ok((m3, r3)) = f.parse(&b, Expect::Any) {
                        assert_eq!(f.encode_raw(&m3, &r3).unwrap(), b);
                        assert_ne!(r3, res);
                    }
                }
                let bits = f.payload_bits(&m);
                if bits % 8 != 0 {
                    padded += 1;
                    let mut b = bytes.clone();
                    *b.last_mut().unwrap() |= 0x80;
                    assert_eq!(f.parse(&b, Expect::Any), Err(WireError::NonZeroPadding));
                }
            }
        }
        assert!(padded > 100, "padding paths exercised: {padded}");
    }

    #[test]
    fn encode_refuses_what_parse_refuses() {
        let f = WireFormat::new(65537, 3, vec![17, 3], b"k").unwrap();
        let m = CiphertextMeta { num_elements: 1, num_towers: 2, level: 0, noise_scale_deg: 2, scaling_factor_int: 5 };
        assert_eq!(f.encode_raw(&m, &[0, 16, 1, 2, 0, 3]), Err(WireError::ResidueOutOfRange { element: 0, tower: 1, index: 2 }));
        assert!(matches!(f.encode_raw(&m, &[0; 5]), Err(WireError::BadLength { .. })));
        assert!(matches!(f.encode_raw(&CiphertextMeta { level: 1, ..m }, &[0; 6]), Err(WireError::BadShape(_))));
        assert!(matches!(f.encode_raw(&CiphertextMeta { scaling_factor_int: 65537, ..m }, &[0; 6]), Err(WireError::BadShape(_))));
        assert!(WireFormat::new(65537, 0, vec![17], b"k").is_err());
        assert!(WireFormat::new(65537, MAX_RING_DIM + 1, vec![17], b"k").is_err());
        assert!(WireFormat::new(65537, 4, vec![], b"k").is_err());
        assert!(WireFormat::new(65537, 4, vec![17, 1], b"k").is_err());
        assert!(WireFormat::new(1, 4, vec![17], b"k").is_err());
        assert!(WireFormat::new(65537, 4, vec![17; u16::MAX as usize + 1], b"k").is_err());
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
