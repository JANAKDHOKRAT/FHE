//! `GF(65537)` as a prio field.
//!
//! prio 0.18.1 implements its fields with a private macro, so this module
//! implements the public traits (`FieldElement`, `FieldElementWithInteger`,
//! `NttFriendlyFieldElement`) directly, following the macro's conventions:
//!
//! * elements are stored fully reduced (`0 <= x < p`), here in plain
//!   (non-Montgomery) form;
//! * `ENCODED_SIZE` little-endian bytes; decoding refuses values `>= p`
//!   (`ModulusOverflow`); `try_from_random` first masks to the bit length of
//!   `p - 1` (17 bits), then refuses `>= p`, which is how prio's `Prng`
//!   rejection-samples uniform elements;
//! * `From<u32>` reduces modulo `p`; `root(l)` is the principal `2^l`-th root
//!   of unity `g^(2^(16 - l))` for the generator `g = 3` of order `2^16`.
//!
//! 65537 = 2^16 + 1 has 2-adicity 16, not the 20 the trait's documentation
//! mentions: `root(l)` is `None` for `l > 16`, and prio's NTT would panic on
//! a size beyond `2^15`. `FlpPlan::new` therefore refuses any circuit whose
//! polynomials would need such a size.
//!
//! Arithmetic does not branch on element values: additions and negation
//! select with masks, multiplication reduces a `< 2^34` product by a
//! constant divisor, and inversion is exponentiation by the public `p - 2`.
use prio::codec::{CodecError, Decode, Encode};
use prio::field::{FieldElement, FieldElementWithInteger, FieldError, NttFriendlyFieldElement};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::io::{Cursor, Read};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

const P: u32 = 65_537;
/// Bit length of `p - 1`: random bytes are masked to this before rejection.
const BIT_MASK: u32 = (1 << 17) - 1;
/// 3 is a primitive root modulo 65537, so it generates the whole
/// multiplicative group, of order 2^16.
const GENERATOR: u32 = 3;
const TWO_ADICITY: usize = 16;

#[derive(Clone, Copy, Default)]
pub struct Field65537(u32);

// Hash and Eq both use the fully reduced value, so equal elements hash equally.
impl std::hash::Hash for Field65537 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        debug_assert!(self.0 < P);
        self.0.hash(state);
    }
}

impl Field65537 {
    /// `x` in `[0, 2p)` to `[0, p)` without branching.
    #[inline]
    fn reduce_once(x: u32) -> u32 {
        let t = x.wrapping_sub(P);
        // t's top bit is set iff x < p (x < 2^18, so t wraps only then)
        let keep_x = 0u32.wrapping_sub(t >> 31);
        (t & !keep_x) | (x & keep_x)
    }

    fn try_from_bytes(bytes: &[u8], mask: u32) -> Result<Self, FieldError> {
        if bytes.len() < Self::ENCODED_SIZE {
            return Err(FieldError::ShortRead);
        }
        let mut int = 0u32;
        for (i, &b) in bytes[..Self::ENCODED_SIZE].iter().enumerate() {
            int |= (b as u32) << (8 * i);
        }
        int &= mask;
        if int >= P {
            return Err(FieldError::ModulusOverflow);
        }
        Ok(Self(int))
    }

    fn to_bytes(self) -> [u8; 3] {
        [self.0 as u8, (self.0 >> 8) as u8, (self.0 >> 16) as u8]
    }
}

impl ConstantTimeEq for Field65537 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Field65537 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u32::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for Field65537 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for Field65537 {}

impl Add for Field65537 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(Self::reduce_once(self.0 + rhs.0))
    }
}
impl Add for &Field65537 {
    type Output = Field65537;
    fn add(self, rhs: Self) -> Field65537 {
        *self + *rhs
    }
}
impl AddAssign for Field65537 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl Sub for Field65537 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(Self::reduce_once(self.0 + P - rhs.0))
    }
}
impl Sub for &Field65537 {
    type Output = Field65537;
    fn sub(self, rhs: Self) -> Field65537 {
        *self - *rhs
    }
}
impl SubAssign for Field65537 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl Mul for Field65537 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(((self.0 as u64 * rhs.0 as u64) % P as u64) as u32)
    }
}
impl Mul for &Field65537 {
    type Output = Field65537;
    fn mul(self, rhs: Self) -> Field65537 {
        *self * *rhs
    }
}
impl MulAssign for Field65537 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}
impl Div for Field65537 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        self * rhs.inv()
    }
}
impl Div for &Field65537 {
    type Output = Field65537;
    fn div(self, rhs: Self) -> Field65537 {
        *self / *rhs
    }
}
impl DivAssign for Field65537 {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}
impl Neg for Field65537 {
    type Output = Self;
    fn neg(self) -> Self {
        Self::zero() - self
    }
}
impl Neg for &Field65537 {
    type Output = Field65537;
    fn neg(self) -> Field65537 {
        -(*self)
    }
}

impl From<u32> for Field65537 {
    fn from(x: u32) -> Self {
        Self(x % P)
    }
}
impl From<Field65537> for u32 {
    fn from(x: Field65537) -> Self {
        x.0
    }
}
impl PartialEq<u32> for Field65537 {
    fn eq(&self, rhs: &u32) -> bool {
        self.0 == *rhs
    }
}

impl TryFrom<&[u8]> for Field65537 {
    type Error = FieldError;
    fn try_from(bytes: &[u8]) -> Result<Self, FieldError> {
        Self::try_from_bytes(bytes, u32::MAX)
    }
}
impl From<Field65537> for [u8; 3] {
    fn from(x: Field65537) -> Self {
        x.to_bytes()
    }
}
impl From<Field65537> for Vec<u8> {
    fn from(x: Field65537) -> Self {
        x.to_bytes().to_vec()
    }
}

impl fmt::Display for Field65537 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl fmt::Debug for Field65537 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Field65537 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}
struct BytesVisitor;
impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Field65537;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} bytes encoding an element of GF(65537)", Field65537::ENCODED_SIZE)
    }
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Field65537, E> {
        if v.len() != Field65537::ENCODED_SIZE {
            return Err(E::invalid_length(v.len(), &self));
        }
        Field65537::try_from(v).map_err(E::custom)
    }
    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Field65537, A::Error> {
        let mut bytes = [0u8; 3];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        if seq.next_element::<u8>()?.is_some() {
            return Err(de::Error::invalid_length(4, &self));
        }
        Field65537::try_from(&bytes[..]).map_err(de::Error::custom)
    }
}
impl<'de> Deserialize<'de> for Field65537 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(BytesVisitor)
    }
}

impl Encode for Field65537 {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        bytes.extend_from_slice(&self.to_bytes());
        Ok(())
    }
    fn encoded_len(&self) -> Option<usize> {
        Some(Self::ENCODED_SIZE)
    }
}
impl Decode for Field65537 {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut v = [0u8; 3];
        bytes.read_exact(&mut v)?;
        Self::try_from_bytes(&v, u32::MAX).map_err(|e| CodecError::Other(Box::new(e)))
    }
}

impl FieldElement for Field65537 {
    const ENCODED_SIZE: usize = 3;

    fn inv(&self) -> Self {
        // Fermat: x^(p-2); the exponent is public. inv(0) = 0, as in prio.
        self.pow(P - 2)
    }
    fn try_from_random(bytes: &[u8]) -> Result<Self, FieldError> {
        Self::try_from_bytes(bytes, BIT_MASK)
    }
    fn zero() -> Self {
        Self(0)
    }
    fn one() -> Self {
        Self(1)
    }
    fn half() -> Self {
        Self(P.div_ceil(2))
    }
}

impl FieldElementWithInteger for Field65537 {
    type Integer = u32;

    /// Square-and-multiply over all 32 exponent bits, selecting without
    /// branches (exponents in the FLP are public, but this costs nothing).
    fn pow(&self, exp: u32) -> Self {
        let mut acc = Self::one();
        for i in (0..32).rev() {
            acc = acc * acc;
            let with = acc * *self;
            acc = Self::conditional_select(&acc, &with, Choice::from(((exp >> i) & 1) as u8));
        }
        acc
    }
    fn modulus() -> u32 {
        P
    }
}

impl NttFriendlyFieldElement for Field65537 {
    fn generator_order() -> u32 {
        1 << TWO_ADICITY
    }
    fn generator() -> Self {
        Self(GENERATOR)
    }
    fn root(l: usize) -> Option<Self> {
        if l > TWO_ADICITY {
            return None;
        }
        Some(Self(GENERATOR).pow(1 << (TWO_ADICITY - l)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitvec::{BitVec, mul_bits_map};
    use prio::flp::Flp;
    use prio::flp::types::Count;

    type F = Field65537;

    fn r(seed: &mut u64) -> u32 {
        *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        (*seed >> 33) as u32
    }

    #[test]
    fn arithmetic_matches_integer_reference() {
        let mut s = 1;
        let mut vals: Vec<u32> = vec![0, 1, 2, P - 1, P - 2, 1 << 16, (1 << 16) - 1, P / 2, P / 2 + 1];
        vals.extend((0..300).map(|_| r(&mut s) % P));
        for &a in &vals {
            for &b in &vals {
                let (x, y) = (F::from(a), F::from(b));
                assert_eq!(u32::from(x + y), (a + b) % P);
                assert_eq!(u32::from(x - y), (a + P - b) % P);
                assert_eq!(u32::from(x * y), ((a as u64 * b as u64) % P as u64) as u32);
                assert_eq!(u32::from(-x), (P - a) % P);
                if b != 0 {
                    assert_eq!(x / y * y, x);
                }
            }
            let mut want = 1u64;
            for e in 0..40u32 {
                assert_eq!(u32::from(F::from(a).pow(e)), want as u32, "{a}^{e}");
                want = want * a as u64 % P as u64;
            }
        }
        assert_eq!(F::from(P), F::zero());
        assert_eq!(F::from(u32::MAX), F::from(u32::MAX % P));
        assert_eq!(F::half() + F::half(), F::one());
    }

    #[test]
    fn every_nonzero_element_has_its_inverse() {
        for a in 1..P {
            assert_eq!(F::from(a) * F::from(a).inv(), F::one(), "{a}");
        }
        assert_eq!(F::zero().inv(), F::zero());
    }

    #[test]
    fn roots_of_unity_and_generator() {
        let one = F::one();
        assert_eq!(F::root(0), Some(one));
        for l in 1..=TWO_ADICITY {
            let w = F::root(l).unwrap();
            assert_eq!(w.pow(1 << l), one, "root({l})^(2^{l})");
            assert_eq!(w.pow(1 << (l - 1)), -one, "root({l}) is principal");
            assert_eq!(F::root(l).unwrap() * F::root(l).unwrap(), F::root(l - 1).unwrap());
        }
        assert_eq!(F::root(TWO_ADICITY + 1), None);
        // the generator's order is exactly 2^16 = p - 1
        assert_eq!(F::generator().pow(F::generator_order()), one);
        assert_ne!(F::generator().pow(F::generator_order() / 2), one);
        assert_eq!(F::modulus(), P);
    }

    #[test]
    fn encodings_are_canonical() {
        for a in [0u32, 1, 255, 256, 65_535, 65_536] {
            let x = F::from(a);
            let bytes: Vec<u8> = x.into();
            assert_eq!(bytes.len(), F::ENCODED_SIZE);
            assert_eq!(F::try_from(&bytes[..]).unwrap(), x);
            assert_eq!(F::get_decoded(&x.get_encoded().unwrap()).unwrap(), x);
            let json = serde_json::to_string(&x).unwrap();
            assert_eq!(serde_json::from_str::<F>(&json).unwrap(), x);
        }
        // p and above are refused by decoding; random bytes are masked first
        assert!(matches!(F::try_from(&[0x01, 0x00, 0x01][..]), Err(FieldError::ModulusOverflow)));
        assert!(F::get_decoded(&[0xff, 0xff, 0xff]).is_err());
        assert!(matches!(F::try_from(&[0x01, 0x00][..]), Err(FieldError::ShortRead)));
        assert_eq!(F::try_from_random(&[0x05, 0x00, 0xfe]).unwrap(), F::from(5)); // 0xfe0005 & 0x1ffff = 5
        assert!(matches!(F::try_from_random(&[0x01, 0x00, 0x01]), Err(FieldError::ModulusOverflow)));
    }

    #[test]
    fn random_vectors_are_in_range_and_spread() {
        let v = F::random_vector(20_000);
        let mean = v.iter().map(|&x| u32::from(x) as f64).sum::<f64>() / v.len() as f64;
        assert!((mean - (P as f64 - 1.0) / 2.0).abs() < 1000.0, "mean {mean}");
        assert!(v.iter().all(|&x| u32::from(x) < P));
        let distinct: std::collections::HashSet<u32> = v.iter().map(|&x| u32::from(x)).collect();
        assert!(distinct.len() > 15_000);
    }

    #[test]
    fn prio_flp_proves_and_decides_in_this_field() {
        let count = Count::<F>::new();
        for (m, ok) in [(F::zero(), true), (F::one(), true), (F::from(2), false), (-F::one(), false)] {
            let proof = count.prove(&[m], &F::random_vector(count.prove_rand_len()), &[]).unwrap();
            let qr = loop {
                let qr = F::random_vector(count.query_rand_len());
                if qr[0].pow(2) != F::one() {
                    break qr;
                }
            };
            let v = count.query(&[m], &proof, &qr, &[], 1).unwrap();
            assert_eq!(count.decide(&v).unwrap(), ok, "x = {m}");
        }
        let bv = BitVec::<F>::new(100).unwrap();
        let mut input = vec![F::one(); 100];
        for bad in [false, true] {
            if bad {
                input[37] = F::from(3);
            }
            let proof = bv.prove(&input, &F::random_vector(bv.prove_rand_len()), &[]).unwrap();
            let mut qr = F::random_vector(bv.query_rand_len());
            *qr.last_mut().unwrap() = F::from(12_345); // not a 128th root of unity
            assert_ne!(qr.last().unwrap().pow(128), F::one());
            let v = bv.query(&input, &proof, &qr, &[], 1).unwrap();
            assert_eq!(bv.decide(&v).unwrap(), !bad);
            // the closed-form verifier map agrees with prio's query in this field
            let (rows, c) = mul_bits_map(100, true, &qr);
            let z: Vec<F> = input.iter().chain(&proof).copied().collect();
            for (k, row) in rows.iter().enumerate() {
                assert_eq!(row.iter().zip(&z).fold(c[k], |a, (&x, &y)| a + x * y), v[k]);
            }
        }
    }
}
