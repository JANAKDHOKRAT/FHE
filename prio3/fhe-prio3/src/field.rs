//! Arithmetic in the prime field F_p for p < 2^32 (the BGV plaintext space).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    p: u64,
}

impl Field {
    /// `p` must be an odd prime below 2^32. Primality is checked
    /// deterministically (Miller–Rabin with the bases sufficient for 2^64).
    pub fn new(p: u64) -> Option<Self> {
        if p < 3 || p >= (1u64 << 32) || !is_prime_u64(p) {
            return None;
        }
        Some(Self { p })
    }
    #[inline]
    pub fn modulus(&self) -> u64 {
        self.p
    }
    #[inline]
    pub fn add(&self, a: u64, b: u64) -> u64 {
        let s = a + b;
        if s >= self.p { s - self.p } else { s }
    }
    #[inline]
    pub fn sub(&self, a: u64, b: u64) -> u64 {
        if a >= b { a - b } else { a + self.p - b }
    }
    #[inline]
    pub fn neg(&self, a: u64) -> u64 {
        if a == 0 { 0 } else { self.p - a }
    }
    #[inline]
    pub fn mul(&self, a: u64, b: u64) -> u64 {
        ((a as u128 * b as u128) % self.p as u128) as u64
    }
    /// Reduces an arbitrary integer.
    #[inline]
    pub fn reduce_i128(&self, a: i128) -> u64 {
        a.rem_euclid(self.p as i128) as u64
    }
    /// log2(p), the soundness contributed by one repetition of the check.
    pub fn log2(&self) -> f64 {
        (self.p as f64).log2()
    }
}

fn mulmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}
fn powmod(mut b: u64, mut e: u64, m: u64) -> u64 {
    let mut r = 1u64;
    b %= m;
    while e > 0 {
        if e & 1 == 1 {
            r = mulmod(r, b, m);
        }
        b = mulmod(b, b, m);
        e >>= 1;
    }
    r
}

/// Deterministic Miller–Rabin, correct for all n < 2^64.
pub fn is_prime_u64(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    for q in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n % q == 0 {
            return n == q;
        }
    }
    let mut d = n - 1;
    let mut s = 0;
    while d % 2 == 0 {
        d /= 2;
        s += 1;
    }
    'outer: for a in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = powmod(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 1..s {
            x = mulmod(x, x, n);
            if x == n - 1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn field_ops() {
        let f = Field::new(4_293_918_721).unwrap();
        let p = f.modulus();
        assert_eq!(f.add(p - 1, 1), 0);
        assert_eq!(f.sub(0, 1), p - 1);
        assert_eq!(f.mul(p - 1, p - 1), 1);
        assert_eq!(f.neg(5), p - 5);
        assert_eq!(f.reduce_i128(-1), p - 1);
    }
    #[test]
    fn primality() {
        assert!(is_prime_u64(4_293_918_721));
        assert!(is_prime_u64(65537));
        assert!(!is_prime_u64(4_293_918_723));
        assert!(Field::new(4_293_918_723).is_none());
        assert!(Field::new(1u64 << 32).is_none());
    }
}
