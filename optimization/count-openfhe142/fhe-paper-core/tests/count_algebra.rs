//! Exhaustive finite-field regression, independent of ciphertext evaluation.
fn power(mut x: u64, mut e: u64, p: u64) -> u64 {
    let mut y = 1;
    while e > 0 {
        if e & 1 == 1 {
            y = y * x % p;
        }
        x = x * x % p;
        e >>= 1;
    }
    y
}
#[test]
fn exhaustive_count_equivalence() {
    for p in [65537u64, 786433] {
        for x in 0..p {
            let old = x * ((1 + p - power(x * ((x + p - 1) % p) % p, p - 1, p)) % p) % p;
            let new = (1 + p - power((x + p - 1) % p, p - 1, p)) % p;
            assert_eq!(old, new, "p={p} x={x}");
            assert_eq!(new, u64::from(x == 1));
        }
    }
}
