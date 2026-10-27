//! `Context::encryption_with`: an encryption of a chosen plaintext
//! polynomial with chosen (wide) randomness decrypts to that polynomial's
//! slots (divided by the reference's scaling factor), multiplies like a fresh encryption, agrees bit for bit with
//! `zero_encryption` on small randomness, and refuses malformed input.
use openfhe_tbgv_rs::*;

/// splitmix64: the crate has no dependencies, and the test needs only spread.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn signed(&mut self, b: i32) -> i32 {
        (self.below(2 * b as u64 + 1) as i64 - b as i64) as i32
    }
}

fn powmod(mut b: u64, mut e: u64, p: u64) -> u64 {
    let mut r = 1u64;
    b %= p;
    while e > 0 {
        if e & 1 == 1 {
            r = ((r as u128 * b as u128) % p as u128) as u64;
        }
        b = ((b as u128 * b as u128) % p as u128) as u64;
        e >>= 1;
    }
    r
}

/// Slot `s` of the plaintext polynomial with coefficients `m`: `m(w_s)`.
fn slot(m: &[u64], w: u64, p: u64) -> u64 {
    let mut acc = 0u64;
    for &c in m.iter().rev() {
        acc = ((acc as u128 * w as u128 + c as u128) % p as u128) as u64;
    }
    acc
}

#[test]
fn encryption_with_chosen_randomness() {
    let p = 786_433u64;
    let ctx = Context::new(Params {
        plain_mod: p,
        mult_depth: 6,
        security_bits: 128,
    })
    .unwrap();
    let (pk0, s0) = keygen_first(&ctx).unwrap();
    let (pk, s1) = keygen_next(&ctx, &pk0).unwrap();
    let tag = pk.tag().unwrap();
    let r1 = EvalMultKey::round1_first(&ctx, &s0).unwrap();
    let r1b = EvalMultKey::round1_next(&ctx, &s1, &r1).unwrap();
    let r1sum = EvalMultKey::round1_add(&ctx, &r1, &r1b, &tag).unwrap();
    let r2a = EvalMultKey::round2(&ctx, &s0, &r1sum, &tag).unwrap();
    let r2b = EvalMultKey::round2(&ctx, &s1, &r1sum, &tag).unwrap();
    ctx.install_eval_mult_key(&EvalMultKey::round2_add(&ctx, &r2a, &r2b, &tag).unwrap(), &tag)
        .unwrap();
    let n = ctx.ring_dim() as usize;
    let dec = |c: &Ciphertext| {
        let a = s0.partial_decrypt(c, true).unwrap();
        let b = s1.partial_decrypt(c, false).unwrap();
        ctx.fuse(&[&a, &b], n).unwrap()
    };
    let reference = ctx.encrypt(&pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
    let w = ctx.monomial_slots().unwrap();
    // decoding divides by the reference's scaling factor
    let sf_inv = powmod(reference.meta().unwrap().scaling_factor_int, p - 2, p);
    let mut rng = Rng(7);
    let m: Vec<u64> = (0..n).map(|_| rng.below(p)).collect();
    for bound in [1i32, 20, 1 << 20, 1 << 28] {
        let u: Vec<i32> = (0..n).map(|_| rng.signed(bound)).collect();
        let e0: Vec<i32> = (0..n).map(|_| rng.signed(bound)).collect();
        let e1: Vec<i32> = (0..n).map(|_| rng.signed(bound)).collect();
        let c = ctx.encryption_with(&pk, &reference, Some(&m), &u, &e0, &e1).unwrap();
        assert_eq!(c.meta().unwrap(), reference.meta().unwrap());
        let got = dec(&c);
        // even 2^28 randomness stays inside the partial decryptions' flooding
        let (_, phase, _) = ctx.raw_decrypt_for_tests(&c, &[&s0, &s1]).unwrap();
        let a = s0.partial_decrypt(&c, true).unwrap();
        let b = s1.partial_decrypt(&c, false).unwrap();
        assert!(ctx.fuse_flooding_check(&[&a, &b], 20).unwrap().0, "bound {bound}");
        assert!(phase < 120.0, "bound {bound}: phase 2^{phase:.1}");
        for s in (0..n).step_by(n / 61) {
            assert_eq!(
                got[s],
                (slot(&m, w[s], p) as u128 * sf_inv as u128 % p as u128) as u64,
                "bound {bound} slot {s}"
            );
        }
        // it multiplies like a fresh encryption
        let sq = dec(&ctx.mult(&c, &c).unwrap());
        for s in (0..n).step_by(n / 37) {
            assert_eq!(sq[s], powmod(got[s], 2, p), "bound {bound} square slot {s}");
        }
    }
    // no plaintext and small randomness: exactly zero_encryption
    let u8_: Vec<i8> = (0..n).map(|_| rng.signed(1) as i8).collect();
    let e08: Vec<i8> = (0..n).map(|_| rng.signed(20) as i8).collect();
    let e18: Vec<i8> = (0..n).map(|_| rng.signed(20) as i8).collect();
    let wide = |v: &[i8]| v.iter().map(|&x| x as i32).collect::<Vec<_>>();
    let a = ctx.encryption_with(&pk, &reference, None, &wide(&u8_), &wide(&e08), &wide(&e18)).unwrap();
    let b = ctx.zero_encryption(&pk, &reference, &u8_, &e08, &e18).unwrap();
    assert_eq!(a.export_residues().unwrap(), b.export_residues().unwrap());
    assert!(dec(&a).iter().all(|&x| x == 0));
    // malformed input is refused
    // coefficients wider than a tower (this chain has a 16-bit tower) are
    // reduced into it: a single coefficient of either sign, any magnitude
    let z = vec![0i32; n];
    for v in [-(1i32 << 30), -131_074, -70_000, 65_537, 1 << 30] {
        let mut x = z.clone();
        x[0] = v;
        let c = ctx.encryption_with(&pk, &reference, None, &z, &x, &z).unwrap();
        let (over_t, _, _) = ctx.raw_decrypt_for_tests(&c, &[&s0, &s1]).unwrap();
        assert_eq!(over_t[0], v as f64, "e0 = {v}");
        assert!(over_t[1..].iter().all(|&x| x == 0.0));
    }
    let mut big = m.clone();
    big[3] = p;
    assert!(ctx.encryption_with(&pk, &reference, Some(&big), &z, &z, &z).is_err());
    let mut minv = z.clone();
    minv[0] = i32::MIN;
    assert!(ctx.encryption_with(&pk, &reference, None, &minv, &z, &z).is_err());
    assert!(ctx.encryption_with(&pk, &reference, None, &z[1..], &z, &z).is_err());
}
