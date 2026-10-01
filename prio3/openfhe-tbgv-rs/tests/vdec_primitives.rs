//! Primitives of verifiable decryption (fhe-prio3 `vdec.rs`): monomial
//! multiplication acts slot-wise as powers of the slot values of `X`; a
//! zero encryption with chosen randomness decrypts to zero on any tower
//! count; and an honest fusion lies far below `q0 / 2`, at the top of the
//! chain and at the bottom of the silent-mode chain.
use openfhe_tbgv_rs::*;

struct Keys {
    ctx: Context,
    pk: PublicKey,
    s: [SecretShare; 2],
    tag: String,
}

fn keys(plain_mod: u64, depth: u32) -> Keys {
    let ctx = Context::new(Params {
        plain_mod,
        mult_depth: depth,
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
    Keys { ctx, pk, s: [s0, s1], tag }
}

impl Keys {
    fn partials(&self, c: &Ciphertext) -> [PartialDecryption; 2] {
        [self.s[0].partial_decrypt(c, true).unwrap(), self.s[1].partial_decrypt(c, false).unwrap()]
    }
    fn dec(&self, c: &Ciphertext) -> Vec<u64> {
        let p = self.partials(c);
        self.ctx.fuse(&[&p[0], &p[1]], self.ctx.ring_dim() as usize).unwrap()
    }
    fn magnitude(&self, c: &Ciphertext) -> (u64, u64) {
        let p = self.partials(c);
        self.ctx.fuse_magnitude(&[&p[0], &p[1]]).unwrap()
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

fn check(k: &Keys, deep: &Ciphertext, label: &str) {
    let p = k.ctx.plain_mod();
    let n = k.ctx.ring_dim() as usize;
    let w = k.ctx.monomial_slots().unwrap();
    assert_eq!(w.len(), n);
    // every slot value of X is a primitive 2N-th root of unity mod p
    for &x in w.iter().take(64) {
        assert_eq!(powmod(x, 2 * n as u64, p), 1);
        assert_eq!(powmod(x, n as u64, p), p - 1);
    }
    let m = k.dec(deep);
    for kk in [0u32, 1, 7, n as u32 - 1, n as u32, n as u32 + 3, 2 * n as u32 - 1] {
        let got = k.dec(&k.ctx.mult_monomial(deep, kk).unwrap());
        for s in 0..n {
            assert_eq!(
                got[s],
                ((m[s] as u128 * powmod(w[s], kk as u64, p) as u128) % p as u128) as u64,
                "{label} k={kk} slot {s}"
            );
        }
    }
    assert!(k.ctx.mult_monomial(deep, 2 * n as u32).is_err());
    // zero encryption with chosen randomness on the ciphertext's towers
    let u: Vec<i8> = (0..n).map(|i| [-1i8, 0, 1][i % 3]).collect();
    let e0: Vec<i8> = (0..n).map(|i| ((i * 7) % 43) as i8 - 21).collect();
    let e1: Vec<i8> = (0..n).map(|i| ((i * 11) % 43) as i8 - 21).collect();
    let z = k.ctx.zero_encryption(&k.pk, deep, &u, &e0, &e1).unwrap();
    assert_eq!(z.meta().unwrap(), deep.meta().unwrap());
    assert!(k.dec(&z).iter().all(|&v| v == 0), "{label}: zero encryption");
    let sum = k.ctx.add(&k.ctx.mult_monomial(deep, 5).unwrap(), &z).unwrap();
    let want: Vec<u64> = (0..n).map(|s| ((m[s] as u128 * powmod(w[s], 5, p) as u128) % p as u128) as u64).collect();
    assert_eq!(k.dec(&sum), want, "{label}: blinded check");
    for (what, c) in [("value", deep), ("check", &sum)] {
        let (mx, q0) = k.magnitude(c);
        let margin = (q0 as f64 / 2.0).log2() - (mx as f64).log2();
        println!(
            "{label} {what}: towers {} max |fused| 2^{:.1}, q0 2^{:.1}, margin {margin:.1} bits",
            c.meta().unwrap().num_towers,
            (mx as f64).log2(),
            (q0 as f64).log2()
        );
        assert!(mx < q0 / 4, "{label} {what}: honest fusion reaches q0/4");
    }
}

#[test]
fn primitives_at_the_top_and_bottom_of_the_chain() {
    // verdict parameters, a sum of fresh encryptions
    let k = keys(4_293_918_721, 3);
    let n = k.ctx.ring_dim() as usize;
    let vals: Vec<u64> = (0..n as u64).map(|i| (i * 2_654_435_761) % 4_293_918_721).collect();
    let a = k.ctx.encrypt(&k.pk, &k.ctx.plaintext(&vals[..k.ctx.row_slots()]).unwrap()).unwrap();
    let b = k.ctx.encrypt(&k.pk, &k.ctx.plaintext(&vals[k.ctx.row_slots()..]).unwrap()).unwrap();
    check(&k, &k.ctx.add(&a, &b).unwrap(), "verdict sum");
    check(&k, &k.ctx.mult(&a, &b).unwrap(), "verdict product");
    Context::clear_keys_for_tag(&k.tag).unwrap();

    // silent parameters, the bottom of the chain (24 squarings)
    let k = keys(786_433, 25);
    let mut g = k.ctx.encrypt(&k.pk, &k.ctx.plaintext(&[1, 2, 3, 4]).unwrap()).unwrap();
    for _ in 0..24 {
        g = k.ctx.square(&g).unwrap();
    }
    check(&k, &g, "silent bottom");
    Context::clear_keys_for_tag(&k.tag).unwrap();
}
