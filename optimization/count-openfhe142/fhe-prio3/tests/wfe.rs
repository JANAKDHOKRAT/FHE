//! Proofs of well-formed encryption (`wfe.rs`): an honest contribution
//! verifies and its effective ciphertext decrypts to the intended slots; a
//! proof does not verify for another context, another ciphertext, a
//! tampered response or a malformed contribution; a prover whose
//! randomness is not short cannot produce one.
use fhe_prio3::wfe::{self, SlotCodec, Witness};
use openfhe_tbgv_rs::*;
use rand::rngs::OsRng;
use rand::{Rng, SeedableRng};

struct Keys {
    ctx: Context,
    pk: PublicKey,
    s: [SecretShare; 2],
    reference: Ciphertext,
}

fn keys() -> Keys {
    let ctx = Context::new(Params {
        plain_mod: 786_433,
        mult_depth: 6,
        security_bits: 128,
    })
    .unwrap();
    let (pk0, s0) = keygen_first(&ctx).unwrap();
    let (pk, s1) = keygen_next(&ctx, &pk0).unwrap();
    let reference = ctx.encrypt(&pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
    Keys {
        ctx,
        pk,
        s: [s0, s1],
        reference,
    }
}

impl Keys {
    fn dec(&self, c: &Ciphertext) -> Vec<u64> {
        let a = self.s[0].partial_decrypt(c, true).unwrap();
        let b = self.s[1].partial_decrypt(c, false).unwrap();
        self.ctx.fuse(&[&a, &b], self.ctx.ring_dim() as usize).unwrap()
    }
    fn uniform(&self, rng: &mut impl Rng) -> Vec<u64> {
        (0..self.ctx.ring_dim()).map(|_| rng.gen_range(0..self.ctx.plain_mod())).collect()
    }
}

#[test]
fn slot_codec_matches_openfhe_slot_order() {
    let k = keys();
    let codec = SlotCodec::new(&k.ctx).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let n = k.ctx.ring_dim() as usize;
    let t = k.ctx.plain_mod();
    let v: Vec<u64> = (0..n).map(|_| rng.gen_range(0..t)).collect();
    let m = codec.coefficients(&v);
    assert_eq!(codec.slots(&m), v);
    // a ciphertext of those raw coefficients, scaled as OpenFHE decodes, decrypts to v
    let sf = k.reference.meta().unwrap().scaling_factor_int;
    let scaled: Vec<u64> = v.iter().map(|&x| (x as u128 * sf as u128 % t as u128) as u64).collect();
    let z = vec![0i32; n];
    let c = k
        .ctx
        .encryption_with(&k.pk, &k.reference, Some(&codec.coefficients(&scaled)), &z, &z, &z)
        .unwrap();
    assert_eq!(k.dec(&c), v);
    // X has the slot values of X
    let mut x = vec![0u64; n];
    x[1] = 1;
    assert_eq!(codec.slots(&x), k.ctx.monomial_slots().unwrap());
}

#[test]
fn honest_contribution_verifies_and_decrypts() {
    let k = keys();
    let codec = SlotCodec::new(&k.ctx).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);
    let n = k.ctx.ring_dim() as usize;
    let sf = k.reference.meta().unwrap().scaling_factor_int;
    // a factor: nonzero at a few slots, zero elsewhere
    let mut v = vec![0u64; n];
    for s in [0usize, 5, 77, n - 1] {
        v[s] = rng.gen_range(1..k.ctx.plain_mod());
    }
    let m = codec.contribution_plaintext(&v, sf);
    let started = std::time::Instant::now();
    let (c, proof) = wfe::encrypt_proven(&k.ctx, &k.pk, &k.reference, &m, b"party 0 factor", &mut OsRng).unwrap();
    let proved = started.elapsed();
    let started = std::time::Instant::now();
    wfe::verify(&k.ctx, &k.pk, &k.reference, &c, &proof, b"party 0 factor").unwrap();
    eprintln!(
        "N = {n}: prove {proved:?}, verify {:?}, proof {} bytes",
        started.elapsed(),
        postcard::to_allocvec(&proof).unwrap().len()
    );
    assert_eq!(k.dec(&wfe::effective(&k.ctx, &c).unwrap()), v);
    // the effective ciphertext's noise stays inside the flooding
    let d = wfe::effective(&k.ctx, &c).unwrap();
    let a = k.s[0].partial_decrypt(&d, true).unwrap();
    let b = k.s[1].partial_decrypt(&d, false).unwrap();
    assert!(k.ctx.fuse_flooding_check(&[&a, &b], 20).unwrap().0);
}

#[test]
fn proofs_bind_context_ciphertext_and_responses() {
    let k = keys();
    let mut rng = rand::rngs::StdRng::seed_from_u64(3);
    let ctx = &k.ctx;
    let (c, proof) = wfe::encrypt_proven(ctx, &k.pk, &k.reference, &k.uniform(&mut rng), b"party 1 mask 0", &mut OsRng).unwrap();
    wfe::verify(ctx, &k.pk, &k.reference, &c, &proof, b"party 1 mask 0").unwrap();
    // replayed as another party's or another value's
    for other in [&b"party 2 mask 0"[..], b"party 1 mask 1", b""] {
        assert!(wfe::verify(ctx, &k.pk, &k.reference, &c, &proof, other).is_err());
    }
    // for another ciphertext: a fresh one, the negation, the double, C + another contribution
    let (c2, _) = wfe::encrypt_proven(ctx, &k.pk, &k.reference, &k.uniform(&mut rng), b"x", &mut OsRng).unwrap();
    for bad in [
        c2.try_clone().unwrap(),
        ctx.negate(&c).unwrap(),
        ctx.add(&c, &c).unwrap(),
        ctx.add(&c, &c2).unwrap(),
    ] {
        assert!(wfe::verify(ctx, &k.pk, &k.reference, &bad, &proof, b"party 1 mask 0").is_err());
    }
    // C with noise added (what a party that inflates its noise would send)
    let noisy = ctx.add_noise_for_tests(&c, 60, 9).unwrap();
    assert!(wfe::verify(ctx, &k.pk, &k.reference, &noisy, &proof, b"party 1 mask 0").is_err());
    // tampered responses: in range but changed, and out of range
    let mut p = proof.clone();
    p.responses[0].zu[3] = if p.responses[0].zu[3] > 0 {
        p.responses[0].zu[3] - 1
    } else {
        p.responses[0].zu[3] + 1
    };
    assert!(wfe::verify(ctx, &k.pk, &k.reference, &c, &p, b"party 1 mask 0").is_err());
    let mut p = proof.clone();
    p.responses[1].ze0[0] = wfe::B_E;
    assert!(
        wfe::verify(ctx, &k.pk, &k.reference, &c, &p, b"party 1 mask 0")
            .err()
            .unwrap()
            .to_string()
            .contains("out of range")
    );
    let mut p = proof.clone();
    p.responses.pop();
    assert!(wfe::verify(ctx, &k.pk, &k.reference, &c, &p, b"party 1 mask 0").is_err());
    let mut p = proof.clone();
    p.commitments[0] ^= 1;
    assert!(wfe::verify(ctx, &k.pk, &k.reference, &c, &p, b"party 1 mask 0").is_err());
    // a ciphertext that is not shaped like a fresh encryption
    let deeper = ctx.mult_plain(&c, &ctx.plaintext(&[1]).unwrap()).unwrap();
    assert!(wfe::verify(ctx, &k.pk, &k.reference, &deeper, &proof, b"party 1 mask 0").is_err());
}

#[test]
fn a_prover_without_short_randomness_cannot_prove() {
    let k = keys();
    let mut rng = rand::rngs::StdRng::seed_from_u64(4);
    let n = k.ctx.ring_dim() as usize;
    // randomness inflated 2^22 beyond the honest bound: the responses fall
    // out of range for every challenge, every attempt
    let big = 1i32 << 22;
    let w = Witness {
        m: k.uniform(&mut rng),
        u: (0..n).map(|_| rng.gen_range(-big..=big)).collect(),
        e0: (0..n).map(|_| rng.gen_range(-20..=20)).collect(),
        e1: (0..n).map(|_| rng.gen_range(-20..=20)).collect(),
    };
    let c = k.ctx.encryption_with(&k.pk, &k.reference, Some(&w.m), &w.u, &w.e0, &w.e1).unwrap();
    assert!(wfe::prove(&k.ctx, &k.pk, &k.reference, &c, &w, b"ctx", &mut rng).is_err());
    // the same with oversized e0
    let w = Witness {
        m: k.uniform(&mut rng),
        u: (0..n).map(|_| rng.gen_range(-1..=1)).collect(),
        e0: (0..n).map(|_| rng.gen_range(-(1 << 27)..=(1 << 27))).collect(),
        e1: (0..n).map(|_| rng.gen_range(-20..=20)).collect(),
    };
    let c = k.ctx.encryption_with(&k.pk, &k.reference, Some(&w.m), &w.u, &w.e0, &w.e1).unwrap();
    assert!(wfe::prove(&k.ctx, &k.pk, &k.reference, &c, &w, b"ctx", &mut rng).is_err());
    // a prover claiming a witness that is not C's opening: the rebuilt
    // commitments differ, so its proof fails
    let honest = Witness {
        m: k.uniform(&mut rng),
        u: (0..n).map(|_| rng.gen_range(-1..=1)).collect(),
        e0: (0..n).map(|_| rng.gen_range(-20..=20)).collect(),
        e1: (0..n).map(|_| rng.gen_range(-20..=20)).collect(),
    };
    let proof = wfe::prove(&k.ctx, &k.pk, &k.reference, &c, &honest, b"ctx", &mut rng).unwrap();
    assert!(wfe::verify(&k.ctx, &k.pk, &k.reference, &c, &proof, b"ctx").is_err());
}
