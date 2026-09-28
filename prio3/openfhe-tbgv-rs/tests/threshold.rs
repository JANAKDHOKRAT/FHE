//! End-to-end tests of the threshold BGV wrapper with 2 and 3 parties.
//! Every ceremony message crosses a serialization boundary, as it would on
//! the wire.

use openfhe_tbgv_rs::*;
use std::sync::Mutex;

/// OpenFHE's key store is process-global and unsynchronised: tests run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const P: u64 = 4_293_918_721; // prime, p ≡ 1 (mod 2^17)

struct Party {
    share: SecretShare,
}

/// Runs the full n-of-n ceremony over serialized messages and returns
/// (context with joint keys installed, joint pk, parties).
fn ceremony(n: usize, indices: &[i32], depth: u32) -> (Context, PublicKey, Vec<Party>) {
    let ctx = Context::new(Params { plain_mod: P, mult_depth: depth, security_bits: 128 }).unwrap();

    // --- public key: sequential -------------------------------------
    let (pk0, sk0) = keygen_first(&ctx).unwrap();
    let mut shares = vec![sk0];
    let mut pk = pk0;
    for _ in 1..n {
        let prev = ctx.deserialize_public_key(&pk.serialize().unwrap()).unwrap();
        let (pk_i, sk_i) = keygen_next(&ctx, &prev).unwrap();
        shares.push(sk_i);
        pk = pk_i;
    }
    let tag = pk.tag().unwrap();

    // --- eval mult key: round 1 --------------------------------------
    let r1_first = EvalMultKey::round1_first(&ctx, &shares[0]).unwrap();
    let r1_first_bytes = r1_first.serialize().unwrap();
    let mut r1_sum = ctx.deserialize_eval_mult_key(&r1_first_bytes).unwrap();
    for sk in &shares[1..] {
        let first = ctx.deserialize_eval_mult_key(&r1_first_bytes).unwrap();
        let contrib = EvalMultKey::round1_next(&ctx, sk, &first).unwrap();
        let contrib = ctx.deserialize_eval_mult_key(&contrib.serialize().unwrap()).unwrap();
        r1_sum = EvalMultKey::round1_add(&ctx, &r1_sum, &contrib, &tag).unwrap();
    }
    // --- round 2 ------------------------------------------------------
    let r1_sum_bytes = r1_sum.serialize().unwrap();
    let mut r2_sum: Option<EvalMultKey> = None;
    for sk in &shares {
        let sum = ctx.deserialize_eval_mult_key(&r1_sum_bytes).unwrap();
        let c = EvalMultKey::round2(&ctx, sk, &sum, &tag).unwrap();
        let c = ctx.deserialize_eval_mult_key(&c.serialize().unwrap()).unwrap();
        r2_sum = Some(match r2_sum {
            None => c,
            Some(acc) => EvalMultKey::round2_add(&ctx, &acc, &c, &tag).unwrap(),
        });
    }
    ctx.install_eval_mult_key(&r2_sum.unwrap(), &tag).unwrap();

    // --- rotation keys: sequential -------------------------------------
    let mut acc = RotationKeys::first(&ctx, &shares[0], indices).unwrap();
    for sk in &shares[1..] {
        let prev = ctx.deserialize_rotation_keys(&acc.serialize().unwrap()).unwrap();
        let contrib = RotationKeys::next(&ctx, sk, &prev, indices, &tag).unwrap();
        let contrib = ctx.deserialize_rotation_keys(&contrib.serialize().unwrap()).unwrap();
        acc = RotationKeys::add(&ctx, &prev, &contrib, &tag).unwrap();
    }
    ctx.install_rotation_keys(&acc, &tag).unwrap();

    let parties = shares.into_iter().map(|share| Party { share }).collect();
    (ctx, pk, parties)
}

fn threshold_decrypt(ctx: &Context, parties: &[Party], ct: &Ciphertext, n: usize) -> Vec<u64> {
    let partials: Vec<PartialDecryption> = parties
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let pd = p.share.partial_decrypt(ct, i == 0).unwrap();
            PartialDecryption::deserialize(ctx, &pd.serialize().unwrap(), pd.is_lead()).unwrap()
        })
        .collect();
    let refs: Vec<&PartialDecryption> = partials.iter().collect();
    ctx.fuse(&refs, n).unwrap()
}

fn check_arith(n_parties: usize) {
    let _g = serial();
    let (ctx, pk, parties) = ceremony(n_parties, &[1, 4, -8], 3);
    assert_eq!(ctx.plain_mod(), P);
    let a: Vec<u64> = (0..64).map(|i| (i * 7919 + 13) % P).collect();
    let b: Vec<u64> = (0..64).map(|i| P - 1 - (i * 104729) % P).collect();
    let pa = ctx.plaintext(&a).unwrap();
    let pb = ctx.plaintext(&b).unwrap();
    let ca = ctx.encrypt(&pk, &pa).unwrap();
    let cb = ctx.deserialize_ciphertext(&ctx.encrypt(&pk, &pb).unwrap().serialize().unwrap()).unwrap();

    let info = ca.info().unwrap();
    assert_eq!(info.level, 0);
    assert_eq!(info.num_elements, 2);
    assert!(info.packed_encoding);
    assert_eq!(info.key_tag, pk.tag().unwrap());

    let mul = |x: u64, y: u64| ((x as u128 * y as u128) % P as u128) as u64;

    let sum = ctx.add(&ca, &cb).unwrap();
    assert_eq!(threshold_decrypt(&ctx, &parties, &sum, 64), a.iter().zip(&b).map(|(x, y)| (x + y) % P).collect::<Vec<_>>());

    let dif = ctx.sub(&ca, &cb).unwrap();
    assert_eq!(threshold_decrypt(&ctx, &parties, &dif, 64), a.iter().zip(&b).map(|(x, y)| (x + P - y) % P).collect::<Vec<_>>());

    let prod = ctx.mult(&ca, &cb).unwrap();
    assert_eq!(threshold_decrypt(&ctx, &parties, &prod, 64), a.iter().zip(&b).map(|(&x, &y)| mul(x, y)).collect::<Vec<_>>());

    let prod_pt = ctx.mult_plain(&ca, &pb).unwrap();
    assert_eq!(threshold_decrypt(&ctx, &parties, &prod_pt, 64), a.iter().zip(&b).map(|(&x, &y)| mul(x, y)).collect::<Vec<_>>());

    // depth 3 with worst-case magnitudes: (a*b)*b*b then flooding decryption
    let d2 = ctx.mult(&prod, &cb).unwrap();
    let d3 = ctx.mult_plain(&d2, &pb).unwrap();
    assert_eq!(d3.info().unwrap().level, 3);
    let expect: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| mul(mul(mul(x, y), y), y)).collect();
    assert_eq!(threshold_decrypt(&ctx, &parties, &d3, 64), expect);

    // rotations: left by 1 and 4, right by 8 (cyclic within the row)
    let row = ctx.row_slots();
    let r1 = threshold_decrypt(&ctx, &parties, &ctx.rotate(&ca, 1).unwrap(), 64);
    assert_eq!(&r1[..63], &a[1..64]);
    assert_eq!(r1[63], 0);
    let r4 = threshold_decrypt(&ctx, &parties, &ctx.rotate(&ca, 4).unwrap(), 64);
    assert_eq!(&r4[..60], &a[4..64]);
    let rm8 = threshold_decrypt(&ctx, &parties, &ctx.rotate(&ca, -8).unwrap(), row);
    assert_eq!(&rm8[8..72], &a[..]);
    assert_eq!(rm8[0], 0); // slot row-8 of a is zero

    // a single share does not decrypt (n >= 2)
    let alone = parties[0].share.decrypt_alone_for_tests(&sum, 64).unwrap();
    assert_ne!(alone, threshold_decrypt(&ctx, &parties, &sum, 64));
}

#[test]
fn two_party_arithmetic_and_threshold_decryption() {
    check_arith(2);
}

#[test]
fn three_party_arithmetic_and_threshold_decryption() {
    check_arith(3);
}

#[test]
fn fuse_requires_exactly_one_lead() {
    let _g = serial();
    let (ctx, pk, parties) = ceremony(2, &[1], 1);
    let ct = ctx.encrypt(&pk, &ctx.plaintext(&[5, 6]).unwrap()).unwrap();
    let p0 = parties[0].share.partial_decrypt(&ct, true).unwrap();
    let p1 = parties[1].share.partial_decrypt(&ct, true).unwrap();
    assert!(ctx.fuse(&[&p0, &p1], 2).is_err());
    let p1 = parties[1].share.partial_decrypt(&ct, false).unwrap();
    assert_eq!(ctx.fuse(&[&p0, &p1], 2).unwrap(), vec![5, 6]);
}

#[test]
fn context_and_key_serialization_roundtrip() {
    let _g = serial();
    let (ctx, pk, parties) = ceremony(2, &[1], 1);
    let ctx2 = Context::deserialize(&ctx.serialize().unwrap()).unwrap();
    assert_eq!(ctx2.plain_mod(), P);
    assert_eq!(ctx2.ring_dim(), ctx.ring_dim());
    let share0 = ctx2.deserialize_secret_share(&parties[0].share.serialize().unwrap()).unwrap();
    let pk2 = ctx2.deserialize_public_key(&pk.serialize().unwrap()).unwrap();
    assert_eq!(pk2.tag().unwrap(), pk.tag().unwrap());
    let ct = ctx2.encrypt(&pk2, &ctx2.plaintext(&[P - 1, 0, 1]).unwrap()).unwrap();
    let p0 = share0.partial_decrypt(&ct, true).unwrap();
    let p1 = parties[1].share.partial_decrypt(&ct, false).unwrap();
    assert_eq!(ctx2.fuse(&[&p0, &p1], 3).unwrap(), vec![P - 1, 0, 1]);
}

#[test]
fn plaintext_rejects_unreduced_values() {
    let _g = serial();
    let ctx = Context::new(Params { plain_mod: P, mult_depth: 1, security_bits: 128 }).unwrap();
    assert!(ctx.plaintext(&[P]).is_err());
    assert!(ctx.plaintext(&[P - 1]).is_ok());
}

#[test]
fn injected_noise_keeps_plaintext_until_it_overflows() {
    let _g = serial();
    let (ctx, pk, parties) = ceremony(2, &[1], 3);
    let v: Vec<u64> = vec![1, 0, 1, 1];
    let ct = ctx.encrypt(&pk, &ctx.plaintext(&v).unwrap()).unwrap();
    // Small extra noise: still a correct encryption of v.
    let small = ctx.add_noise_for_tests(&ct, 40, 1).unwrap();
    assert_eq!(threshold_decrypt(&ctx, &parties, &small, 4), v);
    assert_eq!(small.info().unwrap(), ct.info().unwrap(), "structure is indistinguishable from a fresh ciphertext");
    // Noise far beyond the modulus: no longer decrypts to v.
    let huge = ctx.add_noise_for_tests(&ct, 340, 2).unwrap();
    assert_eq!(huge.info().unwrap(), ct.info().unwrap());
    assert_ne!(threshold_decrypt(&ctx, &parties, &huge, 4), v);
    // square equals mult(a, a)
    let sq = ctx.square(&ct).unwrap();
    let mm = ctx.mult(&ct, &ct).unwrap();
    assert_eq!(threshold_decrypt(&ctx, &parties, &sq, 4), threshold_decrypt(&ctx, &parties, &mm, 4));
    assert_eq!(sq.info().unwrap().level, mm.info().unwrap().level);
    // negate
    let neg = ctx.negate(&ct).unwrap();
    assert_eq!(threshold_decrypt(&ctx, &parties, &neg, 4), vec![P - 1, 0, P - 1, P - 1]);
}
