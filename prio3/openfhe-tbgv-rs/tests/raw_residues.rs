//! Raw residue transport: a ciphertext exported as residues plus metadata
//! and rebuilt from the receiver's own reference is the same object, byte
//! for byte, for every kind of ciphertext the protocols exchange; and the
//! rebuild refuses every malformed argument without touching OpenFHE.

use openfhe_tbgv_rs::*;
use std::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const P: u64 = 4_293_918_721;

struct Party {
    share: SecretShare,
}

/// Runs the full n-of-n ceremony over serialized messages and returns
/// (context with joint keys installed, joint pk, parties).
fn ceremony(n: usize, indices: &[i32], depth: u32) -> (Context, PublicKey, Vec<Party>) {
    let ctx = Context::new(Params {
        plain_mod: P,
        mult_depth: depth,
        security_bits: 128,
    })
    .unwrap();

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

/// Rebuilds `ct` from residues and metadata and checks it is the same
/// ciphertext: identical metadata, identical residues, and (with all key
/// shares) `original - rebuilt` decrypts to zero in every slot of both rows,
/// which fails if any tower parameter differed. Fresh encryptions, which is
/// what clients send, must also serialize byte for byte identically; computed
/// objects can differ in how OpenFHE's serializer records shared parameter
/// objects, which depends on the object's history, not its value.
fn roundtrip(ctx: &Context, reference: &Ciphertext, parties: &[Party], ct: &Ciphertext, fresh: bool) -> Ciphertext {
    let meta = ct.meta().unwrap();
    let res = ct.export_residues().unwrap();
    let back = ctx.build_ciphertext(reference, &meta, &res).unwrap();
    assert_eq!(back.meta().unwrap(), meta);
    assert_eq!(back.export_residues().unwrap(), res);
    assert_eq!(back.info().unwrap(), ct.info().unwrap());
    let diff = ctx.sub(ct, &back).unwrap();
    let all = 2 * ctx.row_slots();
    assert!(
        threshold_decrypt(ctx, parties, &diff, all).iter().all(|&v| v == 0),
        "original - rebuilt is not zero ({meta:?})"
    );
    if fresh {
        let (x, y) = (back.serialize().unwrap(), ct.serialize().unwrap());
        if x != y {
            let d = x.iter().zip(&y).position(|(a, b)| a != b).unwrap_or(x.len().min(y.len()));
            panic!(
                "fresh ciphertext rebuilt differs: lengths {} vs {}, first difference at byte {d}",
                x.len(),
                y.len()
            );
        }
    }
    back
}

/// Partial decryptions carry the sending party's secret-share key tag,
/// which the receiver does not know and which fusion never reads (OpenFHE's
/// `MultipartyDecryptFusion` uses only the elements and the scaling factor).
/// A rebuilt partial therefore carries the joint tag; everything fusion
/// reads is checked to be identical.
fn roundtrip_partial(ctx: &Context, reference: &Ciphertext, ct: &Ciphertext) -> Ciphertext {
    let meta = ct.meta().unwrap();
    let res = ct.export_residues().unwrap();
    let back = ctx.build_ciphertext(reference, &meta, &res).unwrap();
    assert_eq!(back.meta().unwrap(), meta);
    assert_eq!(back.export_residues().unwrap(), res);
    assert_eq!(back.info().unwrap().key_tag, reference.info().unwrap().key_tag);
    back
}

#[test]
fn rebuild_is_exact_for_every_protocol_object_kind() {
    let _g = serial();
    let (ctx, pk, parties) = ceremony(2, &[1, 4, -8], 3);
    verify_rebuild_once(&ctx, 3).unwrap();
    let l = ctx.num_towers();
    let moduli = ctx.moduli().unwrap();
    assert_eq!(moduli.len(), l as usize);
    let reference = ctx.encrypt(&pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
    let a: Vec<u64> = (0..64).map(|i| (i * 7919 + 13) % P).collect();
    let b: Vec<u64> = (0..64).map(|i| (i * 104729 + 7) % P).collect();
    let ca = ctx.encrypt(&pk, &ctx.plaintext(&a).unwrap()).unwrap();
    let cb = ctx.encrypt(&pk, &ctx.plaintext(&b).unwrap()).unwrap();

    // every kind: fresh, sum, product (one level), product of products
    // (two levels), rotation, plaintext product, partial decryptions of each
    let sum = ctx.add(&ca, &cb).unwrap();
    let prod = ctx.mult(&ca, &cb).unwrap();
    let prod2 = ctx.mult(&prod, &ca).unwrap();
    let prod3 = ctx.mult(&prod2, &cb).unwrap();
    let rot = ctx.rotate(&ca, 4).unwrap();
    let pmul = ctx.mult_plain(&ca, &ctx.plaintext(&b).unwrap()).unwrap();
    let mut seen = Vec::new();
    for (name, ct) in [
        ("fresh", &ca),
        ("sum", &sum),
        ("product", &prod),
        ("product2", &prod2),
        ("product3", &prod3),
        ("rotation", &rot),
        ("plain product", &pmul),
    ] {
        let m = ct.meta().unwrap();
        assert_eq!(m.level + m.num_towers, l, "{name}: level + towers must equal the chain length ({m:?})");
        assert!((1..=2).contains(&m.noise_scale_deg), "{name}: {m:?}");
        assert!(m.scaling_factor_int >= 1 && m.scaling_factor_int < P, "{name}: {m:?}");
        let back = roundtrip(&ctx, &reference, &parties, ct, name == "fresh");
        // partial decryptions of that object, lead and main, and their fusion
        let p0 = parties[0].share.partial_decrypt(&back, true).unwrap();
        let p1 = parties[1].share.partial_decrypt(&back, false).unwrap();
        let pm = p0.ciphertext().meta().unwrap();
        assert_eq!(pm.num_elements, 1, "{name} partial");
        assert_eq!(pm.level + pm.num_towers, l, "{name} partial: {pm:?}");
        let r0 = roundtrip_partial(&ctx, &reference, p0.ciphertext());
        let r1 = roundtrip_partial(&ctx, &reference, p1.ciphertext());
        let fused_rebuilt = ctx
            .fuse(
                &[&PartialDecryption::from_ciphertext(r0, true), &PartialDecryption::from_ciphertext(r1, false)],
                64,
            )
            .unwrap();
        let fused_direct = ctx.fuse(&[&p0, &p1], 64).unwrap();
        assert_eq!(fused_rebuilt, fused_direct, "{name}: fusion of rebuilt partials differs");
        seen.push((name, m, pm));
    }
    // the values the protocol cares about decrypt correctly after a round trip
    let dsum = threshold_decrypt(&ctx, &parties, &roundtrip(&ctx, &reference, &parties, &sum, false), 64);
    assert_eq!(dsum, a.iter().zip(&b).map(|(x, y)| (x + y) % P).collect::<Vec<_>>());
    let dprod = threshold_decrypt(&ctx, &parties, &roundtrip(&ctx, &reference, &parties, &prod, false), 64);
    assert_eq!(
        dprod,
        a.iter()
            .zip(&b)
            .map(|(x, y)| ((*x as u128 * *y as u128) % P as u128) as u64)
            .collect::<Vec<_>>()
    );
    // a rebuilt ciphertext is a working ciphertext: evaluate on it
    let rebuilt_a = roundtrip(&ctx, &reference, &parties, &ca, true);
    let d = threshold_decrypt(&ctx, &parties, &ctx.mult(&rebuilt_a, &cb).unwrap(), 64);
    assert_eq!(d, dprod);
    for (name, m, pm) in &seen {
        println!("META {name}: {m:?}; partial {pm:?}");
    }
}

#[test]
fn rebuild_refuses_every_malformed_argument() {
    let _g = serial();
    let (ctx, pk, _parties) = ceremony(2, &[1], 3);
    verify_rebuild_once(&ctx, 3).unwrap();
    let l = ctx.num_towers();
    let n = ctx.ring_dim() as usize;
    let moduli = ctx.moduli().unwrap();
    let reference = ctx.encrypt(&pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
    let ct = ctx.encrypt(&pk, &ctx.plaintext(&[1, 2, 3]).unwrap()).unwrap();
    let good = ct.meta().unwrap();
    let res = ct.export_residues().unwrap();
    ctx.build_ciphertext(&reference, &good, &res).unwrap();
    let refuse = |m: CiphertextMeta, r: &[u64], why: &str| {
        let e = ctx.build_ciphertext(&reference, &m, r).err().unwrap_or_else(|| panic!("accepted: {why}"));
        println!("REFUSED {why}: {}", e.0);
    };
    let with = |f: &dyn Fn(&mut CiphertextMeta)| {
        let mut m = good;
        f(&mut m);
        m
    };
    refuse(with(&|m| m.num_elements = 0), &res, "zero elements");
    refuse(with(&|m| m.num_elements = 3), &res, "three elements");
    refuse(with(&|m| m.num_towers = 0), &res, "zero towers");
    refuse(with(&|m| m.num_towers = l + 1), &res, "more towers than the chain");
    refuse(with(&|m| m.num_towers = u32::MAX), &res, "tower count overflow");
    refuse(with(&|m| m.level = 1), &res, "level inconsistent with towers");
    refuse(with(&|m| m.level = u32::MAX), &res, "level overflow");
    refuse(with(&|m| m.noise_scale_deg = 0), &res, "noise degree 0");
    refuse(with(&|m| m.noise_scale_deg = 3), &res, "noise degree 3");
    refuse(with(&|m| m.scaling_factor_int = 0), &res, "scaling factor 0");
    refuse(with(&|m| m.scaling_factor_int = P), &res, "scaling factor = p");
    refuse(with(&|m| m.scaling_factor_int = u64::MAX), &res, "scaling factor overflow");
    refuse(good, &res[..res.len() - 1], "one residue short");
    let mut long = res.clone();
    long.push(0);
    refuse(good, &long, "one residue extra");
    refuse(good, &[], "no residues");
    // fewer towers with the matching (shorter) residue list is legal; a mismatched list is not
    refuse(
        with(&|m| {
            m.num_towers = l - 1;
            m.level = 1;
        }),
        &res,
        "residues for L towers, metadata for L-1",
    );
    for t in 0..l as usize {
        let mut r = res.clone();
        r[t * n] = moduli[t];
        refuse(good, &r, "residue equal to its modulus");
        let mut r = res.clone();
        r[t * n + n - 1] = u64::MAX;
        refuse(good, &r, "residue u64::MAX");
    }
    // second element too
    let mut r = res.clone();
    r[(l as usize) * n] = moduli[0];
    refuse(good, &r, "residue equal to its modulus in element 1");
    // The rebuilt object takes its key tag from the reference, never from
    // the sender (OpenFHE reuses one context object for identical
    // parameters, so the reference is what binds the key; it is always the
    // receiver's own encryption).
    let back = ctx.build_ciphertext(&reference, &good, &res).unwrap();
    assert_eq!(back.info().unwrap().key_tag, reference.info().unwrap().key_tag);
    // a reference that is not a fresh full-chain ciphertext
    let lower = ctx.mult(&ct, &ct).unwrap();
    let lower = ctx.mult(&lower, &ct).unwrap();
    if lower.meta().unwrap().num_towers < l {
        assert!(ctx.build_ciphertext(&lower, &good, &res).is_err(), "a lower-level reference must be refused");
    }
    // the maximum legal residue (modulus - 1) everywhere is accepted
    let maxed: Vec<u64> = (0..res.len()).map(|i| moduli[(i / n) % l as usize] - 1).collect();
    ctx.build_ciphertext(&reference, &good, &maxed).unwrap();
}

/// Rebuilding is refused until the self-test has passed for the context's
/// parameters in this process (depth 4 is used by no other test here).
#[test]
fn rebuild_is_refused_before_the_self_test() {
    let _g = serial();
    let ctx = Context::new(Params {
        plain_mod: P,
        mult_depth: 4,
        security_bits: 128,
    })
    .unwrap();
    let (pk, _sk) = keygen_first(&ctx).unwrap();
    let reference = ctx.encrypt(&pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
    let ct = ctx.encrypt(&pk, &ctx.plaintext(&[3, 1, 4]).unwrap()).unwrap();
    let (meta, res) = (ct.meta().unwrap(), ct.export_residues().unwrap());
    assert_eq!(rebuild_verified(&ctx).unwrap(), None);
    let e = match ctx.build_ciphertext(&reference, &meta, &res) {
        Ok(_) => panic!("rebuild ran before the self-test"),
        Err(e) => e,
    };
    assert!(e.0.contains("verify_rebuild_once"), "{e}");
    let report = verify_rebuild_once(&ctx, 4).unwrap();
    assert_eq!(report.deepest_level, 4);
    assert_eq!(report.openfhe_version, OPENFHE_VERSION);
    assert!(report.libraries.iter().all(|l| l.ends_with(&format!(".so.{OPENFHE_VERSION}"))), "{report:?}");
    let back = ctx.build_ciphertext(&reference, &meta, &res).unwrap();
    assert_eq!(back.export_residues().unwrap(), res);
    println!("SELFTEST depth 4: {report:?}");
}
