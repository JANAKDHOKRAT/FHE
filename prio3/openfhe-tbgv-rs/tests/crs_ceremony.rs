//! The distributed ceremony primitives: every party generates its key
//! material against a common random `a` and only the `b` residues travel.
//! Three parties, each with its own secret share, build the joint public
//! key, eval-mult key and rotation keys from each other's residues alone;
//! a ciphertext under the joint key is squared, rotated and decrypted with
//! all three partial decryptions. Plus the checks that keep a bad
//! contribution out.
use openfhe_tbgv_rs::*;

const P: u64 = 4_293_918_721;
const TAG: &str = "crs-ceremony-test";

/// SplitMix64 with rejection sampling: uniform residues for the test's `a`
/// (the protocol derives them from a jointly generated seed).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn residues(&mut self, moduli: &[u64], n: usize, polys: usize) -> Vec<u64> {
        let mut v = Vec::with_capacity(polys * moduli.len() * n);
        for _ in 0..polys {
            for &q in moduli {
                let bits = 64 - q.leading_zeros();
                for _ in 0..n {
                    loop {
                        let x = self.next() >> (64 - bits);
                        if x < q {
                            v.push(x);
                            break;
                        }
                    }
                }
            }
        }
        v
    }
}

#[test]
fn three_parties_build_joint_keys_from_residues() {
    let ctx = Context::new(Params { plain_mod: P, mult_depth: 3, security_bits: 128 }).unwrap();
    let n = ctx.ring_dim() as usize;
    let pk_mod = ctx.key_basis_moduli(KeyBasis::PublicKey).unwrap();
    let ks_mod = ctx.key_basis_moduli(KeyBasis::KeySwitch).unwrap();
    let parts = ctx.key_num_parts().unwrap();
    let mut rng = Rng(42);
    let a_pk = rng.residues(&pk_mod, n, 1);
    let a_relin = rng.residues(&ks_mod, n, parts);
    let indices = [1i32, 2, -1];
    let a_rot: Vec<Vec<u64>> = indices.iter().map(|_| rng.residues(&ks_mod, n, parts)).collect();

    // each party: its share and its b residues (all it sends)
    let pk_t = PublicKey::template(&ctx, &a_pk).unwrap();
    let relin_t = EvalMultKey::template(&ctx, &a_relin).unwrap();
    let mut shares = Vec::new();
    let mut pk_b = Vec::new();
    let mut r1_b = Vec::new();
    let mut rot_b: Vec<Vec<Vec<u64>>> = Vec::new();
    for _ in 0..3 {
        let (pk_i, s_i) = PublicKey::share(&ctx, &pk_t).unwrap();
        assert_eq!(pk_i.export(1).unwrap(), a_pk, "share made against the common a");
        pk_b.push(pk_i.export(0).unwrap());
        let r1 = EvalMultKey::round1_next(&ctx, &s_i, &relin_t).unwrap();
        assert!(r1.same_a(&relin_t).unwrap());
        r1_b.push(r1.export(1).unwrap());
        let mut rb = Vec::new();
        for (k, &idx) in indices.iter().enumerate() {
            let t = RotationKeys::single(&ctx, idx, &EvalMultKey::template(&ctx, &a_rot[k]).unwrap()).unwrap();
            let mine = RotationKeys::next(&ctx, &s_i, &t, &[idx], TAG).unwrap();
            let key = mine.get(idx).unwrap();
            assert_eq!(key.export(0).unwrap(), a_rot[k]);
            rb.push(key.export(1).unwrap());
        }
        rot_b.push(rb);
        shares.push(s_i);
    }

    // everyone rebuilds everything from residues and sums
    let mut joint = PublicKey::with_b(&ctx, &pk_t, &pk_b[0]).unwrap();
    for b in &pk_b[1..] {
        joint = PublicKey::add(&ctx, &joint, &PublicKey::with_b(&ctx, &pk_t, b).unwrap(), TAG).unwrap();
    }
    let mut r1 = EvalMultKey::with_b(&ctx, &relin_t, &r1_b[0]).unwrap();
    for b in &r1_b[1..] {
        r1 = EvalMultKey::round1_add(&ctx, &r1, &EvalMultKey::with_b(&ctx, &relin_t, b).unwrap(), TAG).unwrap();
    }
    // round 2 travels as both vectors
    let r2: Vec<(Vec<u64>, Vec<u64>)> = shares
        .iter()
        .map(|s| {
            let k = EvalMultKey::round2(&ctx, s, &r1, TAG).unwrap();
            (k.export(0).unwrap(), k.export(1).unwrap())
        })
        .collect();
    let mut mk = EvalMultKey::build(&ctx, &r2[0].0, &r2[0].1).unwrap();
    for (a, b) in &r2[1..] {
        mk = EvalMultKey::round2_add(&ctx, &mk, &EvalMultKey::build(&ctx, a, b).unwrap(), TAG).unwrap();
    }
    ctx.install_eval_mult_key(&mk, TAG).unwrap();
    ctx.clear_rotation_keys(TAG).unwrap();
    for (k, &idx) in indices.iter().enumerate() {
        let t = EvalMultKey::template(&ctx, &a_rot[k]).unwrap();
        let mut acc = RotationKeys::single(&ctx, idx, &EvalMultKey::with_b(&ctx, &t, &rot_b[0][k]).unwrap()).unwrap();
        for p in 1..3 {
            let c = RotationKeys::single(&ctx, idx, &EvalMultKey::with_b(&ctx, &t, &rot_b[p][k]).unwrap()).unwrap();
            acc = RotationKeys::add(&ctx, &acc, &c, TAG).unwrap();
        }
        ctx.merge_rotation_keys(&acc, TAG).unwrap();
    }

    let row = ctx.row_slots();
    let m: Vec<u64> = (0..row as u64).map(|i| (i * 7919 + 13) % 1000).collect();
    let ct = ctx.encrypt(&joint, &ctx.plaintext(&m).unwrap()).unwrap();
    let decrypt = |c: &Ciphertext| -> Vec<u64> {
        let parts: Vec<PartialDecryption> = shares.iter().enumerate().map(|(i, s)| s.partial_decrypt(c, i == 0).unwrap()).collect();
        let refs: Vec<&PartialDecryption> = parts.iter().collect();
        ctx.fuse(&refs, row).unwrap()
    };
    assert_eq!(decrypt(&ct), m);
    let sq = ctx.square(&ct).unwrap();
    assert_eq!(decrypt(&sq), m.iter().map(|&v| v * v % P).collect::<Vec<_>>());
    for &idx in &indices {
        let r = ctx.rotate(&ct, idx).unwrap();
        let want: Vec<u64> = (0..row).map(|x| m[(x as i64 + idx as i64).rem_euclid(row as i64) as usize]).collect();
        assert_eq!(decrypt(&r), want, "rotation {idx}");
    }
    // two shares cannot decrypt
    let two: Vec<PartialDecryption> = shares[..2].iter().enumerate().map(|(i, s)| s.partial_decrypt(&ct, i == 0).unwrap()).collect();
    assert_ne!(ctx.fuse(&two.iter().collect::<Vec<_>>(), row).unwrap(), m);
    Context::clear_keys_for_tag(TAG).unwrap();
}

fn err<T>(r: Result<T>) -> String {
    match r {
        Ok(_) => panic!("accepted"),
        Err(e) => e.0,
    }
}

#[test]
fn contributions_are_checked_before_they_enter() {
    let ctx = Context::new(Params { plain_mod: P, mult_depth: 3, security_bits: 128 }).unwrap();
    let n = ctx.ring_dim() as usize;
    let pk_mod = ctx.key_basis_moduli(KeyBasis::PublicKey).unwrap();
    let ks_mod = ctx.key_basis_moduli(KeyBasis::KeySwitch).unwrap();
    let parts = ctx.key_num_parts().unwrap();
    let mut rng = Rng(7);
    let a = rng.residues(&pk_mod, n, 1);
    let t = PublicKey::template(&ctx, &a).unwrap();
    let (pk0, s0) = PublicKey::share(&ctx, &t).unwrap();

    // a share against another a does not add
    let other = PublicKey::template(&ctx, &rng.residues(&pk_mod, n, 1)).unwrap();
    let (pk1, _) = PublicKey::share(&ctx, &other).unwrap();
    assert!(err(PublicKey::add(&ctx, &pk0, &pk1, TAG)).contains("different a"));

    // residues at the modulus, and wrong lengths, are refused
    let mut b = pk0.export(0).unwrap();
    b[5] = pk_mod[0];
    assert!(err(PublicKey::with_b(&ctx, &t, &b)).contains("below its tower modulus"));
    let last = b.len() - 1;
    b[5] = 0;
    b[last] = u64::MAX;
    assert!(PublicKey::with_b(&ctx, &t, &b).is_err());
    assert!(err(PublicKey::with_b(&ctx, &t, &b[..last])).contains("residue count"));
    assert!(PublicKey::template(&ctx, &a[1..]).is_err());

    let ks = rng.residues(&ks_mod, n, parts);
    let et = EvalMultKey::template(&ctx, &ks).unwrap();
    assert!(EvalMultKey::template(&ctx, &ks[..ks.len() - n]).is_err());
    let mut bad = ks.clone();
    bad[n] = ks_mod[1];
    assert!(EvalMultKey::with_b(&ctx, &et, &bad).is_err());
    assert!(EvalMultKey::build(&ctx, &ks, &bad).is_err());
    // a contribution against another a is visible as such
    let mine = EvalMultKey::round1_next(&ctx, &s0, &et).unwrap();
    let et2 = EvalMultKey::template(&ctx, &rng.residues(&ks_mod, n, parts)).unwrap();
    assert!(mine.same_a(&et).unwrap());
    assert!(!mine.same_a(&et2).unwrap());

    // rotation maps covering different indices do not add (OpenFHE would drop one)
    let r1 = RotationKeys::next(&ctx, &s0, &RotationKeys::single(&ctx, 1, &et).unwrap(), &[1], TAG).unwrap();
    let r2 = RotationKeys::next(&ctx, &s0, &RotationKeys::single(&ctx, 2, &et).unwrap(), &[2], TAG).unwrap();
    assert!(err(RotationKeys::add(&ctx, &r1, &r2, TAG)).contains("different indices"));
    assert!(r1.get(2).is_err());
    r1.get(1).unwrap();
}
