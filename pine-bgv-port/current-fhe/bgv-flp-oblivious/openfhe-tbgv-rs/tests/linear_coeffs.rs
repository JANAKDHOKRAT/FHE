//! Depth-0 linear contexts, coefficient encoding and coefficient-restricted
//! threshold decryption (`Context::new_linear`, `coef_plaintext`,
//! `partial_decrypt_coeffs`, `fuse_coeffs`).
use openfhe_tbgv_rs::*;

const T: u64 = 4_293_918_721; // prio's FieldPrio2 modulus

fn rng(seed: &mut u64) -> u64 {
    // splitmix64: deterministic test data, not key material
    *seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn setup(parties: usize) -> (Context, PublicKey, Vec<SecretShare>) {
    // digit size 30: the widest last tower OpenFHE allows with BV, see fhe-flp
    let ctx = Context::new_linear(T, 128, parties as u32, 30).expect("context");
    let (mut pk, sk) = keygen_first(&ctx).expect("keygen");
    let mut sks = vec![sk];
    for _ in 1..parties {
        let (p, s) = keygen_next(&ctx, &pk).expect("keygen");
        pk = p;
        sks.push(s);
    }
    (ctx, pk, sks)
}

/// Query polynomial whose product with z(X) holds <rows[j], z> at coefficient j*L.
fn query_poly(n: usize, l: usize, rows: &[Vec<u64>]) -> Vec<u64> {
    let mut q = vec![0u64; n];
    for (j, row) in rows.iter().enumerate() {
        for (i, &c) in row.iter().enumerate() {
            let pos = (j * l) as i64 - i as i64;
            if pos >= 0 {
                q[pos as usize] = (q[pos as usize] + c) % T;
            } else {
                let p = (n as i64 + pos) as usize; // X^-i = -X^(n-i)
                q[p] = (q[p] + T - c) % T;
            }
        }
    }
    q
}

fn inner(row: &[u64], z: &[u64]) -> u64 {
    row.iter().zip(z).fold(0u128, |a, (&x, &y)| (a + x as u128 * y as u128) % T as u128) as u64
}

#[test]
fn linear_context_is_ring_8192_with_q_inside_the_128_bit_bound() {
    let (ctx, _pk, _sks) = setup(2);
    assert_eq!(ctx.ring_dim(), 8192);
    // HE standard, ternary secret, 128-bit classical: log2 Q <= 218 at N = 8192.
    // With BV there is no P, so Q is the whole modulus any sample lives under.
    assert!(ctx.log2_q() <= 218.0, "log2 Q = {}", ctx.log2_q());
}

#[test]
fn restricted_inner_products_are_exact_and_nothing_else_decrypts() {
    for parties in [2usize, 3] {
        let (ctx, pk, sks) = setup(parties);
        let n = ctx.ring_dim() as usize;
        let mut seed = 7 + parties as u64;
        for (l, r) in [(21usize, 16usize), (300, 27), (800, 10)] {
            let z: Vec<u64> = (0..l).map(|_| rng(&mut seed) % T).collect();
            let rows: Vec<Vec<u64>> = (0..r).map(|_| (0..l).map(|_| rng(&mut seed) % T).collect()).collect();
            let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&z).unwrap()).unwrap();
            let prod = ctx.mult_plain(&ct, &ctx.coef_plaintext(&query_poly(n, l, &rows)).unwrap()).unwrap();
            let idx: Vec<u32> = (0..r).map(|j| (j * l) as u32).collect();
            let partials: Vec<PartialDecryption> = sks
                .iter()
                .enumerate()
                .map(|(i, s)| s.partial_decrypt_coeffs(&prod, i == 0, &idx).unwrap())
                .collect();
            let refs: Vec<&PartialDecryption> = partials.iter().collect();
            let got = ctx.fuse_coeffs(&refs, &idx).unwrap();
            let want: Vec<u64> = rows.iter().map(|row| inner(row, &z)).collect();
            assert_eq!(got, want, "parties={parties} L={l} R={r}");
        }
    }
}

#[test]
fn mismatched_restrictions_are_refused() {
    let (ctx, pk, sks) = setup(2);
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&[5, 6, 7]).unwrap()).unwrap();
    let a = sks[0].partial_decrypt_coeffs(&ct, true, &[0]).unwrap();
    let b = sks[1].partial_decrypt_coeffs(&ct, false, &[0, 2]).unwrap();
    // b leaks coefficient 2 of its share; fusing for {0} sees it and refuses
    assert!(ctx.fuse_coeffs(&[&a, &b], &[0]).is_err());
    // asked for {0, 2}, coefficient 2 holds only one share: not the plaintext
    // (callers must derive one index set for all parties; fhe-flp does)
    let got = ctx.fuse_coeffs(&[&a, &b], &[0, 2]).unwrap();
    assert_ne!(got[1], 7);
    let b0 = sks[1].partial_decrypt_coeffs(&ct, false, &[0]).unwrap();
    assert_eq!(ctx.fuse_coeffs(&[&a, &b0], &[0]).unwrap(), vec![5]);
}

#[test]
fn bad_index_sets_are_refused() {
    let (ctx, pk, sks) = setup(2);
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&[1]).unwrap()).unwrap();
    let n = ctx.ring_dim();
    for idx in [vec![], vec![n], vec![3, 3], vec![4, 2]] {
        assert!(sks[0].partial_decrypt_coeffs(&ct, true, &idx).is_err(), "{idx:?}");
    }
    // a SIMD-packed ciphertext is refused
    let simd = ctx.encrypt(&pk, &ctx.plaintext(&[1]).unwrap()).unwrap();
    assert!(sks[0].partial_decrypt_coeffs(&simd, true, &[0]).is_err());
}

/// The noise that flooding must hide, after one dense plaintext
/// multiplication, against the flooding range: each party adds t * E with E
/// uniform in [-Q'/2, Q'/2], Q' = Q / q0. The statistical distance per
/// coefficient is at most |phase| / (t Q' / 2).
#[test]
fn flooding_margin_after_dense_plaintext_product() {
    let (ctx, pk, sks) = setup(2);
    let n = ctx.ring_dim() as usize;
    let moduli = ctx.moduli().unwrap();
    let mut seed = 99;
    // worst-case-sized query: every coefficient a full-size field element
    let z: Vec<u64> = (0..n).map(|_| rng(&mut seed) % T).collect();
    let q: Vec<u64> = (0..n).map(|_| rng(&mut seed) % T).collect();
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&z).unwrap()).unwrap();
    let prod = ctx.mult_plain(&ct, &ctx.coef_plaintext(&q).unwrap()).unwrap();
    let refs: Vec<&SecretShare> = sks.iter().collect();
    let (_, log2_max, _) = ctx.raw_decrypt_for_tests(&prod, &refs).unwrap();
    // the product may sit lower in the chain than a fresh ciphertext: Q' is
    // over the product's own towers
    let towers = prod.meta().unwrap().num_towers as usize;
    let log2_q_prime: f64 = moduli[1..towers].iter().map(|&q| (q as f64).log2()).sum();
    eprintln!("product towers = {towers} of {}", moduli.len());
    let margin = (T as f64).log2() + log2_q_prime - 1.0 - log2_max;
    eprintln!("log2 Q' = {log2_q_prime:.1}, log2 max|phase| = {log2_max:.1}, flooding margin = {margin:.1} bits");
    assert!(margin >= 64.0, "flooding margin {margin:.1} bits is below 64");
}

#[test]
fn restricted_partials_travel_as_their_kept_residues() {
    let (ctx, pk, sks) = setup(2);
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&[11, 0, 0, 0, 22]).unwrap()).unwrap();
    let idx = [0u32, 4];
    let a = sks[0].partial_decrypt_coeffs(&ct, true, &idx).unwrap();
    let b = sks[1].partial_decrypt_coeffs(&ct, false, &idx).unwrap();
    let wire = b.export_coeffs(&idx).unwrap();
    assert_eq!(wire.len(), ctx.num_towers() as usize * idx.len());
    let b2 = PartialDecryption::from_coeffs(&ctx, &a, &idx, &wire, false).unwrap();
    assert_eq!(ctx.fuse_coeffs(&[&a, &b2], &idx).unwrap(), vec![11, 22]);
    // the rebuilt partial is the same object
    assert_eq!(b2.export_coeffs(&idx).unwrap(), wire);
    // residues at or above their modulus are refused
    let mut bad = wire.clone();
    bad[0] = ctx.moduli().unwrap()[0];
    assert!(PartialDecryption::from_coeffs(&ctx, &a, &idx, &bad, false).is_err());
    // wrong length is refused
    assert!(PartialDecryption::from_coeffs(&ctx, &a, &idx, &wire[1..], false).is_err());
}
