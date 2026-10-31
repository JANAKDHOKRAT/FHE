//! Single-key contexts (`Context::new_single`): evaluator-side flooding,
//! modulus reduction and full-key coefficient decryption.
use openfhe_tbgv_rs::*;

const T: u64 = 4_293_918_721; // prio's FieldPrio2 modulus

fn rng(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn setup() -> (Context, PublicKey, SecretShare) {
    let ctx = Context::new_single(T, 128, 60, 55, 3).expect("context");
    let (pk, sk) = keygen_first(&ctx).expect("keygen");
    (ctx, pk, sk)
}

/// Largest flooding width the shim allows for a ciphertext of `towers` towers.
fn width(ctx: &Context, towers: usize) -> u32 {
    let log_q: f64 = ctx.moduli().unwrap()[..towers].iter().map(|&q| (q as f64).log2()).sum();
    log_q.floor() as u32 - (T as f64).log2().ceil() as u32 - 2
}

#[test]
fn single_context_is_ring_8192_with_q_inside_the_128_bit_bound() {
    let (ctx, _, _) = setup();
    assert_eq!(ctx.ring_dim(), 8192);
    assert_eq!(ctx.num_towers(), 3);
    assert!(ctx.log2_q() <= 218.0, "log2 Q = {}", ctx.log2_q());
}

/// Worst case: a plaintext product with every coefficient a full-size field
/// element. Flooding hides the phase up to 2^-lambda per coefficient.
#[test]
fn flooding_margin_after_dense_plaintext_product() {
    let (ctx, pk, sk) = setup();
    let n = ctx.ring_dim() as usize;
    let mut seed = 3;
    let z: Vec<u64> = (0..n).map(|_| rng(&mut seed) % T).collect();
    let q: Vec<u64> = (0..n).map(|_| rng(&mut seed) % T).collect();
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&z).unwrap()).unwrap();
    let prod = ctx.mult_plain(&ct, &ctx.coef_plaintext(&q).unwrap()).unwrap();
    let towers = prod.meta().unwrap().num_towers as usize;
    let (_, log2_phase, _) = ctx.raw_decrypt_for_tests(&prod, &[&sk]).unwrap();
    let w = width(&ctx, towers);
    let lambda = w as f64 - 1.0 - (log2_phase - (T as f64).log2());
    eprintln!("towers = {towers}, flood width = {w}, log2 max|phase| = {log2_phase:.1}, lambda = {lambda:.1} bits");
    assert!(lambda >= 64.0, "lambda {lambda:.1} below 64");
}

#[test]
fn flood_mask_and_reduce_keep_the_selected_coefficients() {
    let (ctx, pk, sk) = setup();
    let n = ctx.ring_dim() as usize;
    let mut seed = 11;
    let z: Vec<u64> = (0..n).map(|_| rng(&mut seed) % T).collect();
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&z).unwrap()).unwrap();
    // product with 1 + X^(n-1): coefficient 0 = z0 - z1
    let mut q = vec![0u64; n];
    q[0] = 1;
    q[n - 1] = 1;
    let prod = ctx.mult_plain(&ct, &ctx.coef_plaintext(&q).unwrap()).unwrap();
    // mask every coefficient but 0 with uniform values, add 5 at coefficient 0
    let mut mask: Vec<u64> = (0..n).map(|_| rng(&mut seed) % T).collect();
    mask[0] = 5;
    let masked = ctx.add_plain(&prod, &ctx.coef_plaintext(&mask).unwrap()).unwrap();
    let towers = masked.meta().unwrap().num_towers as usize;
    let flooded = ctx.flood(&masked, width(&ctx, towers)).unwrap();
    let reduced = ctx.mod_reduce(&flooded, towers as u32 - 1).unwrap();
    assert_eq!(reduced.meta().unwrap().num_towers, 1);
    let want0 = (z[0] + T - z[1] + 5) % T;
    assert_eq!(sk.decrypt_coeffs(&reduced, &[0]).unwrap(), vec![want0]);
    // coefficient 7 is product + mask: not the product's value
    let unmasked7 = sk.decrypt_coeffs(&prod, &[7]).unwrap()[0];
    let masked7 = sk.decrypt_coeffs(&reduced, &[7]).unwrap()[0];
    assert_eq!(masked7, (unmasked7 + mask[7]) % T);
}

#[test]
fn flooding_randomizes_the_ciphertext_not_the_plaintext() {
    let (ctx, pk, sk) = setup();
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&[9, 8, 7]).unwrap()).unwrap();
    let w = width(&ctx, ctx.num_towers() as usize);
    let a = ctx.flood(&ct, w).unwrap();
    let b = ctx.flood(&ct, w).unwrap();
    assert_ne!(a.export_residues().unwrap(), b.export_residues().unwrap());
    for c in [&a, &b] {
        assert_eq!(sk.decrypt_coeffs(c, &[0, 1, 2]).unwrap(), vec![9, 8, 7]);
    }
}

#[test]
fn too_wide_a_flood_is_refused() {
    let (ctx, pk, _) = setup();
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&[1]).unwrap()).unwrap();
    let w = width(&ctx, ctx.num_towers() as usize);
    assert!(ctx.flood(&ct, w + 1).is_err());
    assert!(ctx.flood(&ct, 0).is_err());
    assert!(ctx.mod_reduce(&ct, 3).is_err());
}
