//! `SecretShare::phase_bits`: exact bit length of a ciphertext's phase.
use openfhe_tbgv_rs::{Context, keygen_first};

const T: u64 = 4_293_918_721;

#[test]
fn phase_bits_of_fresh_and_noisy_ciphertexts() {
    let ctx = Context::new_single(T, 128, 60, 55, 3).unwrap();
    let (pk, sk) = keygen_first(&ctx).unwrap();
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&[5, 6, 7]).unwrap()).unwrap();
    let fresh = sk.phase_bits(&ct).unwrap();
    // m + t e with a small e: above the 32 bits of t, far below Q.
    assert!((33..80).contains(&fresh), "fresh phase has {fresh} bits");
    // Flooding with a 64-bit width adds t * E, E below 2^63.
    let flooded = sk.phase_bits(&ctx.flood(&ct, 64).unwrap()).unwrap();
    assert!((90..=96).contains(&flooded), "flooded phase has {flooded} bits");
    // The value agrees with the floating-point statistic used elsewhere.
    let (_, log2_phase, _) = ctx.raw_decrypt_for_tests(&ct, &[&sk]).unwrap();
    assert_eq!(fresh, log2_phase.floor() as u32 + 1);
    // A plaintext product multiplies the phase by the centered plaintext:
    // t - 1 is -1 (no growth beyond the ring dimension), t / 2 is 31 bits.
    let times = |v: u64| sk.phase_bits(&ctx.mult_plain(&ct, &ctx.coef_plaintext(&[v; 8192]).unwrap()).unwrap()).unwrap();
    assert!(times(T - 1) <= fresh + 13, "{} bits", times(T - 1));
    assert!(times(T / 2) > fresh + 30, "{} bits", times(T / 2));
}

/// The bounds a key holder derives a ciphertext admission rule from, on
/// real ciphertexts: the sampler's support, the phase of an honest
/// encryption, and the rounding a modulus switch adds.
#[test]
fn honest_phase_and_modulus_switch_stay_within_the_derived_bounds() {
    let ctx = Context::new_single(T, 128, 60, 55, 3).unwrap();
    let n = ctx.ring_dim() as u128;
    assert_eq!(n, 8192);
    let e = ctx.gaussian_bound().unwrap();
    assert_eq!(e, 39); // ceil(3.19 * 12.0061)
    // Every modulus is 1 modulo t: a modulus switch keeps the plaintext.
    assert!(ctx.moduli().unwrap().iter().all(|q| q % T == 1));
    // |phase| <= |m| + t (2 N + 1) E for an honest encryption.
    let honest = T as u128 + T as u128 * (2 * n + 1) * e as u128;
    let honest_bits = 128 - honest.leading_zeros();
    let dense: Vec<u64> = (0..8192u64).map(|i| i * 524_287 % T).collect();
    for _ in 0..20 {
        let (pk, sk) = keygen_first(&ctx).unwrap();
        let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&dense).unwrap()).unwrap();
        assert!(sk.phase_bits(&ct).unwrap() <= honest_bits);
        // A modulus switch divides the phase by the dropped modulus (55
        // bits) and adds at most t (N + 1) / 2, about 2^44.
        let rounding = T as u128 * (n + 1) / 2;
        let rounding_bits = 128 - (rounding + 1).leading_zeros();
        let small = sk.phase_bits(&ctx.mod_reduce(&ct, 1).unwrap()).unwrap();
        assert!(small <= rounding_bits, "{small} bits after switching a fresh ciphertext");
        let flooded = ctx.flood(&ct, 120).unwrap();
        let before = sk.phase_bits(&flooded).unwrap();
        let after = sk.phase_bits(&ctx.mod_reduce(&flooded, 1).unwrap()).unwrap();
        assert!((before - 56..=before - 54).contains(&after), "{before} bits before, {after} after");
        assert_eq!(sk.decrypt_coeffs(&ctx.mod_reduce(&flooded, 2).unwrap(), &[0, 1, 2]).unwrap(), dense[..3]);
    }
}
