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
