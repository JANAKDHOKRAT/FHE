//! Exact phase arithmetic and counterexamples, with real OpenFHE objects.
use openfhe_tbgv_rs::*;
fn setup() -> (Context, PublicKey, SecretShare) {
    let ctx = Context::new_single(65537, 128, 40, 40, 3).unwrap();
    verify_single_rebuild_once(&ctx).unwrap();
    let (pk, sk) = keygen_first(&ctx).unwrap();
    (ctx, pk, sk)
}
#[test]
fn exact_phase_matches_the_existing_independent_crt_diagnostic() {
    let (ctx, pk, sk) = setup();
    assert_eq!(ctx.single_gaussian_bound().unwrap(), 39);
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&[1, 2, 65536]).unwrap()).unwrap();
    assert!(sk.phase_inf_norm(&ct).is_err()); // fresh multi-tower refused
    let reduced = ctx.mod_reduce(&ctx.flood(&ct, 100).unwrap(), 2).unwrap();
    let (maximum, q) = sk.phase_inf_norm(&reduced).unwrap();
    let (values, _, _) = ctx.raw_decrypt_for_tests(&reduced, &[&sk]).unwrap();
    let independent = values.iter().map(|x| (x.abs() * 65537.0).round() as u64).max().unwrap();
    assert_eq!(maximum, independent);
    assert_eq!(q, ctx.moduli().unwrap()[0]);
    let (_, wrong) = keygen_first(&ctx).unwrap();
    assert!(wrong.phase_inf_norm(&reduced).is_err());
}
#[test]
fn zero_phase_does_not_prove_a_ciphertext_is_an_authorized_aggregate() {
    let (ctx, pk, sk) = setup();
    let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&[1]).unwrap()).unwrap();
    let reference = ctx.mod_reduce(&ct, 2).unwrap();
    // Attacker knows no secret: replace both public ciphertext elements by zero.
    let zero = vec![0; 2 * ctx.ring_dim() as usize];
    let forged = ctx.build_ciphertext(&ct, &reference.meta().unwrap(), &zero).unwrap();
    assert_eq!(sk.phase_inf_norm(&forged).unwrap().0, 0);
    assert_eq!(sk.decrypt_coeffs(&forged, &[0]).unwrap(), [0]);
    assert_eq!(sk.decrypt_coeffs(&reference, &[0]).unwrap(), [1]);
}
#[test]
fn doubling_can_return_below_a_threshold_after_exceeding_it() {
    let (ctx, pk, sk) = setup();
    let fresh = ctx.encrypt(&pk, &ctx.coef_plaintext(&[1]).unwrap()).unwrap();
    let reference = ctx.mod_reduce(&fresh, 2).unwrap();
    let q = ctx.moduli().unwrap()[0];
    // Build the public constant ciphertext (floor(q/2),0). Constant-polynomial
    // NTT evaluations are all floor(q/2). This uses real reconstruction and
    // secret-key phase measurement, with no simulated decryption.
    let n = ctx.ring_dim() as usize;
    let mut residues = vec![0; 2 * n];
    residues[..n].fill(q / 2);
    let high = ctx.build_ciphertext(&fresh, &reference.meta().unwrap(), &residues).unwrap();
    let doubled = ctx.add(&high, &high).unwrap();
    assert_eq!(sk.phase_inf_norm(&high).unwrap().0, q / 2);
    assert_eq!(sk.phase_inf_norm(&doubled).unwrap().0, 1);
}
