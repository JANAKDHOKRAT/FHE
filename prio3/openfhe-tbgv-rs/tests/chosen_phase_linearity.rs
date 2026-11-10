//! Demonstrates a boundary of the FLP reduction, not a PINE proof forgery.
//! Canonical residues do not establish that plaintext products decrypt as
//! linear field queries of a single decoded input.
use openfhe_tbgv_rs::*;

#[test]
fn canonical_chosen_phase_breaks_decoded_scalar_linearity() {
    let p = 4_293_918_721u64;
    let ctx = Context::new_single(p, 128, 60, 55, 3).unwrap();
    verify_single_rebuild_once(&ctx).unwrap();
    let (pk, sk) = keygen_first(&ctx).unwrap();
    let reference = ctx.encrypt(&pk, &ctx.coef_plaintext(&[0]).unwrap()).unwrap();
    let moduli = ctx.moduli().unwrap();
    assert!(moduli.iter().all(|q| q % (2 * p) == 1));
    let n = ctx.ring_dim() as usize;
    // Q is odd. The constant polynomial floor(Q/2) has residue
    // (q_j-1)/2 in each RNS tower. Evaluation coordinates of a constant
    // polynomial are constant. Set c1=0, making phase independent of sk.
    let mut residues = Vec::new();
    for &q in &moduli {
        residues.extend(vec![(q - 1) / 2; n]);
    }
    residues.extend(vec![0; moduli.len() * n]);
    let chosen = ctx.build_ciphertext(&reference, &reference.meta().unwrap(), &residues).unwrap();
    let before = sk.decrypt_coeffs(&chosen, &[0]).unwrap()[0];
    let doubled = ctx.mult_plain(&chosen, &ctx.coef_plaintext(&[2]).unwrap()).unwrap();
    let after = sk.decrypt_coeffs(&doubled, &[0]).unwrap()[0];
    eprintln!(
        "chosen phase: decode={before}, decode(2*ct)={after}, expected field-linear={}",
        (2 * before) % p
    );
    assert_eq!(before, 0);
    assert_eq!(after, p - 1);
    assert_ne!(after, (2 * before) % p);
}
