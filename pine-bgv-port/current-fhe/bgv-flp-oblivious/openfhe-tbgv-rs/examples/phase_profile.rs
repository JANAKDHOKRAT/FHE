//! Real context/noise observations; the accompanying Python derives integer bounds.
use openfhe_tbgv_rs::*;
fn main() {
    for (p, first, scale) in [(65_537u64, 40, 40), (4_293_918_721, 60, 55)] {
        let ctx = Context::new_single(p, 128, first, scale, 3).unwrap();
        let (pk, sk) = keygen_first(&ctx).unwrap();
        let n = ctx.ring_dim() as usize;
        let x: Vec<u64> = (0..n).map(|i| (i as u64 * 2_654_435_761 + 19) % p).collect();
        let q: Vec<u64> = (0..n).map(|i| (i as u64 * 1_178_347_213 + p / 2) % p).collect();
        let ct = ctx.encrypt(&pk, &ctx.coef_plaintext(&x).unwrap()).unwrap();
        let product = ctx.mult_plain(&ct, &ctx.coef_plaintext(&q).unwrap()).unwrap();
        let towers = product.meta().unwrap().num_towers;
        assert_eq!(towers, 3);
        let width = ctx.log2_q().floor() as u32 - (p as f64).log2().ceil() as u32 - 2;
        let reduced = ctx.mod_reduce(&ctx.flood(&product, width).unwrap(), towers - 1).unwrap();
        for c in [0, n / 2] {
            let expected = (0..n).fold(0u128, |acc, i| {
                let j = (n + c - i) % n;
                let v = x[i] as u128 * q[j] as u128 % p as u128;
                (acc + if i <= c { v } else { p as u128 - v }) % p as u128
            });
            assert_eq!(sk.decrypt_coeffs(&reduced, &[c as u32]).unwrap()[0], expected as u64);
        }
        let (phase, bottom) = sk.phase_inf_norm(&reduced).unwrap();
        println!(
            "{{\"p\":{p},\"ring\":{n},\"moduli\":{:?},\"error_support_bound\":{},\"flood_width\":{width},\"observed_max_phase\":{phase},\"bottom_modulus\":{bottom},\"selected_outputs_correct\":true}}",
            ctx.moduli().unwrap(),
            ctx.single_gaussian_bound().unwrap()
        );
    }
}
