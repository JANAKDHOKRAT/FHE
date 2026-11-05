//! Honest phase bound for the inspected OpenFHE 1.3.1 FIXEDMANUAL path.
//! This range guard is NOT an IND-CPA-D or circuit-privacy proof.
use super::*;
use num_bigint::BigUint;

pub(super) struct PhaseBound {
    pub maximum: u64,
    pub modulus: u64,
}
impl PhaseBound {
    pub fn new<F: FheField, T: VerifierMap<F>>(task: &SingleTask<F, T>) -> Result<Self> {
        let qs = task.ctx.moduli()?;
        let p = F::PLAIN_MOD;
        if qs.len() != F::SINGLE_NUM_TOWERS as usize || qs.iter().any(|q| q % p != 1) {
            return Err(Error::Protocol("unqualified phase-bound modulus chain".into()));
        }
        let n = task.layout().ring;
        let e = task.ctx.single_gaussian_bound()?;
        // Inversion sampler support: |e_pk|,|e0|,|e1| <= e. Ternary s,u.
        // pk0=p*e_pk-a*s, pk1=a; fresh phase m+p*(e_pk*u+e0+e1*s).
        // ||a*b||inf <= n ||a||inf ||b||inf, and |m| <= p-1.
        let h = BigUint::from(p - 1) + BigUint::from(p) * BigUint::from(2 * n + 1) * BigUint::from(e);
        let per = n / task.agg.coeffs().len();
        let blocks = task.max_batch().div_ceil(per as u64).max(2);
        // Checks add at most two plaintext products; correction adds at most
        // blocks products. Every plaintext coefficient has magnitude <= p-1.
        // One further plaintext mask contributes at most p-1.
        let a = BigUint::from(blocks) * BigUint::from(n) * BigUint::from(p - 1) * h + BigUint::from(p - 1);
        let mut modulus: BigUint = qs.iter().map(|q| BigUint::from(*q)).product();
        let ceiling_log_p = 64 - (p - 1).leading_zeros();
        let width = (modulus.bits() - 1)
            .checked_sub(ceiling_log_p as u64 + 2)
            .ok_or_else(|| Error::Protocol("insufficient flooding modulus".into()))?;
        let float_width = qs.iter().map(|q| (*q as f64).log2()).sum::<f64>().floor() as u64 - (p as f64).log2().ceil() as u64 - 2;
        if width == 0 || width != float_width {
            return Err(Error::Protocol("flooding-width implementation differs from exact bound".into()));
        }
        // Uniform centered flood is in [-2^(w-1),2^(w-1)-1].
        let mut bound = a + BigUint::from(p) * (BigUint::from(1u8) << (width as usize - 1));
        if (&bound << 1usize) >= modulus {
            return Err(Error::Protocol("honest phase may wrap before reduction".into()));
        }
        for q in qs.iter().skip(1).rev() {
            // OpenFHE ModReduce: (c+p*delta)/q, |delta|<=floor(q/2).
            // Decrypting two components adds delta0+delta1*s, l1(s)<=n.
            let numerator = bound + BigUint::from(p) * BigUint::from(q / 2) * BigUint::from(n + 1);
            bound = (numerator + BigUint::from(q - 1)) / BigUint::from(*q);
            modulus /= BigUint::from(*q);
            if (&bound << 1usize) >= modulus {
                return Err(Error::Protocol("honest phase may wrap during reduction".into()));
            }
        }
        let maximum = u64::try_from(bound).map_err(|_| Error::Protocol("phase bound exceeds native modulus".into()))?;
        Ok(Self { maximum, modulus: qs[0] })
    }
}
