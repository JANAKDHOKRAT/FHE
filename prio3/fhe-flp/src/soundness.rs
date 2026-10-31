//! Soundness of the FLP check, from the formulas the VDAF draft's authors
//! use (draft-irtf-cfrg-vdaf repository, `poc/plot_prio3_multiproof_robustness.py`,
//! commit e1d1e1c, and the draft's "Multiple Proofs" security section):
//!
//! * base soundness of one proof (BBCGGI19, Theorem 4.3):
//!   `sum over gadgets of calls * degree / (p - calls)`;
//! * a circuit with several outputs compressed by a random linear
//!   combination of the verifier's query randomness adds `1/p` (a non-zero
//!   vector is orthogonal to a uniform vector with probability `1/p`);
//! * `PROOFS` independent proofs, each checked with independent query
//!   randomness: `(circuit + flp)^PROOFS`.
//!
//! No joint randomness is used (`Task::new` refuses types that need it), so
//! there is no offline search over joint randomness: the query randomness
//! comes from a key the client never sees, and the bound is per submitted
//! report (multiply by the number of reports an attacker submits).
use prio::field::NttFriendlyFieldElement;
use prio::flp::Flp;

/// `log2` of the probability that one invalid report passes one proof's check
/// in a field of prime order `p` (as `f64`, so other primes can be studied).
pub fn log2_per_proof<T: Flp>(typ: &T, p: f64) -> f64
where
    T::Field: NttFriendlyFieldElement,
{
    let mut eps = 0.0;
    for g in typ.gadget() {
        let calls = g.calls() as f64;
        eps += calls * g.degree() as f64 / (p - calls);
    }
    if typ.eval_output_len() > 1 {
        eps += 1.0 / p;
    }
    eps.log2()
}

/// `log2` of the soundness error with `proofs` independent proofs.
pub fn log2_error<T: Flp>(typ: &T, p: f64, proofs: usize) -> f64
where
    T::Field: NttFriendlyFieldElement,
{
    log2_per_proof(typ, p) * proofs as f64
}

/// The fewest proofs whose error is at most `2^-target_bits`.
pub fn proofs_for<T: Flp>(typ: &T, p: f64, target_bits: f64) -> usize
where
    T::Field: NttFriendlyFieldElement,
{
    let per = -log2_per_proof(typ, p);
    (target_bits / per).ceil().max(1.0) as usize
}
