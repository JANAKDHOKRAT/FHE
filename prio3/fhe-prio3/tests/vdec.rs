//! Verifiable decryption (`vdec.rs`) with real threshold keys: honest
//! partial decryptions pass; a shifted partial of an accumulator or of a
//! check is caught; a cheater who knew the exponents would pass (the check
//! rests on their secrecy until the commitments); a verifier cannot pass
//! an unrelated ciphertext off as a check; a partial that makes the fusion
//! wrap is caught by the magnitude bound.
mod common;

use common::{serial, task_id};
use fhe_prio3::vdec;
use fhe_prio3::*;
use openfhe_tbgv_rs::{Ciphertext, PartialDecryption};

struct Setup {
    ctx: openfhe_tbgv_rs::Context,
    pk: openfhe_tbgv_rs::PublicKey,
    shares: Vec<openfhe_tbgv_rs::SecretShare>,
    _lease: keys::KeyLease,
}

fn setup(id: u8) -> Setup {
    let cfg = TaskConfig::new(task_id(id), MeasurementType::Count, 3);
    let (material, shares) = keys::run_local_ceremony(&cfg).unwrap();
    let ctx = keys::make_context(&cfg).unwrap();
    let lease = keys::install(&ctx, &material).unwrap();
    let pk = ctx.deserialize_public_key(&material.public_key).unwrap();
    // the ceremony hands out encoded AggregatorSecrets; the share is inside
    let shares = shares
        .iter()
        .map(|s| ctx.deserialize_secret_share(&keys::AggregatorSecret::decode(s).unwrap().share).unwrap())
        .collect();
    Setup {
        ctx,
        pk,
        shares,
        _lease: lease,
    }
}

impl Setup {
    fn partials(&self, c: &Ciphertext) -> Vec<PartialDecryption> {
        self.shares.iter().enumerate().map(|(i, s)| s.partial_decrypt(c, i == 0).unwrap()).collect()
    }
    fn enc(&self, v: &[u64]) -> Ciphertext {
        self.ctx.encrypt(&self.pk, &self.ctx.plaintext(v).unwrap()).unwrap()
    }
    /// Partial `p` with its plaintext shifted by `d` in slot 0.
    fn shifted(&self, p: &PartialDecryption, d: u64) -> PartialDecryption {
        let ct = self.ctx.add_plain(p.ciphertext(), &self.ctx.plaintext(&[d]).unwrap()).unwrap();
        PartialDecryption::from_ciphertext(ct, p.is_lead())
    }
}

/// Runs a verification in which aggregator 1 replaces its accumulator
/// partials with `cheat_acc` and its check partials with `cheat_check`.
fn run(
    s: &Setup,
    accs: &[Ciphertext],
    cheat_acc: &dyn Fn(usize, &PartialDecryption) -> PartialDecryption,
    cheat_check: &dyn Fn(usize, &PartialDecryption, &vdec::Opening) -> PartialDecryption,
) -> Result<()> {
    let refs: Vec<&Ciphertext> = accs.iter().collect();
    let opening = vdec::draw(&s.ctx, &refs, &mut rand::thread_rng())?;
    let checks = vdec::build(&s.ctx, &s.pk, &refs, &opening)?;
    // aggregators rebuild the checks from their own accumulators once opened
    for (a, b) in checks.iter().zip(vdec::build(&s.ctx, &s.pk, &refs, &opening)?) {
        assert!(vdec::same(a, &b)?);
    }
    let groups = vdec::groups(&refs)?;
    let powers = vdec::SlotPowers::new(&s.ctx)?;
    let mut fused_accs = Vec::new();
    for (i, c) in accs.iter().enumerate() {
        let mut p = s.partials(c);
        p[1] = cheat_acc(i, &p[1]);
        fused_accs.push(vdec::fuse_checked(&s.ctx, &p.iter().collect::<Vec<_>>(), "accumulator")?);
    }
    let mut fused_checks = Vec::new();
    for (i, c) in checks.iter().enumerate() {
        let mut p = s.partials(c);
        p[1] = cheat_check(i, &p[1], &opening);
        fused_checks.push(vdec::fuse_checked(&s.ctx, &p.iter().collect::<Vec<_>>(), "check")?);
    }
    vdec::verify(&powers, &groups, &fused_accs, &fused_checks, &opening)
}

#[test]
fn checks_accept_honest_and_catch_shifted_partials() {
    let _g = serial();
    let s = setup(120);
    let n = s.ctx.ring_dim() as usize;
    let p = s.ctx.plain_mod();
    let per = vdec::check_count(n);
    assert!(per as u32 * (2 * n as u64).ilog2() >= vdec::CHECK_SECURITY_BITS);
    let a = s.enc(&[1, 2, 3]);
    let b = s.enc(&[40, 50]);
    let prod = s.ctx.mult(&s.enc(&[7, 7, 7]), &s.enc(&[3, 5, 9])).unwrap();
    let accs = vec![a, b, prod];
    let refs: Vec<&Ciphertext> = accs.iter().collect();
    assert_eq!(vdec::groups(&refs).unwrap(), vec![vec![0, 1], vec![2]]);
    let keep = |_: usize, q: &PartialDecryption| PartialDecryption::from_ciphertext(q.ciphertext().try_clone().unwrap(), q.is_lead());
    let keep_c = |_: usize, q: &PartialDecryption, _: &vdec::Opening| PartialDecryption::from_ciphertext(q.ciphertext().try_clone().unwrap(), q.is_lead());
    run(&s, &accs, &keep, &keep_c).unwrap();

    // aggregator 1 shifts the second accumulator by 1 in slot 0
    let e = run(&s, &accs, &|i, q| if i == 1 { s.shifted(q, 1) } else { keep(i, q) }, &keep_c)
        .unwrap_err()
        .to_string();
    assert!(e.contains("fails in slot 0"), "{e}");
    // ... and also shifts every check by what it would need for a guessed exponent
    let guess = |i: usize, q: &PartialDecryption, _: &vdec::Opening| {
        if i < per {
            s.shifted(q, 1)
        } else {
            keep_c(i, q, &vdec::Opening { checks: vec![] })
        }
    };
    let e = run(&s, &accs, &|i, q| if i == 1 { s.shifted(q, 1) } else { keep(i, q) }, &guess)
        .unwrap_err()
        .to_string();
    assert!(e.contains("fails in slot 0"), "{e}");
    // with the exponents in hand the same cheat would pass: the check rests
    // on their secrecy until the commitments are in
    let w = s.ctx.monomial_slots().unwrap();
    let knowing = |i: usize, q: &PartialDecryption, o: &vdec::Opening| {
        if i < per {
            // group 0 holds accumulators 0 and 1; the shift sits in accumulator 1
            let k = o.checks[i].ks[1] as u64;
            let mut x = 1u64;
            for _ in 0..k {
                x = ((x as u128 * w[0] as u128) % p as u128) as u64;
            }
            s.shifted(q, x)
        } else {
            keep_c(i, q, o)
        }
    };
    run(&s, &accs, &|i, q| if i == 1 { s.shifted(q, 1) } else { keep(i, q) }, &knowing).unwrap();
    // a shifted check alone
    let e = run(&s, &accs, &keep, &|i, q, o| if i == per + 1 { s.shifted(q, 3) } else { keep_c(i, q, o) })
        .unwrap_err()
        .to_string();
    assert!(e.contains(&format!("check {} fails", per + 1)), "{e}");
    // a shift that is a multiple of t below the decryption bound changes
    // nothing and passes; one reaching the size of the modulus makes the
    // fusion wrap and is caught by the magnitude bound
    let small = |i: usize, q: &PartialDecryption| {
        if i == 0 {
            PartialDecryption::from_ciphertext(s.ctx.add_noise_for_tests(q.ciphertext(), 60, 9).unwrap(), q.is_lead())
        } else {
            keep(i, q)
        }
    };
    run(&s, &accs, &small, &keep_c).unwrap();
    let wrap_bits = s.ctx.log2_q().floor() as u32 - (64 - p.leading_zeros());
    let e = run(
        &s,
        &accs,
        &|i, q| {
            if i == 0 {
                PartialDecryption::from_ciphertext(s.ctx.add_noise_for_tests(q.ciphertext(), wrap_bits, 9).unwrap(), q.is_lead())
            } else {
                keep(i, q)
            }
        },
        &keep_c,
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("reaches q0/4"), "{e}");
}

#[test]
fn aggregators_refuse_a_check_that_is_not_one() {
    let _g = serial();
    let s = setup(121);
    let accs = [s.enc(&[5, 6]), s.enc(&[7])];
    let refs: Vec<&Ciphertext> = accs.iter().collect();
    let opening = vdec::draw(&s.ctx, &refs, &mut rand::thread_rng()).unwrap();
    let honest = vdec::build(&s.ctx, &s.pk, &refs, &opening).unwrap();
    // a verifier sends a client's ciphertext (plus the blinding) as check 0
    let victim = s.enc(&[31337]);
    let z = s
        .ctx
        .zero_encryption(&s.pk, &victim, &opening.checks[0].u, &opening.checks[0].e0, &opening.checks[0].e1)
        .unwrap();
    let forged = s.ctx.add(&victim, &z).unwrap();
    assert!(!vdec::same(&forged, &honest[0]).unwrap());
    // openings outside the ranges are refused before anything is built
    let mut bad = opening.clone();
    bad.checks[0].u[0] = 2;
    assert!(vdec::build(&s.ctx, &s.pk, &refs, &bad).is_err());
    let mut bad = opening.clone();
    bad.checks[0].e1[3] = vdec::ETA + 1;
    assert!(vdec::build(&s.ctx, &s.pk, &refs, &bad).is_err());
    let mut bad = opening.clone();
    bad.checks[1].ks[0] = 2 * s.ctx.ring_dim();
    assert!(vdec::build(&s.ctx, &s.pk, &refs, &bad).is_err());
    let mut bad = opening.clone();
    bad.checks.pop();
    assert!(vdec::build(&s.ctx, &s.pk, &refs, &bad).is_err());
    // a different opening gives different checks
    let other = vdec::draw(&s.ctx, &refs, &mut rand::thread_rng()).unwrap();
    assert!(!vdec::same(&vdec::build(&s.ctx, &s.pk, &refs, &other).unwrap()[0], &honest[0]).unwrap());
}
