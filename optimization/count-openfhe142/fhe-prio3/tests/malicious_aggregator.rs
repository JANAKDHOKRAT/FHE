//! A malicious aggregator against verifiable decryption. Each attack is
//! first shown to work on the unverified fusion (so the test proves the
//! attack is real), then shown to be stopped by the protocol:
//!
//! 1. Silent mode, count forgery: shifting its count partial so a batch
//!    with one valid report reads as `min_batch_size`, which would make the
//!    honest aggregators release that one report. Honest aggregators'
//!    count checks fail and nothing is released.
//! 2. Verdict mode, forced acceptance: choosing its partial after seeing
//!    the others' so that an invalid report's verdict fuses to zero.
//!    Commit-then-reveal refuses the adapted partial.
//!    Mask cancellation: sending `Enc(r) − honest mask` after seeing the
//!    honest mask, which fixes the combined mask to `r` (forced acceptance
//!    for `r = 0`, the check value itself for a known `r`). Mask
//!    commitments refuse it.
//! 3. Release: shifting a released aggregate partial. The collector's
//!    checks fail and no result is produced.
//! 4. A collector (or relaying leader) passing a victim's ciphertext off as
//!    a check, or asking twice: the aggregators refuse.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::packed::Expect;
use fhe_prio3::*;
use openfhe_tbgv_rs::PartialDecryption;

/// `bytes` (a packed partial decryption) with its plaintext shifted by
/// `shift` (slot values, missing slots 0), re-encoded.
fn shifted(net: &Net, ctx: &openfhe_tbgv_rs::Context, bytes: &[u8], shift: &[u64]) -> Vec<u8> {
    let codec = net.aggs[0].codec();
    let ct = codec.decode(bytes, Expect::Partial).unwrap();
    let moved = ctx.add_plain(&ct, &ctx.plaintext(shift).unwrap()).unwrap();
    codec.encode(&moved).unwrap()
}

fn fuse(net: &Net, parts: &[&Vec<u8>], slots: usize) -> Vec<u64> {
    let codec = net.aggs[0].codec();
    let p: Vec<PartialDecryption> = parts
        .iter()
        .enumerate()
        .map(|(i, b)| PartialDecryption::from_ciphertext(codec.decode(b, Expect::Partial).unwrap(), i == 0))
        .collect();
    let refs: Vec<&PartialDecryption> = p.iter().collect();
    keys::make_context(&net.cfg).unwrap().fuse(&refs, slots).unwrap()
}

#[test]
fn silent_count_forgery_is_caught_before_any_release() {
    let _g = serial();
    let mut cfg = TaskConfig::new_silent(task_id(130), MeasurementType::Count, 2);
    cfg.min_batch_size = 3;
    let mut net = Net::new(cfg.clone());
    let ctx = keys::make_context(&cfg).unwrap();
    // the victim's report and two invalid reports from the attacker's client
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    for _ in 0..2 {
        net.expect_accept(&net.client.shard_raw_elements(&[vec![2]]).unwrap());
    }
    let honest: Vec<CountShare> = net.aggs.iter_mut().map(|a| a.count_share().unwrap()).collect();
    assert_eq!(fuse(&net, &[&honest[0].partial, &honest[1].partial], 1)[0], 1);
    // aggregator 1 sends aggregator 0 a count partial shifted by 2
    let mut forged = honest.clone();
    forged[1].partial = shifted(&net, &ctx, &honest[1].partial, &[2]);
    // unverified, the fused count now meets the minimum
    assert_eq!(
        fuse(&net, &[&forged[0].partial, &forged[1].partial], 1)[0],
        3,
        "the attack works on an unverified fusion"
    );

    let forged: Vec<CountShare> = forged.iter().map(|s| decode(&encode(s).unwrap()).unwrap()).collect();
    let commits: Vec<CountCommit> = vec![net.aggs[0].count_commit(&forged).unwrap(), net.aggs[1].count_commit(&honest).unwrap()];
    let openings: Vec<CountOpening> = net.aggs.iter_mut().map(|a| a.count_open(&commits).unwrap()).collect();
    let mut reveals: Vec<CountReveal> = net.aggs.iter_mut().map(|a| a.count_reveal(&openings).unwrap()).collect();
    // the attacker cannot adapt its check partials any more (committed);
    // revealing adapted ones is refused, keeping them fails the check
    let honest = reveals[1].clone();
    reveals[1].partials[0].1[0] = shifted(&net, &ctx, &reveals[1].partials[0].1[0], &[5]);
    let e = net.aggs[0].count_finish(&reveals).unwrap_err().to_string();
    assert!(e.contains("not the one it committed to"), "{e}");
    reveals[1] = honest;
    let e = net.aggs[0].count_finish(&reveals).unwrap_err().to_string();
    assert!(e.contains("fails in slot 0"), "{e}");
    // no count, no release
    let e = net.aggs[0].aggregate_share().err().expect("refused").to_string();
    assert!(e.contains("run count_share/count_finish"), "{e}");
}

#[test]
fn verdict_forced_acceptance_needs_an_adapted_partial_and_is_refused() {
    let _g = serial();
    let cfg = TaskConfig::new(task_id(131), MeasurementType::Count, 2);
    let mut net = Net::new(cfg.clone());
    let ctx = keys::make_context(&cfg).unwrap();
    let p = cfg.plain_mod;
    let bad = net.client.shard_raw_elements(&[vec![2]]).unwrap(); // not a bit
    let mc: Vec<MaskCommit> = net.aggs.iter_mut().map(|a| a.prepare_init(&bad).unwrap()).collect();
    let masks: Vec<MaskMessage> = net
        .aggs
        .iter_mut()
        .map(|a| {
            let others: Vec<MaskCommit> = mc.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
            a.prepare_mask_reveal(&bad.report_id, &others).unwrap()
        })
        .collect();
    let commits: Vec<VerifierCommit> = net
        .aggs
        .iter_mut()
        .map(|a| {
            let others: Vec<MaskMessage> = masks.iter().filter(|m| m.aggregator != a.index()).cloned().collect();
            a.prepare_masks(&bad.report_id, &others).unwrap()
        })
        .collect();
    let reveal0 = net.aggs[0].prepare_reveal(&bad.report_id, &commits[1..]).unwrap();
    let reveal1 = net.aggs[1].prepare_reveal(&bad.report_id, &commits[..1]).unwrap();
    // aggregator 1 (rushing) sees aggregator 0's partial and computes the
    // shift that makes every result slot fuse to zero
    let layout = net.aggs[0].layout().clone();
    let span = layout.result_span();
    let fused = fuse(&net, &[&reveal0.partial, &reveal1.partial], span);
    assert!((0..layout.repetitions).any(|j| fused[layout.result_slot(j)] != 0), "the report is invalid");
    let mut shift = vec![0u64; span];
    for j in 0..layout.repetitions {
        let s = layout.result_slot(j);
        shift[s] = (p - fused[s]) % p;
    }
    let forged = shifted(&net, &ctx, &reveal1.partial, &shift);
    let refused = fuse(&net, &[&reveal0.partial, &forged], span);
    assert!(
        (0..layout.repetitions).all(|j| refused[layout.result_slot(j)] == 0),
        "the adapted partial would force acceptance"
    );
    // ... but it is not the partial aggregator 1 committed to
    let mut msg = reveal1.clone();
    msg.partial = forged;
    let e = net.aggs[0].prepare_finish(&bad.report_id, &[msg]).expect_err("refused").to_string();
    assert!(e.contains("not the one it committed to"), "{e}");
    // with its committed partial the report is rejected
    assert_eq!(
        net.aggs[0].prepare_finish(&bad.report_id, &[reveal1]).unwrap(),
        Verdict::Rejected(RejectReason::ValidityCheckFailed)
    );
}

#[test]
fn verdict_mask_cancellation_needs_the_honest_mask_and_is_refused() {
    let _g = serial();
    let cfg = TaskConfig::new(task_id(134), MeasurementType::Count, 2);
    let (full, share_bytes) = keys::run_local_ceremony(&cfg).unwrap();
    let mut net = Net::with_keys(cfg.clone(), full, &share_bytes, None);
    let ctx = keys::make_context(&cfg).unwrap();
    let pk = ctx.deserialize_public_key(&net.material.public_key).unwrap();
    let shares: Vec<_> = share_bytes
        .iter()
        .map(|s| ctx.deserialize_secret_share(&keys::AggregatorSecret::decode(s).unwrap().share).unwrap())
        .collect();
    let codec = fhe_prio3::packed::Codec::new(&ctx, &pk, &net.material.public_key).unwrap();
    let layout = net.aggs[0].layout().clone();
    let span = layout.result_span();
    let decrypt = |ct: &openfhe_tbgv_rs::Ciphertext| {
        let parts: Vec<PartialDecryption> = shares.iter().enumerate().map(|(i, s)| s.partial_decrypt(ct, i == 0).unwrap()).collect();
        ctx.fuse(&parts.iter().collect::<Vec<_>>(), span).unwrap()
    };

    let bad = net.client.shard_raw_elements(&[vec![2]]).unwrap(); // not a bit
    let mc: Vec<MaskCommit> = net.aggs.iter_mut().map(|a| a.prepare_init(&bad).unwrap()).collect();
    let m0 = net.aggs[0].prepare_mask_reveal(&bad.report_id, &mc[1..]).unwrap();
    // with the honest mask in hand, aggregator 1 fixes the combined mask to
    // any r it likes: r = 0 forces acceptance; r known reveals E_j = u / r
    let honest = codec.decode(&m0.mask, Expect::Any).unwrap();
    for r in [0u64, 7] {
        let mut v = vec![0u64; span];
        for j in 0..layout.repetitions {
            v[layout.result_slot(j)] = r;
        }
        let forged = ctx.sub(&ctx.encrypt(&pk, &ctx.plaintext(&v).unwrap()).unwrap(), &honest).unwrap();
        let combined = decrypt(&ctx.add(&honest, &forged).unwrap());
        assert!(
            (0..layout.repetitions).all(|j| combined[layout.result_slot(j)] == r),
            "the attack works without mask commitments"
        );
        // ... but aggregator 1 committed to its mask before seeing aggregator 0's
        let msg = MaskMessage {
            report_id: bad.report_id,
            aggregator: 1,
            mask: codec.encode(&forged).unwrap(),
        };
        let e = net.aggs[0].prepare_masks(&bad.report_id, &[msg]).err().expect("refused").to_string();
        assert!(e.contains("mask is not the one it committed to"), "{e}");
    }
    // a changed mask commitment is refused too
    let mut other = mc[1].clone();
    other.digest[0] ^= 1;
    let e = net.aggs[0].prepare_mask_reveal(&bad.report_id, &[other]).err().expect("refused").to_string();
    assert!(e.contains("changed its mask commitment"), "{e}");
    // honestly, the round completes and the report is rejected
    let m1 = net.aggs[1].prepare_mask_reveal(&bad.report_id, &mc[..1]).unwrap();
    let c0 = net.aggs[0].prepare_masks(&bad.report_id, &[m1]).unwrap();
    let c1 = net.aggs[1].prepare_masks(&bad.report_id, &[m0]).unwrap();
    let v0 = net.aggs[0].prepare_reveal(&bad.report_id, &[c1]).unwrap();
    let v1 = net.aggs[1].prepare_reveal(&bad.report_id, &[c0]).unwrap();
    assert_eq!(
        net.aggs[0].prepare_finish(&bad.report_id, &[v1]).unwrap(),
        Verdict::Rejected(RejectReason::ValidityCheckFailed)
    );
    assert_eq!(
        net.aggs[1].prepare_finish(&bad.report_id, &[v0]).unwrap(),
        Verdict::Rejected(RejectReason::ValidityCheckFailed)
    );
}

#[test]
fn a_shifted_release_partial_is_caught_by_the_collector() {
    let _g = serial();
    let cfg = TaskConfig::new(task_id(132), MeasurementType::Sum { max_measurement: 100 }, 2);
    let mut net = Net::new(cfg.clone());
    let ctx = keys::make_context(&cfg).unwrap();
    for v in [10u64, 20, 30] {
        net.expect_accept(&net.client.shard(&Measurement::Sum(v)).unwrap());
    }
    let mut shares: Vec<AggregateShare> = net.aggs.iter_mut().map(|a| a.aggregate_share().unwrap()).collect();
    // aggregator 1 shifts its partial of the sum's lowest slot by 40; the
    // known-answer checks must refuse it before any plausibility check does
    shares[1].partials[0] = shifted(&net, &ctx, &shares[1].partials[0], &[40]);
    let e = net.finish_release(0, shares).expect_err("refused").to_string();
    assert!(e.contains("fails in slot") || e.contains("aggregate inconsistent"), "{e}");
    assert!(e.contains("vdec"), "the checks, not a plausibility check, must refuse it: {e}");
}

#[test]
fn aggregators_refuse_forged_or_repeated_release_checks() {
    let _g = serial();
    let cfg = TaskConfig::new(task_id(133), MeasurementType::Count, 2);
    let mut net = Net::new(cfg.clone());
    let ctx = keys::make_context(&cfg).unwrap();
    let victim = net.client.shard(&Measurement::Count(true)).unwrap();
    net.expect_accept(&victim);
    net.expect_accept(&net.client.shard(&Measurement::Count(false)).unwrap());
    let shares: Vec<AggregateShare> = net.aggs.iter_mut().map(|a| a.aggregate_share().unwrap()).collect();
    let mut pending = net.collector.release_challenge(0, shares.clone()).unwrap();
    // a challenge whose first check is the victim's ciphertext plus the blinding
    let codec = net.aggs[0].codec();
    let honest0 = codec.decode(&pending.challenge.checks[0], Expect::Any).unwrap();
    let v = codec.decode(&victim.chunks[0], Expect::Any).unwrap();
    let pk = ctx.deserialize_public_key(&net.material.public_key).unwrap();
    let o = &pending.opening.checks[0];
    let z = ctx.zero_encryption(&pk, &honest0, &o.u, &o.e0, &o.e1).unwrap();
    // verdict sums keep a fresh ciphertext's shape, so the victim's chunk
    // plus the blinding is a well-shaped "check"
    assert_eq!(v.meta().unwrap(), honest0.meta().unwrap());
    let mut forged = pending.challenge.clone();
    forged.checks[0] = codec.encode(&ctx.add(&v, &z).unwrap()).unwrap();
    let commits: Vec<ReleaseCommit> = net.aggs.iter_mut().map(|a| a.release_commit(&forged).unwrap()).collect();
    let mut p2 = pending.clone();
    p2.challenge = forged.clone();
    let opening = net.collector.release_open(&mut p2, commits).unwrap();
    for a in net.aggs.iter_mut() {
        let e = a.release_reveal(&opening).err().expect("refused").to_string();
        assert!(e.contains("is not what the collector opened"), "{e}");
    }
    // each aggregator has answered its one challenge: the honest one is refused too
    let e = net.aggs[0].release_commit(&pending.challenge).err().expect("refused").to_string();
    assert!(e.contains("refusing a second set"), "{e}");
    let _ = &mut pending;
}
