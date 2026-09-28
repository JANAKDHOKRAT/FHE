//! Tests of the additions on top of the base protocol: client authentication
//! with quotas, batch closing, size caps, behaviour under injected noise,
//! and silent mode.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use std::sync::Arc;

fn verdict_cfg(seed: u8, t: MeasurementType) -> TaskConfig {
    TaskConfig::new(task_id(seed), t, 2)
}

/// A malicious aggregator's forged related report: the honest report's
/// ciphertext plus an encryption of `delta`, re-hashed as a new report.
fn forge_related(net: &Net, honest: &Report, delta_slots: &[u64]) -> Report {
    let ctx = openfhe_tbgv_rs::Context::deserialize(&net.material.context).unwrap();
    let pk = ctx.deserialize_public_key(&net.material.public_key).unwrap();
    let ct = ctx.deserialize_ciphertext(&honest.chunks[0]).unwrap();
    let delta = ctx.encrypt(&pk, &ctx.plaintext(delta_slots).unwrap()).unwrap();
    let chunks = vec![ctx.add(&ct, &delta).unwrap().serialize().unwrap()];
    let report_id = Report::compute_id(&honest.task_id, 0, &chunks);
    Report { task_id: honest.task_id, report_id, group: 0, chunks, auth: None }
}

#[test]
fn authentication_blocks_unregistered_forgeries_and_enforces_quota() {
    let _g = serial();
    let mut cfg = verdict_cfg(30, MeasurementType::Count);
    cfg.auth = AuthPolicy::Required { max_reports_per_client_per_batch: 1 };
    let honest_id = ClientIdentity::generate();
    let attacker_id = ClientIdentity::generate(); // an identity the adversary controls
    let outsider_id = ClientIdentity::generate(); // not registered
    let registry: Arc<dyn ClientRegistry> = StaticRegistry::new([honest_id.public_key(), attacker_id.public_key()]);
    let mut net = Net::with_registry(cfg.clone(), Some(registry));

    let honest_client = Client::new(cfg.clone(), &net.material.context, &net.material.public_key)
        .unwrap()
        .with_identity(ClientIdentity::from_secret_bytes(&honest_id.secret_bytes()));
    let honest = honest_client.shard(&Measurement::Count(true)).unwrap();
    assert!(honest.auth.is_some());
    net.expect_accept(&honest);

    // Unsigned forged related report: refused before any FHE work.
    let forged = forge_related(&net, &honest, &[1]);
    match &net.run_report(&forged)[0] {
        Verdict::Rejected(RejectReason::Unauthenticated(_)) => {}
        v => panic!("expected Unauthenticated, got {v:?}"),
    }

    // Signed by a key that is not registered: refused.
    let mut foreign = forged.clone();
    foreign.auth = Some(outsider_id.sign(&foreign.task_id, &foreign.report_id));
    net.expect_reject(&foreign, RejectReason::UnknownClient);

    // Signature by a registered key over a *different* report: refused.
    let mut replayed_sig = forged.clone();
    replayed_sig.auth = honest.auth.clone();
    match &net.run_report(&replayed_sig)[0] {
        Verdict::Rejected(RejectReason::Unauthenticated(_)) => {}
        v => panic!("expected Unauthenticated, got {v:?}"),
    }

    // The honest identity has used its one report: even a valid new report is refused.
    let second = honest_client.shard(&Measurement::Count(false)).unwrap();
    net.expect_reject(&second, RejectReason::QuotaExceeded);

    // The adversary's own registered identity gets exactly one verified report
    // per batch (here: one forged probe), then nothing.
    let mut probe = forged.clone();
    probe.auth = Some(attacker_id.sign(&probe.task_id, &probe.report_id));
    let v = net.run_report(&probe);
    assert!(v.iter().all(|v| matches!(v, Verdict::Accepted | Verdict::Rejected(RejectReason::ValidityCheckFailed))), "{v:?}");
    let mut probe2 = forge_related(&net, &honest, &[0]);
    probe2.auth = Some(attacker_id.sign(&probe2.task_id, &probe2.report_id));
    net.expect_reject(&probe2, RejectReason::QuotaExceeded);
}

#[test]
fn aggregator_without_registry_refuses_auth_tasks() {
    let _g = serial();
    let mut cfg = verdict_cfg(31, MeasurementType::Count);
    cfg.auth = AuthPolicy::Required { max_reports_per_client_per_batch: 1 };
    let (material, shares) = keys::run_local_ceremony(&cfg).unwrap();
    assert!(Aggregator::new(cfg.clone(), &material, 0, &shares[0], None).is_err());
    let client = Client::new(cfg.clone(), &material.context, &material.public_key).unwrap();
    assert!(client.shard(&Measurement::Count(true)).is_err(), "client without identity cannot produce a report");
}

#[test]
fn batch_closes_after_aggregate_share_and_size_cap_holds() {
    let _g = serial();
    let mut net = Net::new(verdict_cfg(32, MeasurementType::Count));
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    let cap = net.aggs[0].max_report_bytes();
    let mut fat = net.client.shard(&Measurement::Count(true)).unwrap();
    fat.chunks[0].extend(vec![0u8; cap]); // oversize payload
    fat.report_id = Report::compute_id(&fat.task_id, fat.group, &fat.chunks);
    match &net.run_report(&fat)[0] {
        Verdict::Rejected(RejectReason::TooLarge { .. }) => {}
        v => panic!("expected TooLarge, got {v:?}"),
    }
    assert_eq!(net.collect().unwrap(), (AggregateResult::Count(1), 1));
    assert!(net.aggs.iter().all(|a| a.is_closed()));
    net.expect_reject(&net.client.shard(&Measurement::Count(true)).unwrap(), RejectReason::BatchClosed);
    // Partial decryptions are released once: a repeated close returns the
    // same bytes, not a fresh noisy partial decryption of the same sums, and
    // the released share survives a snapshot/restore.
    let first = encode(&net.aggs[0].aggregate_share().unwrap()).unwrap();
    assert_eq!(encode(&net.aggs[0].aggregate_share().unwrap()).unwrap(), first);
    let st = net.aggs[0].snapshot().unwrap();
    net.aggs[0].restore(st, &[]).unwrap();
    assert_eq!(encode(&net.aggs[0].aggregate_share().unwrap()).unwrap(), first);
}

/// Injected noise below the point where the depth-3 check overflows leaves
/// the check exact and the aggregate exact; noise beyond it makes the check
/// output garbage, which is rejected. A ciphertext can therefore not pass
/// the check while corrupting the level-0 sum.
#[test]
fn verdict_mode_noise_ordering() {
    let _g = serial();
    let t = MeasurementType::Sum { max_measurement: 100 };
    let mut net = Net::new(verdict_cfg(33, t.clone()));
    net.expect_accept(&net.client.shard(&Measurement::Sum(51)).unwrap());
    // ~2^80 extra noise on a fresh ciphertext (honest noise is ~2^5): still exact.
    net.expect_accept(&net.client.shard_noisy_for_tests(&Measurement::Sum(49), 80, 11).unwrap());
    // ~2^300: the depth-3 check overflows the ~2^345-bit modulus chain.
    net.expect_reject(&net.client.shard_noisy_for_tests(&Measurement::Sum(7), 300, 12).unwrap(), RejectReason::ValidityCheckFailed);
    net.expect_reject(&net.client.shard_noisy_for_tests(&Measurement::Sum(7), 200, 13).unwrap(), RejectReason::ValidityCheckFailed);
    assert_eq!(net.collect().unwrap(), (AggregateResult::Sum(100), 2));
}

#[test]
fn silent_mode_sum_with_invalid_report_contributing_zero() {
    let _g = serial();
    let t = MeasurementType::Sum { max_measurement: 100 };
    let cfg = TaskConfig::new_silent(task_id(34), t.clone(), 2);
    assert_eq!(cfg.mult_depth(), 25);
    let mut net = Net::new(cfg.clone());
    assert_eq!(net.aggs[0].layout().classes, 4);

    let honest = [Measurement::Sum(51), Measurement::Sum(49)];
    for m in &honest {
        net.expect_accept(&net.client.shard(m).unwrap());
    }
    // Out of range: 101 with a saturated offset half. Admitted (no verdict is
    // ever produced) but must contribute exactly zero to every slot.
    let bits = |v: u64| -> Vec<u64> { (0..7).map(|i| (v >> i) & 1).collect() };
    let mut bad = bits(101);
    bad.extend(bits(127));
    let r = net.client.shard_raw_elements(&[bad]).unwrap();
    assert!(net.run_report(&r).iter().all(|v| *v == Verdict::Accepted), "silent mode never reports a verdict");
    // A non-bit value as well.
    let mut nonbit = bits(3);
    nonbit[0] = 5;
    nonbit.extend(bits(3 + 27));
    let r = net.client.shard_raw_elements(&[nonbit]).unwrap();
    assert!(net.run_report(&r).iter().all(|v| *v == Verdict::Accepted));

    let r = net.collect_full().unwrap();
    assert_eq!(r.aggregate, AggregateResult::Sum(100));
    assert_eq!(r.report_count, 4, "admitted reports, including the two that contributed zero");
    assert_eq!(r.valid_count, 2, "decrypted from the encrypted counter");
}

#[test]
fn silent_mode_histogram_three_aggregators_and_noisy_report_detected() {
    let _g = serial();
    let t = MeasurementType::Histogram { length: 4 };
    let mut cfg = TaskConfig::new_silent(task_id(35), t.clone(), 3);
    cfg.min_batch_size = 1;
    let mut net = Net::new(cfg);
    net.expect_accept(&net.client.shard(&Measurement::Histogram(2)).unwrap());
    net.expect_accept(&net.client.shard_raw_elements(&[vec![1, 1, 0, 0]]).unwrap()); // two-hot: contributes zero
    let r = net.collect_full().unwrap();
    assert_eq!((r.aggregate, r.report_count, r.valid_count), (AggregateResult::Histogram(vec![0, 0, 1, 0]), 2, 1));
    // Release the three aggregators (and their 2 GiB of keys each) before
    // building the next network; two complete silent-mode key sets in one
    // process exceed a 16 GiB machine.
    drop(net);

    // A second batch containing a ciphertext with overflowing noise: the
    // decrypted sums are inconsistent and the collector refuses the batch.
    let mut net = Net::new(TaskConfig::new_silent(task_id(36), t.clone(), 2));
    net.expect_accept(&net.client.shard(&Measurement::Histogram(1)).unwrap());
    net.expect_accept(&net.client.shard_noisy_for_tests(&Measurement::Histogram(3), 1200, 21).unwrap());
    let err = net.collect().err().expect("corrupted batch must be refused");
    assert!(err.to_string().contains("inconsistent") || err.to_string().contains("corrupted"), "{err}");
}

#[test]
fn silent_mode_min_batch_counts_valid_reports_only() {
    let _g = serial();
    let t = MeasurementType::Count;
    let mut cfg = TaskConfig::new_silent(task_id(37), t, 2);
    cfg.min_batch_size = 2;
    let mut net = Net::new(cfg);
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    net.expect_accept(&net.client.shard_raw_elements(&[vec![2]]).unwrap()); // invalid, contributes zero
    // Two admitted, one valid: the aggregators reveal the count (1) and then
    // refuse to release the sum.
    let err = net.collect().err().expect("one valid report is below the minimum");
    assert!(err.to_string().contains("valid reports"), "{err}");
    // The count share was released once; asking again returns the same bytes.
    let first = encode(&net.aggs[1].count_share().unwrap()).unwrap();
    assert_eq!(encode(&net.aggs[1].count_share().unwrap()).unwrap(), first);
}

#[test]
fn messages_roundtrip_with_auth() {
    let id = ClientIdentity::generate();
    let r = Report { task_id: [1; 32], report_id: [2; 32], group: 0, chunks: vec![vec![1, 2, 3]], auth: Some(id.sign(&[1; 32], &[2; 32])) };
    let back: Report = decode(&encode(&r).unwrap()).unwrap();
    assert_eq!(back.auth, r.auth);
    assert_eq!(back.chunks, r.chunks);
}

/// Batched silent mode: several reports share one verification ciphertext.
/// Valid reports are summed, invalid ones contribute zero, the count is
/// exact, and a report that reuses a group simply starts a new sub-batch.
#[test]
fn batched_silent_sum_shares_one_chain() {
    let _g = serial();
    let t = MeasurementType::Sum { max_measurement: 100 };
    let mut cfg = TaskConfig::new_silent(task_id(40), t.clone(), 2);
    cfg.silent_batch_groups = 4;
    let mut net = Net::new(cfg.clone());
    let l = net.aggs[0].layout().clone();
    assert_eq!((l.groups, l.classes), (4, 4));
    let honest = [51u64, 49, 100, 0, 7];
    // groups 0,1,2,3 fill one sub-batch (flushed automatically); the fifth
    // report reuses group 0 and starts another.
    for (i, v) in honest.iter().enumerate() {
        let r = net.client.shard_in_group(&Measurement::Sum(*v), (i % 4) as u32).unwrap();
        net.expect_accept(&r);
    }
    assert_eq!(net.aggs[0].pending_silent_reports(), 1);
    // an invalid report in group 1 of the second sub-batch
    let bits = |v: u64| -> Vec<u64> { (0..7).map(|i| (v >> i) & 1).collect() };
    let mut bad = bits(101);
    bad.extend(bits(127));
    net.expect_accept(&net.client.shard_raw_elements_in_group(&[bad], 1).unwrap());
    let r = net.collect_full().unwrap();
    assert_eq!(r.aggregate, AggregateResult::Sum(207));
    assert_eq!((r.report_count, r.valid_count), (6, 5));
}

/// A client assigned to group 1 that writes into group 0's slots (or any
/// other slot) must not change group 0's validity nor reach the aggregate.
#[test]
fn batched_silent_cross_group_injection_is_ignored() {
    let _g = serial();
    let t = MeasurementType::Histogram { length: 4 };
    let mut cfg = TaskConfig::new_silent(task_id(41), t.clone(), 2);
    cfg.silent_batch_groups = 4;
    let mut net = Net::new(cfg.clone());
    let l = net.aggs[0].layout().clone();
    // honest report in group 0: bucket 2
    net.expect_accept(&net.client.shard_in_group(&Measurement::Histogram(2), 0).unwrap());
    // attacker in group 1: a valid one-hot in its own slots, plus garbage in
    // group 0's slots (would make group 0 look two-hot if it were counted),
    // plus large values in group 2's and 3's slots and in the class-1..3 slots.
    let mut slots = vec![0u64; l.row];
    slots[l.group_slot(1, 3)] = 1; // its own vote: bucket 3
    slots[l.group_slot(0, 0)] = 1; // into group 0 (would add bucket 0)
    slots[l.group_slot(2, 1)] = 5; // into group 2
    slots[l.group_slot(3, 2)] = cfg.plain_mod - 1;
    slots[1 + l.classes * 1] = 9; // class 1 of its own group
    slots[l.row - 1] = 3;
    net.expect_accept(&net.client.shard_raw_in_group(&[slots], 1).unwrap());
    // honest report in group 2: bucket 1
    net.expect_accept(&net.client.shard_in_group(&Measurement::Histogram(1), 2).unwrap());
    let r = net.collect_full().unwrap();
    assert_eq!(r.aggregate, AggregateResult::Histogram(vec![0, 1, 1, 1]));
    assert_eq!((r.report_count, r.valid_count), (3, 3));
}

/// Correctness gate for the depth-25 batched circuit on worst-case inputs:
/// invalid reports whose every slot is `p-1` (the largest magnitude the
/// plaintext multiplications can see) mixed with valid ones, over several
/// independent chains. Every decryption must be exact.
#[test]
fn batched_silent_worst_case_inputs_gate() {
    let _g = serial();
    let t = MeasurementType::Count;
    let mut cfg = TaskConfig::new_silent(task_id(42), t.clone(), 2);
    cfg.silent_batch_groups = 4;
    let mut net = Net::new(cfg.clone());
    let l = net.aggs[0].layout().clone();
    let chains = 3;
    let mut expected = 0u64;
    for chain in 0..chains {
        for g in 0..4u32 {
            if (chain + g as usize) % 2 == 0 {
                // worst case: every slot of the row holds p-1
                let slots = vec![cfg.plain_mod - 1; l.row];
                net.expect_accept(&net.client.shard_raw_in_group(&[slots], g).unwrap());
            } else {
                net.expect_accept(&net.client.shard_in_group(&Measurement::Count(true), g).unwrap());
                expected += 1;
            }
        }
    }
    let r = net.collect_full().unwrap();
    assert_eq!(r.aggregate, AggregateResult::Count(expected));
    assert_eq!((r.report_count, r.valid_count), (4 * chains as u64, expected));
}
