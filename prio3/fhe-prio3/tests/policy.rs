//! Per-collector release policies: each declared collector receives exactly
//! its elements (whole chunks cut at visibility boundaries, so nothing else
//! is ever partially decrypted), sealed to its key; moments only for its own
//! elements; release once per collector; unknown collectors refused; the
//! leader-visible envelope is opaque.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::types::regression_plain;
use fhe_prio3::*;

fn policy(elements: &[usize], moments: bool, key: &CollectorSealKey) -> CollectorPolicy {
    CollectorPolicy { elements: elements.to_vec(), moments, seal_key: key.public_key() }
}

#[test]
fn verdict_two_collectors_disjoint_elements_and_moments() {
    let _g = serial();
    // four bounded values: collector 0 sees {0, 1}; collector 1 sees {2, 3} with moments (target = 3)
    let t = MeasurementType::BoundedSumVec { bounds: vec![100, 5, 15, 15] };
    let k0 = CollectorSealKey::generate();
    let k1 = CollectorSealKey::generate();
    let mut cfg = TaskConfig::new(task_id(70), t.clone(), 2);
    cfg.moments = true;
    cfg.collectors = vec![policy(&[0, 1], false, &k0), policy(&[2, 3], true, &k1)];
    cfg.validate().unwrap();
    // chunks are cut between element 1 and element 2: two chunks
    assert_eq!(cfg.chunk_cuts(), vec![2 * 7 + 2 * 3]);
    let mut net = Net::new(cfg.clone());
    assert_eq!(net.aggs[0].layout().num_chunks, 2);
    assert_eq!(cfg.collector_chunks(net.aggs[0].layout(), 0), vec![0]);
    assert_eq!(cfg.collector_chunks(net.aggs[0].layout(), 1), vec![1]);
    assert_eq!(cfg.collector_moment_pairs(1).unwrap(), vec![(2, 2), (2, 3), (3, 3)]);
    assert!(cfg.collector_moment_pairs(0).unwrap().is_empty());

    let rows = vec![vec![10u64, 1, 8, 8], vec![20, 5, 7, 6], vec![100, 3, 15, 15], vec![40, 1, 11, 12], vec![0, 0, 8, 9], vec![55, 5, 15, 14]];
    for r in &rows {
        net.expect_accept(&net.client.shard(&Measurement::SumVec(r.clone())).unwrap());
    }
    // an out-of-range element 3 is rejected as before (the check spans both chunks)
    let mut bad = t.encode(&Measurement::SumVec(vec![1, 1, 1, 15])).unwrap();
    bad[t.input_len() - 1] = 0; // offset half of element 3 wrong (offset 0 -> value != offset value)
    let l = net.aggs[0].layout().clone();
    let chunks: Vec<Vec<u64>> = (0..l.num_chunks).map(|c| bad[l.chunk_range(c)].to_vec()).collect();
    net.expect_reject(&net.client.shard_raw(&chunks).unwrap(), RejectReason::ValidityCheckFailed);

    let plain_all = t.aggregate_plain(&rows.iter().map(|r| Measurement::SumVec(r.clone())).collect::<Vec<_>>()).unwrap();
    let AggregateResult::SumVec(all) = &plain_all else { panic!() };

    // collector 0, sealed path: exactly elements 0 and 1, no regression
    let r0 = net.collect_sealed_for(0, &k0).unwrap();
    assert_eq!((r0.collector, &r0.elements, r0.report_count, r0.valid_count), (0, &vec![0, 1], 6, 6));
    assert_eq!(r0.aggregate, AggregateResult::SumVec(vec![all[0], all[1], 0, 0]));
    assert!(r0.regression.is_none());

    // collector 1: elements 2 and 3 plus the regression of 3 on 2
    let r1 = net.collect_sealed_for(1, &k1).unwrap();
    assert_eq!((r1.collector, &r1.elements), (1, &vec![2, 3]));
    assert_eq!(r1.aggregate, AggregateResult::SumVec(vec![0, 0, all[2], all[3]]));
    let sub: Vec<Vec<u64>> = rows.iter().map(|r| vec![r[2], r[3]]).collect();
    let plain = regression_plain(&sub);
    let reg = r1.regression.expect("moments for collector 1");
    assert_eq!((reg.n, &reg.first, &reg.second), (plain.n, &plain.first, &plain.second));
    for (a, b) in reg.beta.iter().zip(&plain.beta) {
        assert!((a - b).abs() < 1e-9, "{:?} vs {:?}", reg.beta, plain.beta);
    }

    // the shares themselves carry only the allowed chunks and pairs
    let s0 = net.aggs[1].aggregate_share_for(0).unwrap();
    assert_eq!((s0.collector, s0.partials.len(), s0.moment_partials.len()), (0, 1, 0));
    let s1 = net.aggs[1].aggregate_share_for(1).unwrap();
    assert_eq!((s1.collector, s1.partials.len(), s1.moment_partials.len()), (1, 1, 3));
    // release once per collector: identical bytes on repeat, and after restore
    assert_eq!(encode(&net.aggs[1].aggregate_share_for(1).unwrap()).unwrap(), encode(&s1).unwrap());
    let st = net.aggs[1].snapshot().unwrap();
    net.aggs[1].restore(st, &[]).unwrap();
    assert_eq!(encode(&net.aggs[1].aggregate_share_for(0).unwrap()).unwrap(), encode(&s0).unwrap());
    // unknown collector and the legacy entry point are refused
    assert!(net.aggs[0].aggregate_share_for(2).is_err());
    assert!(net.aggs[0].aggregate_share().is_err());
    assert!(net.collector.release_challenge(0, vec![s0.clone(), s0.clone()]).is_err());

    // a share released to collector 1 is refused by collector 0's release, and vice versa
    let mut mixed = vec![net.aggs[0].aggregate_share_for(0).unwrap(), s1.clone()];
    assert!(net.collector.release_challenge(0, mixed.clone()).is_err());
    mixed[1] = s0.clone();
    net.collector.release_challenge(0, mixed).unwrap();

    // sealed envelopes: opaque to the relaying leader, bound to their collector
    let sealed1 = net.aggs[1].sealed_share_for(1).unwrap();
    assert!(fhe_prio3::seal::open(&sealed1, &k0).is_err());
    let opened = fhe_prio3::seal::open(&sealed1, &k1).unwrap();
    assert_eq!(encode(&opened).unwrap(), encode(&s1).unwrap());
    let rt: SealedShare = decode(&encode(&sealed1).unwrap()).unwrap();
    assert_eq!(rt.ciphertext, sealed1.ciphertext);
    // the collector refuses a key that is not the declared one
    assert!(net.collector.release_challenge_sealed(1, &k0, &[sealed1.clone(), sealed1]).is_err());
}

#[test]
fn overlapping_and_full_view_policies() {
    let _g = serial();
    // histogram of 4 buckets: collector 0 sees all, collector 1 sees {2, 3}; the
    // full-view collector gets the consistency check, the restricted one only
    // the per-slot bound (its constraint spans hidden slots)
    let t = MeasurementType::Histogram { length: 4 };
    let k0 = CollectorSealKey::generate();
    let k1 = CollectorSealKey::generate();
    let mut cfg = TaskConfig::new(task_id(71), t.clone(), 2);
    cfg.collectors = vec![policy(&[0, 1, 2, 3], false, &k0), policy(&[2, 3], false, &k1)];
    cfg.validate().unwrap();
    assert_eq!(cfg.chunk_cuts(), vec![2]);
    let mut net = Net::new(cfg);
    for i in [0usize, 2, 3, 3, 1] {
        net.expect_accept(&net.client.shard(&Measurement::Histogram(i)).unwrap());
    }
    let r0 = net.collect_for(0).unwrap();
    assert_eq!(r0.aggregate, AggregateResult::Histogram(vec![1, 1, 1, 2]));
    let r1 = net.collect_for(1).unwrap();
    assert_eq!((r1.aggregate, r1.elements), (AggregateResult::Histogram(vec![0, 0, 1, 2]), vec![2, 3]));

    // MultihotCountVec: the weight bits serve a constraint over every element and
    // go to the full-view collector only
    let m = MeasurementType::MultihotCountVec { length: 4, max_weight: 2 };
    let mut cfg = TaskConfig::new(task_id(72), m.clone(), 2);
    cfg.collectors = vec![policy(&[0, 1], false, &k1), policy(&[0, 1, 2, 3], false, &k0)];
    cfg.validate().unwrap();
    let mut net = Net::new(cfg.clone());
    let l = net.aggs[0].layout().clone();
    // elements 2,3 and the weight bits share a visibility class (collector 1 only), hence one chunk
    assert_eq!(l.num_chunks, 2);
    assert_eq!(cfg.collector_chunks(&l, 0), vec![0]); // elements 0,1
    assert_eq!(cfg.collector_chunks(&l, 1), vec![0, 1]); // + elements 2,3 + weight bits
    net.expect_accept(&net.client.shard(&Measurement::MultihotCountVec(vec![true, false, true, false])).unwrap());
    net.expect_accept(&net.client.shard(&Measurement::MultihotCountVec(vec![true, true, false, false])).unwrap());
    // weight 3 claimed as 2 is still caught by the check (weight bits: 2 + offset 1 = 3 -> [1, 1])
    net.expect_reject(&net.client.shard_raw(&[vec![1, 1], vec![1, 0, 1, 1]]).unwrap(), RejectReason::ValidityCheckFailed);
    assert_eq!(net.collect_for(0).unwrap().aggregate, AggregateResult::MultihotCountVec(vec![2, 1, 0, 0]));
    assert_eq!(net.collect_for(1).unwrap().aggregate, AggregateResult::MultihotCountVec(vec![2, 1, 1, 0]));
}

#[test]
fn policy_validation() {
    let k = CollectorSealKey::generate();
    let t = MeasurementType::SumVec { length: 4, bits: 3 };
    let ok = |ps: Vec<CollectorPolicy>| {
        let mut cfg = TaskConfig::new(task_id(73), t.clone(), 2);
        cfg.collectors = ps;
        cfg.validate()
    };
    assert!(ok(vec![policy(&[0, 1], false, &k), policy(&[2, 3], false, &k)]).is_ok());
    assert!(ok(vec![policy(&[0, 1, 2, 3], false, &k), policy(&[1, 2], false, &k)]).is_ok());
    // element 3 released to nobody
    assert!(ok(vec![policy(&[0, 1, 2], false, &k)]).is_err());
    // interleaved policies are allowed and cost one chunk per run: {0, 2} and {1, 3} -> 4 chunks
    assert!(ok(vec![policy(&[0, 2], false, &k), policy(&[1, 3], false, &k)]).is_ok());
    {
        let mut cfg = TaskConfig::new(task_id(73), t.clone(), 2);
        cfg.collectors = vec![policy(&[0, 2], false, &k), policy(&[1, 3], false, &k)];
        assert_eq!(cfg.chunk_cuts(), vec![3, 6, 9]);
        let l = cfg.layout(16384).unwrap();
        assert_eq!(l.num_chunks, 4);
        assert_eq!(cfg.collector_chunks(&l, 0), vec![0, 2]);
        assert_eq!(cfg.collector_chunks(&l, 1), vec![1, 3]);
    }
    // unsorted, duplicate, out of range, empty
    assert!(ok(vec![policy(&[1, 0, 2, 3], false, &k)]).is_err());
    assert!(ok(vec![policy(&[0, 0, 1, 2, 3], false, &k)]).is_err());
    assert!(ok(vec![policy(&[0, 1, 2, 4], false, &k)]).is_err());
    assert!(ok(vec![policy(&[], false, &k), policy(&[0, 1, 2, 3], false, &k)]).is_err());
    // moments for a collector need the task's moments and two elements
    assert!(ok(vec![policy(&[0, 1, 2, 3], true, &k)]).is_err());
    let mut cfg = TaskConfig::new(task_id(73), t.clone(), 2);
    cfg.moments = true;
    cfg.collectors = vec![policy(&[0], true, &k), policy(&[1, 2, 3], true, &k)];
    assert!(cfg.validate().is_err());
    cfg.collectors = vec![policy(&[0, 1], true, &k), policy(&[2, 3], true, &k)];
    cfg.validate().unwrap();
    // policies are in the digest
    let mut other = cfg.clone();
    other.collectors[0].elements = vec![0, 1, 2];
    other.collectors[1].elements = vec![3];
    assert!(other.validate().is_err()); // moments with one element
    other.collectors[1].moments = false;
    other.validate().unwrap();
    assert_ne!(other.digest(), cfg.digest());
}

#[test]
fn silent_batched_policies_with_invalid_report() {
    let _g = serial();
    let t = MeasurementType::BoundedSumVec { bounds: vec![100, 5] };
    let k0 = CollectorSealKey::generate();
    let k1 = CollectorSealKey::generate();
    let mut cfg = TaskConfig::new_silent(task_id(74), t.clone(), 2);
    cfg.silent_batch_groups = 4;
    cfg.collectors = vec![policy(&[0], false, &k0), policy(&[1], false, &k1)];
    cfg.validate().unwrap();
    let mut net = Net::new(cfg);
    assert_eq!(net.aggs[0].layout().num_chunks, 2);
    net.expect_accept(&net.client.shard_in_group(&Measurement::SumVec(vec![100, 5]), 0).unwrap());
    net.expect_accept(&net.client.shard_in_group(&Measurement::SumVec(vec![7, 2]), 1).unwrap());
    // element 1 = 6 > 5: admitted, contributes nothing to either collector
    let mut raw = t.encode(&Measurement::SumVec(vec![3, 5])).unwrap();
    raw[14..17].copy_from_slice(&[0, 1, 1]); // value 6
    raw[17..20].copy_from_slice(&[1, 1, 1]); // offset half saturated
    net.expect_accept(&net.client.shard_raw_in_group(&[raw[..14].to_vec(), raw[14..].to_vec()], 2).unwrap());
    let r0 = net.collect_sealed_for(0, &k0).unwrap();
    assert_eq!((r0.aggregate, r0.report_count, r0.valid_count), (AggregateResult::SumVec(vec![107, 0]), 3, 2));
    let r1 = net.collect_sealed_for(1, &k1).unwrap();
    assert_eq!((r1.aggregate, r1.report_count, r1.valid_count), (AggregateResult::SumVec(vec![0, 7]), 3, 2));
}
