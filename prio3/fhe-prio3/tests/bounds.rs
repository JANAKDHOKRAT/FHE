//! Per-element bounds (`BoundedSumVec`): exact ranges per element, enforced
//! by the draft's range-checked encoding against each element's own bound
//! (weights `1, 2, .., 2^(b-2), bound - 2^(b-1) + 1`, which sum to the
//! bound), so that no 0/1 vector is out of range and the bit check alone
//! decides validity; second moments over values of mixed widths, including
//! bounds whose last weight is not a power of two; and the bounds bound
//! into the task so that aggregators, not clients, decide them.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::field::Field;
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::types::{decode_range_checked, is_valid_plain, range_bits, range_weights, regression_plain};
use fhe_prio3::*;

/// Raw slots for a bounded vector where element `e`'s slots are replaced by
/// `slots`, everything else honest.
fn raw_with(t: &MeasurementType, honest: &[u64], e: usize, slots: &[u64]) -> Vec<u64> {
    let mut raw = t.encode(&Measurement::SumVec(honest.to_vec())).unwrap();
    let (start, b) = t.value_slots().unwrap()[e];
    assert_eq!(slots.len(), b as usize);
    raw[start..start + b as usize].copy_from_slice(slots);
    raw
}

const BOUNDS: [u64; 4] = [100, 255, 5, 1];

/// No linear constraint exists: over 0/1 slots the weighted sum of an
/// element cannot leave `[0, bound]`, so validity is the bit check alone.
#[test]
fn every_bit_vector_is_in_range_and_no_constraint_is_needed() {
    let t = MeasurementType::BoundedSumVec { bounds: BOUNDS.to_vec() };
    assert!(t.linear_constraints().is_empty());
    let f = Field::new(4_293_918_721).unwrap();
    for (e, &b) in BOUNDS.iter().enumerate() {
        let (start, bits) = t.value_slots().unwrap()[e];
        assert_eq!(bits, range_bits(b));
        assert_eq!(range_weights(b).iter().sum::<u64>(), b);
        for mask in 0u64..(1 << bits) {
            let slots: Vec<u64> = (0..bits).map(|i| (mask >> i) & 1).collect();
            assert!(decode_range_checked(&slots, b) <= b as u128);
            let raw = raw_with(&t, &[0, 0, 0, 0], e, &slots);
            assert!(is_valid_plain(&t, &f, &raw), "element {e} slots {slots:?}");
            let _ = start;
        }
    }
}

#[test]
fn verdict_mode_per_element_bounds_are_exact() {
    let _g = serial();
    let t = MeasurementType::BoundedSumVec { bounds: BOUNDS.to_vec() };
    let mut net = Net::new(TaskConfig::new(task_id(60), t.clone(), 2));
    let honest = [100u64, 255, 5, 1];
    // every element at its bound passes; zeros pass
    net.expect_accept(&net.client.shard(&Measurement::SumVec(honest.to_vec())).unwrap());
    net.expect_accept(&net.client.shard(&Measurement::SumVec(vec![0, 0, 0, 0])).unwrap());
    // bound + 1 needs a non-bit slot; every such attempt fails the bit check
    // element 0: 101 = 2 * 32 + 37
    net.expect_reject(
        &net.client.shard_raw(&[raw_with(&t, &honest, 0, &[0, 0, 0, 0, 0, 2, 1])]).unwrap(),
        RejectReason::ValidityCheckFailed,
    );
    // element 2: 6 = 0 + 2 + 2 * 2 (weights 1, 2, 2)
    net.expect_reject(
        &net.client.shard_raw(&[raw_with(&t, &honest, 2, &[0, 1, 2])]).unwrap(),
        RejectReason::ValidityCheckFailed,
    );
    // element 3: 2 in its only slot
    net.expect_reject(
        &net.client.shard_raw(&[raw_with(&t, &honest, 3, &[2])]).unwrap(),
        RejectReason::ValidityCheckFailed,
    );
    // a non-bit that stays in range is still invalid (element 1: 3 * 1 = 3)
    net.expect_reject(
        &net.client.shard_raw(&[raw_with(&t, &honest, 1, &[3, 0, 0, 0, 0, 0, 0, 0])]).unwrap(),
        RejectReason::ValidityCheckFailed,
    );
    // p - 1 in a slot (a "-1") is not a bit either
    net.expect_reject(
        &net.client
            .shard_raw(&[raw_with(&t, &honest, 0, &[net.cfg.plain_mod - 1, 1, 0, 0, 0, 0, 1])])
            .unwrap(),
        RejectReason::ValidityCheckFailed,
    );
    let (agg, n) = net.collect().unwrap();
    assert_eq!((agg, n), (AggregateResult::SumVec(vec![100, 255, 5, 1]), 2));
}

#[test]
fn silent_mode_bounded_invalid_contributes_zero() {
    let _g = serial();
    let t = MeasurementType::BoundedSumVec { bounds: vec![100, 5] };
    let mut cfg = TaskConfig::new_silent(task_id(62), t.clone(), 2);
    cfg.silent_batch_groups = 4;
    let mut net = Net::new(cfg);
    net.expect_accept(&net.client.shard_in_group(&Measurement::SumVec(vec![100, 5]), 0).unwrap());
    net.expect_accept(&net.client.shard_in_group(&Measurement::SumVec(vec![7, 2]), 1).unwrap());
    // element 1 = 6 > 5 via a non-bit, placed at group 2's own slots:
    // admitted, contributes nothing
    let raw = raw_with(&t, &[3, 5], 1, &[0, 1, 2]);
    net.expect_accept(&net.client.shard_raw_elements_in_group(&[raw], 2).unwrap());
    let res = net.collect_full().unwrap();
    assert_eq!(
        (res.aggregate, res.report_count, res.valid_count),
        (AggregateResult::SumVec(vec![107, 7]), 3, 2)
    );
}

/// Bounds 100 and 5 have last weights 37 and 2, so each is two moment
/// pieces (`v = P + L b`); 15 is plain binary. The collector recombines
/// the piece products into the exact second moments.
#[test]
fn moments_over_mixed_widths_match_plaintext() {
    let _g = serial();
    let t = MeasurementType::BoundedSumVec { bounds: vec![100, 5, 15] };
    let mut cfg = TaskConfig::new(task_id(63), t.clone(), 2);
    cfg.moments = true;
    // pieces: 6 + 1 bits (100), 2 + 1 bits (5), 4 bits (15): the widest piece
    // is 6 bits and 63^2 * 2^20 < p, so every piece is a single 6-bit digit
    let pieces = t.moment_pieces().unwrap();
    assert_eq!(
        pieces.iter().map(|p| (p.element, p.bits, p.multiplier)).collect::<Vec<_>>(),
        vec![(0, 6, 1), (0, 1, 37), (1, 2, 1), (1, 1, 2), (2, 4, 1)]
    );
    assert_eq!((cfg.max_batch_size, cfg.moment_digit_bits()), (1 << 20, Some(6)));
    let mut net = Net::new(cfg);
    let rows = vec![
        vec![10u64, 1, 8],
        vec![20, 5, 7],
        vec![100, 3, 15],
        vec![40, 1, 11],
        vec![0, 0, 8],
        vec![55, 5, 15],
        vec![64, 4, 1],
        vec![99, 2, 0],
    ];
    for r in &rows {
        net.expect_accept(&net.client.shard(&Measurement::SumVec(r.clone())).unwrap());
    }
    // a non-bit in the narrowest element: rejected, enters nothing
    net.expect_reject(
        &net.client.shard_raw(&[raw_with(&t, &[1, 1, 1], 1, &[0, 1, 2])]).unwrap(),
        RejectReason::ValidityCheckFailed,
    );
    let res = net.collect_full().unwrap();
    let plain = regression_plain(&rows);
    let reg = res.regression.expect("moments enabled");
    assert_eq!((reg.n, &reg.first, &reg.second), (plain.n, &plain.first, &plain.second));
    for (a, b) in reg.beta.iter().zip(&plain.beta) {
        assert!((a - b).abs() < 1e-9, "{:?} vs {:?}", reg.beta, plain.beta);
    }
}

/// The bounds are part of the task binding (its digest), so aggregators,
/// not clients, decide them. A client that encodes against other bounds
/// of the same widths produces valid slots that the task reads with its
/// own weights: the report is accepted and means what the task's bounds
/// say, never more than the bound. Also: the type round-trips.
#[test]
fn bounds_are_bound_into_the_task() {
    let _g = serial();
    let t = MeasurementType::BoundedSumVec { bounds: vec![100, 5] };
    let mut net = Net::new(TaskConfig::new(task_id(64), t.clone(), 2));
    let loose = MeasurementType::BoundedSumVec { bounds: vec![127, 7] }; // same widths, plain binary
    let mut loose_cfg = net.cfg.clone();
    loose_cfg.measurement_type = loose.clone();
    assert_ne!(loose_cfg.digest(), net.cfg.digest());
    let other = Client::new(loose_cfg, &net.material.context, &net.material.public_key).unwrap();
    // 120 under the loose bounds is the bits 0001111 (LSB first); read with
    // the task's weights 1, 2, 4, 8, 16, 32, 37 that is 8 + 16 + 32 + 37 = 93.
    // 7 under the loose bound 7 is 111; read with the task's weights 1, 2, 2
    // that is 5, the bound.
    net.expect_accept(&other.shard(&Measurement::SumVec(vec![120, 7])).unwrap());
    net.expect_accept(&net.client.shard(&Measurement::SumVec(vec![7, 0])).unwrap());
    let (agg, n) = net.collect().unwrap();
    assert_eq!((agg, n), (AggregateResult::SumVec(vec![93 + 7, 5]), 2));
    let rt: MeasurementType = decode(&encode(&t).unwrap()).unwrap();
    assert_eq!(rt, t);
}

/// Silent mode's prime (786,433) admits a range-checked bound only while
/// `2^bits < p` (the draft's rule). A task beyond that is refused when it
/// is configured, by every party; a task inside it enforces the range: the
/// largest honest value passes, and a non-bit contributes zero.
#[test]
fn silent_mode_sum_range_is_enforced_up_to_what_p_allows() {
    let _g = serial();
    // a bound the prime cannot carry: refused before any key exists
    for t in [
        MeasurementType::Sum { max_measurement: 600_000 },
        MeasurementType::BoundedSumVec { bounds: vec![100, 524_288] },
    ] {
        let e = TaskConfig::new_silent(task_id(64), t.clone(), 2).validate().unwrap_err().to_string();
        assert!(e.contains("2^bits < p = 786433"), "{t:?}: {e}");
        assert!(keys::run_local_ceremony(&TaskConfig::new_silent(task_id(64), t, 2)).is_err());
    }
    // 400,000 needs 19 slots (2^19 = 524,288 < p), last weight 137,857
    let max = 400_000u64;
    assert_eq!(range_bits(max), 19);
    let mut cfg = TaskConfig::new_silent(task_id(65), MeasurementType::Sum { max_measurement: max }, 2);
    cfg.silent_batch_groups = 4;
    let mut net = Net::new(cfg);
    net.expect_accept(&net.client.shard_in_group(&Measurement::Sum(max), 0).unwrap());
    net.expect_accept(&net.client.shard_in_group(&Measurement::Sum(0), 1).unwrap());
    // 450,000 = 400,000 + 50,000 with slot 0 (weight 1) holding 50,001: not a bit
    let mut raw = fhe_prio3::types::encode_range_checked(max, max);
    raw[0] = 50_001;
    assert_eq!(decode_range_checked(&raw, max), 450_000);
    net.expect_accept(&net.client.shard_raw_elements_in_group(&[raw], 2).unwrap());
    let res = net.collect_full().unwrap();
    assert_eq!((res.aggregate, res.report_count, res.valid_count), (AggregateResult::Sum(max as u128), 3, 2));
}
