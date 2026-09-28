//! Per-element bounds (`BoundedSumVec`): exact ranges per element, enforced
//! homomorphically by one linear constraint per element folded into the
//! random linear combination, in both modes; second moments over values of
//! mixed widths; and the bounds bound into the task so that aggregators,
//! not clients, decide them.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::types::regression_plain;
use fhe_prio3::*;

fn bits(v: u64, n: u32) -> Vec<u64> {
    (0..n).map(|i| (v >> i) & 1).collect()
}

/// Raw slots for a bounded vector where element `e` is written with value
/// `v` and offset half `y`, everything else honest. Layout: per element,
/// `bits_e` value bits then `bits_e` offset bits.
fn raw_with(t: &MeasurementType, honest: &[u64], e: usize, v: u64, y: u64) -> Vec<u64> {
    let mut slots = t.encode(&Measurement::SumVec(honest.to_vec())).unwrap();
    let (start, b) = t.value_slots().unwrap()[e];
    let b = b as usize;
    slots[start..start + b].copy_from_slice(&bits(v, b as u32));
    slots[start + b..start + 2 * b].copy_from_slice(&bits(y, b as u32));
    slots
}

const BOUNDS: [u64; 4] = [100, 255, 5, 1];

#[test]
fn verdict_mode_per_element_bounds_are_exact() {
    let _g = serial();
    let t = MeasurementType::BoundedSumVec { bounds: BOUNDS.to_vec() };
    let mut net = Net::new(TaskConfig::new(task_id(60), t.clone(), 2));
    let honest = [100u64, 255, 5, 1];
    // every element at its bound passes; zeros pass
    net.expect_accept(&net.client.shard(&Measurement::SumVec(honest.to_vec())).unwrap());
    net.expect_accept(&net.client.shard(&Measurement::SumVec(vec![0, 0, 0, 0])).unwrap());
    // each element whose bound is below 2^bits - 1 (100 and 5) at bound + 1
    // fails whatever the offset half claims: wrapped, saturated, or zero.
    // Bounds of the form 2^bits - 1 (255 and 1) are enforced by the bit
    // check alone; a value above them cannot be written in the slots.
    for e in [0usize, 2] {
        let (_, b) = t.value_slots().unwrap()[e];
        let over = BOUNDS[e] + 1;
        assert!(over < (1u64 << b));
        let offset = (1u64 << b) - 1 - BOUNDS[e];
        for y in [0u64, (over + offset) & ((1 << b) - 1), (1 << b) - 1] {
            let raw = raw_with(&t, &honest, e, over, y);
            net.expect_reject(&net.client.shard_raw(&[raw]).unwrap(), RejectReason::ValidityCheckFailed);
        }
    }
    // the last element (tail slots) inconsistent: value 1 with offset half 0 (offset is 0, so 1 + 0 - 0 != 0)
    net.expect_reject(&net.client.shard_raw(&[raw_with(&t, &honest, 3, 1, 0)]).unwrap(), RejectReason::ValidityCheckFailed);
    // element 0 at 2^7 - 1 = 127 (> 100) with a saturated offset half fails
    net.expect_reject(&net.client.shard_raw(&[raw_with(&t, &honest, 0, 127, 127)]).unwrap(), RejectReason::ValidityCheckFailed);
    // value bits fine, offset bits inconsistent
    net.expect_reject(&net.client.shard_raw(&[raw_with(&t, &honest, 2, 5, 6)]).unwrap(), RejectReason::ValidityCheckFailed);
    // only element 2 out of range with a zero offset half
    net.expect_reject(&net.client.shard_raw(&[raw_with(&t, &honest, 2, 6, 0)]).unwrap(), RejectReason::ValidityCheckFailed);
    // a non-bit in an offset slot fails the bit check
    let mut nb = t.encode(&Measurement::SumVec(honest.to_vec())).unwrap();
    nb[33] = 2;
    net.expect_reject(&net.client.shard_raw(&[nb]).unwrap(), RejectReason::ValidityCheckFailed);
    let (agg, n) = net.collect().unwrap();
    assert_eq!((agg, n), (AggregateResult::SumVec(vec![100, 255, 5, 1]), 2));
}

/// Two elements out of range in opposite directions: element 0 violates
/// its constraint by +1 and element 2 by -1. They cancel only if the two
/// challenge coefficients coincide, probability 1/p per repetition, so over
/// many report ids every attempt must fail.
#[test]
fn opposite_violations_do_not_cancel_across_challenges() {
    let _g = serial();
    let t = MeasurementType::BoundedSumVec { bounds: vec![100, 5] };
    let mut net = Net::new(TaskConfig::new(task_id(61), t.clone(), 2));
    // element 0: value 100 with offset half 126 (constraint value +1: 100 + 27 - 126)
    // element 1: value 5 with offset half 8 -> 8 does not fit in 3 bits; use value 4 with offset half 7 (4 + 2 - 7 = -1)
    let mut raw = bits(100, 7);
    raw.extend(bits(126, 7));
    raw.extend(bits(4, 3));
    raw.extend(bits(7, 3));
    assert!(!fhe_prio3::types::is_valid_plain(&t, &net.cfg.field(), &raw));
    for _ in 0..12 {
        // each shard is a fresh encryption, hence a fresh report id and fresh challenge
        net.expect_reject(&net.client.shard_raw(&[raw.clone()]).unwrap(), RejectReason::ValidityCheckFailed);
    }
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
    // element 1 = 6 > 5 with a saturated offset half: admitted, contributes nothing
    let mut raw = bits(3, 7);
    raw.extend(bits(3 + 27, 7));
    raw.extend(bits(6, 3));
    raw.extend(bits(7, 3));
    net.expect_accept(&net.client.shard_raw_in_group(&[raw], 2).unwrap());
    let res = net.collect_full().unwrap();
    assert_eq!((res.aggregate, res.report_count, res.valid_count), (AggregateResult::SumVec(vec![107, 7]), 3, 2));
}

#[test]
fn moments_over_mixed_widths_match_plaintext() {
    let _g = serial();
    // 7-bit, 3-bit and 4-bit values; target is the last
    let t = MeasurementType::BoundedSumVec { bounds: vec![100, 5, 15] };
    let mut cfg = TaskConfig::new(task_id(63), t.clone(), 2);
    cfg.moments = true;
    cfg.max_batch_size = cfg.moments_max_batch().unwrap().min(1 << 20);
    assert_eq!(cfg.moments_max_batch().unwrap(), (cfg.plain_mod - 1) >> (7 + 4));
    let mut net = Net::new(cfg);
    let rows = vec![vec![10u64, 1, 8], vec![20, 5, 7], vec![100, 3, 15], vec![40, 1, 11], vec![0, 0, 8], vec![55, 5, 15]];
    for r in &rows {
        net.expect_accept(&net.client.shard(&Measurement::SumVec(r.clone())).unwrap());
    }
    // out of range in the narrowest element: rejected, enters nothing
    net.expect_reject(&net.client.shard_raw(&[raw_with(&t, &[1, 1, 1], 1, 6, 7)]).unwrap(), RejectReason::ValidityCheckFailed);
    let res = net.collect_full().unwrap();
    let plain = regression_plain(&rows);
    let reg = res.regression.expect("moments enabled");
    assert_eq!((reg.n, &reg.first, &reg.second), (plain.n, &plain.first, &plain.second));
    for (a, b) in reg.beta.iter().zip(&plain.beta) {
        assert!((a - b).abs() < 1e-9, "{:?} vs {:?}", reg.beta, plain.beta);
    }
}

/// The bounds are part of the task binding: a client that encodes under
/// other bounds produces a report the aggregators reject, so bounds are
/// decided by the task, never by the client. Also: the type round-trips.
#[test]
fn bounds_are_bound_into_the_task() {
    let _g = serial();
    let t = MeasurementType::BoundedSumVec { bounds: vec![100, 5] };
    let mut net = Net::new(TaskConfig::new(task_id(64), t.clone(), 2));
    let loose = MeasurementType::BoundedSumVec { bounds: vec![127, 7] }; // same widths, offsets 0
    let mut loose_cfg = net.cfg.clone();
    loose_cfg.measurement_type = loose.clone();
    assert_ne!(loose_cfg.digest(), net.cfg.digest());
    let other = Client::new(loose_cfg, &net.material.context, &net.material.public_key).unwrap();
    // 120 is valid under the loose bounds and encodes to in-range bits; under the task's bounds it must fail
    net.expect_reject(&other.shard(&Measurement::SumVec(vec![120, 7])).unwrap(), RejectReason::ValidityCheckFailed);
    // and an in-range value encoded under the loose offsets is also rejected: the offset halves differ
    net.expect_reject(&other.shard(&Measurement::SumVec(vec![50, 3])).unwrap(), RejectReason::ValidityCheckFailed);
    net.expect_accept(&net.client.shard(&Measurement::SumVec(vec![50, 3])).unwrap());
    let rt: MeasurementType = decode(&encode(&t).unwrap()).unwrap();
    assert_eq!(rt, t);
}
