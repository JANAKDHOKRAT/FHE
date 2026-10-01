//! Post-validation computation pilot: ordinary least squares from encrypted
//! first and second moments of range-validated SumVec records. The
//! collector never sees a record; it solves the normal equations from the
//! decrypted sums. Checked against the plaintext computation on the same
//! records.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::types::regression_plain;
use fhe_prio3::*;

fn records() -> Vec<Vec<u64>> {
    // two 4-bit features and a 4-bit target with a rough linear relation
    vec![vec![1, 2, 8], vec![2, 1, 7], vec![3, 5, 15], vec![4, 1, 11], vec![0, 3, 8], vec![5, 5, 15]]
}

#[test]
fn verdict_mode_regression_matches_plaintext() {
    let _g = serial();
    let t = MeasurementType::SumVec {
        length: 3,
        max_measurement: 15,
    };
    let mut cfg = TaskConfig::new(task_id(50), t.clone(), 2);
    cfg.moments = true;
    let mut net = Net::new(cfg);
    let rows = records();
    for r in &rows {
        net.expect_accept(&net.client.shard(&Measurement::SumVec(r.clone())).unwrap());
    }
    // an out-of-range row is rejected and does not enter the moments
    net.expect_reject(
        &net.client.shard_raw_elements(&[vec![1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 2]]).unwrap(),
        RejectReason::ValidityCheckFailed,
    );
    let res = net.collect_full().unwrap();
    let plain = regression_plain(&rows);
    let reg = res.regression.expect("moments enabled");
    assert_eq!((reg.n, &reg.first, &reg.second), (plain.n, &plain.first, &plain.second));
    for (a, b) in reg.beta.iter().zip(&plain.beta) {
        assert!((a - b).abs() < 1e-9, "{:?} vs {:?}", reg.beta, plain.beta);
    }
    assert_eq!(
        res.aggregate,
        t.aggregate_plain(&rows.iter().map(|r| Measurement::SumVec(r.clone())).collect::<Vec<_>>())
            .unwrap()
    );
}

#[test]
fn silent_batched_regression_excludes_invalid_records() {
    let _g = serial();
    let t = MeasurementType::SumVec {
        length: 3,
        max_measurement: 15,
    };
    let mut cfg = TaskConfig::new_silent(task_id(51), t.clone(), 2);
    cfg.moments = true;
    cfg.silent_batch_groups = 4;
    let mut net = Net::new(cfg);
    let rows = records();
    for (i, r) in rows.iter().enumerate() {
        net.expect_accept(&net.client.shard_in_group(&Measurement::SumVec(r.clone()), (i % 4) as u32).unwrap());
    }
    // invalid record (a non-bit) in group 2: admitted, contributes nothing
    net.expect_accept(&net.client.shard_raw_elements_in_group(&[vec![1, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0]], 2).unwrap());
    let res = net.collect_full().unwrap();
    let plain = regression_plain(&rows);
    let reg = res.regression.expect("moments enabled");
    assert_eq!((res.report_count, res.valid_count), (7, 6));
    assert_eq!((reg.n, &reg.first, &reg.second), (plain.n, &plain.first, &plain.second));
    for (a, b) in reg.beta.iter().zip(&plain.beta) {
        assert!((a - b).abs() < 1e-9, "{:?} vs {:?}", reg.beta, plain.beta);
    }
}

/// Silent mode with 8-bit values, a batch of 16 and room for 65,536
/// reports. The former cap was 12 reports; the sums of squares here exceed
/// p = 786,433, so an undecomposed accumulator would wrap. With 2-bit
/// digits every accumulator slot stays below p and the collector
/// recombines the exact integers.
#[test]
fn silent_eight_bit_regression_beyond_the_former_cap() {
    let _g = serial();
    let t = MeasurementType::SumVec {
        length: 3,
        max_measurement: 255,
    };
    let mut cfg = TaskConfig::new_silent(task_id(52), t.clone(), 2);
    cfg.moments = true;
    cfg.silent_batch_groups = 4;
    assert_eq!((cfg.max_batch_size, cfg.moment_digit_bits()), (1 << 16, Some(2)));
    let mut net = Net::new(cfg.clone());
    let rows: Vec<Vec<u64>> = (0..16u64)
        .map(|i| {
            let x1 = 200 + (i * 37) % 56;
            let x2 = 100 + (i * 53) % 156;
            vec![x1, x2, x1 / 2 + x2 / 3 + i % 7]
        })
        .collect();
    for (i, r) in rows.iter().enumerate() {
        net.expect_accept(&net.client.shard_in_group(&Measurement::SumVec(r.clone()), (i % 4) as u32).unwrap());
    }
    // invalid (a non-bit in the target): admitted, contributes nothing
    let mut raw = vec![1u64; 24];
    raw[20] = 2;
    net.expect_accept(&net.client.shard_raw_elements_in_group(&[raw], 1).unwrap());
    let res = net.collect_full().unwrap();
    let plain = regression_plain(&rows);
    assert!(plain.second.iter().flatten().any(|&m| m >= cfg.plain_mod as u128), "test must exceed p");
    let reg = res.regression.expect("moments enabled");
    assert_eq!((res.report_count, res.valid_count), (17, 16));
    assert_eq!((reg.n, &reg.first, &reg.second), (plain.n, &plain.first, &plain.second));
    for (a, b) in reg.beta.iter().zip(&plain.beta) {
        assert!((a - b).abs() < 1e-9, "{:?} vs {:?}", reg.beta, plain.beta);
    }
}
