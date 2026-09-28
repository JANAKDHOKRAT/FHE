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
    let t = MeasurementType::SumVec { length: 3, bits: 4 };
    let mut cfg = TaskConfig::new(task_id(50), t.clone(), 2);
    cfg.moments = true;
    cfg.max_batch_size = cfg.moments_max_batch().unwrap().min(1 << 20);
    let mut net = Net::new(cfg);
    let rows = records();
    for r in &rows {
        net.expect_accept(&net.client.shard(&Measurement::SumVec(r.clone())).unwrap());
    }
    // an out-of-range row is rejected and does not enter the moments
    net.expect_reject(&net.client.shard_raw_elements(&[vec![1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 2]]).unwrap(), RejectReason::ValidityCheckFailed);
    let res = net.collect_full().unwrap();
    let plain = regression_plain(&rows);
    let reg = res.regression.expect("moments enabled");
    assert_eq!((reg.n, &reg.first, &reg.second), (plain.n, &plain.first, &plain.second));
    for (a, b) in reg.beta.iter().zip(&plain.beta) {
        assert!((a - b).abs() < 1e-9, "{:?} vs {:?}", reg.beta, plain.beta);
    }
    assert_eq!(res.aggregate, t.aggregate_plain(&rows.iter().map(|r| Measurement::SumVec(r.clone())).collect::<Vec<_>>()).unwrap());
}

#[test]
fn silent_batched_regression_excludes_invalid_records() {
    let _g = serial();
    let t = MeasurementType::SumVec { length: 3, bits: 4 };
    let mut cfg = TaskConfig::new_silent(task_id(51), t.clone(), 2);
    cfg.moments = true;
    cfg.silent_batch_groups = 4;
    cfg.max_batch_size = cfg.moments_max_batch().unwrap();
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
