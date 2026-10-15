//! Secret-shared upload (`Upload::Shares`) with post-validation moments:
//! the regression accumulators are computed from the sum of the key
//! parties' contributions, restricted to the occupied groups, exactly as
//! from client ciphertexts. Its own file: another measurement type means
//! another key set, and one process holds one.
mod common;

use common::{ShareNet, serial, task_id, with_share_upload};
use fhe_prio3::*;

#[test]
fn regression_moments_run_through_the_shared_input() {
    let _g = serial();
    let mut c = TaskConfig::new_silent(task_id(221), MeasurementType::BoundedSumVec { bounds: vec![15, 15, 255] }, 2);
    c.silent_batch_groups = 4;
    c.repetitions = 4;
    c.moments = true;
    let c = with_share_upload(c);
    let k = keys::run_local_key_ceremony(&c).unwrap();
    let mut net = ShareNet::from_local_keys(c, &k);
    let rows: [[u64; 3]; 5] = [[1, 2, 13], [3, 1, 19], [5, 4, 33], [7, 3, 41], [2, 9, 40]];
    for r in rows {
        let rep = net.client.shard(&Measurement::SumVec(r.to_vec())).unwrap();
        net.expect_accept(&rep);
    }
    let res = net.collect_full().unwrap();
    let mut sums = [0u128; 3];
    for r in rows {
        for i in 0..3 {
            sums[i] += r[i] as u128;
        }
    }
    assert_eq!(res.aggregate, AggregateResult::SumVec(sums.to_vec()));
    let reg = res.regression.expect("moments");
    for a in 0..3 {
        for b in 0..3 {
            let want: u128 = rows.iter().map(|r| r[a] as u128 * r[b] as u128).sum();
            assert_eq!(reg.second[a][b], want, "moment ({a}, {b})");
        }
    }
}
