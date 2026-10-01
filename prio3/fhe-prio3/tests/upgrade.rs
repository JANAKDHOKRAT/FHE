//! State written before the packed wire format. Such a state has the same
//! `AggregatorState` layout, but every ciphertext that came from another
//! party (stored client reports) or was released to one (partial
//! decryptions returned again on a retried close) is in OpenFHE's own
//! serialization. These tests build exactly that state, by converting those
//! fields of a real state back to OpenFHE's format, and check what the
//! current build does with it.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::packed::{Expect, LEGACY_STATE};
use fhe_prio3::*;

/// OpenFHE's own serialization of a packed ciphertext or partial.
fn to_openfhe(net: &Net, packed: &[u8]) -> Vec<u8> {
    let c = net.aggs[0].codec();
    c.decode(packed, Expect::Any).unwrap().serialize().unwrap()
}

#[test]
fn open_verdict_batch_from_before_resumes() {
    // An open verdict-mode batch stores only the aggregator's own
    // accumulators (OpenFHE's format before and after) and bookkeeping.
    let _g = serial();
    let mut net = Net::new(TaskConfig::new(task_id(120), MeasurementType::Count, 2));
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    for a in net.aggs.iter_mut() {
        let st = a.snapshot().unwrap();
        a.restore(st, &[]).unwrap();
    }
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    assert_eq!(net.collect().unwrap(), (AggregateResult::Count(2), 2));
}

#[test]
fn released_shares_from_before_are_refused_at_restore() {
    let _g = serial();
    let mut net = Net::new(TaskConfig::new(task_id(121), MeasurementType::Count, 2));
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    let released: Vec<AggregateShare> = net.aggs.iter_mut().map(|a| a.aggregate_share().unwrap()).collect();
    let st = net.aggs[0].snapshot().unwrap();
    let mut old = st.clone();
    for s in old.released_aggregate_shares.values_mut() {
        for p in s.partials.iter_mut() {
            *p = to_openfhe(&net, p);
        }
    }
    let e = net.aggs[0].restore(old, &[]).unwrap_err().to_string();
    assert!(e.contains(LEGACY_STATE) && e.contains("aggregate share released to collector 0"), "{e}");
    // a corrupt packed share is reported as corrupt, not as an old state
    let mut corrupt = st.clone();
    corrupt.released_aggregate_shares.values_mut().next().unwrap().partials[0].pop();
    let e = net.aggs[0].restore(corrupt, &[]).unwrap_err().to_string();
    assert!(e.contains("stored ciphertext is not valid") && e.contains("BadLength"), "{e}");
    // the state as written by this build restores, and a retried close
    // returns the same released bytes, which the collector unshards
    net.aggs[0].restore(st, &[]).unwrap();
    let again = net.aggs[0].aggregate_share().unwrap();
    assert_eq!(again.partials, released[0].partials);
    assert_eq!(
        net.finish_release(0, vec![again, released[1].clone()]).unwrap().aggregate,
        AggregateResult::Count(1)
    );
}

#[test]
fn silent_state_from_before_is_refused_at_restore() {
    let _g = serial();
    let mut net = Net::new(TaskConfig::new_silent(task_id(122), MeasurementType::Count, 2));
    let good = net.client.shard(&Measurement::Count(true)).unwrap();
    net.expect_accept(&good);

    // a report still pending in its batch, stored in OpenFHE's format
    let st = net.aggs[0].snapshot().unwrap();
    assert_eq!(st.silent_pending.len(), 1);
    let mut old_report = good.clone();
    old_report.chunks = vec![to_openfhe(&net, &good.chunks[0])];
    old_report.report_id = Report::compute_id(&old_report.task_id, old_report.group, &old_report.chunks);
    let mut old = st.clone();
    old.silent_pending[0].1 = old_report.report_id;
    let e = net.aggs[0].restore(old, &[old_report]).unwrap_err().to_string();
    assert!(e.contains(LEGACY_STATE) && e.contains("pending report"), "{e}");
    net.aggs[0].restore(st, std::slice::from_ref(&good)).unwrap();

    // a count share released before the upgrade
    let counts: Vec<CountShare> = net.aggs.iter_mut().map(|a| a.count_share().unwrap()).collect();
    let mut old = net.aggs[0].snapshot().unwrap();
    let c = old.released_count_share.as_mut().unwrap();
    c.partial = to_openfhe(&net, &c.partial);
    let e = net.aggs[0].restore(old, &[]).unwrap_err().to_string();
    assert!(e.contains(LEGACY_STATE) && e.contains("released count share"), "{e}");

    // this build's own state still completes the batch (the verified count
    // round returns the count shares released above)
    let _ = counts;
    assert_eq!(net.collect().unwrap(), (AggregateResult::Count(1), 1));
}

#[test]
fn collector_tells_old_stored_shares_from_corrupt_ones() {
    let _g = serial();
    let mut net = Net::new(TaskConfig::new(task_id(123), MeasurementType::Count, 2));
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    let share = net.aggs[0].aggregate_share().unwrap();
    net.collector.check_stored_share(&share).unwrap();
    let mut old = share.clone();
    old.partials[0] = to_openfhe(&net, &old.partials[0]);
    let e = net.collector.check_stored_share(&old).unwrap_err().to_string();
    assert!(e.contains(LEGACY_STATE) && e.contains("aggregator 0"), "{e}");
    let mut truncated = share;
    truncated.partials[0].truncate(40);
    let e = net.collector.check_stored_share(&truncated).unwrap_err().to_string();
    assert!(e.contains("Truncated"), "{e}");
}
