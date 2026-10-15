//! Secret-shared upload (`Upload::Shares`) with one aggregator and the
//! collector holding the two key shares. Clients send a few hundred bytes
//! of sealed shares; the aggregator and the collector each encrypt their
//! shares of a verification batch as a contribution proven well formed,
//! and the unchanged validity circuit, gates and release run on the sum.
//! Every test runs the real protocol on keys from one in-process ceremony.
//!
//! Attacks covered: invalid encodings (one-hot violations, out-of-range
//! values, the cancelling errors of an unweighted check), shares that do
//! not open, malformed and replayed reports, reports for another task, a
//! batch below the minimum, contributions with a broken or misbound proof,
//! contributions replayed from another flush or party, a replayed report
//! in a later flush (the collector refuses to count it twice), a flush
//! requested twice with different reports, and restarts at every step.
mod common;

use common::{ShareNet, serial, task_id, upload_secrets, with_share_upload};
use fhe_prio3::keys::LocalKeys;
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use std::sync::OnceLock;

const LEN: usize = 5;
const GROUPS: usize = 4;

fn cfg(min_batch: usize, min_cell: u64) -> TaskConfig {
    let mut c = TaskConfig::new_split_key(task_id(210), MeasurementType::Histogram { length: LEN });
    c.silent_batch_groups = GROUPS;
    c.repetitions = 4;
    c.min_batch_size = min_batch;
    c.min_cell_count = min_cell;
    with_share_upload(c)
}

fn keys() -> &'static LocalKeys {
    static K: OnceLock<LocalKeys> = OnceLock::new();
    K.get_or_init(|| keys::run_local_key_ceremony(&cfg(1, 0)).expect("ceremony"))
}

fn make(min_batch: usize, min_cell: u64) -> ShareNet {
    ShareNet::from_local_keys(cfg(min_batch, min_cell), keys())
}

fn p() -> u64 {
    cfg(1, 0).plain_mod
}

fn histogram(net: &mut ShareNet, buckets: &[usize]) {
    for &b in buckets {
        let r = net.client.shard(&Measurement::Histogram(b)).unwrap();
        net.expect_accept(&r);
    }
}

/// An encoded measurement that is not a valid one-hot vector: admitted
/// (nobody can tell), zeroed under encryption by the check.
fn invalid(net: &mut ShareNet, x: &[u64]) {
    let r = net.client.shard_encoded(x).unwrap();
    net.expect_accept(&r);
}

fn sq(a: u64, p: u64) -> u64 {
    (a as u128 * a as u128 % p as u128) as u64
}

/// A non-one-hot vector whose *unweighted* check is zero: the bit errors
/// `x_i (x_i - 1)` plus the one-hot constraint `sum x_i - 1` add up to 0
/// mod p. The first two elements carry the errors 2 and -2 of the
/// professor's counterexample ([2, 336449, ...]); the last is solved for.
fn cancelling_vector(p: u64) -> Vec<u64> {
    let e = |x: u64| (sq(x, p) + p - x) % p; // x(x-1)
    assert_eq!((e(2), e(336_449)), (2, p - 2));
    for x2 in 3..p {
        // with x = [2, 336449, x2, 0, x4]:
        // sum e + (sum x - 1) = e(x2) + x2 + x4^2 + 336450, so x4^2 = c
        let c = (2 * p - (e(x2) + x2 + 336_450) % p) % p;
        // brute-force square root (p is below 2^20)
        if let Some(x4) = (1..p).find(|&y| sq(y, p) == c) {
            let x = vec![2, 336_449, x2, 0, x4];
            let unweighted: u64 = x.iter().map(|&v| e(v)).sum::<u64>() % p;
            let constraint = (x.iter().sum::<u64>() + p - 1) % p;
            assert_eq!((unweighted + constraint) % p, 0);
            return x;
        }
    }
    unreachable!("half of the residues are squares")
}

#[test]
fn aggregate_is_exact_over_valid_reports_and_reports_are_small() {
    let _g = serial();
    let mut net = make(3, 0);
    let r = net.client.shard(&Measurement::Histogram(1)).unwrap();
    let bytes = encode(&r).unwrap().len();
    eprintln!("share report: {bytes} bytes on the wire ({} sealed)", r.sealed_bytes());
    assert!(bytes < 400, "{bytes}");
    net.expect_accept(&r);
    histogram(&mut net, &[0, 2, 2, 4, 4]);
    invalid(&mut net, &[1, 0, 0, 1, 0]);
    invalid(&mut net, &[0, 0, 0, 0, 0]);
    invalid(&mut net, &[0, 2, 0, 0, 0]);
    invalid(&mut net, &[0, 0, p() - 1, 1, 1]);
    // ten reports: two full flushes of four and two pending until the close
    assert_eq!(net.net.aggs[0].share_round().next_seq, 2);
    assert_eq!(net.net.aggs[0].share_pending(), 2);
    let started = std::time::Instant::now();
    let res = net.collect_full().unwrap();
    eprintln!("last flush, gate and release: {:?}", started.elapsed());
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![1, 1, 2, 0, 2]));
    assert_eq!((res.report_count, res.valid_count), (10, 6));
}

#[test]
fn the_cancelling_errors_of_an_unweighted_check_are_caught() {
    let _g = serial();
    let mut net = make(1, 0);
    let x = cancelling_vector(p());
    invalid(&mut net, &x);
    histogram(&mut net, &[3]);
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![0, 0, 0, 1, 0]));
    assert_eq!((res.report_count, res.valid_count), (2, 1));
}

#[test]
fn shares_that_do_not_open_count_as_zero_and_the_report_is_zeroed() {
    let _g = serial();
    let mut net = make(1, 0);
    let cfg = net.net.cfg.clone();
    // party 1's input sealed to a key that is not the collector's: the
    // collector takes a zero share, the report adds up to party 0's share
    // alone (uniform), which the check zeroes
    let mut wrong = cfg.clone();
    wrong.upload_keys[1] = UploadKey::generate().public_key();
    let other = ShareClient::new(wrong).unwrap();
    let a = other.shard(&Measurement::Histogram(2)).unwrap();
    let r = net.client.finish_altered_for_tests(a.nonce, a.inputs.clone()).unwrap();
    net.expect_accept(&r);
    // an explicit share element equal to p (not canonical): party 0 takes zero
    let mut explicit = Vec::new();
    for v in [p() as u32, 0, 0, 0, 0] {
        explicit.extend_from_slice(&v.to_le_bytes());
    }
    let r = net.client.shard_raw_inputs_for_tests(&[explicit, vec![7u8; 32]]).unwrap();
    net.expect_accept(&r);
    histogram(&mut net, &[4]);
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![0, 0, 0, 0, 1]));
    assert_eq!((res.report_count, res.valid_count), (3, 1));
}

#[test]
fn malformed_replayed_and_foreign_reports_are_refused() {
    let _g = serial();
    let mut net = make(1, 0);
    let good = net.client.shard(&Measurement::Histogram(0)).unwrap();
    net.expect_accept(&good);
    // the same report again
    net.expect_reject(&good, RejectReason::Replay);
    // any changed byte breaks the report id
    let mut t = net.client.shard(&Measurement::Histogram(0)).unwrap();
    t.inputs[1].ciphertext[0] ^= 1;
    net.expect_reject(&t, RejectReason::ReportIdMismatch);
    let mut t = net.client.shard(&Measurement::Histogram(0)).unwrap();
    t.nonce[3] ^= 1;
    net.expect_reject(&t, RejectReason::ReportIdMismatch);
    // the wrong number of inputs, the wrong lengths
    let r = net.client.shard_raw_inputs_for_tests(&[vec![0u8; 4 * LEN]]).unwrap();
    net.expect_reject(&r, RejectReason::WrongInputShareCount { expected: 2, got: 1 });
    let r = net.client.shard_raw_inputs_for_tests(&[vec![0u8; 4 * LEN], vec![0u8; 31]]).unwrap();
    net.expect_reject(
        &r,
        RejectReason::MalformedInputShare {
            party: 1,
            expected: 48,
            got: 47,
        },
    );
    let r = net.client.shard_raw_inputs_for_tests(&[vec![0u8; 4 * LEN + 4], vec![0u8; 32]]).unwrap();
    assert!(matches!(net.submit(&r), Err(Error::Reject(RejectReason::TooLarge { .. }))));
    // a report for another task
    let mut other_task = net.net.cfg.clone();
    other_task.task_id = task_id(211);
    let r = ShareClient::new(other_task).unwrap().shard(&Measurement::Histogram(1)).unwrap();
    net.expect_reject(&r, RejectReason::WrongTask);
    // a ciphertext report to a task whose clients upload shares
    let ct = net.net.client.shard(&Measurement::Histogram(1)).unwrap();
    assert!(matches!(net.net.aggs[0].process_silent(&ct), Err(Error::Reject(RejectReason::WrongUpload))));
    // after the close nothing more is admitted
    net.collect_full().unwrap();
    let late = net.client.shard(&Measurement::Histogram(1)).unwrap();
    net.expect_reject(&late, RejectReason::BatchClosed);
}

#[test]
fn a_batch_below_the_minimum_is_refused_and_small_cells_are_suppressed() {
    let _g = serial();
    // three admitted, two valid: the batch-size gate is zero
    let mut net = make(3, 0);
    histogram(&mut net, &[1, 1]);
    invalid(&mut net, &[1, 1, 0, 0, 0]);
    let e = net.collect_full().err().unwrap().to_string();
    assert!(e.contains("batch below minimum size"), "{e}");
    drop(net);
    // suppression: cells below 2 are zeroed under encryption
    let mut net = make(1, 2);
    histogram(&mut net, &[0, 0, 0, 1, 3, 3, 4]);
    invalid(&mut net, &[0, 0, 0, 0, 2]);
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![3, 0, 0, 2, 0]));
    // cells [3, 1, 0, 2, 1]: every cell below 2 is suppressed, the empty one too
    assert_eq!(res.suppressed, vec![1, 2, 4]);
    assert!(res.counts_withheld);
}

#[test]
fn contributions_with_broken_or_misbound_proofs_are_refused() {
    let _g = serial();
    let mut net = make(1, 0);
    histogram(&mut net, &[0, 1, 2]);
    let req = net.net.aggs[0].share_flush_request().unwrap();
    let good = net.contributions(&req).unwrap();
    let finish = |net: &mut ShareNet, cs: &[ShareContribution]| net.net.aggs[0].share_finish(&req, cs).err().map(|e| e.to_string());

    // a response coefficient changed: the proof no longer verifies
    let mut cs = good.clone();
    cs[1].proofs[0].responses[0].zu[0] ^= 1;
    let e = finish(&mut net, &cs).unwrap();
    assert!(e.contains("key party 1") && e.contains("wfe"), "{e}");
    // the ciphertext changed: the proof is for another statement
    let mut cs = good.clone();
    let k = cs[1].chunks[0].len() - 1;
    cs[1].chunks[0][k] ^= 1;
    let e = finish(&mut net, &cs).unwrap();
    assert!(e.contains("key party 1"), "{e}");
    // the collector's contribution presented as the aggregator's
    let mut cs = good.clone();
    cs[0] = good[1].clone();
    cs[0].party = 0;
    let e = finish(&mut net, &cs).unwrap();
    assert!(e.contains("this party's own"), "{e}");
    // relabelled for another flush number or digest
    let mut cs = good.clone();
    cs[1].seq += 1;
    assert!(finish(&mut net, &cs).unwrap().contains("another task or flush"));
    let mut cs = good.clone();
    cs[1].flush_digest[0] ^= 1;
    assert!(finish(&mut net, &cs).unwrap().contains("another task or flush"));
    // a contribution missing, or one party twice
    assert!(finish(&mut net, &good[..1]).unwrap().contains("each of 2 key parties"));
    let cs = vec![good[0].clone(), good[0].clone()];
    assert!(finish(&mut net, &cs).unwrap().contains("each of 2 key parties"));
    // the honest set still finishes, and a repeated finish is a no-op
    net.net.aggs[0].share_finish(&req, &good).unwrap();
    net.net.aggs[0].share_finish(&req, &good).unwrap();
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![1, 1, 1, 0, 0]));
    assert_eq!(res.valid_count, 3);
}

#[test]
fn contributions_replayed_from_another_flush_are_refused() {
    let _g = serial();
    let mut net = make(1, 0);
    histogram(&mut net, &[0, 1, 2, 3]); // flush 0 runs
    assert_eq!(net.net.aggs[0].share_round().next_seq, 1);
    histogram(&mut net, &[4, 4]);
    let req1 = net.net.aggs[0].share_flush_request().unwrap();
    let good = net.contributions(&req1).unwrap();
    // the two contributions with their party labels swapped: each proof is
    // bound to its author's party index
    let mut cs = good.clone();
    cs[1].party = 0;
    cs[0].party = 1;
    cs.swap(0, 1);
    assert!(net.net.aggs[0].share_finish(&req1, &cs).is_err());
    // a contribution to flush 1 whose chunk is the aggregator's own
    // (another party's valid proof context) is refused
    let mut cs = good.clone();
    cs[1].chunks = good[0].chunks.clone();
    cs[1].proofs = good[0].proofs.clone();
    let e = net.net.aggs[0].share_finish(&req1, &cs).err().unwrap().to_string();
    assert!(e.contains("key party 1"), "{e}");
    net.net.aggs[0].share_finish(&req1, &good).unwrap();
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![1, 1, 1, 1, 2]));
}

#[test]
fn the_collector_refuses_replayed_reports_and_equivocating_flushes() {
    let _g = serial();
    let mut net = make(1, 0);
    let a = net.client.shard(&Measurement::Histogram(0)).unwrap();
    let b = net.client.shard(&Measurement::Histogram(1)).unwrap();
    let c = net.client.shard(&Measurement::Histogram(2)).unwrap();
    let tid = net.net.cfg.task_id;
    // the aggregator (malicious) asks for flush 0 with [a, b]
    let req0 = ShareFlushRequest {
        task_id: tid,
        seq: 0,
        reports: vec![a.clone(), b.clone()],
    };
    let first = net.net.collector.share_contribute(&req0).unwrap();
    // asked again: the same bytes
    let again = net.net.collector.share_contribute(&req0).unwrap();
    assert_eq!(encode(&first).unwrap(), encode(&again).unwrap());
    // flush 0 again with other reports: refused
    let other = ShareFlushRequest {
        task_id: tid,
        seq: 0,
        reports: vec![a.clone(), c.clone()],
    };
    assert!(
        net.net
            .collector
            .share_contribute(&other)
            .err()
            .unwrap()
            .to_string()
            .contains("with other reports")
    );
    // flush 1 replaying report a (count it twice): refused
    let replay = ShareFlushRequest {
        task_id: tid,
        seq: 1,
        reports: vec![c.clone(), a.clone()],
    };
    assert!(
        net.net
            .collector
            .share_contribute(&replay)
            .err()
            .unwrap()
            .to_string()
            .contains("replayed report")
    );
    // one report twice in one flush, a skipped number, another task
    let dup = ShareFlushRequest {
        task_id: tid,
        seq: 1,
        reports: vec![c.clone(), c.clone()],
    };
    assert!(net.net.collector.share_contribute(&dup).err().unwrap().to_string().contains("twice"));
    let skip = ShareFlushRequest {
        task_id: tid,
        seq: 3,
        reports: vec![c.clone()],
    };
    assert!(net.net.collector.share_contribute(&skip).is_err());
    let foreign = ShareFlushRequest {
        task_id: task_id(9),
        seq: 1,
        reports: vec![c.clone()],
    };
    assert!(net.net.collector.share_contribute(&foreign).is_err());
    // more reports than the layout has groups
    let big = ShareFlushRequest {
        task_id: tid,
        seq: 1,
        reports: (0..GROUPS + 1).map(|_| net.client.shard(&Measurement::Histogram(0)).unwrap()).collect(),
    };
    assert!(net.net.collector.share_contribute(&big).is_err());
    // a malformed report inside a flush
    let mut bad = c.clone();
    bad.inputs[0].ciphertext.pop();
    let malformed = ShareFlushRequest {
        task_id: tid,
        seq: 1,
        reports: vec![bad],
    };
    assert!(net.net.collector.share_contribute(&malformed).err().unwrap().to_string().contains("malformed"));
    // the next flush in order is accepted
    let next = ShareFlushRequest {
        task_id: tid,
        seq: 1,
        reports: vec![c.clone()],
    };
    net.net.collector.share_contribute(&next).unwrap();
}

#[test]
fn contributions_are_deterministic_and_each_flush_is_contributed_once() {
    let _g = serial();
    let mut net = make(1, 0);
    histogram(&mut net, &[1, 2]);
    let req = net.net.aggs[0].share_flush_request().unwrap();
    let a = net.net.aggs[0].share_contribute(&req).unwrap();
    let b = net.net.aggs[0].share_contribute(&req).unwrap();
    assert_eq!(encode(&a).unwrap(), encode(&b).unwrap());
    // admission is closed while the flush is being contributed
    let r = net.client.shard(&Measurement::Histogram(0)).unwrap();
    assert!(net.net.aggs[0].admit_share_report(&r).is_err());
    // closing with a flush open is refused
    assert!(net.net.aggs[0].gate_commit().err().unwrap().to_string().contains("share flush is open"));
    // a request that is not the leader's open flush is refused
    let mut forged = req.clone();
    forged.reports.pop();
    assert!(net.net.aggs[0].share_contribute(&forged).is_err());
    net.flush().unwrap();
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![0, 1, 1, 0, 0]));
}

#[test]
fn every_party_resumes_after_a_restart_at_every_step() {
    let _g = serial();
    let cfg = cfg(1, 0);
    let k = keys();
    let secrets = upload_secrets(2);
    let mut net = make(1, 0);
    let restart_aggregator = |net: &mut ShareNet| {
        let st: AggregatorState = decode(&encode(&net.net.aggs[0].snapshot().unwrap()).unwrap()).unwrap();
        let mut a = Aggregator::new(cfg.clone(), &k.material, 0, &k.aggregator_secrets[0], None)
            .unwrap()
            .with_upload_key(UploadKey::from_secret_bytes(&secrets[0]))
            .unwrap();
        a.restore(st, &[]).unwrap();
        net.net.aggs[0] = a;
    };
    let restart_collector = |net: &mut ShareNet| {
        let st: CollectorShareState = decode(&encode(net.net.collector.share_state()).unwrap()).unwrap();
        let gate = net.net.collector.gate_state().clone();
        let mut c = Collector::with_key_share(cfg.clone(), &net.net.material, k.collector_secret.as_ref().unwrap())
            .unwrap()
            .with_upload_key(UploadKey::from_secret_bytes(&secrets[1]))
            .unwrap();
        c.restore_share_state(st).unwrap();
        c.restore_gate_state(gate);
        net.net.collector = c;
    };
    histogram(&mut net, &[0, 1]);
    // restart with reports pending in the open flush
    restart_aggregator(&mut net);
    histogram(&mut net, &[2]);
    let r = net.client.shard(&Measurement::Histogram(3)).unwrap();
    net.net.aggs[0].admit_share_report(&r).unwrap();
    let req = net.net.aggs[0].share_flush_request().unwrap();
    // both contribute, then both restart before the aggregator finishes
    let cs = net.contributions(&req).unwrap();
    restart_aggregator(&mut net);
    restart_collector(&mut net);
    // asked again after the restart, each returns the same contribution
    let again = net.contributions(&req).unwrap();
    for (x, y) in cs.iter().zip(&again) {
        assert_eq!(encode(x).unwrap(), encode(y).unwrap());
    }
    net.net.aggs[0].share_finish(&req, &cs).unwrap();
    // restart after the finish: the flush is not applied twice
    restart_aggregator(&mut net);
    net.net.aggs[0].share_finish(&req, &cs).unwrap();
    assert_eq!(net.net.aggs[0].share_round().next_seq, 1);
    // the collector still refuses report r a second time
    let replay = ShareFlushRequest {
        task_id: cfg.task_id,
        seq: 1,
        reports: vec![r.clone()],
    };
    assert!(net.net.collector.share_contribute(&replay).is_err());
    histogram(&mut net, &[4]);
    restart_collector(&mut net);
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![1, 1, 1, 1, 1]));
    assert_eq!(res.report_count, 5);
}
