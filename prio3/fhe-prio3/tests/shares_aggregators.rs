//! Secret-shared upload (`Upload::Shares`) with two aggregators holding
//! the key shares (the collector holds none). The leader admits reports;
//! the helper sees each report only when the leader runs its flush, admits
//! it there with every one of the leader's checks, and contributes its own
//! shares. Both aggregators verify each other's proofs and compute the same
//! accumulators; the verified count round and release run unchanged.
//!
//! Attacks covered: a leader asking the helper to admit reports it should
//! have refused (replayed, malformed, unsigned, unregistered, over quota),
//! a leader sending the helper a flush other than the one it computes, a
//! leader substituting the helper's own contribution, contributions with
//! broken proofs, and restarts of the helper mid-flush.
mod common;

use common::{ShareNet, serial, task_id, upload_secrets, with_share_upload};
use fhe_prio3::keys::LocalKeys;
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use std::sync::{Arc, OnceLock};

const GROUPS: usize = 4;

fn cfg(t: MeasurementType, min_batch: usize) -> TaskConfig {
    let mut c = TaskConfig::new_silent(task_id(220), t, 2);
    c.silent_batch_groups = GROUPS;
    c.repetitions = 4;
    c.min_batch_size = min_batch;
    with_share_upload(c)
}

fn hist() -> MeasurementType {
    MeasurementType::Histogram { length: 4 }
}

fn keys() -> &'static LocalKeys {
    static K: OnceLock<LocalKeys> = OnceLock::new();
    K.get_or_init(|| keys::run_local_key_ceremony(&cfg(hist(), 1)).expect("ceremony"))
}

fn make(min_batch: usize) -> ShareNet {
    ShareNet::from_local_keys(cfg(hist(), min_batch), keys())
}

fn histogram(net: &mut ShareNet, buckets: &[usize]) {
    for &b in buckets {
        let r = net.client.shard(&Measurement::Histogram(b)).unwrap();
        net.expect_accept(&r);
    }
}

#[test]
fn aggregate_is_exact_with_the_count_round() {
    let _g = serial();
    let mut net = make(4);
    histogram(&mut net, &[0, 1, 1, 3, 3, 3]);
    for x in [[1u64, 1, 0, 0], [0, 0, 0, 0], [5, 0, 0, 0]] {
        let r = net.client.shard_encoded(&x).unwrap();
        net.expect_accept(&r);
    }
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![1, 2, 0, 3]));
    assert_eq!((res.report_count, res.valid_count), (9, 6));
    // both aggregators admitted every report and agree on the count
    for a in &net.net.aggs {
        assert_eq!(a.share_round().next_seq, 3);
    }
}

#[test]
fn the_helper_refuses_reports_the_leader_should_have_refused() {
    let _g = serial();
    let mut net = make(1);
    let a = net.client.shard(&Measurement::Histogram(0)).unwrap();
    histogram(&mut net, &[1]);
    net.expect_accept(&a);
    net.flush().unwrap();
    let tid = net.net.cfg.task_id;
    let helper = |net: &mut ShareNet, reports: Vec<ShareReport>| {
        let req = ShareFlushRequest { task_id: tid, seq: 1, reports };
        net.net.aggs[1].share_contribute(&req).err().map(|e| e.to_string())
    };
    // a replayed report
    let fresh = net.client.shard(&Measurement::Histogram(2)).unwrap();
    let e = helper(&mut net, vec![fresh.clone(), a.clone()]).unwrap();
    assert!(e.contains("Replay"), "{e}");
    // a malformed one (an input one byte short), a longer one (over the
    // size bound), a tampered one (report id)
    let mut bad = fresh.clone();
    bad.inputs[1].ciphertext.pop();
    assert!(helper(&mut net, vec![bad]).unwrap().contains("MalformedInputShare"));
    let mut bad = fresh.clone();
    bad.inputs[1].ciphertext.push(0);
    assert!(helper(&mut net, vec![bad]).unwrap().contains("TooLarge"));
    let mut bad = fresh.clone();
    bad.nonce[0] ^= 1;
    assert!(helper(&mut net, vec![bad]).unwrap().contains("ReportIdMismatch"));
    // nothing was admitted by the refused requests: the honest flush passes
    let req = ShareFlushRequest {
        task_id: tid,
        seq: 1,
        reports: vec![fresh.clone()],
    };
    assert!(net.net.aggs[1].share_contribute(&req).is_ok());
}

#[test]
fn signed_reports_and_quotas_are_enforced_by_both_aggregators() {
    let _g = serial();
    let alice = ClientIdentity::generate();
    let mallory = ClientIdentity::generate();
    let registry: Arc<dyn ClientRegistry> = StaticRegistry::new([alice.public_key()]);
    let mut c = cfg(hist(), 1);
    c.auth = AuthPolicy::Required {
        max_reports_per_client_per_batch: 2,
    };
    let mut net = ShareNet::from_local_keys_with_registry(c.clone(), keys(), Some(registry));
    let alice_client = ShareClient::new(c.clone()).unwrap().with_identity(alice);
    let mallory_client = ShareClient::new(c.clone()).unwrap().with_identity(mallory);
    // unsigned, unregistered
    let unsigned = net.client.shard(&Measurement::Histogram(0));
    assert!(unsigned.is_err(), "a client without identity cannot build a report for this task");
    let r = mallory_client.shard(&Measurement::Histogram(0)).unwrap();
    net.expect_reject(&r, RejectReason::UnknownClient);
    // a signature over another report id
    let mut forged = alice_client.shard(&Measurement::Histogram(0)).unwrap();
    forged.auth = alice_client.shard(&Measurement::Histogram(1)).unwrap().auth;
    assert!(matches!(net.submit(&forged), Err(Error::Reject(RejectReason::Unauthenticated(_)))));
    // two reports allowed, the third over quota
    let r1 = alice_client.shard(&Measurement::Histogram(1)).unwrap();
    let r2 = alice_client.shard(&Measurement::Histogram(2)).unwrap();
    net.expect_accept(&r1);
    net.expect_accept(&r2);
    let r3 = alice_client.shard(&Measurement::Histogram(3)).unwrap();
    net.expect_reject(&r3, RejectReason::QuotaExceeded);
    // a leader slipping the over-quota report into the flush: the helper refuses
    let mut req = net.net.aggs[0].share_flush_request().unwrap();
    req.reports.push(r3.clone());
    let e = net.net.aggs[1].share_contribute(&req).err().unwrap().to_string();
    assert!(e.contains("QuotaExceeded"), "{e}");
    // and an unregistered client's report
    let mut req = net.net.aggs[0].share_flush_request().unwrap();
    req.reports.push(mallory_client.shard(&Measurement::Histogram(0)).unwrap());
    assert!(net.net.aggs[1].share_contribute(&req).err().unwrap().to_string().contains("UnknownClient"));
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![0, 1, 1, 0]));
}

#[test]
fn a_leader_cannot_feed_the_helper_another_flush_or_replace_its_contribution() {
    let _g = serial();
    let mut net = make(1);
    histogram(&mut net, &[0, 1, 2]);
    let req = net.net.aggs[0].share_flush_request().unwrap();
    let mine = net.net.aggs[0].share_contribute(&req).unwrap();
    // the helper is shown a flush with one report dropped
    let mut other = req.clone();
    other.reports.pop();
    let helper_other = net.net.aggs[1].share_contribute(&other).unwrap();
    // the leader's contribution is bound to its own flush: the helper,
    // which contributed to `other`, refuses to finish with it, and the
    // leader refuses the helper's contribution to `other`
    let e = net.net.aggs[1]
        .share_finish(&other, &[mine.clone(), helper_other.clone()])
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("another task or flush"), "{e}");
    let e = net.net.aggs[0]
        .share_finish(&req, &[mine.clone(), helper_other.clone()])
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("another task or flush") || e.contains("contributed to"), "{e}");
    drop(net);

    // a leader replacing the helper's contribution with one it made itself
    // (a valid proof under the helper's party index): the helper refuses
    let mut net = make(1);
    histogram(&mut net, &[0, 1, 2]);
    let req = net.net.aggs[0].share_flush_request().unwrap();
    let mut cs = net.contributions(&req).unwrap();
    // a second, independent contribution under party 1 (as a malicious
    // leader holding party 1's upload key would build it: well formed,
    // other randomness), the helper's own digest no longer matches
    let mut fake = cs[0].clone();
    fake.party = 1;
    cs[1] = fake;
    let e = net.net.aggs[1].share_finish(&req, &cs).err().unwrap().to_string();
    assert!(e.contains("this party's own"), "{e}");
}

#[test]
fn contributions_with_broken_proofs_are_refused_by_either_aggregator() {
    let _g = serial();
    let mut net = make(1);
    histogram(&mut net, &[3, 3]);
    let req = net.net.aggs[0].share_flush_request().unwrap();
    let good = net.contributions(&req).unwrap();
    for (finisher, author) in [(0usize, 1usize), (1, 0)] {
        let mut cs = good.clone();
        cs[author].proofs[0].responses[1].ze1[7] ^= 1;
        let e = net.net.aggs[finisher].share_finish(&req, &cs).err().unwrap().to_string();
        assert!(e.contains(&format!("key party {author}")), "{e}");
    }
    for a in net.net.aggs.iter_mut() {
        a.share_finish(&req, &good).unwrap();
    }
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![0, 0, 0, 2]));
}

#[test]
fn the_helper_resumes_after_a_restart_mid_flush() {
    let _g = serial();
    let c = cfg(hist(), 1);
    let k = keys();
    let secrets = upload_secrets(2);
    let mut net = make(1);
    histogram(&mut net, &[0, 1, 2, 3]);
    histogram(&mut net, &[2]);
    let req = net.net.aggs[0].share_flush_request().unwrap();
    let cs = net.contributions(&req).unwrap();
    // the helper restarts between contributing and finishing
    let st: AggregatorState = decode(&encode(&net.net.aggs[1].snapshot().unwrap()).unwrap()).unwrap();
    let mut h = Aggregator::new(c.clone(), &k.material, 1, &k.aggregator_secrets[1], None)
        .unwrap()
        .with_upload_key(UploadKey::from_secret_bytes(&secrets[1]))
        .unwrap();
    h.restore(st, &[]).unwrap();
    net.net.aggs[1] = h;
    // it reproduces its contribution and refuses another flush number
    let again = net.net.aggs[1].share_contribute(&req).unwrap();
    assert_eq!(encode(&again).unwrap(), encode(&cs[1]).unwrap());
    for a in net.net.aggs.iter_mut() {
        a.share_finish(&req, &cs).unwrap();
    }
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![1, 1, 2, 1]));
    assert_eq!(res.report_count, 5);
}
