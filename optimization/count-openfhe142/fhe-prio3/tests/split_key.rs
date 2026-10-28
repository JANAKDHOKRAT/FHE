//! One aggregator and the collector holding the two key shares
//! (`KeyTopology::AggregatorAndCollector`): the batch size is gated under
//! encryption (`gate.rs`), the collector is the only party that fuses a
//! decryption of data, and the aggregator only ever sees values masked by
//! the collector. Every test runs the real protocol on keys from one
//! in-process ceremony (the thresholds do not enter the keys).
mod common;

use common::{GateStage, Net, serial, task_id};
use fhe_prio3::keys::{AggregatorSecret, CollectorSecret, LocalKeys};
use fhe_prio3::packed::Expect;
use fhe_prio3::*;
use openfhe_tbgv_rs::{Ciphertext, Context, PartialDecryption, SecretShare};
use std::sync::OnceLock;

fn cfg(t: MeasurementType, min_batch: usize) -> TaskConfig {
    let mut c = TaskConfig::new_split_key(task_id(200), t);
    // one report per verification ciphertext keeps the key set small
    c.silent_batch_groups = 1;
    c.repetitions = 4;
    c.min_batch_size = min_batch;
    c
}

fn keys() -> &'static LocalKeys {
    static K: OnceLock<LocalKeys> = OnceLock::new();
    K.get_or_init(|| keys::run_local_key_ceremony(&cfg(MeasurementType::Histogram { length: 5 }, 1)).expect("ceremony"))
}

fn make(t: MeasurementType, min_batch: usize, min_cell: u64) -> Net {
    let mut c = cfg(t, min_batch);
    c.min_cell_count = min_cell;
    Net::from_local_keys(c, keys())
}

/// The two key shares, for tests that check what each alone can decrypt.
fn shares(ctx: &Context) -> (SecretShare, SecretShare) {
    let k = keys();
    let a = AggregatorSecret::decode(&k.aggregator_secrets[0]).unwrap();
    let c = CollectorSecret::decode(k.collector_secret.as_ref().unwrap()).unwrap();
    (ctx.deserialize_secret_share(&a.share).unwrap(), ctx.deserialize_secret_share(&c.share).unwrap())
}

fn joint(ctx: &Context, s: &(SecretShare, SecretShare), ct: &Ciphertext) -> Vec<u64> {
    let a = s.0.partial_decrypt(ct, true).unwrap();
    let b = s.1.partial_decrypt(ct, false).unwrap();
    ctx.fuse(&[&a, &b], ctx.ring_dim() as usize).unwrap()
}

fn histogram(net: &mut Net, buckets: &[usize]) {
    for &b in buckets {
        let r = net.client.shard(&Measurement::Histogram(b)).unwrap();
        net.expect_accept(&r);
    }
}

/// A report that is not one-hot: admitted, verified invalid under
/// encryption, and silently left out of every sum and of the count.
fn invalid(net: &mut Net, ones: &[usize], len: usize) {
    let mut v = vec![0u64; len];
    for &i in ones {
        v[i] = 1;
    }
    let r = net.client.shard_raw_elements(&[v]).unwrap();
    net.expect_accept(&r);
}

fn fraction_equal(a: &[u64], b: &[u64]) -> f64 {
    a.iter().zip(b).filter(|(x, y)| x == y).count() as f64 / a.len() as f64
}

#[test]
fn aggregate_is_exact_over_valid_reports() {
    let _g = serial();
    let mut net = make(MeasurementType::Histogram { length: 5 }, 3, 0);
    histogram(&mut net, &[0, 2, 2, 4]);
    invalid(&mut net, &[1, 3], 5);
    invalid(&mut net, &[], 5);
    let started = std::time::Instant::now();
    let r = net.collect_full().unwrap();
    eprintln!("gated release (min 3): {:?}", started.elapsed());
    assert_eq!(r.aggregate, AggregateResult::Histogram(vec![1, 0, 2, 0, 1]));
    assert_eq!((r.report_count, r.valid_count, r.counts_withheld), (6, 4, false));
    assert!(r.suppressed.is_empty());
}

#[test]
fn batch_below_the_minimum_is_refused() {
    let _g = serial();
    // three admitted reports, two valid: the gate is zero, the collector
    // learns only that the batch is too small
    let mut net = make(MeasurementType::Histogram { length: 5 }, 3, 0);
    histogram(&mut net, &[1, 1]);
    invalid(&mut net, &[0, 4], 5);
    let e = net.collect_full().err().unwrap().to_string();
    assert!(e.contains("batch below minimum size"), "{e}");
    // the decrypted gated values were all zero: nothing about the two
    // valid reports reached the collector (checked inside ungate: a gated
    // value nonzero where its gate is zero is refused as inconsistent)

    // fewer admitted reports than the minimum: the aggregator does not start
    drop(net); // one deployment in memory at a time (gigabytes of keys)
    let mut net2 = make(MeasurementType::Histogram { length: 5 }, 3, 0);
    histogram(&mut net2, &[1, 2]);
    let e = net2.aggs[0].gate_commit().err().unwrap().to_string();
    assert!(e.contains("minimum is 3"), "{e}");
    // and there is no count round to ask for instead
    assert!(net2.aggs[0].count_share().err().unwrap().to_string().contains("no count round"));
}

#[test]
fn each_share_alone_decrypts_only_noise() {
    let _g = serial();
    let mut net = make(MeasurementType::Histogram { length: 5 }, 1, 0);
    let ctx = Context::deserialize(&net.material.context).unwrap();
    let s = shares(&ctx);
    let n = ctx.ring_dim() as usize;
    let report = net.client.shard(&Measurement::Histogram(3)).unwrap();
    let ct = net.client.codec().decode(&report.chunks[0], fhe_prio3::packed::Expect::Any).unwrap();
    let truth = joint(&ctx, &s, &ct);
    assert_eq!(truth[net.client.layout().client_slot(3)], 1);
    for (who, share) in [("aggregator", &s.0), ("collector", &s.1)] {
        let alone = share.decrypt_alone_for_tests(&ct, n).unwrap();
        let eq = fraction_equal(&alone, &truth);
        assert!(eq < 0.01, "{who}'s share alone agrees with the plaintext in {:.1}% of the slots", 100.0 * eq);
    }
    // what each party learns in the refresh: y = x + both masks, uniform
    // to each (the test, holding both shares, can compute x)
    net.expect_accept(&report);
    let r = net.collect_full().unwrap();
    assert_eq!(r.aggregate, AggregateResult::Histogram(vec![0, 0, 0, 1, 0]));
    let xs = net.aggs[0].gate_values_for_tests().unwrap();
    let ys = net.aggs[0].gate_state_for_tests().y.clone().unwrap();
    let collector_ys = net.collector.gate_state().y.clone().unwrap();
    assert_eq!(ys, collector_ys, "both parties learned the same y");
    for (x, y) in xs.iter().zip(&ys) {
        let x = joint(&ctx, &s, x);
        let eq = fraction_equal(&x, y);
        assert!(eq < 0.01, "y agrees with x in {:.1}% of the slots", 100.0 * eq);
    }
}

#[test]
fn a_raw_report_sent_to_be_refreshed_comes_back_masked() {
    let _g = serial();
    // a malicious aggregator asks the collector to refresh a client's raw
    // report instead of its accumulators
    let mut net = make(MeasurementType::Histogram { length: 5 }, 1, 0);
    let ctx = Context::deserialize(&net.material.context).unwrap();
    let s = shares(&ctx);
    let victim = net.client.shard(&Measurement::Histogram(2)).unwrap();
    net.expect_accept(&victim);
    let raw = net.client.codec().decode(&victim.chunks[0], fhe_prio3::packed::Expect::Any).unwrap();
    let truth = joint(&ctx, &s, &raw);
    let k = net.aggs[0].gate_values_for_tests().unwrap().len();
    let xs: Vec<Ciphertext> = (0..k).map(|_| raw.try_clone().unwrap()).collect();
    net.aggs[0].gate_commit_substituted_for_tests(&xs).unwrap();
    let mut agg_masks: Vec<Ciphertext> = Vec::new();
    let _ = net.gated_collect_with(|stage| {
        if let GateStage::Contributions(c) = stage {
            let codec = net_codec();
            for m in &c[0].masks {
                let ct = codec.decode(m, fhe_prio3::packed::Expect::Any).unwrap();
                agg_masks.push(ctx.add(&ct, &ct).unwrap()); // effective 2C
            }
        }
    });
    // everything the aggregator learned: y = report + its mask + the
    // collector's mask. Remove its own mask: still uniform.
    let ys = net.aggs[0].gate_state_for_tests().y.clone().expect("the refresh ran");
    let p = ctx.plain_mod();
    for (y, m) in ys.iter().zip(&agg_masks) {
        let m = joint(&ctx, &s, m);
        let seen: Vec<u64> = y.iter().zip(&m).map(|(&a, &b)| (a + p - b) % p).collect();
        let eq = fraction_equal(&seen, &truth);
        assert!(eq < 0.01, "the aggregator recovers {:.1}% of the report's slots", 100.0 * eq);
    }

    // accumulators other than those committed to are refused before the
    // collector decrypts anything
    drop(net); // one deployment in memory at a time (gigabytes of keys)
    let mut net = net_fresh_with(&[1]);
    let honest = net.aggs[0].gate_values_for_tests().unwrap();
    let e = net
        .gated_collect_with(|stage| {
            if let GateStage::Contributions(c) = stage {
                let codec = net_codec();
                c[0].accumulators[0] = codec.encode(&raw_like(&honest[0])).unwrap();
            }
        })
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("not the one it committed to"), "{e}");
}

/// The packed codec of the task (same parameters for every net here).
fn net_codec() -> fhe_prio3::packed::Codec {
    let m = &keys().material;
    let ctx = Context::deserialize(&m.context).unwrap();
    let pk = ctx.deserialize_public_key(&m.public_key).unwrap();
    fhe_prio3::packed::Codec::new(&ctx, &pk, &m.public_key).unwrap()
}

fn raw_like(c: &Ciphertext) -> Ciphertext {
    let m = &keys().material;
    let ctx = Context::deserialize(&m.context).unwrap();
    ctx.add(c, c).unwrap()
}

fn net_fresh_with(buckets: &[usize]) -> Net {
    let mut n = make(MeasurementType::Histogram { length: 5 }, 1, 0);
    histogram(&mut n, buckets);
    n
}

#[test]
fn a_shifted_partial_of_the_count_is_caught() {
    let _g = serial();
    // a malicious collector shifts its partial decryption of the masked
    // count by +2 in every slot, so that a batch of one valid report would
    // pass a gate of minimum 3: the aggregator's checks catch it and
    // nothing is gated or released
    let mut net = make(MeasurementType::Histogram { length: 5 }, 3, 0);
    histogram(&mut net, &[0]);
    invalid(&mut net, &[1, 2], 5);
    invalid(&mut net, &[3, 4], 5);
    let ctx = Context::deserialize(&net.material.context).unwrap();
    let s = shares(&ctx);
    let codec = net_codec();
    let r = net.gated_collect_with(|stage| {
        if let GateStage::Shares(sh, ys) = stage {
            let i = ys.len() - 1; // the spread count is refreshed after the chunks
            let n = ctx.ring_dim() as usize;
            // the collector is not the lead party: its partial is c1 * s_c
            // plus flooding, so the shift goes into the partial itself
            let honest: PartialDecryption = s.1.partial_decrypt(&ys[i], false).unwrap();
            let shifted = ctx.add_plain(honest.ciphertext(), &ctx.plaintext(&vec![2u64; n]).unwrap()).unwrap();
            let agg = PartialDecryption::from_ciphertext(codec.decode(&sh[0].partials[i], Expect::Any).unwrap(), true);
            let before = ctx.fuse(&[&agg, &honest], n).unwrap();
            let after = ctx
                .fuse(&[&agg, &PartialDecryption::from_ciphertext(shifted.try_clone().unwrap(), false)], n)
                .unwrap();
            let p = ctx.plain_mod();
            // the attack is real: the fused count moves by +2 at every slot
            assert!((0..n).step_by(101).all(|k| after[k] == (before[k] + 2) % p), "the shift did not take");
            sh[1].partials[i] = codec.encode(&shifted).unwrap();
        }
    });
    let e = r.err().unwrap().to_string();
    assert!(e.contains("fails in slot"), "{e}");
    assert!(net.aggs[0].gate_state_for_tests().outputs.is_none(), "nothing was gated or released");
}

#[test]
fn malformed_or_replayed_contributions_are_refused() {
    let _g = serial();
    let codec = net_codec();
    let ctx = Context::deserialize(&keys().material.context).unwrap();
    // the collector sends a mask with inflated noise (it would read the
    // release's noise above the aggregator's flooding): no proof verifies
    let mut net = net_fresh_with(&[1]);
    let e = net
        .gated_collect_with(|stage| {
            if let GateStage::Contributions(c) = stage {
                let m = codec.decode(&c[1].masks[0], fhe_prio3::packed::Expect::Any).unwrap();
                c[1].masks[0] = codec.encode(&ctx.add_noise_for_tests(&m, 80, 1).unwrap()).unwrap();
            }
        })
        .err()
        .unwrap()
        .to_string();
    // the tampered contribution no longer matches the commitment
    assert!(e.contains("not the one it committed to"), "{e}");

    // the same, with the commitment changed to match: the proof fails
    drop(net); // one deployment in memory at a time (gigabytes of keys)
    let mut net = net_fresh_with(&[1]);
    let tampered: Option<[u8; 32]>;
    {
        let agg_commit = net.aggs[0].gate_commit().unwrap();
        net.collector.gate_commit(&agg_commit).unwrap();
        let st = net.collector.gate_state_for_tests();
        let own = st.own_contribution.as_mut().unwrap();
        let m = codec.decode(&own.masks[0], fhe_prio3::packed::Expect::Any).unwrap();
        own.masks[0] = codec.encode(&ctx.add_noise_for_tests(&m, 80, 2).unwrap()).unwrap();
        tampered = Some(own.digest());
    }
    let digest = tampered.unwrap();
    let e = net
        .gated_collect_with(|stage| {
            if let GateStage::Commits(c) = stage {
                c[1].digest = digest;
            }
        })
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("wfe") && e.contains("does not verify"), "{e}");

    // the collector replays the aggregator's mask and proof as its own (to
    // cancel it): the proof is bound to the aggregator's party index
    drop(net); // one deployment in memory at a time (gigabytes of keys)
    let mut net = net_fresh_with(&[1]);
    let e = net
        .gated_collect_with(|stage| {
            if let GateStage::Contributions(c) = stage {
                let agg = c[0].clone();
                c[1].masks[0] = agg.masks[0].clone();
                c[1].proofs[0] = agg.proofs[0].clone();
            }
        })
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("not the one it committed to") || e.contains("does not verify"), "{e}");
}

#[test]
fn small_cells_are_suppressed_with_the_split_key() {
    let _g = serial();
    // k = 3: bucket 0 holds 2 (k-1), bucket 1 holds 3 (k), bucket 2 holds 4
    // (k+1), bucket 3 none, bucket 4 one; invalid reports mixed in
    let mut net = make(MeasurementType::Histogram { length: 5 }, 2, 3);
    histogram(&mut net, &[0, 1, 2, 1, 2, 0, 2, 1, 4, 2]);
    invalid(&mut net, &[0, 1], 5);
    invalid(&mut net, &[3, 3], 5);
    let started = std::time::Instant::now();
    let r = net.collect_full().unwrap();
    eprintln!("gated release (min 2, k 3): {:?}", started.elapsed());
    assert_eq!(r.aggregate, AggregateResult::Histogram(vec![0, 3, 4, 0, 0]));
    assert_eq!(r.suppressed, vec![0, 3, 4]);
    assert!(r.counts_withheld);
    assert_eq!((r.report_count, r.valid_count), (0, 0));
}
