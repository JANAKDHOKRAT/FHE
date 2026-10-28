//! Small-cell suppression with the aggregators holding every key share:
//! each released cell below `min_cell_count` is zeroed under encryption
//! (`gate.rs`) before anyone decrypts, the others are exact, invalid
//! reports count nowhere, the counts are withheld, and the attacks a
//! malicious aggregator can mount on the refresh are refused. Keys from one
//! in-process ceremony serve every test (the thresholds do not enter them).
mod common;

use common::{GateStage, Net, serial, task_id};
use fhe_prio3::keys::LocalKeys;
use fhe_prio3::packed::{Codec, Expect};
use fhe_prio3::*;
use openfhe_tbgv_rs::Context;
use std::sync::OnceLock;

fn cfg(t: MeasurementType, k: u64) -> TaskConfig {
    let mut c = TaskConfig::new_silent(task_id(210), t, 2);
    c.silent_batch_groups = 1;
    c.repetitions = 4;
    c.min_batch_size = 2;
    c.min_cell_count = k;
    c
}

fn keys() -> &'static LocalKeys {
    static K: OnceLock<LocalKeys> = OnceLock::new();
    K.get_or_init(|| keys::run_local_key_ceremony(&cfg(MeasurementType::Histogram { length: 6 }, 3)).expect("ceremony"))
}

fn make(t: MeasurementType, k: u64) -> Net {
    Net::from_local_keys(cfg(t, k), keys())
}

fn codec() -> Codec {
    let m = &keys().material;
    let ctx = Context::deserialize(&m.context).unwrap();
    let pk = ctx.deserialize_public_key(&m.public_key).unwrap();
    Codec::new(&ctx, &pk, &m.public_key).unwrap()
}

fn submit(net: &mut Net, m: Measurement) {
    let r = net.client.shard(&m).unwrap();
    net.expect_accept(&r);
}

fn invalid(net: &mut Net, slots: Vec<u64>) {
    let r = net.client.shard_raw_elements(&[slots]).unwrap();
    net.expect_accept(&r);
}

#[test]
fn cells_below_k_are_zero_and_the_others_exact() {
    let _g = serial();
    // k = 3. Bucket 0: k-1 = 2, bucket 1: k = 3, bucket 2: k+1 = 4,
    // bucket 3: 0, bucket 4: 1, bucket 5: 7. Two invalid reports (not
    // one-hot) would push bucket 0 to k and bucket 4 to 2 if counted.
    let mut net = make(MeasurementType::Histogram { length: 6 }, 3);
    for (b, n) in [(0usize, 2usize), (1, 3), (2, 4), (4, 1), (5, 7)] {
        for _ in 0..n {
            submit(&mut net, Measurement::Histogram(b));
        }
    }
    invalid(&mut net, vec![1, 0, 0, 0, 1, 0]);
    invalid(&mut net, vec![2, 0, 0, 0, 0, 0]);
    let started = std::time::Instant::now();
    let r = net.collect_full().unwrap();
    eprintln!("count round + gated release (k 3): {:?}", started.elapsed());
    assert_eq!(r.aggregate, AggregateResult::Histogram(vec![0, 3, 4, 0, 0, 7]));
    assert_eq!(r.suppressed, vec![0, 3, 4]);
    assert!(r.counts_withheld);
    assert_eq!((r.report_count, r.valid_count), (0, 0));
}

#[test]
fn multihot_weight_slots_are_never_released() {
    let _g = serial();
    // MultihotCountVec: the weight's range-check slots sum the reports'
    // weights; released, they would reveal the total of the suppressed
    // cells. Only cell slots carry a nonzero gate factor.
    let t = MeasurementType::MultihotCountVec { length: 4, max_weight: 2 };
    let mut net = make(t, 2);
    for v in [
        [true, true, false, false],
        [true, false, false, false],
        [false, true, false, true],
        [true, false, false, false],
    ] {
        submit(&mut net, Measurement::MultihotCountVec(v.to_vec()));
    }
    let r = net.collect_full().unwrap();
    // counts: [3, 2, 0, 1] with k = 2
    assert_eq!(r.aggregate, AggregateResult::MultihotCountVec(vec![3, 2, 0, 0]));
    assert_eq!(r.suppressed, vec![2, 3]);
}

#[test]
fn a_count_below_k_is_suppressed() {
    let _g = serial();
    let mut net = make(MeasurementType::Count, 4);
    for b in [true, true, true, false, false] {
        submit(&mut net, Measurement::Count(b));
    }
    let r = net.collect_full().unwrap();
    assert_eq!(r.aggregate, AggregateResult::Count(0));
    assert_eq!(r.suppressed, vec![0]);
}

#[test]
fn a_mask_cancelling_another_is_refused() {
    let _g = serial();
    // aggregator 1 replaces its mask by aggregator 0's negation (so that y
    // would reveal x to it). It cannot prove the negation well formed: it
    // does not know aggregator 0's randomness, and the proof it copies is
    // bound to aggregator 0.
    let mut net = make(MeasurementType::Histogram { length: 6 }, 3);
    for b in [0usize, 1, 1, 2] {
        submit(&mut net, Measurement::Histogram(b));
    }
    let codec = codec();
    let ctx = Context::deserialize(&keys().material.context).unwrap();
    let e = net
        .gated_collect_with(|stage| {
            if let GateStage::Contributions(c) = stage {
                let m0 = codec.decode(&c[0].masks[0], Expect::Any).unwrap();
                c[1].masks[0] = codec.encode(&ctx.negate(&m0).unwrap()).unwrap();
                c[1].proofs[0] = c[0].proofs[0].clone();
            }
        })
        .err()
        .unwrap()
        .to_string();
    // refused as not committed; with a matching commitment, the proof fails
    assert!(e.contains("not the one it committed to"), "{e}");
    drop(net); // one deployment in memory at a time (gigabytes of keys)
    let mut net = make(MeasurementType::Histogram { length: 6 }, 3);
    for b in [0usize, 1, 1, 2] {
        submit(&mut net, Measurement::Histogram(b));
    }
    net.count_round().unwrap();
    net.aggs[0].gate_commit().unwrap();
    let theirs = net.aggs[0].gate_state_for_tests().own_contribution.clone().unwrap();
    net.aggs[1].gate_commit().unwrap();
    {
        let own = net.aggs[1].gate_state_for_tests().own_contribution.as_mut().unwrap();
        let m0 = codec.decode(&theirs.masks[0], Expect::Any).unwrap();
        own.masks[0] = codec.encode(&ctx.negate(&m0).unwrap()).unwrap();
        own.proofs[0] = theirs.proofs[0].clone();
    }
    let e = net.gated_collect().err().unwrap().to_string();
    assert!(e.contains("does not verify"), "{e}");
}

#[test]
fn a_shifted_partial_of_y_is_caught() {
    let _g = serial();
    // aggregator 1 shifts its partial decryption of the masked cells by +3
    // so that every small cell would pass the gate
    let mut net = make(MeasurementType::Histogram { length: 6 }, 3);
    for b in [0usize, 1, 1, 2] {
        submit(&mut net, Measurement::Histogram(b));
    }
    let codec = codec();
    let ctx = Context::deserialize(&keys().material.context).unwrap();
    let share1 = {
        let s = keys::AggregatorSecret::decode(&keys().aggregator_secrets[1]).unwrap();
        ctx.deserialize_secret_share(&s.share).unwrap()
    };
    let e = net
        .gated_collect_with(|stage| {
            if let GateStage::Shares(sh, ys) = stage {
                let n = ctx.ring_dim() as usize;
                // aggregator 1 is not the lead: the shift goes into its partial
                let honest = share1.partial_decrypt(&ys[0], false).unwrap();
                let shifted = ctx.add_plain(honest.ciphertext(), &ctx.plaintext(&vec![3u64; n]).unwrap()).unwrap();
                let lead = openfhe_tbgv_rs::PartialDecryption::from_ciphertext(codec.decode(&sh[0].partials[0], Expect::Any).unwrap(), true);
                let before = ctx.fuse(&[&lead, &honest], n).unwrap();
                let after = ctx
                    .fuse(
                        &[&lead, &openfhe_tbgv_rs::PartialDecryption::from_ciphertext(shifted.try_clone().unwrap(), false)],
                        n,
                    )
                    .unwrap();
                let p = ctx.plain_mod();
                assert!((0..n).step_by(101).all(|k| after[k] == (before[k] + 3) % p), "the shift did not take");
                sh[1].partials[0] = codec.encode(&shifted).unwrap();
            }
        })
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("fails in slot"), "{e}");
    assert!(net.aggs[0].gate_state_for_tests().outputs.is_none());
}

#[test]
fn diverging_outputs_and_released_counts_are_refused() {
    let _g = serial();
    // one aggregator releases other outputs than the other (say, ungated)
    let mut net = make(MeasurementType::Histogram { length: 6 }, 3);
    for b in [0usize, 1, 1, 2] {
        submit(&mut net, Measurement::Histogram(b));
    }
    let e = net
        .gated_collect_with(|stage| {
            if let GateStage::Released(r) = stage {
                r[1].accumulators.swap(0, 1);
            }
        })
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("other gated outputs"), "{e}");
    // an aggregator that releases the report count (the subtraction attack's input)
    drop(net); // one deployment in memory at a time (gigabytes of keys)
    let mut net = make(MeasurementType::Histogram { length: 6 }, 3);
    for b in [0usize, 1, 1, 2] {
        submit(&mut net, Measurement::Histogram(b));
    }
    let e = net
        .gated_collect_with(|stage| {
            if let GateStage::Released(r) = stage {
                for s in r.iter_mut() {
                    s.report_count = 4;
                }
            }
        })
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("must be withheld"), "{e}");
}

#[test]
fn the_count_round_still_enforces_the_batch_minimum() {
    let _g = serial();
    // two admitted, one valid, minimum 2: refused before any contribution
    let mut net = make(MeasurementType::Histogram { length: 6 }, 3);
    submit(&mut net, Measurement::Histogram(1));
    invalid(&mut net, vec![1, 1, 0, 0, 0, 0]);
    net.count_round().unwrap();
    let e = net.aggs[0].gate_commit().err().unwrap().to_string();
    assert!(e.contains("1 valid reports, minimum is 2"), "{e}");
    // and the ordinary release path is closed for gated tasks
    drop(net); // one deployment in memory at a time (gigabytes of keys)
    let mut agg_only = make(MeasurementType::Histogram { length: 6 }, 3);
    submit(&mut agg_only, Measurement::Histogram(1));
    submit(&mut agg_only, Measurement::Histogram(1));
    let e = local::release(&mut agg_only.aggs, &agg_only.collector, 0).err().unwrap().to_string();
    assert!(e.contains("gated"), "{e}");
}
