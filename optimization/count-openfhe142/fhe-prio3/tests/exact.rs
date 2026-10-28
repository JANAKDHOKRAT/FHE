//! The exact silent check (`SilentCheck::Exact`, Eq. 9 of the paper) end to
//! end at the production parameters: real keys from the in-process
//! ceremony, reports from the client, the aggregator's per-report group
//! mask, the shared Fermat chain over a batch of thousands of groups, and
//! the verified (or gated) release. Every result is compared with the
//! plaintext predicate.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::keys::AggregatorSecret;
use fhe_prio3::verify::Circuit;
use fhe_prio3::*;
use openfhe_tbgv_rs::SecretShare;

const P: u64 = fhe_prio3::config::SILENT_PLAIN_MOD;

/// Raw slots of one report in `group`: `elems` at its element slots and
/// `extra` written anywhere else in the row.
fn raw(net: &Net, group: usize, elems: &[u64], extra: &[(usize, u64)]) -> Report {
    let l = net.client.layout().clone();
    let mut slots = vec![0u64; l.row];
    for (i, &v) in elems.iter().enumerate() {
        slots[l.group_slot(group, i)] = v;
    }
    for &(s, v) in extra {
        slots[s] = v;
    }
    net.client.shard_raw_in_group(&[slots], group as u32).unwrap()
}

/// Histogram(3), the paper's EDSS severity classes, on the split key with
/// small-cell suppression: valid reports counted exactly; every way of
/// breaking the encoding zeroed under encryption, including values written
/// into the slots where the one-hot residual is formed and into another
/// report's group. Nothing per report is decrypted.
#[test]
fn split_key_histogram_counts_exactly_the_valid_reports() {
    let _g = serial();
    let t = MeasurementType::Histogram { length: 3 };
    let mut cfg = TaskConfig::new_exact(task_id(140), t.clone(), 1);
    cfg.num_aggregators = 1;
    cfg.key_topology = KeyTopology::AggregatorAndCollector;
    cfg.min_batch_size = 3;
    cfg.min_cell_count = 2;
    cfg.validate().unwrap();
    assert_eq!((cfg.silent_batch_groups, cfg.mult_depth()), (4096, 27));
    let mut net = Net::new(cfg);
    let l = net.client.layout().clone();
    assert_eq!((l.classes, l.block, l.groups), (2, 4, 4096));
    let mut group = 0usize;
    let mut next = || {
        group += 7; // scattered over the row
        group
    };
    // valid: bucket 0 twice, bucket 1 three times, bucket 2 once
    for b in [0usize, 0, 1, 1, 1, 2] {
        let r = net.client.shard_in_group(&Measurement::Histogram(b), next() as u32).unwrap();
        net.expect_accept(&r);
    }
    // invalid encodings: admitted, then zeroed by the check
    let bad: Vec<Vec<u64>> = vec![
        vec![1, 1, 0],     // two-hot: bits fine, one-hot residual 1
        vec![0, 0, 0],     // zero-hot: one-hot residual -1
        vec![2, 0, 0],     // a non-bit, and the sum is 2
        vec![2, P - 1, 0], // the sum is 1 modulo p; bit residuals 2 and 2
        vec![P - 1, 1, 1], // the sum is 1 modulo p; one non-bit
    ];
    for v in &bad {
        let g = next();
        let r = raw(&net, g, v, &[]);
        net.expect_accept(&r);
    }
    // two-hot, plus p - 1 written where the one-hot residual of its group
    // is formed (class 1): the group mask removes it before the check
    let g = next();
    let r = raw(&net, g, &[1, 1, 0], &[(l.group_slot(g, 0) + 1, P - 1), (l.group_slot(g, 3) + 1, P - 1)]);
    net.expect_accept(&r);
    // a valid bucket-0 report that also writes a 1 into bucket 2 of another
    // report's group and into its own padding position: only its own
    // bucket counts
    let g = next();
    let r = raw(&net, g, &[1, 0, 0], &[(l.group_slot(7, 2), 1), (l.group_slot(g, 3), 1)]);
    net.expect_accept(&r);
    let started = std::time::Instant::now();
    let res = net.collect_full().unwrap();
    eprintln!("exact check, 13 reports in one batch of 4096 groups, gated release: {:?}", started.elapsed());
    // counts [3, 3, 1]: bucket 2 is below 2 and suppressed
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![3, 3, 0]));
    assert_eq!(res.suppressed, vec![2]);
    assert!(res.counts_withheld);
}

/// Sum(100) with two aggregators: the cancellation pair of the paper (bit
/// coordinates 2 and 336449, residuals 2 and -2, which an unweighted sum
/// of residuals accepts) is zeroed, and so is every other non-bit, while
/// any pattern of bits is admissible and counted. Two reports in one group
/// put them in two verification batches.
#[test]
fn sum_rejects_the_cancellation_pair() {
    let _g = serial();
    assert_eq!((2u128 + 336_449u128 * 336_448) % P as u128, 0, "the residuals cancel modulo p");
    let mut net = Net::new(TaskConfig::new_exact(task_id(141), MeasurementType::Sum { max_measurement: 100 }, 2));
    let l = net.client.layout().clone();
    assert_eq!((l.classes, l.block, l.groups), (1, 8, 4096));
    let mut expected = 0u64;
    for (g, v) in [(0usize, 0u64), (1, 100), (2, 37), (3, 63), (4, 99)] {
        let r = net.client.shard_in_group(&Measurement::Sum(v), g as u32).unwrap();
        net.expect_accept(&r);
        expected += v;
    }
    // all seven bits set: weights 1+2+4+8+16+32+37 = 100, admissible
    let r = raw(&net, 5, &[1; 7], &[]);
    net.expect_accept(&r);
    expected += 100;
    for (g, v) in [
        (6usize, vec![2, 336_449, 0, 0, 0, 0, 0]),
        (7, vec![0, 0, 0, 2, 336_449, 0, 0]),
        (8, vec![1, 1, 1, 1, 1, 1, 2]),
        (9, vec![0, 0, 0, 0, 0, 0, P - 1]),
        (10, vec![123_456, 0, 0, 0, 0, 0, 0]),
    ] {
        let r = raw(&net, g, &v, &[]);
        net.expect_accept(&r);
    }
    // group 0 again: the first batch runs, this report opens the second
    let r = net.client.shard_in_group(&Measurement::Sum(42), 0).unwrap();
    net.expect_accept(&r);
    expected += 42;
    let r = raw(&net, 1, &[2, 336_449, 0, 0, 0, 0, 0], &[]);
    net.expect_accept(&r);
    let (agg, valid) = net.collect().unwrap();
    assert_eq!((agg, valid), (AggregateResult::Sum(expected as u128), 7));
}

/// `2^-k mod p`.
fn inverse_of_power_of_two(k: u32) -> u64 {
    let (mut base, mut e, mut acc) = (2u128, (P - 1 - k as u64) as u128, 1u128);
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * base % P as u128;
        }
        base = base * base % P as u128;
        e >>= 1;
    }
    acc as u64
}

/// Histogram(8) at depth 28 with all 2048 groups of a verification
/// ciphertext in use. As in `batch_noise.rs`, one ciphertext carrying every
/// group's report is masked as the aggregator masks a report and doubled
/// 14 times, which bounds the noise of 2^14 masked fresh reports from
/// above (a batch here has 2^11). The batch runs through the real count
/// round and verified release, and the decryption points are decrypted
/// directly with both key shares to measure the noise margin left at the
/// bottom of the chain.
#[test]
fn full_batch_at_depth_28_is_exact_with_margin() {
    let _g = serial();
    const DOUBLINGS: u32 = 14;
    let t = MeasurementType::Histogram { length: 8 };
    let cfg = TaskConfig::new_exact(task_id(142), t.clone(), 2);
    assert_eq!((cfg.silent_batch_groups, cfg.mult_depth(), cfg.key_switch_digits()), (2048, 28, 5));
    let k = keys::run_local_key_ceremony(&cfg).unwrap();
    let ctx = keys::make_context(&cfg).unwrap();
    let _lease = keys::install(&ctx, &k.material).unwrap();
    let shares: Vec<SecretShare> = k
        .aggregator_secrets
        .iter()
        .map(|s| ctx.deserialize_secret_share(&AggregatorSecret::decode(s).unwrap().share).unwrap())
        .collect();
    let mut net = Net::from_local_keys(cfg.clone(), &k);
    let l = net.aggs[0].layout().clone();
    assert_eq!((l.classes, l.block, l.groups, ctx.ring_dim()), (2, 8, 2048, 65536));
    let pk = ctx.deserialize_public_key(&net.material.public_key).unwrap();
    let inv = inverse_of_power_of_two(DOUBLINGS);
    let scaled = |v: u64| (v as u128 * inv as u128 % P as u128) as u64;
    // group r: bucket r % 8, except three broken groups
    let mut want = vec![0u64; 8];
    let mut valid = vec![true; l.groups];
    let mut slots = vec![0u64; l.row];
    for r in 0..l.groups {
        let mut x = [0u64; 8];
        match r {
            5 => x[1] = 2,
            700 => {
                x[2] = 1;
                x[6] = 1;
            }
            2047 => {}
            _ => x[r % 8] = 1,
        }
        valid[r] = x.iter().all(|&v| v <= 1) && x.iter().sum::<u64>() == 1;
        if valid[r] {
            want[r % 8] += 1;
        }
        for (i, &v) in x.iter().enumerate() {
            slots[l.group_slot(r, i)] = scaled(v);
        }
    }
    let n_valid = valid.iter().filter(|&&v| v).count() as u64;
    assert_eq!(n_valid, 2045);
    let fresh = ctx.encrypt(&pk, &ctx.plaintext(&slots).unwrap()).unwrap();
    let mut mask = vec![0u64; l.row];
    for r in 0..l.groups {
        for i in 0..8 {
            mask[l.group_slot(r, i)] = 1;
        }
    }
    let mut x = ctx.mult_plain(&fresh, &ctx.plaintext(&mask).unwrap()).unwrap();
    for _ in 0..DOUBLINGS {
        x = ctx.add(&x, &x).unwrap();
    }

    // the decryption points, computed as the aggregator computes them, and
    // decrypted without flooding to read the noise
    let groups: Vec<usize> = (0..l.groups).collect();
    let circuit = Circuit::new(&ctx, &l).unwrap();
    let started = std::time::Instant::now();
    let g = circuit.exact_validity(&cfg, &cfg.field(), std::slice::from_ref(&x), &groups).unwrap();
    eprintln!("exact check over 2048 groups (residuals, Fermat, product): {:?}", started.elapsed());
    let sum = circuit.finalize_chunk(&ctx.mult(&x, &g).unwrap(), 0).unwrap();
    let count = circuit.finalize_count(&circuit.count_of_groups(&g, &groups).unwrap()).unwrap();
    let refs: Vec<&SecretShare> = shares.iter().collect();
    for (what, ct, expect) in [("sum", &sum, want.clone()), ("count", &count, vec![n_valid])] {
        let (_, noise, logq) = ctx.raw_decrypt_for_tests(ct, &refs).unwrap();
        let margin = logq - 1.0 - noise;
        eprintln!("{what}: log2 |m + t e| = {noise:.1}, log2 Q = {logq:.1}, margin {margin:.1} bits");
        assert!(margin > 10.0, "{what}: only {margin:.1} bits below Q/2");
        let a = shares[0].partial_decrypt(ct, true).unwrap();
        let b = shares[1].partial_decrypt(ct, false).unwrap();
        let fused = ctx.fuse(&[&a, &b], l.row).unwrap();
        for (i, &e) in expect.iter().enumerate() {
            assert_eq!(fused[l.group_slot(0, i)], e, "{what} slot {i}");
        }
        // every slot outside group 0's element slots is zero after the fold mask
        let read: Vec<usize> = (0..expect.len()).map(|i| l.group_slot(0, i)).collect();
        assert!(
            fused.iter().enumerate().all(|(s, &v)| read.contains(&s) || v == 0),
            "{what}: data outside group 0"
        );
    }
    drop(circuit);

    // the same batch through the protocol: the aggregators' own circuit,
    // count round and verified release with their flooding checks
    let zero = ctx.encrypt(&pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
    let id = |r: usize| {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&(r as u64).to_le_bytes());
        b[31] = 0xE1;
        b
    };
    for agg in net.aggs.iter_mut() {
        agg.accumulate_silent_for_tests(0, id(0), vec![x.try_clone().unwrap()]).unwrap();
        for r in 1..l.groups {
            agg.accumulate_silent_for_tests(r, id(r), vec![zero.try_clone().unwrap()]).unwrap();
        }
    }
    let res = net.collect_full().unwrap();
    assert_eq!(
        (res.aggregate, res.report_count, res.valid_count),
        (AggregateResult::Histogram(want), l.groups as u64, n_valid)
    );
}

/// A task whose collector policies cut the measurement into two chunks:
/// each chunk's bit residuals take their own class, and the check must see
/// both (a non-bit in either chunk zeroes the whole report, in both
/// collectors' results).
#[test]
fn two_chunks_are_checked_together() {
    let _g = serial();
    let t = MeasurementType::SumVec { length: 2, max_measurement: 3 };
    let keys: Vec<CollectorSealKey> = (0..2).map(|_| CollectorSealKey::generate()).collect();
    let mut cfg = TaskConfig::new_exact(task_id(143), t.clone(), 2);
    cfg.collectors = (0..2)
        .map(|e| CollectorPolicy {
            elements: vec![e],
            moments: false,
            seal_key: keys[e].public_key(),
        })
        .collect();
    let (chunks, classes, block) = cfg.exact_shape();
    assert_eq!((chunks, classes, block), (2, 2, 2));
    cfg.silent_batch_groups = fhe_prio3::config::EXACT_ROW / (classes * block);
    cfg.validate().unwrap();
    let mut net = Net::new(cfg);
    let l = net.client.layout().clone();
    assert_eq!((l.num_chunks, l.groups), (2, 8192));
    for (g, v) in [(0u32, vec![3u64, 1]), (1, vec![2, 2]), (2, vec![0, 3])] {
        let r = net.client.shard_in_group(&Measurement::SumVec(v), g).unwrap();
        net.expect_accept(&r);
    }
    // a non-bit in the second chunk only, and in the first chunk only
    for (g, c0, c1) in [(3usize, vec![1u64, 1], vec![2u64, 0]), (4, vec![0, 336_449], vec![1, 0])] {
        let mut s0 = vec![0u64; l.row];
        let mut s1 = vec![0u64; l.row];
        for i in 0..2 {
            s0[l.group_slot(g, i)] = c0[i];
            s1[l.group_slot(g, i)] = c1[i];
        }
        let r = net.client.shard_raw_in_group(&[s0, s1], g as u32).unwrap();
        net.expect_accept(&r);
    }
    let r0 = net.collect_sealed_for(0, &keys[0]).unwrap();
    assert_eq!((r0.aggregate, r0.valid_count), (AggregateResult::SumVec(vec![5, 0]), 3));
    let r1 = net.collect_sealed_for(1, &keys[1]).unwrap();
    assert_eq!((r1.aggregate, r1.valid_count), (AggregateResult::SumVec(vec![0, 6]), 3));
}
