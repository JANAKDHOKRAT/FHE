mod common;

use common::{Net, serial, task_id};
use fhe_prio3::field::Field;
use fhe_prio3::types::is_valid_plain;
use fhe_prio3::verify::Challenge;
use fhe_prio3::*;

fn cfg(seed: u8, t: MeasurementType, n: usize) -> TaskConfig {
    TaskConfig::new(task_id(seed), t, n)
}

fn check_honest(seed: u8, t: MeasurementType, n: usize, ms: Vec<Measurement>) {
    let cfg = cfg(seed, t.clone(), n);
    let mut net = Net::new(cfg);
    for m in &ms {
        let r = net.client.shard(m).unwrap();
        net.expect_accept(&r);
    }
    let (agg, count) = net.collect().unwrap();
    assert_eq!(count, ms.len() as u64);
    assert_eq!(agg, t.aggregate_plain(&ms).unwrap());
}

#[test]
fn count_two_aggregators() {
    let _g = serial();
    check_honest(
        1,
        MeasurementType::Count,
        2,
        vec![Measurement::Count(true), Measurement::Count(false), Measurement::Count(true)],
    );
}

#[test]
fn sum_two_aggregators() {
    let _g = serial();
    check_honest(
        2,
        MeasurementType::Sum { max_measurement: 100 },
        2,
        vec![Measurement::Sum(51), Measurement::Sum(49), Measurement::Sum(0), Measurement::Sum(100)],
    );
}

#[test]
fn sumvec_two_aggregators() {
    let _g = serial();
    check_honest(
        3,
        MeasurementType::SumVec {
            length: 3,
            max_measurement: 15,
        },
        2,
        vec![Measurement::SumVec(vec![15, 0, 7]), Measurement::SumVec(vec![1, 2, 3])],
    );
}

#[test]
fn histogram_three_aggregators() {
    let _g = serial();
    check_honest(
        4,
        MeasurementType::Histogram { length: 5 },
        3,
        vec![Measurement::Histogram(0), Measurement::Histogram(4), Measurement::Histogram(4)],
    );
}

#[test]
fn multihot_two_aggregators() {
    let _g = serial();
    check_honest(
        5,
        MeasurementType::MultihotCountVec { length: 5, max_weight: 2 },
        2,
        vec![
            Measurement::MultihotCountVec(vec![true, false, false, true, false]),
            Measurement::MultihotCountVec(vec![false, false, false, false, false]),
            Measurement::MultihotCountVec(vec![true, true, false, false, false]),
        ],
    );
}

#[test]
fn large_sumvec_spans_two_chunks() {
    let _g = serial();
    // 1200 * 4 = 4800 slots > 4096-slot blocks with 4 repetitions: 2 chunks.
    let t = MeasurementType::SumVec {
        length: 1200,
        max_measurement: 15,
    };
    let cfg = cfg(6, t.clone(), 2);
    let mut net = Net::new(cfg);
    assert_eq!(net.client.layout().num_chunks, 2);
    let ms = vec![
        Measurement::SumVec((0..1200).map(|i| (i % 16) as u64).collect()),
        Measurement::SumVec((0..1200).map(|i| ((i * 7) % 16) as u64).collect()),
    ];
    for m in &ms {
        net.expect_accept(&net.client.shard(m).unwrap());
    }
    assert_eq!(net.collect().unwrap().0, t.aggregate_plain(&ms).unwrap());
}

/// Finds two non-bit slot values whose bit-check terms cancel modulo p:
/// x(x-1) + y(y-1) == 0 (mod p). This is the vector that bypasses an
/// unrandomised check `sum_i x_i(x_i-1) == 0`.
fn cancellation_pair(p: u64) -> (u64, u64) {
    fn isqrt(n: u128) -> u128 {
        let mut r = (n as f64).sqrt() as u128;
        while r * r > n {
            r -= 1;
        }
        while (r + 1) * (r + 1) <= n {
            r += 1;
        }
        r
    }
    for c in 1u128..=256 {
        let target = c * p as u128;
        let mut x = 2u128;
        while x * (x - 1) < target {
            let want = target - x * (x - 1);
            // y(y-1) == want  <=>  (2y-1)^2 == 4*want + 1
            let d = 4 * want + 1;
            let r = isqrt(d);
            if r * r == d && r % 2 == 1 {
                let y = r.div_ceil(2); // r is odd, so this is (r + 1) / 2
                if y >= 2 {
                    return (x as u64, y as u64);
                }
            }
            x += 1;
        }
    }
    panic!("no cancellation pair found");
}

#[test]
fn malicious_clients_are_rejected() {
    let _g = serial();
    // SumVec with two 1-bit elements: the encoded vector is just two bits and
    // there are no linear constraints, so only the bit check stands in the way.
    let t = MeasurementType::SumVec { length: 2, max_measurement: 1 };
    let cfg = cfg(7, t.clone(), 2);
    let field = Field::new(cfg.plain_mod).unwrap();
    let mut net = Net::new(cfg.clone());

    let (x, y) = cancellation_pair(cfg.plain_mod);
    let sum_of_terms = field.add(field.mul(x, field.sub(x, 1)), field.mul(y, field.sub(y, 1)));
    assert_eq!(sum_of_terms, 0, "the pair must defeat the unrandomised check");
    assert!(!is_valid_plain(&t, &field, &[x, y]));
    net.expect_reject(&net.client.shard_raw(&[vec![x, y]]).unwrap(), RejectReason::ValidityCheckFailed);

    // plain non-bit values
    net.expect_reject(&net.client.shard_raw(&[vec![2, 0]]).unwrap(), RejectReason::ValidityCheckFailed);
    net.expect_reject(&net.client.shard_raw(&[vec![0, cfg.plain_mod - 1]]).unwrap(), RejectReason::ValidityCheckFailed);

    // valid data with garbage in unused slots is accepted and the garbage
    // never reaches the aggregate
    net.expect_accept(&net.client.shard_raw(&[vec![1, 0, 12345, cfg.plain_mod - 7]]).unwrap());
    net.expect_accept(&net.client.shard(&Measurement::SumVec(vec![1, 1])).unwrap());
    assert_eq!(net.collect().unwrap().0, AggregateResult::SumVec(vec![2, 1]));
}

#[test]
fn linear_constraints_are_enforced() {
    let _g = serial();
    // Sum with max 100: 7 range-checked slots, weights 1, 2, 4, 8, 16, 32, 37.
    // Every 0/1 vector is in range, so the only way to claim 101 is a
    // non-bit slot: 2 * 32 + 37.
    let t = MeasurementType::Sum { max_measurement: 100 };
    let mut net = Net::new(cfg(8, t.clone(), 2));
    assert!(t.linear_constraints().is_empty());
    net.expect_reject(&net.client.shard_raw(&[vec![0, 0, 0, 0, 0, 2, 1]]).unwrap(), RejectReason::ValidityCheckFailed);
    // honest 100 and 0 pass
    net.expect_accept(&net.client.shard(&Measurement::Sum(100)).unwrap());
    net.expect_accept(&net.client.shard(&Measurement::Sum(0)).unwrap());
    assert_eq!(net.collect().unwrap().0, AggregateResult::Sum(100));

    let h = MeasurementType::Histogram { length: 4 };
    let mut net = Net::new(cfg(9, h, 2));
    net.expect_reject(&net.client.shard_raw(&[vec![0, 1, 1, 0]]).unwrap(), RejectReason::ValidityCheckFailed);
    net.expect_reject(&net.client.shard_raw(&[vec![0, 0, 0, 0]]).unwrap(), RejectReason::ValidityCheckFailed);
    net.expect_accept(&net.client.shard_raw(&[vec![0, 0, 1, 0]]).unwrap());

    let m = MeasurementType::MultihotCountVec { length: 4, max_weight: 1 };
    let mut net = Net::new(cfg(10, m, 2));
    // weight 2 claimed as 1: [1,1,0,0] with the weight slot (weight 1) set
    net.expect_reject(&net.client.shard_raw(&[vec![1, 1, 0, 0, 1]]).unwrap(), RejectReason::ValidityCheckFailed);
    net.expect_accept(&net.client.shard_raw(&[vec![0, 1, 0, 0, 1]]).unwrap());
}

#[test]
fn structural_rejections_and_replay() {
    let _g = serial();
    let mut net = Net::new(cfg(11, MeasurementType::Count, 2));
    let r = net.client.shard(&Measurement::Count(true)).unwrap();
    net.expect_accept(&r);
    net.expect_reject(&r, RejectReason::Replay);

    let mut wrong_task = r.clone();
    wrong_task.task_id[5] ^= 1;
    net.expect_reject(&wrong_task, RejectReason::WrongTask);

    let mut bad_id = net.client.shard(&Measurement::Count(true)).unwrap();
    bad_id.report_id[0] ^= 1;
    net.expect_reject(&bad_id, RejectReason::ReportIdMismatch);

    // Too many chunks trips the size cap before the chunk-count check ...
    let mut two_chunks = net.client.shard(&Measurement::Count(true)).unwrap();
    two_chunks.chunks.push(two_chunks.chunks[0].clone());
    two_chunks.report_id = Report::compute_id(&two_chunks.task_id, two_chunks.group, &two_chunks.chunks);
    match &net.run_report(&two_chunks)[0] {
        Verdict::Rejected(RejectReason::TooLarge { .. }) => {}
        v => panic!("expected TooLarge, got {v:?}"),
    }
    // ... and too few chunks is a chunk-count rejection.
    let mut no_chunks = net.client.shard(&Measurement::Count(true)).unwrap();
    no_chunks.chunks.clear();
    no_chunks.report_id = Report::compute_id(&no_chunks.task_id, no_chunks.group, &no_chunks.chunks);
    net.expect_reject(&no_chunks, RejectReason::WrongChunkCount { expected: 1, got: 0 });

    let mut garbage = net.client.shard(&Measurement::Count(true)).unwrap();
    garbage.chunks[0].truncate(100);
    garbage.report_id = Report::compute_id(&garbage.task_id, garbage.group, &garbage.chunks);
    match &net.run_report(&garbage)[0] {
        Verdict::Rejected(RejectReason::MalformedCiphertext(_)) => {}
        v => panic!("expected MalformedCiphertext, got {v:?}"),
    }

    // A ciphertext under a different joint key (from a second ceremony).
    let other = Net::new(cfg(12, MeasurementType::Count, 2));
    let mut foreign = other.client.shard(&Measurement::Count(true)).unwrap();
    foreign.task_id = net.cfg.task_id;
    foreign.report_id = Report::compute_id(&foreign.task_id, foreign.group, &foreign.chunks);
    // the packed format's fingerprint binds the joint key
    net.expect_reject(&foreign, RejectReason::WrongParameters);

    assert_eq!(net.collect().unwrap(), (AggregateResult::Count(1), 1));
}

#[test]
fn min_batch_size_is_enforced() {
    let _g = serial();
    let mut c = cfg(13, MeasurementType::Count, 2);
    c.min_batch_size = 2;
    let mut net = Net::new(c);
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    assert!(net.collect().is_err(), "one report is below the minimum batch");
    net.expect_accept(&net.client.shard(&Measurement::Count(false)).unwrap());
    assert_eq!(net.collect().unwrap(), (AggregateResult::Count(1), 2));
}

#[test]
fn collector_needs_every_aggregator_and_agreement() {
    let _g = serial();
    let mut net = Net::new(cfg(14, MeasurementType::Count, 2));
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    let shares: Vec<AggregateShare> = net.aggs.iter_mut().map(|a| a.aggregate_share().unwrap()).collect();
    assert!(net.collector.release_challenge(0, shares[..1].to_vec()).is_err());
    let mut tampered = shares.clone();
    tampered[1].report_count += 1;
    assert!(net.collector.release_challenge(0, tampered).is_err());
    let mut dup = shares.clone();
    dup[1] = dup[0].clone();
    assert!(net.collector.release_challenge(0, dup).is_err());
    // an aggregator claiming other accumulators than the others
    let mut other = shares.clone();
    other[1].accumulators[0] = other[1].accumulators[0].iter().rev().copied().collect();
    assert!(
        net.collector
            .release_challenge(0, other)
            .err()
            .expect("refused")
            .to_string()
            .contains("other accumulators")
    );
    let r = net.finish_release(0, shares).unwrap();
    assert_eq!((r.aggregate, r.report_count, r.valid_count), (AggregateResult::Count(1), 1, 1));
}

#[test]
fn challenge_is_bound_to_report_task_and_verify_key() {
    let c1 = cfg(15, MeasurementType::Histogram { length: 4 }, 2);
    let mut c2 = c1.clone();
    c2.task_id[0] ^= 1;
    let f = Field::new(c1.plain_mod).unwrap();
    let layout = c1.layout(16384).unwrap();
    let k1 = keys::VerifyKey::from_bytes([7u8; 32]);
    let mut other = [7u8; 32];
    other[31] ^= 1;
    let k2 = keys::VerifyKey::from_bytes(other);
    let a = Challenge::derive(&c1, &f, &layout, &k1, &[1u8; 32], 0);
    let b = Challenge::derive(&c1, &f, &layout, &k1, &[1u8; 32], 0);
    let c = Challenge::derive(&c1, &f, &layout, &k1, &[2u8; 32], 0);
    let d = Challenge::derive(&c2, &f, &layout, &k1, &[1u8; 32], 0);
    // one bit of the secret key changes every coefficient: whoever lacks the
    // key (every client) cannot compute the challenge of any report
    let e = Challenge::derive(&c1, &f, &layout, &k2, &[1u8; 32], 0);
    assert_eq!(a.bit_coeffs, b.bit_coeffs);
    assert_ne!(a.bit_coeffs, c.bit_coeffs);
    assert_ne!(a.bit_coeffs, d.bit_coeffs);
    for j in 0..layout.repetitions {
        assert!((0..4).all(|i| a.bit_coeffs[0][j][i] != e.bit_coeffs[0][j][i]), "repetition {j}");
    }
    // coefficients live only in the encoded input positions
    for j in 0..layout.repetitions {
        assert!(a.bit_coeffs[0][j][..4].iter().any(|&v| v != 0));
        assert!(a.bit_coeffs[0][j][4..].iter().all(|&v| v == 0));
        assert!(a.lin_coeffs[0][j][4..].iter().all(|&v| v == 0));
        assert_ne!(a.bit_coeffs[0][j], a.bit_coeffs[0][(j + 1) % layout.repetitions]);
    }
    assert!(c1.soundness_bits() > 127.0);
}

/// A client that places values where a cyclic rotation would bring them
/// into another repetition's block must not be able to cancel its own
/// bit-check terms. If the circuit rotated before applying coefficients,
/// repetition `j` would see `sum_{t=j-k+1}^{j} e[t*block]` (indices modulo
/// the row); with `k` even, the alternating pattern
/// `e[t*block] = (-1)^t * a` makes every such window zero although slot 0
/// holds a non-bit.
#[test]
fn tail_slots_cannot_cancel_the_check() {
    let _g = serial();
    let t = MeasurementType::Count;
    let cfg = cfg(16, t, 2);
    assert_eq!(cfg.repetitions % 2, 0, "this attack pattern needs an even number of repetitions");
    let field = Field::new(cfg.plain_mod).unwrap();
    let mut net = Net::new(cfg.clone());
    let layout = net.client.layout().clone();
    let (x, y) = cancellation_pair(cfg.plain_mod); // term(x) + term(y) == 0
    let k = layout.repetitions as i64;
    let mut slots = vec![0u64; layout.row];
    for tt in -(k - 1)..=(k - 1) {
        let pos = (tt * layout.block as i64).rem_euclid(layout.row as i64) as usize;
        slots[pos] = if tt.rem_euclid(2) == 0 { x } else { y };
    }
    assert_eq!(slots[0], x);
    assert_eq!(field.add(field.mul(x, field.sub(x, 1)), field.mul(y, field.sub(y, 1))), 0);
    net.expect_reject(&net.client.shard_raw(&[slots]).unwrap(), RejectReason::ValidityCheckFailed);
    // and an honest report still passes afterwards
    net.expect_accept(&net.client.shard(&Measurement::Count(true)).unwrap());
    assert_eq!(net.collect().unwrap(), (AggregateResult::Count(1), 1));
}

/// The verify key is part of what makes the aggregators agree: an
/// aggregator holding another key computes another check for the same
/// report, and the joint decryption of the check is then not zero, so even
/// valid reports are refused. (The ceremony stops a party that splits the
/// key; this shows the key is really in the computation.)
#[test]
fn aggregators_with_different_verify_keys_accept_nothing() {
    let _g = serial();
    let c = cfg(16, MeasurementType::Histogram { length: 4 }, 2);
    let (material, secrets) = keys::run_local_ceremony(&c).unwrap();
    let mut split = keys::AggregatorSecret::decode(&secrets[1]).unwrap();
    split.verify_key = keys::VerifyKey::random();
    let mut net = Net::with_keys(c.clone(), material, &[secrets[0].clone(), split.encode()], None);
    let report = net.client.shard(&Measurement::Histogram(2)).unwrap();
    for v in net.run_report(&report) {
        assert_eq!(v, Verdict::Rejected(RejectReason::ValidityCheckFailed));
    }
    // the same report under agreeing keys is accepted
    let mut net = Net::new(c);
    net.expect_accept(&net.client.shard(&Measurement::Histogram(2)).unwrap());
}
