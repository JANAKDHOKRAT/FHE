//! The paper's architecture (`fhe-paper-core`) end to end at the production
//! parameters: the collector's setup, clients, one evaluator, the
//! collector's decryption. Every result is compared with the plaintext.
mod common;

use common::{serial, task_id};
use fhe_paper_core::*;
use fhe_prio3::config::SilentCheck;
use fhe_prio3::*;

const P: u64 = fhe_prio3::config::SILENT_PLAIN_MOD;

struct Run {
    client: PaperClient,
    /// The same encryption, for reports a client can build by hand
    /// (invalid encodings, writes outside its own slots).
    raw: Client,
    evaluator: PaperEvaluator,
    collector: PaperCollector,
    layout_row: usize,
}

fn deploy(task: PaperTask) -> Run {
    let started = std::time::Instant::now();
    let (em, cm, key) = setup(&task).unwrap();
    eprintln!(
        "setup: {:?}, {} rotation keys ({:.2} GiB)",
        started.elapsed(),
        em.rotation_indices.len(),
        em.rotation_key_bytes() as f64 / (1u64 << 30) as f64
    );
    let client = PaperClient::new(&task, &cm).unwrap();
    let raw = Client::new(task.config().clone(), &cm.context, &cm.public_key).unwrap();
    let collector = PaperCollector::new(task.clone(), &cm, &key).unwrap();
    let evaluator = PaperEvaluator::new(task.clone(), &em).unwrap();
    drop(em);
    let layout_row = task.config().layout(fhe_prio3::config::EXACT_ROW).unwrap().row;
    Run {
        client,
        raw,
        evaluator,
        collector,
        layout_row,
    }
}

/// Histogram(3) with the exact check: valid reports counted exactly, every
/// broken encoding and every write outside a report's own slots zeroed;
/// structural refusals; the collector refuses a ciphertext that is not an
/// aggregate.
#[test]
fn histogram_exact_counts_exactly_the_valid_reports() {
    let _g = serial();
    let task = PaperTask::new(task_id(150), MeasurementType::Histogram { length: 3 }, SilentCheck::Exact).unwrap();
    let l = task.config().layout(fhe_prio3::config::EXACT_ROW).unwrap();
    let mut r = deploy(task);
    for (g, b) in [(3u32, 0usize), (9, 1), (17, 1), (40, 2), (41, 1), (4095, 0)] {
        let rep = r.client.report(&Measurement::Histogram(b), g).unwrap();
        r.evaluator.admit(&rep).unwrap();
    }
    for (g, v) in [
        (50u32, vec![1u64, 1, 0]),
        (51, vec![0, 0, 0]),
        (52, vec![2, 0, 0]),
        (53, vec![2, P - 1, 0]),
        (54, vec![P - 1, 1, 1]),
    ] {
        let rep = r.raw.shard_raw_elements_in_group(std::slice::from_ref(&v), g).unwrap();
        r.evaluator.admit(&rep).unwrap();
    }
    // two-hot plus p - 1 where its one-hot residual is formed (class 1),
    // and a valid report that also writes into group 3's bucket 2
    let mut slots = vec![0u64; r.layout_row];
    slots[l.group_slot(60, 0)] = 1;
    slots[l.group_slot(60, 1)] = 1;
    slots[l.group_slot(60, 0) + 1] = P - 1;
    r.evaluator.admit(&r.raw.shard_raw_in_group(std::slice::from_ref(&slots), 60).unwrap()).unwrap();
    let mut slots = vec![0u64; r.layout_row];
    slots[l.group_slot(61, 2)] = 1;
    slots[l.group_slot(3, 2)] = 1;
    r.evaluator.admit(&r.raw.shard_raw_in_group(std::slice::from_ref(&slots), 61).unwrap()).unwrap();
    // structural refusals: another task, a group outside the row, a forged id
    let mut other = r.client.report(&Measurement::Histogram(0), 70).unwrap();
    other.task_id[0] ^= 1;
    assert!(r.evaluator.admit(&other).unwrap_err().to_string().contains("another task"));
    let mut forged = r.client.report(&Measurement::Histogram(0), 70).unwrap();
    forged.report_id[0] ^= 1;
    assert!(r.evaluator.admit(&forged).unwrap_err().to_string().contains("identifier"));
    let mut far = r.client.report(&Measurement::Histogram(0), 70).unwrap();
    far.group = 4096;
    assert!(r.evaluator.admit(&far).is_err());
    assert_eq!(r.evaluator.admitted(), 13);
    let t = std::time::Instant::now();
    let agg = r.evaluator.finish().unwrap();
    eprintln!("exact check and finish, 13 reports in one ciphertext of 4096: {:?}", t.elapsed());
    let t = std::time::Instant::now();
    let res = r.collector.decrypt_aggregate(&agg).unwrap();
    eprintln!("collector decryption: {:?}", t.elapsed());
    assert_eq!(res.aggregate, AggregateResult::Histogram(vec![2, 3, 2]));
    assert_eq!(res.reports, 13);
    // the batch is closed; a client ciphertext is not an aggregate
    assert!(r.evaluator.admit(&r.client.report(&Measurement::Histogram(0), 1).unwrap()).is_err());
    let raw = r.client.report(&Measurement::Histogram(0), 0).unwrap();
    let fake = PaperAggregate {
        output: raw.chunks[0].clone(),
        ..agg.clone()
    };
    assert!(r.collector.decrypt_aggregate(&fake).unwrap_err().to_string().contains("level"));
    let swapped = PaperAggregate { task_id: [0; 32], ..agg };
    assert!(r.collector.decrypt_aggregate(&swapped).is_err());
}

/// Sum(100) with the randomised check: `A_T` runs under encryption, so the
/// decrypted output is the sum alone (every other slot zero: no
/// per-coordinate sums reach the collector); the paper's cancellation pair
/// and other non-bits are zeroed; two reports in one group put them in two
/// verification ciphertexts.
#[test]
fn sum_randomised_decodes_under_encryption() {
    let _g = serial();
    let task = PaperTask::new(task_id(151), MeasurementType::Sum { max_measurement: 100 }, SilentCheck::Randomised).unwrap();
    assert_eq!((task.groups(), task.mult_depth(), task.max_batch()), (512, 28, 7864));
    let mut r = deploy(task);
    let mut want = 0u128;
    for (g, v) in [(0u32, 0u64), (1, 100), (2, 37), (3, 63), (511, 99)] {
        r.evaluator.admit(&r.client.report(&Measurement::Sum(v), g).unwrap()).unwrap();
        want += v as u128;
    }
    r.evaluator.admit(&r.raw.shard_raw_elements_in_group(&[vec![1; 7]], 4).unwrap()).unwrap(); // 1+2+4+8+16+32+37 = 100
    want += 100;
    for (g, v) in [
        (5u32, vec![2u64, 336_449, 0, 0, 0, 0, 0]),
        (6, vec![0, 0, 0, 0, 0, 2, 336_449]),
        (7, vec![1, 1, 1, 1, 1, 1, 2]),
        (8, vec![P - 1, 0, 0, 0, 0, 0, 0]),
    ] {
        r.evaluator
            .admit(&r.raw.shard_raw_elements_in_group(std::slice::from_ref(&v), g).unwrap())
            .unwrap();
    }
    // group 0 again: the first ciphertext is verified, this report opens the second
    r.evaluator.admit(&r.client.report(&Measurement::Sum(42), 0).unwrap()).unwrap();
    want += 42;
    r.evaluator
        .admit(&r.raw.shard_raw_elements_in_group(&[vec![2, 336_449, 0, 0, 0, 0, 0]], 1).unwrap())
        .unwrap();
    assert_eq!(r.evaluator.pending(), 2); // the first ciphertext was verified when group 0 came again
    let res = r.collector.decrypt_aggregate(&r.evaluator.finish().unwrap()).unwrap();
    assert_eq!((res.aggregate, res.reports), (AggregateResult::Sum(want), 12));
}

/// SumVec(10, max 1), the binary-vector workload of the paper's
/// preliminary experiments at L = 10, with the exact check: 16 slots per
/// report, depth 28, 2048 reports per ciphertext.
#[test]
fn binary_vector_exact() {
    let _g = serial();
    let task = PaperTask::new(
        task_id(152),
        MeasurementType::SumVec {
            length: 10,
            max_measurement: 1,
        },
        SilentCheck::Exact,
    )
    .unwrap();
    assert_eq!((task.groups(), task.mult_depth()), (2048, 28));
    let mut r = deploy(task);
    let mut want = vec![0u128; 10];
    for g in 0..6u32 {
        let v: Vec<u64> = (0..10).map(|j| ((g as usize + j) % 2) as u64).collect();
        for (w, &x) in want.iter_mut().zip(&v) {
            *w += x as u128;
        }
        r.evaluator.admit(&r.client.report(&Measurement::SumVec(v), g * 300).unwrap()).unwrap();
    }
    let mut bad = vec![0u64; 10];
    bad[9] = 2;
    r.evaluator
        .admit(&r.raw.shard_raw_elements_in_group(std::slice::from_ref(&bad), 7).unwrap())
        .unwrap();
    let mut pair = vec![1u64; 10];
    pair[3] = 2;
    pair[4] = 336_449;
    r.evaluator
        .admit(&r.raw.shard_raw_elements_in_group(std::slice::from_ref(&pair), 8).unwrap())
        .unwrap();
    let res = r.collector.decrypt_aggregate(&r.evaluator.finish().unwrap()).unwrap();
    assert_eq!((res.aggregate, res.reports), (AggregateResult::SumVec(want), 8));
}
