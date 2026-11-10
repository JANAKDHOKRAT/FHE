//! PINE in the one-aggregator protocol end to end in one process: sizes
//! and times, one JSON line.
//!
//!   measure_pine --dimension D [--bound B] [--frac-bits F] [--chunk C]
//!                [--chunk-norm-equality C1] [--proofs K]
//!                [--proofs-norm-equality K1] [--reports R]
//!
//! Defaults: the reference's Pine32 proof counts (5 and 1), norm bound 1.0
//! with 15 fractional bits (`--bound 32768 --frac-bits 15`), 4 reports.
//! The gradients are pseudorandom with norm below the bound; the decoded
//! sum is compared with the exact sum of the encoded gradients.
use fhe_flp::pine::{PineClient, PineCollector, PineEvaluator, PineParams, PineTask};
use std::time::{Duration, Instant};

fn arg(args: &[String], name: &str, default: usize) -> usize {
    args.iter().position(|a| a == name).map(|i| args[i + 1].parse().expect(name)).unwrap_or(default)
}
fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let params = PineParams {
        dimension: arg(&args, "--dimension", 1000),
        l2_norm_bound: arg(&args, "--bound", 32768) as u64,
        num_frac_bits: arg(&args, "--frac-bits", 15) as u32,
        chunk_length: arg(&args, "--chunk", 4),
        chunk_length_norm_equality: arg(&args, "--chunk-norm-equality", 4),
        num_proofs: arg(&args, "--proofs", 5),
        num_proofs_norm_equality: arg(&args, "--proofs-norm-equality", 1),
    };
    let reports = arg(&args, "--reports", 4);
    let d = params.dimension;

    let t = Instant::now();
    let task = PineTask::new(params.clone(), [7; 32]).expect("task");
    // Both parties' ledgers, removed at the end.
    let ledger = std::env::temp_dir().join(format!("fhe-flp-measure-pine-{}", std::process::id()));
    std::fs::create_dir(&ledger).expect("ledger directory");
    let (mut collector, pk) = PineCollector::new(&task, &ledger).expect("collector");
    let setup = t.elapsed();
    let client = PineClient::new(&task, &pk);
    let mut evaluator = PineEvaluator::new(&task, &pk, [42; 32], &ledger).expect("evaluator");

    // Real norm about half the bound.
    let scale = params.l2_norm_bound as f64 / 2f64.powi(params.num_frac_bits as i32);
    let mut state = 1u64;
    let gradients: Vec<Vec<f64>> = (0..reports)
        .map(|_| {
            (0..d)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    ((state >> 11) as f64 / (1u64 << 53) as f64 - 0.5) * scale / (d as f64).sqrt()
                })
                .collect()
        })
        .collect();

    let t = Instant::now();
    let shards: Vec<Vec<u8>> = gradients.iter().map(|g| client.shard(g).expect("shard")).collect();
    let shard = t.elapsed();
    let t = Instant::now();
    for s in &shards {
        evaluator.ingest(s).expect("ingest");
    }
    let ingest = t.elapsed();
    let t = Instant::now();
    let request = evaluator.check_request().expect("check request");
    let check_request = t.elapsed();
    let t = Instant::now();
    let verdicts = collector.check(&request).expect("check");
    let check = t.elapsed();
    assert_eq!(collector.accepted(), Some(reports as u64), "an honest report was rejected");
    let t = Instant::now();
    let aggregate = evaluator.aggregate_request(&verdicts).expect("aggregate request");
    let aggregate_request = t.elapsed();
    let t = Instant::now();
    let sum = collector.unshard(&aggregate).expect("unshard");
    let unshard = t.elapsed();

    let mut want = vec![0i64; d];
    for g in &gradients {
        for (w, q) in want.iter_mut().zip(task.shape().encode_gradient(g).expect("encode")) {
            *w += q;
        }
    }
    let want: Vec<f64> = want.into_iter().map(|w| w as f64 / 2f64.powi(params.num_frac_bits as i32)).collect();
    assert_eq!(sum, want, "the decoded sum is not the sum of the encoded gradients");

    std::fs::remove_dir_all(&ledger).expect("remove the ledger directory");

    let per = reports as f64;
    println!(
        "{{\"dimension\":{d},\"l2_norm_bound\":{},\"num_frac_bits\":{},\"chunk_length\":{},\"chunk_length_norm_equality\":{},\"num_proofs\":{},\"num_proofs_norm_equality\":{},\"reports\":{reports},\"ciphertexts_per_report\":{},\"report_bytes\":{},\"verifier_len\":{},\"check_bytes_per_report\":{},\"aggregate_bytes\":{},\"log2_query_soundness\":{:.1},\"log2_joint_rand_per_attempt\":{:.1},\"max_batch\":{},\"setup_ms\":{:.1},\"shard_ms_per_report\":{:.1},\"ingest_ms_per_report\":{:.1},\"check_request_ms_per_report\":{:.1},\"collector_check_ms_per_report\":{:.1},\"aggregate_request_ms\":{:.1},\"unshard_ms\":{:.1}}}",
        params.l2_norm_bound,
        params.num_frac_bits,
        params.chunk_length,
        params.chunk_length_norm_equality,
        params.num_proofs,
        params.num_proofs_norm_equality,
        task.ciphertexts_per_report(),
        task.report_len(),
        task.verifier_len(),
        (request.len() - 36) / reports,
        aggregate.len(),
        task.log2_query_soundness(),
        task.log2_joint_rand_per_attempt(),
        task.max_batch(),
        ms(setup),
        ms(shard) / per,
        ms(ingest) / per,
        ms(check_request) / per,
        ms(check) / per,
        ms(aggregate_request),
        ms(unshard),
    );
}
