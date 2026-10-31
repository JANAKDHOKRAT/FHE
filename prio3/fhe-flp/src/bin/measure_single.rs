//! The one-aggregator protocol end to end in one process: sizes and times.
//!
//!   measure_single count  [--reports R] [--proofs k]
//!   measure_single bitvec --len L [--reports R] [--proofs k]
//!
//! The default number of proofs is the fewest reaching soundness 2^-128.
use fhe_flp::bitvec::BitVec;
use fhe_flp::single::{Evaluator, SingleClient, SingleCollector, SingleTask};
use fhe_flp::soundness::proofs_for;
use fhe_flp::{Field, PLAIN_MOD, VerifierMap};
use prio::flp::types::Count;
use std::time::{Duration, Instant};

fn arg(args: &[String], name: &str, default: usize) -> usize {
    args.iter().position(|a| a == name).map(|i| args[i + 1].parse().expect(name)).unwrap_or(default)
}
fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn run<T: VerifierMap>(
    name: &str,
    typ: T,
    ms_of: impl Fn(usize) -> T::Measurement,
    expect: impl Fn(&[T::Measurement]) -> T::AggregateResult,
    reports: usize,
    k: usize,
) where
    T::AggregateResult: PartialEq + std::fmt::Debug,
{
    let t0 = Instant::now();
    let task = SingleTask::new(typ, [3u8; 32], k).expect("task");
    let t_task = t0.elapsed();
    let t0 = Instant::now();
    let (mut collector, pk) = SingleCollector::new(&task).expect("collector");
    let t_keys = t0.elapsed();
    let mut ev = Evaluator::new(&task, &pk, [9u8; 32]).expect("evaluator");
    let client = SingleClient::new(&task, &pk);
    let measurements: Vec<T::Measurement> = (0..reports).map(&ms_of).collect();
    let (mut t_client, mut t_ingest) = (Duration::ZERO, Duration::ZERO);
    for m in &measurements {
        let t0 = Instant::now();
        let r = client.shard(m).expect("shard");
        t_client += t0.elapsed();
        let t0 = Instant::now();
        ev.ingest(&r).expect("ingest");
        t_ingest += t0.elapsed();
    }
    let t0 = Instant::now();
    let req = ev.check_request().expect("check request");
    let t_req = t0.elapsed();
    let t0 = Instant::now();
    let verdicts = collector.check(&req).expect("check");
    let t_check = t0.elapsed();
    let t0 = Instant::now();
    let agg = ev.aggregate_request(&verdicts).expect("aggregate request");
    let t_agg = t0.elapsed();
    let t0 = Instant::now();
    let got = collector.unshard(&agg).expect("unshard");
    let t_unshard = t0.elapsed();
    assert_eq!(got, expect(&measurements), "wrong aggregate");
    let per = |d: Duration| ms(d) / reports as f64;
    let l = task.layout();
    println!(
        "{{\"type\":\"{name}\",\"mode\":\"one-aggregator\",\"proofs\":{k},\"reports\":{reports},\"ring\":{},\"log2_q\":{:.1},\"z_len\":{},\"groups\":{},\
\"report_bytes\":{},\"check_request_bytes_per_report\":{},\"verdict_bytes_per_report\":{:.3},\"aggregate_request_bytes\":{},\"public_key_bytes\":{},\
\"client_ms\":{:.2},\"evaluator_ingest_ms\":{:.2},\"evaluator_check_ms\":{:.2},\"collector_check_ms\":{:.2},\"evaluator_aggregate_ms\":{:.2},\"collector_unshard_ms\":{:.2},\
\"task_setup_ms\":{:.1},\"collector_keygen_ms\":{:.1}}}",
        l.ring,
        task.context().log2_q(),
        l.z_len,
        l.groups().len(),
        task.report_len(),
        (req.len() - 4) / reports,
        verdicts.len() as f64 / reports as f64,
        agg.len(),
        pk.serialize().unwrap().len(),
        per(t_client),
        per(t_ingest),
        per(t_req),
        per(t_check),
        ms(t_agg),
        ms(t_unshard),
        ms(t_task),
        ms(t_keys)
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let reports = arg(&args, "--reports", 16);
    match args.get(1).map(String::as_str) {
        Some("count") => {
            let k = arg(&args, "--proofs", proofs_for(&Count::<Field>::new(), PLAIN_MOD as f64, 128.0));
            run(
                "count",
                Count::<Field>::new(),
                |i| i % 3 != 0,
                |m| m.iter().filter(|&&b| b).count() as u32,
                reports,
                k,
            );
        }
        Some("bitvec") => {
            let len = arg(&args, "--len", 100);
            let k = arg(&args, "--proofs", proofs_for(&BitVec::<Field>::new(len).unwrap(), PLAIN_MOD as f64, 128.0));
            run(
                &format!("bitvec{len}"),
                BitVec::<Field>::new(len).unwrap(),
                |i| (0..len).map(|j| (i * 7 + j * 3) % 5 < 2).collect(),
                |m| (0..len).map(|j| m.iter().filter(|v| v[j]).count() as u32).collect(),
                reports,
                k,
            );
        }
        _ => {
            eprintln!("usage: measure_single count|bitvec [--len L] [--reports R] [--proofs k]");
            std::process::exit(2);
        }
    }
}
