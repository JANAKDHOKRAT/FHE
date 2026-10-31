//! The one-aggregator protocol end to end in one process: sizes and times.
//!
//!   measure_single count     [common]
//!   measure_single bitvec    --len L [common]
//!   measure_single sum       --max M [common]
//!   measure_single sumvec    --len L --max M [common]
//!   measure_single histogram --len L [common]
//!   measure_single multihot  --len L --weight W [common]
//!   common: [--field prio2|65537] [--reports R] [--proofs k]
//!
//! `--field` picks the FLP field and BGV plaintext modulus (default prio2,
//! p = 4293918721). The default number of proofs is the fewest reaching
//! soundness 2^-128 in that field, joint randomness included. SumVec,
//! Histogram and MultihotCountVec use Prio3's chunk length
//! (`optimal_chunk_length`).
use fhe_flp::bitvec::BitVec;
use fhe_flp::f65537::Field65537;
use fhe_flp::single::{Evaluator, SingleClient, SingleCollector, SingleTask};
use fhe_flp::soundness::proofs_for_with_joint_rand;
use fhe_flp::{FheField, Field, VerifierMap};
use prio::flp::gadgets::{Mul, ParallelSum};
use prio::flp::types::{Count, Histogram, MultihotCountVec, Sum, SumVec};
use prio::vdaf::prio3::optimal_chunk_length;
use std::time::{Duration, Instant};

fn arg(args: &[String], name: &str, default: usize) -> usize {
    args.iter().position(|a| a == name).map(|i| args[i + 1].parse().expect(name)).unwrap_or(default)
}
fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn run<F: FheField, T: VerifierMap<F>>(
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
        "{{\"type\":\"{name}\",\"mode\":\"one-aggregator\",\"p\":{},\"proofs\":{k},\"reports\":{reports},\"ring\":{},\"log2_q\":{:.1},\"z_len\":{},\"groups\":{},\
\"ciphertexts_per_report\":{},\"log2_soundness\":{:.1},\"log2_joint_rand_per_attempt\":{},\"max_batch\":{},\"report_bytes\":{},\"check_request_bytes_per_report\":{},\"verdict_bytes_per_report\":{:.3},\"aggregate_request_bytes\":{},\"public_key_bytes\":{},\
\"client_ms\":{:.2},\"evaluator_ingest_ms\":{:.2},\"evaluator_check_ms\":{:.2},\"collector_check_ms\":{:.2},\"evaluator_aggregate_ms\":{:.2},\"collector_unshard_ms\":{:.2},\
\"task_setup_ms\":{:.1},\"collector_keygen_ms\":{:.1}}}",
        F::PLAIN_MOD,
        l.ring,
        task.context().log2_q(),
        l.z_len,
        l.groups().len(),
        task.ciphertexts_per_report(),
        task.log2_soundness(),
        match fhe_flp::soundness::log2_joint_rand_per_attempt(F::PLAIN_MOD as f64, k, task.typ().joint_rand_degree()) {
            x if x.is_finite() => format!("{x:.1}"),
            _ => "null".into(),
        },
        task.max_batch(),
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
    match args.iter().position(|a| a == "--field").map(|i| args[i + 1].as_str()) {
        None | Some("prio2") => main_for::<Field>(&args),
        Some("65537") => main_for::<Field65537>(&args),
        Some(other) => {
            eprintln!("unknown field {other}: use prio2 or 65537");
            std::process::exit(2);
        }
    }
}

fn k_for<F: FheField, T: VerifierMap<F>>(args: &[String], typ: &T) -> usize {
    arg(
        args,
        "--proofs",
        proofs_for_with_joint_rand(typ, F::PLAIN_MOD as f64, 128.0, typ.joint_rand_degree()),
    )
}

fn sums(m: &[Vec<u32>], len: usize) -> Vec<u32> {
    (0..len).map(|j| m.iter().map(|v| v[j]).sum()).collect()
}

fn main_for<F: FheField>(args: &[String]) {
    let reports = arg(args, "--reports", 16);
    match args.get(1).map(String::as_str) {
        Some("count") => {
            let k = k_for(args, &Count::<F>::new());
            run(
                "count",
                Count::<F>::new(),
                |i| i % 3 != 0,
                |m| m.iter().filter(|&&b| b).count() as u32,
                reports,
                k,
            );
        }
        Some("bitvec") => {
            let len = arg(args, "--len", 100);
            let k = k_for(args, &BitVec::<F>::new(len).unwrap());
            run(
                &format!("bitvec{len}"),
                BitVec::<F>::new(len).unwrap(),
                |i| (0..len).map(|j| (i * 7 + j * 3) % 5 < 2).collect(),
                |m| (0..len).map(|j| m.iter().filter(|v| v[j]).count() as u32).collect(),
                reports,
                k,
            );
        }
        Some("sum") => {
            let max = arg(args, "--max", 100) as u32;
            let typ = Sum::<F>::new(max).unwrap();
            let k = k_for(args, &typ);
            run(&format!("sum{max}"), typ, |i| (i as u32 * 37) % (max + 1), |m| m.iter().sum(), reports, k);
        }
        Some("sumvec") => {
            let (len, max) = (arg(args, "--len", 100), arg(args, "--max", 1) as u32);
            let bits = max.ilog2() as usize + 1;
            let typ = SumVec::<F, ParallelSum<F, Mul>>::new(max, len, optimal_chunk_length(len * bits)).unwrap();
            let k = k_for(args, &typ);
            run(
                &format!("sumvec{len}x{max}"),
                typ,
                |i| (0..len).map(|j| ((i * 7 + j * 3) as u32) % (max + 1)).collect(),
                |m| sums(m, len),
                reports,
                k,
            );
        }
        Some("histogram") => {
            let len = arg(args, "--len", 100);
            let typ = Histogram::<F, ParallelSum<F, Mul>>::new(len, optimal_chunk_length(len)).unwrap();
            let k = k_for(args, &typ);
            run(
                &format!("histogram{len}"),
                typ,
                |i| (i * 7) % len,
                |m| (0..len).map(|j| m.iter().filter(|&&b| b == j).count() as u32).collect(),
                reports,
                k,
            );
        }
        Some("multihot") => {
            let (len, weight) = (arg(args, "--len", 100), arg(args, "--weight", 10));
            let bits = weight.ilog2() as usize + 1;
            let typ = MultihotCountVec::<F, ParallelSum<F, Mul>>::new(len, weight, optimal_chunk_length(len + bits)).unwrap();
            let k = k_for(args, &typ);
            run(
                &format!("multihot{len}w{weight}"),
                typ,
                |i| (0..len).map(|j| (i + j) % len < weight).collect(),
                |m| (0..len).map(|j| m.iter().filter(|v| v[j]).count() as u32).collect(),
                reports,
                k,
            );
        }
        _ => {
            eprintln!(
                "usage: measure_single count|bitvec|sum|sumvec|histogram|multihot [--len L] [--max M] [--weight W] [--field prio2|65537] [--reports R] [--proofs k]"
            );
            std::process::exit(2);
        }
    }
}
