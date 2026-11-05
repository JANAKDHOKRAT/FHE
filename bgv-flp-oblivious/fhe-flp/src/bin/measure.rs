//! Runs reports through the full protocol in one process and reports sizes
//! and per-step times.
//!
//!   measure count  [--reports R] [--aggregators n] [--proofs k]
//!   measure bitvec --len L [--reports R] [--aggregators n] [--proofs k]
//!
//! Aggregators run one after another; times are per aggregator per report.
//! The default number of proofs is the fewest reaching soundness 2^-128.
use fhe_flp::bitvec::BitVec;
use fhe_flp::soundness::proofs_for;
use fhe_flp::{Aggregator, Client, Collector, Field, PLAIN_MOD, Task, TaskParams, VerifierMap, key_ceremony};
use prio::flp::types::Count;
use std::time::{Duration, Instant};

fn arg(args: &[String], name: &str, default: usize) -> usize {
    args.iter().position(|a| a == name).map(|i| args[i + 1].parse().expect(name)).unwrap_or(default)
}
fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn run<T: VerifierMap<Field>>(
    name: &str,
    typ: T,
    ms_of: impl Fn(usize) -> T::Measurement,
    expect: impl Fn(&[T::Measurement]) -> T::AggregateResult,
    reports: usize,
    n: usize,
    k: usize,
) where
    T::AggregateResult: PartialEq + std::fmt::Debug,
{
    let t0 = Instant::now();
    let task = Task::new(
        typ,
        TaskParams {
            task_id: [3u8; 32],
            num_aggregators: n,
            num_proofs: k,
        },
    )
    .expect("task");
    let t_task = t0.elapsed();
    let t0 = Instant::now();
    let (pk, shares) = key_ceremony(&task).expect("keys");
    let t_keys = t0.elapsed();
    let t0 = Instant::now();
    let mut aggs: Vec<Aggregator<T>> = shares
        .into_iter()
        .enumerate()
        .map(|(i, s)| Aggregator::new(&task, i, s, &pk, [9u8; 32]).expect("agg"))
        .collect();
    let t_aggs = t0.elapsed() / n as u32;
    let client = Client::new(&task, &pk);
    let measurements: Vec<T::Measurement> = (0..reports).map(&ms_of).collect();
    let (mut t_client, mut t_init, mut t_finish, mut t_query) = (Duration::ZERO, Duration::ZERO, Duration::ZERO, Duration::ZERO);
    for m in &measurements {
        let t0 = Instant::now();
        let r = client.shard(m).expect("shard");
        t_client += t0.elapsed();
        assert_eq!(r.len(), task.report_len());
        // the FLP-side share of prepare_init, measured separately
        let t0 = Instant::now();
        let qrs = task.query_rands(&[9u8; 32], &r).unwrap();
        let _ = task.linear_map(&qrs).unwrap();
        t_query += t0.elapsed();
        let mut states = Vec::new();
        let mut vshares = Vec::new();
        for a in aggs.iter_mut() {
            let t0 = Instant::now();
            let (st, sh) = a.prepare_init(&r).expect("init");
            t_init += t0.elapsed();
            assert_eq!(sh.len(), task.verifier_share_len());
            states.push(st);
            vshares.push(sh);
        }
        for (a, st) in aggs.iter_mut().zip(states) {
            let t0 = Instant::now();
            assert!(a.prepare_finish(st, &vshares).expect("finish").accepted);
            t_finish += t0.elapsed();
        }
    }
    let t0 = Instant::now();
    let agg_shares: Vec<Vec<u8>> = aggs.iter().map(|a| a.aggregate_share().expect("share")).collect();
    let t_agg_share = t0.elapsed() / n as u32;
    let t0 = Instant::now();
    let got = Collector::new(&task).expect("collector").unshard(&agg_shares).expect("unshard");
    let t_collect = t0.elapsed();
    assert_eq!(got, expect(&measurements), "wrong aggregate");
    let per = |d: Duration, div: usize| ms(d) / div as f64;
    let l = task.layout();
    println!(
        "{{\"type\":\"{name}\",\"aggregators\":{n},\"proofs\":{k},\"reports\":{reports},\"ring\":{},\"log2_q\":{:.1},\"z_len\":{},\"groups\":{},\
\"report_bytes\":{},\"verifier_share_bytes\":{},\"aggregate_share_bytes\":{},\"public_key_bytes\":{},\
\"client_ms\":{:.2},\"prepare_init_ms\":{:.2},\"of_which_flp_query_ms\":{:.2},\"prepare_finish_ms\":{:.2},\"aggregate_share_ms\":{:.2},\"collector_ms\":{:.2},\
\"task_setup_ms\":{:.1},\"key_ceremony_ms\":{:.1},\"aggregator_setup_ms\":{:.1}}}",
        l.ring,
        task.context().log2_q(),
        l.z_len,
        l.groups().len(),
        task.report_len(),
        task.verifier_share_len(),
        task.aggregate_share_len(),
        pk.serialize().unwrap().len(),
        per(t_client, reports),
        per(t_init, reports * n),
        per(t_query, reports),
        per(t_finish, reports * n),
        ms(t_agg_share),
        ms(t_collect),
        ms(t_task),
        ms(t_keys),
        ms(t_aggs)
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let reports = arg(&args, "--reports", 8);
    let n = arg(&args, "--aggregators", 2);
    match args.get(1).map(String::as_str) {
        Some("count") => {
            let k = arg(&args, "--proofs", proofs_for(&Count::<Field>::new(), PLAIN_MOD as f64, 128.0));
            run(
                "count",
                Count::<Field>::new(),
                |i| i % 3 != 0,
                |m| m.iter().filter(|&&b| b).count() as u32,
                reports,
                n,
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
                n,
                k,
            );
        }
        _ => {
            eprintln!("usage: measure count|bitvec [--len L] [--reports R] [--aggregators n] [--proofs k]");
            std::process::exit(2);
        }
    }
}
