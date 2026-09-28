//! End-to-end simulation with timings and message sizes.
//!
//! Runs the key ceremony, `--reports` honest clients, the two-round
//! verification on every aggregator and the collector's unsharding, all over
//! serialized messages, then checks the aggregate against the plaintext sum.
//!
//! Example:
//!   simulate --type sum --max 100 --reports 8 --aggregators 2
//!   simulate --type sum --max 100 --mode silent --reports 2
//!   simulate --type count --auth --reports 4
//!   simulate --type histogram --length 64 --reports 4
//!   simulate --type sumvec --length 1200 --bits 4 --reports 2
//!   simulate --type bounded --bounds 100,255,5 --moments --reports 6

use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Args {
    ty: String,
    aggregators: usize,
    reports: usize,
    repetitions: usize,
    length: usize,
    bits: u32,
    max: u64,
    max_weight: usize,
    silent: bool,
    auth: bool,
    groups: usize,
    moments: bool,
    bounds: Vec<u64>,
}

fn parse() -> Args {
    let mut a = Args { ty: "sum".into(), aggregators: 2, reports: 4, repetitions: 0, length: 8, bits: 4, max: 100, max_weight: 2, silent: false, auth: false, groups: 0, moments: false, bounds: vec![100, 255, 5] };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let v = argv.get(i + 1).map(|s| s.as_str()).unwrap_or("");
        match argv[i].as_str() {
            "--type" => a.ty = v.to_string(),
            "--aggregators" => a.aggregators = v.parse().expect("--aggregators"),
            "--reports" => a.reports = v.parse().expect("--reports"),
            "--repetitions" => a.repetitions = v.parse().expect("--repetitions"),
            "--length" => a.length = v.parse().expect("--length"),
            "--bits" => a.bits = v.parse().expect("--bits"),
            "--max" => a.max = v.parse().expect("--max"),
            "--max-weight" => a.max_weight = v.parse().expect("--max-weight"),
            "--mode" => a.silent = match v {
                "silent" => true,
                "verdict" => false,
                other => panic!("unknown mode {other}"),
            },
            "--groups" => a.groups = v.parse().expect("--groups"),
            "--bounds" => a.bounds = v.split(',').map(|x| x.parse().expect("--bounds")).collect(),
            "--auth" => {
                a.auth = true;
                i -= 1; // flag without value
            }
            "--moments" => {
                a.moments = true;
                i -= 1;
            }
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
        i += 2;
    }
    a
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}
fn mib(b: usize) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

fn measurement(ty: &MeasurementType, i: usize) -> Measurement {
    match ty {
        MeasurementType::Count => Measurement::Count(i % 3 != 0),
        MeasurementType::Sum { max_measurement } => Measurement::Sum((i as u64 * 37) % (max_measurement + 1)),
        // Distinct, non-collinear columns so the regression pilot's normal equations are regular.
        MeasurementType::SumVec { length, bits } => {
            Measurement::SumVec((0..*length).map(|j| ((i * (2 * j + 3) + j * j + (i * j) % 5) as u64) % (1u64 << bits)).collect())
        }
        MeasurementType::BoundedSumVec { bounds } => {
            Measurement::SumVec(bounds.iter().enumerate().map(|(j, &b)| ((i * (2 * j + 3) + j * j + (i * j) % 5) as u64) % (b + 1)).collect())
        }
        MeasurementType::Histogram { length } => Measurement::Histogram((i * 5) % length),
        MeasurementType::MultihotCountVec { length, max_weight } => {
            Measurement::MultihotCountVec((0..*length).map(|j| j % length < *max_weight && (i + j) % 2 == 0).collect())
        }
    }
}

fn main() {
    let a = parse();
    let ty = match a.ty.as_str() {
        "count" => MeasurementType::Count,
        "sum" => MeasurementType::Sum { max_measurement: a.max },
        "sumvec" => MeasurementType::SumVec { length: a.length, bits: a.bits },
        "bounded" => MeasurementType::BoundedSumVec { bounds: a.bounds.clone() },
        "histogram" => MeasurementType::Histogram { length: a.length },
        "multihot" => MeasurementType::MultihotCountVec { length: a.length, max_weight: a.max_weight },
        other => {
            eprintln!("unknown type {other}");
            std::process::exit(2);
        }
    };
    let mut cfg = if a.silent { TaskConfig::new_silent([7u8; 32], ty.clone(), a.aggregators) } else { TaskConfig::new([7u8; 32], ty.clone(), a.aggregators) };
    if a.repetitions > 0 {
        cfg.repetitions = a.repetitions;
    }
    if a.auth {
        cfg.auth = AuthPolicy::Required { max_reports_per_client_per_batch: 1 };
    }
    if a.groups > 0 {
        cfg.silent_batch_groups = a.groups;
    }
    if a.moments {
        cfg.moments = true;
        cfg.max_batch_size = cfg.moments_max_batch().expect("moments need SumVec").min(cfg.max_batch_size);
    }
    cfg.validate().expect("config");
    let identities: Vec<ClientIdentity> = (0..a.reports).map(|_| ClientIdentity::generate()).collect();
    let registry: Option<Arc<dyn ClientRegistry>> =
        if a.auth { Some(StaticRegistry::new(identities.iter().map(|i| i.public_key()))) } else { None };

    println!("type={:?} mode={:?} auth={:?} aggregators={} repetitions={} reports={} groups={}", ty, cfg.mode, cfg.auth, a.aggregators, cfg.repetitions, a.reports, cfg.silent_batch_groups);
    println!("plain_mod={} mult_depth={} soundness=2^-{:.1} per report", cfg.plain_mod, cfg.mult_depth(), cfg.soundness_bits());

    let t0 = Instant::now();
    let (material, shares) = keys::run_local_ceremony(&cfg).expect("ceremony");
    let ceremony = t0.elapsed();
    let material_bytes = encode(&material).unwrap();
    let material: PublicMaterial = decode(&material_bytes).unwrap();
    println!(
        "ceremony: {:.0} ms  | context {:.2} MiB, public key {:.2} MiB, eval-mult key {:.2} MiB, rotation keys {:.2} MiB ({} indices)",
        ms(ceremony),
        mib(material.context.len()),
        mib(material.public_key.len()),
        mib(material.eval_mult_key.len()),
        mib(material.rotation_key_bytes()),
        material.rotation_indices.len()
    );

    let t0 = Instant::now();
    let mut aggs: Vec<Aggregator> =
        shares.iter().enumerate().map(|(i, s)| Aggregator::new(cfg.clone(), &material, i, s, registry.clone()).expect("aggregator")).collect();
    println!("aggregator setup: {:.0} ms total for {} aggregators", ms(t0.elapsed()), aggs.len());
    let collector = Collector::new(cfg.clone(), &material).expect("collector");
    let layout = cfg.layout(aggs[0].layout().row).expect("layout");
    println!(
        "layout: {:?} input_len={} block={} chunks={} groups={} row={} ring_dim={}",
        layout.kind,
        layout.input_len,
        layout.block,
        layout.num_chunks,
        layout.groups,
        layout.row,
        layout.row * 2
    );

    let mut t_shard = Duration::ZERO;
    let mut t_init = Duration::ZERO;
    let mut t_masks = Duration::ZERO;
    let mut t_finish = Duration::ZERO;
    let mut report_bytes = 0usize;
    let mut mask_bytes = 0usize;
    let mut verifier_bytes = 0usize;
    let mut ms_list = Vec::new();

    let mut t_silent = Duration::ZERO;
    for i in 0..a.reports {
        let m = measurement(&ty, i);
        let mut client = Client::new(cfg.clone(), &material.context, &material.public_key).expect("client");
        if a.auth {
            client = client.with_identity(ClientIdentity::from_secret_bytes(&identities[i].secret_bytes()));
        }
        let t0 = Instant::now();
        let group = if a.silent { (i % cfg.silent_batch_groups) as u32 } else { 0 };
        let report = client.shard_in_group(&m, group).expect("shard");
        t_shard += t0.elapsed();
        let rb = encode(&report).unwrap();
        report_bytes = rb.len();
        let report: Report = decode(&rb).unwrap();
        ms_list.push(m);

        if a.silent {
            for ag in aggs.iter_mut() {
                let t0 = Instant::now();
                ag.process_silent(&report).expect("process_silent");
                t_silent += t0.elapsed();
            }
            continue;
        }

        let mut masks = Vec::new();
        for ag in aggs.iter_mut() {
            let t0 = Instant::now();
            let mm = ag.prepare_init(&report).expect("prepare_init");
            t_init += t0.elapsed();
            let b = encode(&mm).unwrap();
            mask_bytes = b.len();
            masks.push(decode::<MaskMessage>(&b).unwrap());
        }
        let mut verifiers = Vec::new();
        for ag in aggs.iter_mut() {
            let others: Vec<MaskMessage> = masks.iter().filter(|x| x.aggregator != ag.index()).cloned().collect();
            let t0 = Instant::now();
            let v = ag.prepare_masks(&report.report_id, &others).expect("prepare_masks");
            t_masks += t0.elapsed();
            let b = encode(&v).unwrap();
            verifier_bytes = b.len();
            verifiers.push(decode::<VerifierMessage>(&b).unwrap());
        }
        for ag in aggs.iter_mut() {
            let others: Vec<VerifierMessage> = verifiers.iter().filter(|x| x.aggregator != ag.index()).cloned().collect();
            let t0 = Instant::now();
            let verdict = ag.prepare_finish(&report.report_id, &others).expect("prepare_finish");
            t_finish += t0.elapsed();
            assert_eq!(verdict, Verdict::Accepted, "honest report {i} rejected");
        }
    }

    let n_ag = aggs.len() as f64;
    let n_r = a.reports as f64;
    // Batch close (silent: runs the last shared chain) is measured before the
    // per-report summary so that it can be amortised into it.
    let t0 = Instant::now();
    let mut t_close = Duration::ZERO;
    let mut counts_opt: Option<Vec<CountShare>> = None;
    if a.silent {
        let counts: Vec<CountShare> = aggs.iter_mut().map(|ag| decode(&encode(&ag.count_share().expect("count share")).unwrap()).unwrap()).collect();
        t_close = t0.elapsed();
        counts_opt = Some(counts);
    }
    println!("per report:");
    println!("  client shard            {:>8.1} ms   report {:.2} MiB ({} chunk(s))", ms(t_shard) / n_r, mib(report_bytes), layout.num_chunks);
    if a.silent {
        println!(
            "  aggregator process_silent {:>6.1} ms per report per aggregator, amortised over {} reports incl. batch close (no messages, no per-report decryption)",
            (ms(t_silent) + ms(t_close)) / n_r / n_ag,
            a.reports
        );
    } else {
    println!("  aggregator prepare_init {:>8.1} ms   mask message {:.2} MiB", ms(t_init) / n_r / n_ag, mib(mask_bytes));
    println!("  aggregator prepare_masks{:>8.1} ms   verifier message {:.2} MiB", ms(t_masks) / n_r / n_ag, mib(verifier_bytes));
    println!("  aggregator prepare_finish{:>7.1} ms", ms(t_finish) / n_r / n_ag);
    println!(
        "  aggregator total        {:>8.1} ms per report per aggregator",
        (ms(t_init) + ms(t_masks) + ms(t_finish)) / n_r / n_ag
    );
    }

    let t0 = Instant::now();
    if let Some(counts) = counts_opt {
        for ag in aggs.iter_mut() {
            ag.count_finish(&counts).expect("count finish");
        }
    }
    let shares: Vec<AggregateShare> = aggs.iter_mut().map(|ag| decode(&encode(&ag.aggregate_share().expect("share")).unwrap()).unwrap()).collect();
    let t_share = t0.elapsed();
    let t0 = Instant::now();
    let BatchResult { aggregate: agg, report_count: count, valid_count, regression, .. } = collector.unshard(&shares).expect("unshard");
    if let Some(r) = &regression {
        println!("regression: n={} beta={:?}", r.n, r.beta);
    }
    let t_unshard = t0.elapsed();
    let expected = ty.aggregate_plain(&ms_list).unwrap();
    println!(
        "batch: aggregate_share {:.1} ms per aggregator ({:.2} MiB each), collector unshard {:.1} ms, {} reports",
        ms(t_share) / n_ag,
        mib(encode(&shares[0]).unwrap().len()),
        ms(t_unshard),
        count
    );
    println!("aggregate = {agg:?} (valid reports: {valid_count})");
    assert_eq!(agg, expected, "aggregate mismatch");
    println!("aggregate matches plaintext reference: OK");
}
