use fhe_paper_core::*;
use fhe_prio3::{
    AggregateResult, Client, MeasurementType,
    config::SilentCheck,
    messages::{self, Report},
};
use serde_json::json;
use std::time::Instant;
fn ns(t: Instant) -> u64 {
    t.elapsed().as_nanos().try_into().unwrap()
}
fn peak() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(openfhe_tbgv_rs::OPENFHE_VERSION, "1.4.2");
    let epoch: u64 = std::env::args().nth(1).unwrap().parse()?;
    let t = Instant::now();
    let task = PaperTask::new_native(
        [0xC1; 32],
        MeasurementType::Count,
        SilentCheck::Exact,
        NativeParameters {
            plain_mod: 65537,
            key_switch_digits: 7,
            count_projection: true,
            groups: Some(4),
            ..Default::default()
        },
    )?
    .with_batch_limit(32)?;
    let task_init_ns = ns(t);
    let t = Instant::now();
    let (em, cm, key) = setup(&task)?;
    let setup_ns = ns(t);
    let ctx = task.make_context()?;
    assert_eq!(ctx.ring_dim(), 32768);
    assert_eq!(task.mult_depth(), 18);
    println!(
        "{}",
        json!({"type":"parameters","openfhe":openfhe_tbgv_rs::OPENFHE_VERSION,"loaded_libraries":openfhe_tbgv_rs::loaded_openfhe_libraries()?,"p":task.config().plain_mod,"n":ctx.ring_dim(),"depth":task.mult_depth(),"digits":ctx.key_num_parts()?,"q":ctx.moduli()?.iter().map(|q|q.to_string()).collect::<Vec<_>>(),"qp":ctx.key_basis_moduli(openfhe_tbgv_rs::KeyBasis::KeySwitch)?.iter().map(|q|q.to_string()).collect::<Vec<_>>(),"groups":task.groups()})
    );
    let t = Instant::now();
    let client = Client::new_native(task.config().clone(), &cm.context, &cm.public_key)?;
    let client_init = ns(t);
    let t = Instant::now();
    let collector = PaperCollector::new(task.clone(), &cm, &key)?;
    let collector_init = ns(t);
    println!(
        "{}",
        json!({"type":"setup","backend":"BGV","epoch":epoch,"task_init_ns":task_init_ns,"setup_including_key_serialize_ns":setup_ns,"client_init_ns":client_init,"collector_init_ns":collector_init,"context_bytes":cm.context.len(),"public_key_bytes":cm.public_key.len(),"mult_key_bytes":em.eval_mult_key.len(),"rotation_key_bytes":em.rotation_key_bytes(),"rotation_indices":em.rotation_indices,"peak_rss_kib":peak()})
    );
    for n in [4usize] {
        for run in -2i32..3 {
            let invalid = run == -2;
            let values: Vec<u64> = (0..n)
                .map(|i| {
                    if invalid && i + 2 >= n {
                        if i + 1 == n { 3 } else { 2 }
                    } else {
                        (i % 2) as u64
                    }
                })
                .collect();
            let expected = values.iter().filter(|&&x| x == 1).count() as u64;
            let t = Instant::now();
            let mut ev = PaperEvaluator::new(task.clone(), &em)?;
            let init = ns(t);
            let (mut client_ns, mut decode_ns, mut evaluate_ns, mut report_bytes) = (0u64, 0u64, 0u64, 0usize);
            for (i, &value) in values.iter().enumerate() {
                let t = Instant::now();
                let report = client.shard_raw_elements_in_group(&[vec![value]], (i % task.groups()) as u32)?;
                let wire = messages::encode(&report)?;
                client_ns += ns(t);
                report_bytes = wire.len();
                drop(report);
                let t = Instant::now();
                let report: Report = messages::decode(&wire)?;
                decode_ns += ns(t);
                let t = Instant::now();
                ev.admit(&report)?;
                evaluate_ns += ns(t);
            }
            let t = Instant::now();
            let aggregate = ev.finish()?;
            let wire = messages::encode(&aggregate)?;
            evaluate_ns += ns(t);
            let aggregate_bytes = wire.len();
            drop(aggregate);
            let t = Instant::now();
            let aggregate: PaperAggregate = messages::decode(&wire)?;
            let output = collector.decrypt_aggregate(&aggregate)?;
            let collector_ns = ns(t);
            assert_eq!(output.aggregate, AggregateResult::Count(expected));
            let actual = match output.aggregate {
                AggregateResult::Count(v) => v,
                _ => unreachable!(),
            };
            assert_eq!(report_bytes, 6176895);
            assert_eq!(output.reports, n as u64);
            println!(
                "{}",
                json!({"type":"batch","backend":"BGV","epoch":epoch,"n":n,"run":run,"invalid_reports":if invalid{2}else{0},"expected":expected,"actual":actual,"report_bytes":report_bytes,"aggregate_bytes":aggregate_bytes,"evaluator_init_ns":init,"client_ns":client_ns,"decode_ns":decode_ns,"evaluate_ns":evaluate_ns,"collector_ns":collector_ns,"peak_rss_kib":peak(),"correct":true})
            );
        }
    }
    Ok(())
}
