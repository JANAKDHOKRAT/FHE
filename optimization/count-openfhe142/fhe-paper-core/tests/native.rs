//! Real native single-key Count qualification; no threshold fusion.
use fhe_paper_core::*;
use fhe_prio3::config::SilentCheck;
use fhe_prio3::{AggregateResult, Client, Measurement, MeasurementType};

#[test]
fn native_count_complete() {
    let p = std::env::var("NATIVE_TEST_PRIME").unwrap_or_else(|_| "786433".into()).parse().unwrap();
    let digits = std::env::var("NATIVE_TEST_DIGITS").unwrap_or_else(|_| "5".into()).parse().unwrap();
    let task = PaperTask::new_native(
        [0xAB; 32],
        MeasurementType::Count,
        SilentCheck::Exact,
        NativeParameters {
            plain_mod: p,
            key_switch_digits: digits,
            ..Default::default()
        },
    )
    .unwrap();
    let (em, cm, key) = setup(&task).unwrap();
    eprintln!(
        "native Count p={} depth={} row={} report keys={} bytes",
        p,
        task.mult_depth(),
        task.row_slots(),
        em.rotation_key_bytes() + em.eval_mult_key.len()
    );
    let client = PaperClient::new(&task, &cm).unwrap();
    let raw = Client::new_native(task.config().clone(), &cm.context, &cm.public_key).unwrap();
    let collector = PaperCollector::new(task.clone(), &cm, &key).unwrap();
    let mut ev = PaperEvaluator::new(task.clone(), &em).unwrap();
    drop(em);
    for (g, bit) in [(0, false), (1, true), ((task.groups() - 1) as u32, true)] {
        ev.admit(&client.report(&Measurement::Count(bit), g).unwrap()).unwrap();
    }
    for (g, value) in [(2, 2), (3, p - 1), (4, p / 2)] {
        ev.admit(&raw.shard_raw_elements_in_group(&[vec![value]], g).unwrap()).unwrap();
    }
    let l = task.layout(task.row_slots()).unwrap();
    let mut slots = vec![0; task.row_slots()];
    slots[l.group_slot(5, 0)] = 1;
    slots[l.group_slot(6, 0)] = 1;
    ev.admit(&raw.shard_raw_in_group(&[slots], 5).unwrap()).unwrap();
    ev.admit(&client.report(&Measurement::Count(true), 0).unwrap()).unwrap();
    let aggregate = ev.finish().unwrap();
    let result = collector.decrypt_aggregate(&aggregate).unwrap();
    assert_eq!(result.aggregate, AggregateResult::Count(4));
    assert_eq!(result.reports, 8);
    let mut wrong = aggregate.clone();
    wrong.task_id[0] ^= 1;
    assert!(collector.decrypt_aggregate(&wrong).is_err());
    let r = client.report(&Measurement::Count(true), 0).unwrap();
    wrong = aggregate;
    wrong.output = r.chunks[0].clone();
    assert!(collector.decrypt_aggregate(&wrong).is_err());
}
