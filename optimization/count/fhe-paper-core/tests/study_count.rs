//! Complete Count circuit qualification for isolated parameter-study builds.
//! These tests cover honestly encrypted adversarial field values, not arbitrary
//! malformed ciphertext security. Never infer a probability bound from a pass.
use fhe_paper_core::*;
use fhe_prio3::config::{EXACT_ROW, SILENT_PLAIN_MOD, SilentCheck};
use fhe_prio3::{AggregateResult, Client, Measurement, MeasurementType};

#[test]
fn count_exact_boundary_invalid_and_slot_isolation() {
    let task = PaperTask::new([0xD1; 32], MeasurementType::Count, SilentCheck::Exact).unwrap();
    let (em, cm, key) = setup(&task).unwrap();
    let client = PaperClient::new(&task, &cm).unwrap();
    let raw = Client::new(task.config().clone(), &cm.context, &cm.public_key).unwrap();
    let collector = PaperCollector::new(task.clone(), &cm, &key).unwrap();
    let mut ev = PaperEvaluator::new(task.clone(), &em).unwrap();
    drop(em);
    let last = (task.groups() - 1) as u32;
    for (group, bit) in [(0, false), (1, true), (last, true)] {
        ev.admit(&client.report(&Measurement::Count(bit), group).unwrap()).unwrap();
    }
    for (group, value) in [(2, 2), (3, SILENT_PLAIN_MOD - 1), (4, SILENT_PLAIN_MOD / 2)] {
        ev.admit(&raw.shard_raw_elements_in_group(&[vec![value]], group).unwrap()).unwrap();
    }
    // A report may contribute its own 1 but cannot write into another group.
    let layout = task.config().layout(EXACT_ROW).unwrap();
    let mut slots = vec![0; EXACT_ROW];
    slots[layout.group_slot(5, 0)] = 1;
    slots[layout.group_slot(6, 0)] = 1;
    ev.admit(&raw.shard_raw_in_group(&[slots], 5).unwrap()).unwrap();
    // Reusing a group forces a second verification ciphertext and exercises flush.
    ev.admit(&client.report(&Measurement::Count(true), 0).unwrap()).unwrap();
    let result = collector.decrypt_aggregate(&ev.finish().unwrap()).unwrap();
    assert_eq!(result.aggregate, AggregateResult::Count(4));
    assert_eq!(result.reports, 8);
}
