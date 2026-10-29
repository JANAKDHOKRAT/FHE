//! Exact existing Count profile port: actual SDK, modulus arrays, wire size and complete outputs.
use fhe_paper_core::*;
use fhe_prio3::{
    AggregateResult, Client, MeasurementType,
    config::SilentCheck,
    messages::{self, Report},
};
mod frozen {
    include!("fixtures/count142_profile.rs");
}
#[test]
fn existing_small_count_profile_on_openfhe142() {
    assert_eq!(openfhe_tbgv_rs::OPENFHE_VERSION, "1.4.2");
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
    )
    .unwrap()
    .with_batch_limit(32)
    .unwrap();
    let ctx = task.make_context().unwrap();
    assert_eq!(ctx.ring_dim(), 32768);
    assert_eq!(task.mult_depth(), 18);
    assert_eq!(ctx.key_num_parts().unwrap(), 7);
    assert_eq!(ctx.moduli().unwrap().as_slice(), frozen::Q);
    assert_eq!(ctx.key_basis_moduli(openfhe_tbgv_rs::KeyBasis::KeySwitch).unwrap().as_slice(), frozen::QP);
    assert!(openfhe_tbgv_rs::loaded_openfhe_libraries().unwrap().iter().all(|p| p.ends_with(".so.1.4.2")));
    let (em, cm, key) = setup(&task).unwrap();
    let client = Client::new_native(task.config().clone(), &cm.context, &cm.public_key).unwrap();
    let collector = PaperCollector::new(task.clone(), &cm, &key).unwrap();
    for values in [
        vec![0],
        vec![1],
        vec![0, 1, 0, 1],
        vec![0, 1, 2, 3],
        vec![1, 65536, 2, 3],
        vec![0; 32],
        vec![1; 32],
        (0..32).map(|i| if i % 3 == 0 { 1 } else { 65536 }).collect(),
    ] {
        let expected = values.iter().filter(|&&x| x == 1).count() as u64;
        let mut ev = PaperEvaluator::new(task.clone(), &em).unwrap();
        for (i, value) in values.iter().enumerate() {
            let r = client.shard_raw_elements_in_group(&[vec![*value]], (i % 4) as u32).unwrap();
            let wire = messages::encode(&r).unwrap();
            assert_eq!(wire.len(), 6176895);
            let decoded: Report = messages::decode(&wire).unwrap();
            ev.admit(&decoded).unwrap();
        }
        if values.len() == 32 {
            let extra = client.shard_raw_elements_in_group(&[vec![1]], 0).unwrap();
            assert!(ev.admit(&extra).is_err(), "33rd report must be refused");
        }
        let aggregate = ev.finish().unwrap();
        let wire = messages::encode(&aggregate).unwrap();
        let decoded: PaperAggregate = messages::decode(&wire).unwrap();
        let result = collector.decrypt_aggregate(&decoded).unwrap();
        assert_eq!(result.aggregate, AggregateResult::Count(expected));
        assert_eq!(result.reports, values.len() as u64);
    }
}
