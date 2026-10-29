//! Supplementary local attack reproduction. Known gaps are explicitly observed,
//! not called security passes. Run only with our own isolated keys.
use fhe_paper_core::*;
use fhe_prio3::{
    AggregateResult, Measurement, MeasurementType, Report,
    config::SilentCheck,
    keys,
    packed::{Codec, Expect},
};
#[test]
fn count_boundaries_and_attack_reproductions() {
    let task = PaperTask::new_native(
        [0xC7; 32],
        MeasurementType::Count,
        SilentCheck::Exact,
        NativeParameters {
            plain_mod: 65537,
            key_switch_digits: 7,
            groups: Some(4),
            count_projection: true,
            ..Default::default()
        },
    )
    .unwrap()
    .with_batch_limit(32)
    .unwrap();
    let (em, cm, key) = setup(&task).unwrap();
    let client = PaperClient::new(&task, &cm).unwrap();
    let collector = PaperCollector::new(task.clone(), &cm, &key).unwrap();
    let ctx = task.make_context().unwrap();
    let pk = ctx.deserialize_public_key(&cm.public_key).unwrap();
    let sk = ctx.deserialize_secret_share(key.as_bytes()).unwrap();
    let codec = Codec::new(&ctx, &pk, &cm.public_key).unwrap();
    let mut one = None;
    for n in 1..=32u64 {
        let mut ev = PaperEvaluator::new(task.clone(), &em).unwrap();
        for i in 0..n {
            ev.admit(&client.report(&Measurement::Count(true), (i % 4) as u32).unwrap()).unwrap();
        }
        let agg = ev.finish().unwrap();
        assert_eq!(collector.decrypt_aggregate(&agg).unwrap().aggregate, AggregateResult::Count(n));
        let ct = codec.decode(&agg.output, Expect::Any).unwrap();
        let slots = sk.decrypt_single(&ct, ctx.ring_dim() as usize).unwrap();
        assert_eq!(slots[0], n);
        assert!(slots[1..].iter().all(|&x| x == 0));
        if n == 1 {
            one = Some(agg);
        }
        eprintln!("BOUNDARY N={n} all-one batch correct; all other slots in both rows zero");
    }
    // Finite noise stress: large field values, zero, and deterministic random nonbits.
    let raw = fhe_prio3::Client::new_native(task.config().clone(), &cm.context, &cm.public_key).unwrap();
    let mut seed = 0xBADC0FFEEu64;
    for case in 0..4 {
        let mut ev = PaperEvaluator::new(task.clone(), &em).unwrap();
        for i in 0..32 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let x = match case {
                0 => 0,
                1 => 65536,
                2 => 32768,
                _ => 2 + seed % 65535,
            };
            ev.admit(&raw.shard_raw_elements_in_group(&[vec![x]], (i % 4) as u32).unwrap()).unwrap();
        }
        let agg = ev.finish().unwrap();
        assert_eq!(collector.decrypt_aggregate(&agg).unwrap().aggregate, AggregateResult::Count(0));
        eprintln!("STRESS case={case} N=32 output=0 (finite noise evidence)");
    }
    let mut ev = PaperEvaluator::new(task.clone(), &em).unwrap();
    assert!(ev.finish().is_err());
    let original = client.report(&Measurement::Count(true), 0).unwrap();
    // Wrong key material must be refused with the original (unforged) fingerprint.
    let (other_pk, _other_sk) = keys::keygen_step(&ctx, None).unwrap();
    let other_cm = ClientMaterial {
        context: cm.context.clone(),
        public_key: other_pk.serialize().unwrap(),
    };
    let other_client = PaperClient::new(&task, &other_cm).unwrap();
    assert!(ev.admit(&other_client.report(&Measurement::Count(true), 0).unwrap()).is_err());
    // Recompute report IDs so tests reach structural parsers, not just ID checks.
    for i in 0..64 {
        let mut bad = original.clone();
        let offset = [0, 4, 5, 6, 8, 12, 13, 16, 24, 56][i % 10];
        if offset == 56 {
            bad.chunks[0][56..64].fill(0xFF);
        } else {
            bad.chunks[0][offset] ^= 0xFF;
        }
        bad.report_id = Report::compute_id(&bad.task_id, bad.group, &bad.chunks);
        let state = (ev.admitted(), ev.pending());
        assert!(ev.admit(&bad).is_err(), "offset={offset}");
        assert_eq!(state, (ev.admitted(), ev.pending()));
    }
    let mut bad = original.clone();
    bad.group = u32::MAX;
    bad.report_id = Report::compute_id(&bad.task_id, bad.group, &bad.chunks);
    assert!(ev.admit(&bad).is_err());
    let mut bad = original.clone();
    bad.chunks[0].truncate(56);
    bad.report_id = Report::compute_id(&bad.task_id, bad.group, &bad.chunks);
    assert!(ev.admit(&bad).is_err());
    // Canonical, structurally acceptable ciphertext coefficients need not carry
    // any proof they came from honest randomized encryption.
    let mut zero = original.clone();
    zero.chunks[0][56..].fill(0);
    zero.report_id = Report::compute_id(&zero.task_id, zero.group, &zero.chunks);
    ev.admit(&zero).unwrap();
    let agg = ev.finish().unwrap();
    assert_eq!(collector.decrypt_aggregate(&agg).unwrap().aggregate, AggregateResult::Count(0));
    eprintln!("OBSERVATION all-zero ciphertext payload admitted; this alone is not an exploit or a security proof");
    // Same single-report aggregate can be presented as a 32-report aggregate.
    let mut forged = one.unwrap();
    forged.reports = 32;
    assert_eq!(collector.decrypt_aggregate(&forged).unwrap().aggregate, AggregateResult::Count(1));
    eprintln!("GAP evaluator can substitute N=1 aggregate with claimed N=32; accepted");
    // The collector has the full key; direct individual decryption succeeds.
    let ct = codec.decode(&original.chunks[0], Expect::Exactly(codec.fresh_meta())).unwrap();
    assert_eq!(sk.decrypt_single(&ct, task.row_slots()).unwrap()[0], 1);
    eprintln!("TRUST collector can decrypt individual report if obtained; release policy external");
}
