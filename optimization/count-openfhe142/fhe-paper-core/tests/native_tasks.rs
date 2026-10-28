//! Per-process native complete-circuit qualification, selected by explicit env.
use fhe_paper_core::*;
use fhe_prio3::config::SilentCheck;
use fhe_prio3::{Client, Measurement, MeasurementType, Report};

#[test]
fn native_task_complete() {
    let read = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.into());
    let p: u64 = read("NATIVE_TEST_PRIME", "786433").parse().unwrap();
    let digits = read("NATIVE_TEST_DIGITS", "3").parse().unwrap();
    let mode = match read("NATIVE_TEST_MODE", "exact").as_str() {
        "exact" => SilentCheck::Exact,
        "randomised" => SilentCheck::Randomised,
        _ => panic!("mode"),
    };
    let length = read("NATIVE_TEST_LENGTH", "10").parse().unwrap();
    let ty = match read("NATIVE_TEST_TYPE", "sumvec").as_str() {
        "count" => MeasurementType::Count,
        "sum" => MeasurementType::Sum { max_measurement: 100 },
        "sumvec" => MeasurementType::SumVec { length, max_measurement: 1 },
        "histogram" => MeasurementType::Histogram { length },
        _ => panic!("type"),
    };
    let groups = std::env::var("NATIVE_TEST_GROUPS").ok().map(|v| v.parse().unwrap());
    let mut task = PaperTask::new_native(
        [0xAD; 32],
        ty.clone(),
        mode,
        NativeParameters {
            count_projection: read("COUNT_PROJECTION", "false") == "true",
            plain_mod: p,
            key_switch_digits: digits,
            groups,
            ..Default::default()
        },
    )
    .unwrap();
    let declared_limit = std::env::var("NATIVE_TEST_LIMIT").ok().map(|v| v.parse::<u64>().unwrap());
    if let Some(limit) = declared_limit {
        task = task.with_batch_limit(limit).unwrap();
    }
    let (em, cm, key) = setup(&task).unwrap();
    let client = PaperClient::new(&task, &cm).unwrap();
    let raw = Client::new_native(task.config().clone(), &cm.context, &cm.public_key).unwrap();
    let collector = PaperCollector::new(task.clone(), &cm, &key).unwrap();
    let mut ev = PaperEvaluator::new(task.clone(), &em).unwrap();
    drop(em);
    let mut sums = vec![0; ty.input_len()];
    let mut admitted = 0;
    let value = |i: usize| match &ty {
        MeasurementType::Count => Measurement::Count(i % 2 == 1),
        MeasurementType::Sum { .. } => Measurement::Sum([0, 100, 37, 63][i % 4]),
        MeasurementType::SumVec { length, .. } => Measurement::SumVec((0..*length).map(|j| ((i + j) % 2) as u64).collect()),
        MeasurementType::Histogram { length } => Measurement::Histogram(if i.is_multiple_of(2) { 0 } else { length - 1 }),
        _ => unreachable!(),
    };
    for (i, g) in [0u32, 1, (task.groups() - 1) as u32].into_iter().enumerate() {
        let m = value(i);
        for (s, v) in sums.iter_mut().zip(ty.encode(&m).unwrap()) {
            *s += v;
        }
        ev.admit(&client.report(&m, g).unwrap()).unwrap();
        admitted += 1;
    }
    if ty == MeasurementType::Count {
        // Replay is a documented deployment gap, not a rejected attack.
        let replay = client.report(&Measurement::Count(true), 0).unwrap();
        ev.admit(&replay).unwrap();
        ev.admit(&replay).unwrap();
        admitted += 2;
        sums[0] += 2;
        eprintln!("ATTACK replay: same report admitted twice; no participation authentication");
        // Opposite nonzero residuals from x=2/5,y=-1/5, separate reports.
        let inv5 = (1..5).map(|k| (1 + k * p) / 5).find(|v| (v * 5) % p == 1).unwrap();
        let x = 2 * inv5 % p;
        let y = p - inv5;
        assert_eq!((x * ((x + p - 1) % p) % p + y * ((y + p - 1) % p) % p) % p, 0);
        for v in [x, y] {
            ev.admit(&raw.shard_raw_elements_in_group(&[vec![v]], 0).unwrap()).unwrap();
            admitted += 1;
        }
    }
    let n = ty.input_len();
    let mut invalids = vec![];
    let mut bad = vec![0; n];
    bad[n - 1] = 2;
    invalids.push(bad);
    let mut bad = vec![0; n];
    bad[0] = p - 1;
    invalids.push(bad);
    let mut bad = vec![0; n];
    bad[0] = p / 2;
    invalids.push(bad);
    if n >= 2 {
        // x=2/5, y=-1/5 have nonzero cancelling bitness residuals.
        let inv5 = (1..5).map(|k| (1 + k * p) / 5).find(|v| (v * 5) % p == 1).unwrap();
        let mut bad = vec![0; n];
        bad[0] = (2 * inv5) % p;
        bad[1] = p - inv5;
        assert_ne!(bad[0] * (bad[0] - 1) % p, 0);
        invalids.push(bad);
    }
    if matches!(ty, MeasurementType::Histogram { .. }) {
        invalids.push(vec![0; n]);
        if n >= 2 {
            let mut bad = vec![0; n];
            bad[0] = 1;
            bad[n - 1] = 1;
            invalids.push(bad);
        }
    }
    for (i, bad) in invalids.iter().enumerate() {
        ev.admit(
            &raw.shard_raw_elements_in_group(std::slice::from_ref(bad), ((i + 2) % task.groups()) as u32)
                .unwrap(),
        )
        .unwrap();
        admitted += 1;
    }
    // Reuse a group: force a verification flush; only its own slots survive.
    let m = value(3);
    let encoded = ty.encode(&m).unwrap();
    let l = task.layout(task.row_slots()).unwrap();
    let mut slots = vec![0; 2 * task.row_slots()];
    for (i, &v) in encoded.iter().enumerate() {
        slots[l.group_slot(0, i)] = v;
    }
    slots[l.group_slot(1, 0)] = p - 1;
    slots[task.row_slots()] = p - 1;
    ev.admit(&raw.shard_raw_in_group(&[slots], 0).unwrap()).unwrap();
    admitted += 1;
    for (s, v) in sums.iter_mut().zip(encoded) {
        *s += v;
    }
    // Parser and provenance refusals, with IDs recomputed to reach the parser.
    for offset in [0, 4, 13, 24] {
        let mut report = client.report(&m, 1).unwrap();
        report.chunks[0][offset] ^= 0x80;
        report.report_id = Report::compute_id(&report.task_id, report.group, &report.chunks);
        let before = (ev.admitted(), ev.pending());
        assert!(ev.admit(&report).is_err());
        assert_eq!(before, (ev.admitted(), ev.pending()));
    }
    let mut report = client.report(&m, 1).unwrap();
    report.chunks[0].pop();
    report.report_id = Report::compute_id(&report.task_id, report.group, &report.chunks);
    assert!(ev.admit(&report).is_err());
    assert!(client.report(&m, u32::MAX).is_err());
    if declared_limit.is_some() {
        let maximum = match &ty {
            MeasurementType::Count => Measurement::Count(true),
            MeasurementType::Sum { max_measurement } => Measurement::Sum(*max_measurement),
            MeasurementType::SumVec { length, max_measurement } => Measurement::SumVec(vec![*max_measurement; *length]),
            MeasurementType::Histogram { length } => Measurement::Histogram(length - 1),
            _ => unreachable!(),
        };
        while admitted < task.max_batch() {
            let group = (admitted as usize % task.groups()) as u32;
            ev.admit(&client.report(&maximum, group).unwrap()).unwrap();
            for (s, v) in sums.iter_mut().zip(ty.encode(&maximum).unwrap()) {
                *s += v;
            }
            admitted += 1;
        }
        let extra = client.report(&maximum, 0).unwrap();
        assert!(ev.admit(&extra).unwrap_err().to_string().contains("batch full"));
    }
    let agg = ev.finish().unwrap();
    let result = collector.decrypt_aggregate(&agg).unwrap();
    assert_eq!(result.aggregate, ty.decode_aggregate(&sums).unwrap());
    assert_eq!(result.reports, admitted);
    // No authenticated provenance binds the declared number of reports.
    // A malicious evaluator can inflate metadata while retaining valid output.
    if admitted < task.max_batch() {
        let mut forged = agg.clone();
        forged.reports += 1;
        assert!(collector.decrypt_aggregate(&forged).is_ok());
        eprintln!("ATTACK aggregate metadata forgery accepted: honest-evaluator assumption required");
    }
    let mut oversized = agg;
    oversized.reports = task.max_batch() + 1;
    assert!(collector.decrypt_aggregate(&oversized).is_err());
    eprintln!(
        "QUALIFIED type={ty:?} mode={mode:?} p={p} digits={digits} row={} groups={} repetitions={} invalid={} admitted={admitted}",
        task.row_slots(),
        task.groups(),
        task.config().repetitions,
        invalids.len()
    );
}
