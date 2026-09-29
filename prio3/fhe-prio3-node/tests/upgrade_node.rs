//! Nodes started on a database written before the packed wire format. The
//! database layout is unchanged; what differs is that ciphertexts from or
//! to other parties are stored in OpenFHE's serialization. These tests
//! write exactly such databases and check that each node refuses to start
//! with the reason, except where the stored state is still usable.
use fhe_prio3::messages::encode;
use fhe_prio3::packed::{Expect, LEGACY_STATE};
use fhe_prio3::*;
use fhe_prio3_node::aggregator_node::{AggregatorNode, AggregatorNodeConfig};
use fhe_prio3_node::collector_node::{CollectorNode, CollectorNodeConfig};
use fhe_prio3_node::store::Store;
use std::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::new(());

/// The database keys the aggregator node writes (its on-disk format).
const K_STATE: &str = "aggregator_state";
const K_TASK: &str = "task_config";

struct Batch {
    task: TaskConfig,
    material: PublicMaterial,
    shares: Vec<Vec<u8>>,
    aggs: Vec<Aggregator>,
    released: Vec<AggregateShare>,
}

/// One accepted report and every aggregator's released share, in process.
fn released_batch(seed: u8) -> Batch {
    let mut task_id = [0u8; 32];
    task_id[0] = seed;
    let task = TaskConfig::new(task_id, MeasurementType::Count, 2);
    let (material, shares) = keys::run_local_ceremony(&task).unwrap();
    let mut aggs: Vec<Aggregator> = shares.iter().enumerate().map(|(i, s)| Aggregator::new(task.clone(), &material, i, s, None).unwrap()).collect();
    let client = Client::new(task.clone(), &material.context, &material.public_key).unwrap();
    let report = client.shard(&Measurement::Count(true)).unwrap();
    let masks: Vec<MaskMessage> = aggs.iter_mut().map(|a| a.prepare_init(&report).unwrap()).collect();
    let mut verifiers = Vec::new();
    for a in aggs.iter_mut() {
        let others: Vec<MaskMessage> = masks.iter().filter(|m| m.aggregator != a.index()).cloned().collect();
        verifiers.push(a.prepare_masks(&report.report_id, &others).unwrap());
    }
    for a in aggs.iter_mut() {
        let others: Vec<VerifierMessage> = verifiers.iter().filter(|v| v.aggregator != a.index()).cloned().collect();
        assert_eq!(a.prepare_finish(&report.report_id, &others).unwrap(), Verdict::Accepted);
    }
    let released = aggs.iter_mut().map(|a| a.aggregate_share().unwrap()).collect();
    Batch { task, material, shares, aggs, released }
}

fn to_openfhe(agg: &Aggregator, packed: &[u8]) -> Vec<u8> {
    agg.codec().decode(packed, Expect::Any).unwrap().serialize().unwrap()
}

fn agg_config(b: &Batch, i: usize, db: std::path::PathBuf) -> AggregatorNodeConfig {
    AggregatorNodeConfig {
        index: i,
        task: b.task.clone(),
        material: b.material.clone(),
        share: b.shares[i].clone(),
        aggregators: vec!["https://localhost:1".into(), "https://localhost:2".into()],
        collectors: vec!["https://localhost:3".into()],
        token: "t".into(),
        db,
        registry: None,
        ca_pem: Vec::new(),
    }
}

fn col_config(b: &Batch, db: std::path::PathBuf) -> CollectorNodeConfig {
    CollectorNodeConfig { task: b.task.clone(), material: b.material.clone(), collector_id: 0, seal_key: None, token: "t".into(), db }
}

#[test]
fn aggregator_node_refuses_a_state_with_shares_released_before_the_format() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let b = released_batch(140);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("agg0.db");
    let mut st = b.aggs[0].snapshot().unwrap();
    for s in st.released_aggregate_shares.values_mut() {
        for p in s.partials.iter_mut() {
            *p = to_openfhe(&b.aggs[0], p);
        }
    }
    let mut store = Store::open(&db).unwrap();
    store.put(K_TASK, &encode(&b.task).unwrap()).unwrap();
    store.put(K_STATE, &encode(&st).unwrap()).unwrap();
    drop(store);
    let e = match AggregatorNode::new(agg_config(&b, 0, db)) {
        Ok(_) => panic!("node started on a state from before the packed format"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains(LEGACY_STATE), "{e}");
}

#[test]
fn collector_node_refuses_waiting_shares_from_before_but_keeps_a_stored_result() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let b = released_batch(141);
    let dir = tempfile::tempdir().unwrap();

    // one share received before the upgrade, still waiting for the other
    let db = dir.path().join("waiting.db");
    let mut old = b.released[0].clone();
    old.partials[0] = to_openfhe(&b.aggs[0], &old.partials[0]);
    let mut store = Store::open(&db).unwrap();
    store.put("share:0", &encode(&old).unwrap()).unwrap();
    drop(store);
    let e = match CollectorNode::new(col_config(&b, db.clone())) {
        Ok(_) => panic!("collector started on a share from before the packed format"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains(LEGACY_STATE) && e.contains("aggregator 0"), "{e}");

    // the same batch already collected: the stored result stays readable
    let collector = Collector::new(b.task.clone(), &b.material).unwrap();
    let result = collector.unshard(&b.released).unwrap();
    assert_eq!(result.aggregate, AggregateResult::Count(1));
    let mut store = Store::open(&db).unwrap();
    store.put("share:1", &encode(&b.released[1]).unwrap()).unwrap();
    store.put("result", &encode(&result).unwrap()).unwrap();
    drop(store);
    CollectorNode::new(col_config(&b, db)).unwrap();

    // a share in this build's format, waiting: starts
    let db = dir.path().join("current.db");
    let mut store = Store::open(&db).unwrap();
    store.put("share:0", &encode(&b.released[0]).unwrap()).unwrap();
    drop(store);
    CollectorNode::new(col_config(&b, db)).unwrap();
}
