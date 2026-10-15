//! The load-test tool end to end, against a split-key deployment in this
//! process (the aggregator and the collector over real TLS sockets, each
//! with its metrics listener), at small parameters: every report delivered,
//! the released result checked exactly (small cells suppressed), the nodes'
//! metrics scraped into the report. The run is interrupted and resumed from
//! its client state, with a report the leader committed but whose answer
//! the client never journaled (the machine died in between): resent with
//! the same bytes, it is answered as a replay and counted once. The
//! production-size runs use the same code through `loadtest/run.sh`
//! (README, "Load test").

use fhe_prio3::*;
use fhe_prio3_node::aggregator_node::{AggregatorNode, AggregatorNodeConfig};
use fhe_prio3_node::collector_node::{CollectorNode, CollectorNodeConfig};
use fhe_prio3_node::loadtest::{self, LoadConfig};
use fhe_prio3_node::metrics::spawn_metrics_server;
use fhe_prio3_node::wire::ServerHandle;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn wait_listening(handle: &ServerHandle) {
    tokio::time::timeout(Duration::from_secs(60), handle.listening())
        .await
        .expect("server did not start within 60 s")
        .expect("server did not start listening");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loadtest_against_a_split_key_deployment() {
    let dir = tempfile::tempdir().unwrap();
    // TLS: a CA and a localhost leaf
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    let (cert, key) = (dir.path().join("server.pem"), dir.path().join("server.key"));
    std::fs::write(&cert, format!("{}{}", leaf.pem(), ca.pem())).unwrap();
    std::fs::write(&key, leaf_key.serialize_pem()).unwrap();
    let ca_pem = ca.pem().into_bytes();

    let mut task = TaskConfig::new_split_key([0x5a; 32], MeasurementType::Histogram { length: 4 });
    task.silent_batch_groups = 1;
    task.repetitions = 4;
    task.min_batch_size = 2;
    task.min_cell_count = 2;
    let keys::LocalKeys {
        material,
        aggregator_secrets,
        collector_secret,
    } = keys::run_local_key_ceremony(&task).unwrap();
    let (agg_port, col_port) = (free_port(), free_port());
    let token = "loadt0k3n".to_string();

    let collector = CollectorNode::new(CollectorNodeConfig {
        task: task.clone(),
        material: fhe_prio3_node::router::client_material(&material),
        collector_id: 0,
        seal_key: None,
        token: token.clone(),
        db: dir.path().join("collector.db"),
        key_share: collector_secret,
        upload_key: None,
    })
    .unwrap();
    let col_metrics = spawn_metrics_server(collector.metrics(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let aggregator = AggregatorNode::new(AggregatorNodeConfig {
        index: 0,
        task: task.clone(),
        material: material.clone(),
        share: aggregator_secrets[0].clone(),
        aggregators: vec![format!("https://localhost:{agg_port}")],
        collectors: vec![format!("https://localhost:{col_port}")],
        token: token.clone(),
        db: dir.path().join("aggregator.db"),
        registry: None,
        ca_pem: ca_pem.clone(),
        upload_key: None,
    })
    .unwrap();
    let agg_metrics = spawn_metrics_server(aggregator.metrics(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut handles = Vec::new();
    for (node, port) in [(Ok(collector), col_port), (Err(aggregator), agg_port)] {
        let handle = ServerHandle::new();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let tls = AggregatorNode::tls_config(cert.clone(), key.clone()).await.unwrap();
        let h = handle.clone();
        match node {
            Ok(c) => drop(tokio::spawn(async move { c.serve(addr, Some(tls), h).await })),
            Err(a) => drop(tokio::spawn(async move { a.serve(addr, Some(tls), h).await })),
        }
        wait_listening(&handle).await;
        handles.push(handle);
    }

    let reports = 20;
    let state = dir.path().join("client-state");
    let cfg = |reports: u64, close: bool, timeline: &str| LoadConfig {
        task: task.clone(),
        material: fhe_prio3_node::router::client_material(&material),
        leader: format!("https://localhost:{agg_port}"),
        ca_pem: ca_pem.clone(),
        token: token.clone(),
        reports,
        workers: 2,
        seed: 3,
        invalid_every: 5,
        metrics: vec![
            ("aggregator".into(), format!("http://{agg_metrics}")),
            ("collector".into(), format!("http://{col_metrics}")),
        ],
        scrape_every: Duration::from_secs(1),
        timeline: Some(dir.path().join(timeline)),
        close,
        close_timeout: Duration::from_secs(3600),
        state_dir: Some(state.clone()),
    };
    // first run: reports 0..19, no close
    let first = loadtest::run(cfg(reports - 1, false, "timeline-1.jsonl")).await.unwrap();
    assert_eq!(first.verdict, Ok(()));
    assert_eq!((first.outcomes.accepted, first.answered_before, first.resent), (reports - 1, 0, 0));
    // report 19 (invalid: 19 % 5 == 4) built exactly as the tool builds it,
    // committed by the leader, left pending in the client state
    let client = Client::new(task.clone(), &material.context, &material.public_key).unwrap();
    let r19 = loadtest::make_report(&client, &task, 3, 5, reports - 1, 0).unwrap();
    let bytes = fhe_prio3::messages::encode(&r19).unwrap();
    let http = fhe_prio3_node::wire::https_client(&ca_pem).unwrap();
    let out: fhe_prio3_node::wire::SubmitOutcome = fhe_prio3_node::wire::http_post(&http, &format!("https://localhost:{agg_port}/v1/submit"), None, &r19)
        .await
        .unwrap();
    assert_eq!(out, fhe_prio3_node::wire::SubmitOutcome::Accepted);
    std::fs::write(state.join("pending").join(format!("{}.report", reports - 1)), &bytes).unwrap();
    // resumed run over all 20: 19 answered before, report 19 resent and
    // answered as a replay (counted once, as accepted), then the close
    let report = loadtest::run(cfg(reports, true, "timeline.jsonl")).await.unwrap();
    for h in handles {
        h.shutdown();
    }
    assert_eq!((report.answered_before, report.resent), (reports - 1, 1));
    assert!(std::fs::read_dir(state.join("pending")).unwrap().next().is_none(), "nothing left pending");
    let journal = std::fs::read_to_string(state.join("answers.log")).unwrap();
    assert_eq!(journal.lines().count(), reports as usize);

    // every report delivered once, the released result exactly the expected one
    assert_eq!(report.verdict, Ok(()), "{:?}", report.close_error);
    assert_eq!((report.outcomes.accepted, report.outcomes.failed), (reports, 0));
    assert!(report.outcomes.rejected.is_empty(), "{:?}", report.outcomes.rejected);
    assert_eq!((report.expected.valid, report.expected.invalid), (16, 4));
    let r = report.result.as_ref().expect("released result");
    let want: Vec<u64> = report.expected.elements.iter().map(|&c| if c < 2 { 0 } else { c as u64 }).collect();
    assert_eq!(r.aggregate, AggregateResult::Histogram(want));
    assert!(r.counts_withheld);
    assert_eq!(r.suppressed, (0..4).filter(|&e| report.expected.elements[e] < 2).collect::<Vec<_>>());
    // client timings: the first run's 19 encryptions; the resumed run only
    // resent (no encryption), with a submit time and a close duration
    assert_eq!((first.encrypt.n, first.submit.n), (reports as usize - 1, reports as usize - 1));
    assert!(first.encrypt.p50 > 0.0 && first.submit.max >= first.submit.p50);
    assert_eq!((report.encrypt.n, report.submit.n), (0, 1));
    assert!(report.close_seconds.unwrap() > 0.0);
    // the nodes' metrics were scraped: peaks and the final exposition; the
    // leader saw 20 accepted reports and one replay
    assert!(report.peaks["aggregator"].resident_memory_bytes > 0.0);
    assert!(report.peaks["collector"].db_size_bytes > 0.0);
    let agg = loadtest::parse_metrics(&report.final_metrics["aggregator"]);
    assert_eq!(agg[r#"fhe_prio3_reports_total{outcome="accepted",reason="none"}"#], reports as f64);
    assert_eq!(agg[r#"fhe_prio3_reports_total{outcome="rejected",reason="Replay"}"#], 1.0);
    assert_eq!(agg[r#"fhe_prio3_batch{field="closed"}"#], 1.0);
    let col = loadtest::parse_metrics(&report.final_metrics["collector"]);
    assert_eq!(col[r#"fhe_prio3_batch{field="result_ready"}"#], 1.0);
    let timeline = std::fs::read_to_string(dir.path().join("timeline.jsonl")).unwrap();
    assert!(timeline.lines().count() >= 2, "{timeline}");
}
