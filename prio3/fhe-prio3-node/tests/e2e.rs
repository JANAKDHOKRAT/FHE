//! End-to-end over real TLS sockets on localhost: two aggregator nodes, a
//! collector node, and a client. Verdict mode Count, then a restart of the
//! leader from its database in the middle of a batch.

use fhe_prio3::*;
use fhe_prio3_node::aggregator_node::{AggregatorNode, AggregatorNodeConfig};
use fhe_prio3_node::client::NetworkClient;
use fhe_prio3_node::collector_node::{CollectorNode, CollectorNodeConfig};
use fhe_prio3_node::wire::{SubmitOutcome, http_get, http_post, https_client};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::new(());

struct Tls {
    ca_pem: Vec<u8>,
    cert: PathBuf,
    key: PathBuf,
}

fn make_tls(dir: &std::path::Path) -> Tls {
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let cert = dir.join("server.pem");
    let key = dir.join("server.key");
    std::fs::write(&cert, format!("{}{}", leaf.pem(), ca.pem())).unwrap();
    std::fs::write(&key, leaf_key.serialize_pem()).unwrap();
    Tls { ca_pem: ca.pem().into_bytes(), cert, key }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Cluster {
    dir: tempfile::TempDir,
    tls: Tls,
    task: TaskConfig,
    material: PublicMaterial,
    shares: Vec<Vec<u8>>,
    agg_urls: Vec<String>,
    col_urls: Vec<String>,
    agg_ports: Vec<u16>,
    col_ports: Vec<u16>,
    /// Sealing keys by collector id (empty without policies).
    seal_keys: Vec<CollectorSealKey>,
    token: String,
    handles: Vec<axum_server::Handle>,
}

impl Cluster {
    fn new(task: TaskConfig) -> Self {
        Self::with_seal_keys(task, Vec::new())
    }

    fn with_seal_keys(task: TaskConfig, seal_keys: Vec<CollectorSealKey>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let tls = make_tls(dir.path());
        let (material, shares) = keys::run_local_ceremony(&task).unwrap();
        let n = task.num_aggregators;
        let agg_ports: Vec<u16> = (0..n).map(|_| free_port()).collect();
        let col_ports: Vec<u16> = (0..task.num_collectors()).map(|_| free_port()).collect();
        let agg_urls = agg_ports.iter().map(|p| format!("https://localhost:{p}")).collect();
        let col_urls = col_ports.iter().map(|p| format!("https://localhost:{p}")).collect();
        Self { dir, tls, task, material, shares, agg_urls, col_urls, agg_ports, col_ports, seal_keys, token: "t0k3n".into(), handles: Vec::new() }
    }

    fn agg_config(&self, i: usize) -> AggregatorNodeConfig {
        AggregatorNodeConfig {
            index: i,
            task: self.task.clone(),
            material: self.material.clone(),
            share: self.shares[i].clone(),
            aggregators: self.agg_urls.clone(),
            collectors: self.col_urls.clone(),
            token: self.token.clone(),
            db: self.dir.path().join(format!("agg{i}.db")),
            registry: None,
            ca_pem: self.tls.ca_pem.clone(),
        }
    }

    async fn start_aggregator(&mut self, i: usize) {
        let node = AggregatorNode::new(self.agg_config(i)).unwrap();
        let handle = axum_server::Handle::new();
        let addr: SocketAddr = format!("127.0.0.1:{}", self.agg_ports[i]).parse().unwrap();
        let tls = AggregatorNode::tls_config(self.tls.cert.clone(), self.tls.key.clone()).await.expect("tls config");
        let h = handle.clone();
        let task = tokio::spawn(async move { node.serve(addr, Some(tls), h).await });
        self.await_listening(&handle, task).await;
        self.handles.push(handle);
    }

    /// Waits for the server to listen, failing fast if it exited instead.
    async fn await_listening(&self, handle: &axum_server::Handle, task: tokio::task::JoinHandle<anyhow::Result<()>>) {
        tokio::select! {
            r = handle.listening() => assert!(r.is_some(), "server did not start listening"),
            r = task => panic!("server exited before listening: {:?}", r),
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => panic!("server did not start within 30 s"),
        }
    }

    async fn start_collector(&mut self, c: usize) {
        let node = CollectorNode::new(CollectorNodeConfig {
            task: self.task.clone(),
            material: self.material.clone(),
            collector_id: c as u32,
            seal_key: self.seal_keys.get(c).map(|k| CollectorSealKey::from_secret_bytes(&k.secret_bytes())),
            token: self.token.clone(),
            db: self.dir.path().join(format!("collector{c}.db")),
        })
        .unwrap();
        let handle = axum_server::Handle::new();
        let addr: SocketAddr = format!("127.0.0.1:{}", self.col_ports[c]).parse().unwrap();
        let tls = CollectorNode::tls_config(self.tls.cert.clone(), self.tls.key.clone()).await.expect("tls config");
        let h = handle.clone();
        let task = tokio::spawn(async move { node.serve(addr, Some(tls), h).await });
        self.await_listening(&handle, task).await;
        self.handles.push(handle);
    }

    async fn start_all(&mut self) {
        for c in 0..self.task.num_collectors() {
            self.start_collector(c).await;
        }
        for i in 0..self.task.num_aggregators {
            self.start_aggregator(i).await;
        }
    }

    fn client(&self) -> NetworkClient {
        NetworkClient::new(self.task.clone(), &self.material, None, self.agg_urls[0].clone(), &self.tls.ca_pem, None).unwrap()
    }

    async fn close(&self) -> anyhow::Result<BatchResult> {
        let http = https_client(&self.tls.ca_pem)?;
        let r: fhe_prio3_node::wire::CloseReply = http_post(&http, &format!("{}/v1/close", self.agg_urls[0]), Some(&self.token), &()).await?;
        r.result.ok_or_else(|| anyhow::anyhow!("no result on close"))
    }

    async fn close_policies(&self) -> anyhow::Result<Vec<u32>> {
        let http = https_client(&self.tls.ca_pem)?;
        let r: fhe_prio3_node::wire::CloseReply = http_post(&http, &format!("{}/v1/close", self.agg_urls[0]), Some(&self.token), &()).await?;
        assert!(r.result.is_none(), "policy tasks return no result to the leader");
        Ok(r.released_to)
    }

    async fn result_of(&self, c: usize) -> anyhow::Result<Option<BatchResult>> {
        let http = https_client(&self.tls.ca_pem)?;
        http_get(&http, &format!("{}/v1/result", self.col_urls[c]), Some(&self.token)).await
    }

    fn stop_all(&mut self) {
        for h in self.handles.drain(..) {
            h.shutdown();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_count_over_tls_with_leader_restart() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let task = TaskConfig::new([9u8; 32], MeasurementType::Count, 2);
    let mut c = Cluster::new(task);
    c.start_all().await;
    let client = c.client();

    assert_eq!(client.submit(&Measurement::Count(true)).await.unwrap(), SubmitOutcome::Accepted);
    assert_eq!(client.submit(&Measurement::Count(false)).await.unwrap(), SubmitOutcome::Accepted);
    // an invalid report is rejected by every node and the leader reports it
    let bad = client.inner().shard_raw(&[vec![2]]).unwrap();
    match client.submit_report(&bad).await.unwrap() {
        SubmitOutcome::Rejected(r) => assert!(r.contains("ValidityCheckFailed"), "{r}"),
        o => panic!("expected rejection, got {o:?}"),
    }
    // a replay is refused before any FHE work
    let first = client.inner().shard(&Measurement::Count(true)).unwrap();
    assert_eq!(client.submit_report(&first).await.unwrap(), SubmitOutcome::Accepted);
    match client.submit_report(&first).await.unwrap() {
        SubmitOutcome::Rejected(r) => assert!(r.contains("Replay"), "{r}"),
        o => panic!("expected replay rejection, got {o:?}"),
    }
    // unauthenticated internal calls are refused
    let http = https_client(&c.tls.ca_pem).unwrap();
    // malformed and oversized bodies are refused without touching the aggregator
    // (an all-zero body decodes as a report for task id 0 and is rejected as WrongTask;
    // a truncated body cannot decode at all)
    let resp = http.post(format!("{}/v1/submit", c.agg_urls[0])).body(vec![0xffu8; 3]).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 400, "undecodable body");
    let resp = http.post(format!("{}/v1/submit", c.agg_urls[0])).body(vec![0u8; 100]).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let out: SubmitOutcome = fhe_prio3::messages::decode(&resp.bytes().await.unwrap()).unwrap();
    assert!(matches!(out, SubmitOutcome::Rejected(ref r) if r.contains("WrongTask")), "{out:?}");
    let cap = 4 << 20; // above one fresh ciphertext (3.5 MiB) plus slack
    // The server answers 413 as soon as the declared length exceeds the cap,
    // while the client may still be uploading; the client then sees either
    // the 413 or a reset connection. Both mean the upload was refused.
    let mut refused = false;
    for _ in 0..5 {
        match http.post(format!("{}/v1/submit", c.agg_urls[0])).body(vec![0u8; cap]).send().await {
            Ok(resp) => {
                assert_eq!(resp.status().as_u16(), 413, "oversized body");
                refused = true;
                break;
            }
            Err(e) => assert!(e.is_request() || e.is_body() || e.is_connect(), "unexpected error on oversized upload: {e}"),
        }
    }
    if !refused {
        // Five resets in a row: the server closed on us each time; it must still be up.
        let st: fhe_prio3_node::wire::StatusReply = http_get(&http, &format!("{}/v1/status", c.agg_urls[0]), None).await.unwrap();
        assert_eq!(st.accepted, 3);
    }
    // a helper refuses client submissions and group tickets
    let resp = http.get(format!("{}/v1/group", c.agg_urls[1])).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    // a wrong-token close is refused
    let resp = http.post(format!("{}/v1/close", c.agg_urls[0])).header("x-fhe-prio3-token", "nope").send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let r: anyhow::Result<CountShare> = http_post(&http, &format!("{}/v1/count-share", c.agg_urls[1]), Some("wrong"), &()).await;
    match r {
        Err(e) => assert!(e.to_string().contains("401"), "{e}"),
        Ok(_) => panic!("internal endpoint accepted a wrong token"),
    }

    // Restart the leader from its database: three accepted reports so far.
    // (handles: [collector, aggregator 0, aggregator 1])
    c.handles[1].shutdown();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    c.start_aggregator(0).await;
    let st: fhe_prio3_node::wire::StatusReply = http_get(&http, &format!("{}/v1/status", c.agg_urls[0]), None).await.unwrap();
    assert_eq!((st.accepted, st.closed), (3, false));

    assert_eq!(client.submit(&Measurement::Count(true)).await.unwrap(), SubmitOutcome::Accepted);
    let r = c.close().await.unwrap();
    assert_eq!((r.aggregate, r.report_count, r.valid_count), (AggregateResult::Count(3), 4, 4));
    // closed: further reports refused, close again fails
    match client.submit(&Measurement::Count(true)).await.unwrap() {
        SubmitOutcome::Rejected(r) => assert!(r.contains("BatchClosed"), "{r}"),
        o => panic!("expected BatchClosed, got {o:?}"),
    }
    c.stop_all();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_batched_sum_over_tls() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut task = TaskConfig::new_silent([10u8; 32], MeasurementType::Sum { max_measurement: 100 }, 2);
    task.silent_batch_groups = 2;
    let mut c = Cluster::new(task);
    c.start_all().await;
    let client = c.client();
    for v in [51u64, 49, 100] {
        assert_eq!(client.submit(&Measurement::Sum(v)).await.unwrap(), SubmitOutcome::Accepted);
    }
    // invalid (out of range) report is admitted and contributes zero
    let bits = |v: u64| -> Vec<u64> { (0..7).map(|i| (v >> i) & 1).collect() };
    let mut bad = bits(101);
    bad.extend(bits(127));
    let r = client.inner().shard_raw_elements_in_group(&[bad], 1).unwrap();
    assert_eq!(client.submit_report(&r).await.unwrap(), SubmitOutcome::Accepted);
    let r = c.close().await.unwrap();
    assert_eq!((r.aggregate, r.report_count, r.valid_count), (AggregateResult::Sum(200), 4, 3));
    c.stop_all();
}

/// Two collectors with disjoint release policies over TLS: each collector
/// process receives only its own sealed shares, opens them with its own key
/// and serves only its own elements; the leader relays opaque envelopes and
/// gets no result; a helper refuses an unknown collector id; a collector
/// refuses an envelope sealed for another collector; a wrong sealing key
/// fails at startup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_collectors_with_policies_over_tls() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = MeasurementType::BoundedSumVec { bounds: vec![100, 5, 15, 15] };
    let k0 = CollectorSealKey::generate();
    let k1 = CollectorSealKey::generate();
    let mut task = TaskConfig::new([11u8; 32], t.clone(), 2);
    task.moments = true;
    task.max_batch_size = task.moments_max_batch().unwrap().min(1 << 20);
    task.collectors = vec![
        CollectorPolicy { elements: vec![0, 1], moments: false, seal_key: k0.public_key() },
        CollectorPolicy { elements: vec![2, 3], moments: true, seal_key: k1.public_key() },
    ];
    task.validate().unwrap();
    let mut c = Cluster::with_seal_keys(task.clone(), vec![CollectorSealKey::from_secret_bytes(&k0.secret_bytes()), CollectorSealKey::from_secret_bytes(&k1.secret_bytes())]);
    c.start_all().await;
    let client = c.client();
    let rows = vec![vec![10u64, 1, 8, 8], vec![20, 5, 7, 6], vec![100, 3, 15, 15], vec![40, 1, 11, 12]];
    for r in &rows {
        assert_eq!(client.submit(&Measurement::SumVec(r.clone())).await.unwrap(), SubmitOutcome::Accepted);
    }
    let http = https_client(&c.tls.ca_pem).unwrap();
    // a helper refuses a collector id the task does not declare
    let r: anyhow::Result<fhe_prio3_node::wire::ShareReply> =
        http_post(&http, &format!("{}/v1/aggregate-share", c.agg_urls[1]), Some(&c.token), &fhe_prio3_node::wire::ShareRequest { collector: 7 }).await;
    assert!(r.err().expect("unknown collector").to_string().contains("400"));
    // the leader closes: releases go to both collectors, no result comes back
    assert_eq!(c.close_policies().await.unwrap(), vec![0, 1]);
    let all = t.aggregate_plain(&rows.iter().map(|r| Measurement::SumVec(r.clone())).collect::<Vec<_>>()).unwrap();
    let AggregateResult::SumVec(all) = all else { panic!() };
    let r0 = c.result_of(0).await.unwrap().expect("collector 0 complete");
    assert_eq!((r0.collector, &r0.elements, r0.aggregate.clone(), r0.report_count), (0, &vec![0, 1], AggregateResult::SumVec(vec![all[0], all[1], 0, 0]), 4));
    assert!(r0.regression.is_none());
    let r1 = c.result_of(1).await.unwrap().expect("collector 1 complete");
    assert_eq!((r1.collector, &r1.elements, r1.aggregate.clone()), (1, &vec![2, 3], AggregateResult::SumVec(vec![0, 0, all[2], all[3]])));
    let reg = r1.regression.expect("collector 1 has moments");
    let plain = fhe_prio3::types::regression_plain(&rows.iter().map(|r| vec![r[2], r[3]]).collect::<Vec<_>>());
    assert_eq!((reg.n, &reg.first, &reg.second), (plain.n, &plain.first, &plain.second));
    // an envelope sealed for collector 1 is refused by collector 0
    let sealed1: fhe_prio3_node::wire::ShareReply =
        http_post(&http, &format!("{}/v1/aggregate-share", c.agg_urls[1]), Some(&c.token), &fhe_prio3_node::wire::ShareRequest { collector: 1 }).await.unwrap();
    let fhe_prio3_node::wire::ShareReply::Sealed(sealed1) = sealed1 else { panic!("policy tasks seal") };
    assert!(fhe_prio3::seal::open(&sealed1, &k0).is_err(), "the leader-visible envelope is opaque to another key");
    let r: anyhow::Result<fhe_prio3_node::wire::ShareReceipt> =
        http_post(&http, &format!("{}/v1/aggregate-share", c.col_urls[0]), Some(&c.token), &fhe_prio3_node::wire::SealedEnvelope { sealed: sealed1 }).await;
    assert!(r.err().expect("wrong collector").to_string().contains("400"));
    // closing again is idempotent: the same releases
    assert_eq!(c.close_policies().await.unwrap(), vec![0, 1]);
    c.stop_all();
    // a collector started with a key the task does not declare refuses to start
    let bad = CollectorNode::new(CollectorNodeConfig {
        task: task.clone(),
        material: c.material.clone(),
        collector_id: 1,
        seal_key: Some(CollectorSealKey::generate()),
        token: c.token.clone(),
        db: c.dir.path().join("bad.db"),
    });
    assert!(bad.is_err());
    let none = CollectorNode::new(CollectorNodeConfig { task, material: c.material.clone(), collector_id: 0, seal_key: None, token: c.token.clone(), db: c.dir.path().join("bad2.db") });
    assert!(none.is_err());
}
