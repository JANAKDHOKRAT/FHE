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
    col_url: String,
    agg_ports: Vec<u16>,
    col_port: u16,
    token: String,
    handles: Vec<axum_server::Handle>,
}

impl Cluster {
    fn new(task: TaskConfig) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let tls = make_tls(dir.path());
        let (material, shares) = keys::run_local_ceremony(&task).unwrap();
        let n = task.num_aggregators;
        let agg_ports: Vec<u16> = (0..n).map(|_| free_port()).collect();
        let col_port = free_port();
        let agg_urls = agg_ports.iter().map(|p| format!("https://localhost:{p}")).collect();
        let col_url = format!("https://localhost:{col_port}");
        Self { dir, tls, task, material, shares, agg_urls, col_url, agg_ports, col_port, token: "t0k3n".into(), handles: Vec::new() }
    }

    fn agg_config(&self, i: usize) -> AggregatorNodeConfig {
        AggregatorNodeConfig {
            index: i,
            task: self.task.clone(),
            material: self.material.clone(),
            share: self.shares[i].clone(),
            aggregators: self.agg_urls.clone(),
            collector: self.col_url.clone(),
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

    async fn start_collector(&mut self) {
        let node = CollectorNode::new(CollectorNodeConfig {
            task: self.task.clone(),
            material: self.material.clone(),
            token: self.token.clone(),
            db: self.dir.path().join("collector.db"),
        })
        .unwrap();
        let handle = axum_server::Handle::new();
        let addr: SocketAddr = format!("127.0.0.1:{}", self.col_port).parse().unwrap();
        let tls = CollectorNode::tls_config(self.tls.cert.clone(), self.tls.key.clone()).await.expect("tls config");
        let h = handle.clone();
        let task = tokio::spawn(async move { node.serve(addr, Some(tls), h).await });
        self.await_listening(&handle, task).await;
        self.handles.push(handle);
    }

    async fn start_all(&mut self) {
        self.start_collector().await;
        for i in 0..self.task.num_aggregators {
            self.start_aggregator(i).await;
        }
    }

    fn client(&self) -> NetworkClient {
        NetworkClient::new(self.task.clone(), &self.material, None, self.agg_urls[0].clone(), &self.tls.ca_pem, None).unwrap()
    }

    async fn close(&self) -> anyhow::Result<BatchResult> {
        let http = https_client(&self.tls.ca_pem)?;
        http_post(&http, &format!("{}/v1/close", self.agg_urls[0]), Some(&self.token), &()).await
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
