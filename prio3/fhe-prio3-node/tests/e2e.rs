//! End-to-end over real TLS sockets on localhost: two aggregator nodes, a
//! collector node, and a client. Verdict mode Count, then a restart of the
//! leader from its database in the middle of a batch.

use fhe_prio3::*;
use fhe_prio3_node::aggregator_node::{AggregatorNode, AggregatorNodeConfig};
use fhe_prio3_node::client::NetworkClient;
use fhe_prio3_node::collector_node::{CollectorNode, CollectorNodeConfig};
use fhe_prio3_node::metrics::spawn_metrics_server;
use fhe_prio3_node::store::{IdKind, Store};
use fhe_prio3_node::wire::{ServerHandle, SubmitOutcome, http_get, http_post, https_client};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;

/// Serialises the tests of this file. An async lock: each guard is held
/// across the awaits of a whole deployment.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    Tls {
        ca_pem: ca.pem().into_bytes(),
        cert,
        key,
    }
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
    /// Split-key tasks: the collector's key share.
    collector_share: Option<Vec<u8>>,
    agg_urls: Vec<String>,
    col_urls: Vec<String>,
    agg_ports: Vec<u16>,
    col_ports: Vec<u16>,
    /// Sealing keys by collector id (empty without policies).
    seal_keys: Vec<CollectorSealKey>,
    token: String,
    handles: Vec<ServerHandle>,
    /// Metrics listener of each node's latest start.
    agg_metrics: Vec<Option<SocketAddr>>,
    col_metrics: Vec<Option<SocketAddr>>,
}

/// One scrape of a node's `/metrics`: (series name, labels, value).
struct Scrape(Vec<(String, std::collections::BTreeMap<String, String>, f64)>);

impl Scrape {
    async fn of(addr: SocketAddr) -> Self {
        let text = reqwest::get(format!("http://{addr}/metrics")).await.unwrap().text().await.unwrap();
        let mut out = Vec::new();
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let (series, value) = line.rsplit_once(' ').unwrap();
            let value: f64 = value.parse().unwrap();
            let (name, labels) = match series.split_once('{') {
                None => (series.to_string(), Default::default()),
                Some((n, rest)) => {
                    let mut labels = std::collections::BTreeMap::new();
                    let body = rest.strip_suffix('}').unwrap();
                    // label values here never contain `",`
                    for pair in body.split("\",").filter(|p| !p.is_empty()) {
                        let (k, v) = pair.split_once("=\"").unwrap();
                        labels.insert(k.to_string(), v.trim_end_matches('"').to_string());
                    }
                    (n.to_string(), labels)
                }
            };
            out.push((name, labels, value));
        }
        Scrape(out)
    }

    /// The value of the series with exactly these labels (0 when absent:
    /// a labelled counter has no series until its first increment).
    fn get(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        let want: std::collections::BTreeMap<String, String> = labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        self.0.iter().find(|(n, l, _)| n == name && *l == want).map(|(_, _, v)| *v).unwrap_or(0.0)
    }

    /// Sum over every series of `name` whose labels include these.
    fn sum(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        self.0
            .iter()
            .filter(|(n, l, _)| n == name && labels.iter().all(|(k, v)| l.get(*k).map(String::as_str) == Some(*v)))
            .map(|(_, _, v)| *v)
            .sum()
    }
}

impl Cluster {
    fn new(task: TaskConfig) -> Self {
        Self::with_seal_keys(task, Vec::new())
    }

    fn with_seal_keys(task: TaskConfig, seal_keys: Vec<CollectorSealKey>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let tls = make_tls(dir.path());
        let keys::LocalKeys {
            material,
            aggregator_secrets: shares,
            collector_secret: collector_share,
        } = keys::run_local_key_ceremony(&task).unwrap();
        let n = task.num_aggregators;
        let agg_ports: Vec<u16> = (0..n).map(|_| free_port()).collect();
        let col_ports: Vec<u16> = (0..task.num_collectors()).map(|_| free_port()).collect();
        let agg_urls = agg_ports.iter().map(|p| format!("https://localhost:{p}")).collect();
        let col_urls = col_ports.iter().map(|p| format!("https://localhost:{p}")).collect();
        let num_collectors = task.num_collectors();
        Self {
            dir,
            tls,
            task,
            material,
            shares,
            collector_share,
            agg_urls,
            col_urls,
            agg_ports,
            col_ports,
            seal_keys,
            token: "t0k3n".into(),
            handles: Vec::new(),
            agg_metrics: vec![None; n],
            col_metrics: vec![None; num_collectors],
        }
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

    /// Client reports stored in each aggregator's database.
    fn stored_reports(&self) -> Vec<usize> {
        (0..self.task.num_aggregators)
            .map(|i| {
                Store::open(&self.dir.path().join(format!("agg{i}.db")))
                    .unwrap()
                    .names_with_prefix("report:")
                    .unwrap()
                    .len()
            })
            .collect()
    }

    async fn start_aggregator(&mut self, i: usize) {
        let node = AggregatorNode::new(self.agg_config(i)).unwrap();
        self.agg_metrics[i] = Some(spawn_metrics_server(node.metrics(), "127.0.0.1:0".parse().unwrap()).unwrap());
        let handle = ServerHandle::new();
        let addr: SocketAddr = format!("127.0.0.1:{}", self.agg_ports[i]).parse().unwrap();
        let tls = AggregatorNode::tls_config(self.tls.cert.clone(), self.tls.key.clone())
            .await
            .expect("tls config");
        let h = handle.clone();
        let task = tokio::spawn(async move { node.serve(addr, Some(tls), h).await });
        self.await_listening(&handle, task).await;
        self.handles.push(handle);
    }

    /// Waits for the server to listen, failing fast if it exited instead.
    async fn await_listening(&self, handle: &ServerHandle, task: tokio::task::JoinHandle<anyhow::Result<()>>) {
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
            key_share: self.collector_share.clone(),
        })
        .unwrap();
        self.col_metrics[c] = Some(spawn_metrics_server(node.metrics(), "127.0.0.1:0".parse().unwrap()).unwrap());
        let handle = ServerHandle::new();
        let addr: SocketAddr = format!("127.0.0.1:{}", self.col_ports[c]).parse().unwrap();
        let tls = CollectorNode::tls_config(self.tls.cert.clone(), self.tls.key.clone())
            .await
            .expect("tls config");
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
    let _g = SERIAL.lock().await;
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
    // (a truncated body cannot decode at all; a well-formed report for
    // another task decodes and is rejected as WrongTask; a body with bytes
    // after the message is refused, since a message has exactly one encoding)
    let resp = http.post(format!("{}/v1/submit", c.agg_urls[0])).body(vec![0xffu8; 3]).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 400, "undecodable body");
    let mut other_task = client.inner().shard(&Measurement::Count(true)).unwrap();
    other_task.task_id = [0u8; 32];
    let body = fhe_prio3::messages::encode(&other_task).unwrap();
    let resp = http.post(format!("{}/v1/submit", c.agg_urls[0])).body(body.clone()).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let out: SubmitOutcome = fhe_prio3::messages::decode(&resp.bytes().await.unwrap()).unwrap();
    assert!(matches!(out, SubmitOutcome::Rejected(ref r) if r.contains("WrongTask")), "{out:?}");
    let mut trailing = body;
    trailing.push(0);
    let resp = http.post(format!("{}/v1/submit", c.agg_urls[0])).body(trailing).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 400, "trailing byte after the report");
    let cap = 4 << 20; // above one packed fresh ciphertext (2.7 MiB) plus the 64 KiB slack
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
    // The server closes a connection it refused with 413; a pooled client
    // could race that close on its next request, so continue on a new one.
    let http = https_client(&c.tls.ca_pem).unwrap();
    if !refused {
        // Five resets in a row: the server closed on us each time; it must still be up.
        let st: fhe_prio3_node::wire::StatusReply = http_get(&http, &format!("{}/v1/status", c.agg_urls[0]), None).await.unwrap();
        assert_eq!(st.accepted, 3);
    }
    // a helper refuses client submissions and group tickets
    let resp = http.get(format!("{}/v1/group", c.agg_urls[1])).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    // a wrong-token close is refused
    let resp = http
        .post(format!("{}/v1/close", c.agg_urls[0]))
        .header("x-fhe-prio3-token", "nope")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let r: anyhow::Result<CountShare> = http_post(&http, &format!("{}/v1/count-share", c.agg_urls[1]), Some("wrong"), &()).await;
    match r {
        Err(e) => assert!(e.to_string().contains("401"), "{e}"),
        Ok(_) => panic!("internal endpoint accepted a wrong token"),
    }

    // The leader's and the helper's metrics count each outcome above.
    let leader = Scrape::of(c.agg_metrics[0].unwrap()).await;
    let helper = Scrape::of(c.agg_metrics[1].unwrap()).await;
    assert_eq!(leader.get("fhe_prio3_reports_total", &[("outcome", "accepted"), ("reason", "none")]), 3.0);
    for reason in ["ValidityCheckFailed", "Replay", "WrongTask"] {
        assert_eq!(
            leader.get("fhe_prio3_reports_total", &[("outcome", "rejected"), ("reason", reason)]),
            1.0,
            "{reason}"
        );
    }
    // the undecodable body and the one with a trailing byte
    assert_eq!(leader.get("fhe_prio3_reports_total", &[("outcome", "error"), ("reason", "Undecodable")]), 2.0);
    assert_eq!(leader.get("fhe_prio3_http_requests_total", &[("route", "/v1/submit"), ("status", "400")]), 2.0);
    assert_eq!(leader.get("fhe_prio3_http_requests_total", &[("route", "/v1/close"), ("status", "401")]), 1.0);
    assert_eq!(helper.get("fhe_prio3_http_requests_total", &[("route", "/v1/group"), ("status", "404")]), 1.0);
    assert_eq!(
        helper.get("fhe_prio3_http_requests_total", &[("route", "/v1/count-share"), ("status", "401")]),
        1.0
    );
    // a verdict-mode report is five rounds with the helper
    for (route, n) in [
        ("/v1/report", 4.0),
        ("/v1/mask-commits", 4.0),
        ("/v1/masks", 4.0),
        ("/v1/commits", 4.0),
        ("/v1/verifiers", 4.0),
    ] {
        assert_eq!(
            helper.get("fhe_prio3_http_requests_total", &[("route", route), ("status", "200")]),
            n,
            "{route}"
        );
    }

    // Restart the leader from its database: three accepted reports so far.
    // (handles: [collector, aggregator 0, aggregator 1])
    // Verdict mode adds an accepted report to the sums at once, so no
    // report is stored. A report row no restore needs (an earlier build
    // stored every accepted report) is deleted when the node starts.
    c.handles[1].shutdown();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(c.stored_reports(), vec![0, 0]);
    Store::open(&c.dir.path().join("agg0.db"))
        .unwrap()
        .put(&format!("report:{}", hex::encode([7u8; 32])), &[1, 2, 3])
        .unwrap();
    assert_eq!(c.stored_reports(), vec![1, 0]);
    // Report ids are appended to their own table, one row each, not
    // rewritten with every step: four seen (the invalid report too), three
    // accepted, none in the snapshot.
    let db0 = c.dir.path().join("agg0.db");
    {
        let s = Store::open(&db0).unwrap();
        let (seen, accepted) = (s.ids(IdKind::Seen).unwrap(), s.ids(IdKind::Accepted).unwrap());
        assert_eq!((seen.len(), accepted.len()), (4, 3));
        assert!(accepted.iter().all(|a| seen.contains(a)));
        let mut st: AggregatorState = fhe_prio3::messages::decode(&s.get("aggregator_state").unwrap().unwrap()).unwrap();
        assert!(st.seen.is_empty() && st.accepted_ids.is_empty());
        // Turn it into a database of an earlier build (ids inside the
        // snapshot, no ids table rows): the node must start from it and
        // move the ids to the table at its next commit.
        st.seen = seen;
        st.accepted_ids = accepted;
        drop(s);
        let mut s = Store::open(&db0).unwrap();
        s.put("aggregator_state", &fhe_prio3::messages::encode(&st).unwrap()).unwrap();
        rusqlite::Connection::open(&db0).unwrap().execute("DELETE FROM ids", []).unwrap();
        assert!(s.ids(IdKind::Seen).unwrap().is_empty());
    }
    c.start_aggregator(0).await;
    assert_eq!(c.stored_reports(), vec![0, 0]);
    let st: fhe_prio3_node::wire::StatusReply = http_get(&http, &format!("{}/v1/status", c.agg_urls[0]), None).await.unwrap();
    assert_eq!((st.accepted, st.closed), (3, false));
    // the restarted leader still refuses a replay of a report it admitted
    match client.submit_report(&first).await.unwrap() {
        SubmitOutcome::Rejected(r) => assert!(r.contains("Replay"), "{r}"),
        o => panic!("expected replay rejection after the restart, got {o:?}"),
    }

    assert_eq!(client.submit(&Measurement::Count(true)).await.unwrap(), SubmitOutcome::Accepted);
    // that commit moved every id to the table (and out of the snapshot)
    {
        let s = Store::open(&db0).unwrap();
        assert_eq!((s.ids(IdKind::Seen).unwrap().len(), s.ids(IdKind::Accepted).unwrap().len()), (5, 4));
        let st: AggregatorState = fhe_prio3::messages::decode(&s.get("aggregator_state").unwrap().unwrap()).unwrap();
        assert!(st.seen.is_empty() && st.accepted_ids.is_empty());
    }
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
    let _g = SERIAL.lock().await;
    let mut task = TaskConfig::new_silent([10u8; 32], MeasurementType::Sum { max_measurement: 100 }, 2);
    task.silent_batch_groups = 2;
    let mut c = Cluster::new(task);
    c.start_all().await;
    let client = c.client();
    // A stored report is kept only while its verification ciphertext is
    // open (restore rebuilds that ciphertext from it); two groups, so every
    // second report flushes the pair and both rows go, on every aggregator.
    for (v, kept) in [(51u64, 1usize), (49, 0), (100, 1)] {
        assert_eq!(client.submit(&Measurement::Sum(v)).await.unwrap(), SubmitOutcome::Accepted);
        assert_eq!(c.stored_reports(), vec![kept; 2], "after submitting {v}");
    }
    // invalid (a non-bit slot claiming 101) report is admitted and contributes zero
    let bad = vec![0u64, 0, 0, 0, 0, 2, 1];
    let r = client.inner().shard_raw_elements_in_group(&[bad], 1).unwrap();
    assert_eq!(client.submit_report(&r).await.unwrap(), SubmitOutcome::Accepted);
    assert_eq!(c.stored_reports(), vec![0, 0]);
    // every admitted report's id appended once on each aggregator
    for i in 0..2 {
        let s = Store::open(&c.dir.path().join(format!("agg{i}.db"))).unwrap();
        assert_eq!(
            (s.ids(IdKind::Seen).unwrap().len(), s.ids(IdKind::Accepted).unwrap().len()),
            (4, 4),
            "aggregator {i}"
        );
    }
    let r = c.close().await.unwrap();
    assert_eq!((r.aggregate, r.report_count, r.valid_count), (AggregateResult::Sum(200), 4, 3));

    // What each node's /metrics says about this batch, exactly.
    let leader = Scrape::of(c.agg_metrics[0].unwrap()).await;
    let helper = Scrape::of(c.agg_metrics[1].unwrap()).await;
    let collector = Scrape::of(c.col_metrics[0].unwrap()).await;
    let h = c.agg_urls[1].as_str();
    // silent mode admits the invalid report too (it is zeroed under encryption)
    assert_eq!(leader.get("fhe_prio3_reports_total", &[("outcome", "accepted"), ("reason", "none")]), 4.0);
    assert_eq!(leader.sum("fhe_prio3_reports_total", &[("outcome", "rejected")]), 0.0);
    assert_eq!(leader.get("fhe_prio3_http_requests_total", &[("route", "/v1/submit"), ("status", "200")]), 4.0);
    assert_eq!(leader.get("fhe_prio3_http_requests_total", &[("route", "/v1/group"), ("status", "200")]), 3.0);
    assert_eq!(leader.get("fhe_prio3_http_requests_total", &[("route", "/v1/close"), ("status", "200")]), 1.0);
    assert_eq!(leader.get("fhe_prio3_step_duration_seconds_count", &[("step", "silent_admit")]), 4.0);
    assert_eq!(helper.get("fhe_prio3_step_duration_seconds_count", &[("step", "silent_admit")]), 4.0);
    assert_eq!(
        leader.get("fhe_prio3_peer_requests_total", &[("outcome", "ok"), ("peer", h), ("route", "/v1/report")]),
        4.0
    );
    assert_eq!(leader.sum("fhe_prio3_peer_requests_total", &[("outcome", "error")]), 0.0);
    assert_eq!(helper.get("fhe_prio3_http_requests_total", &[("route", "/v1/report"), ("status", "200")]), 4.0);
    for route in ["/v1/count-share", "/v1/count-commit", "/v1/count-open", "/v1/count-reveal", "/v1/count-finish"] {
        assert_eq!(
            helper.get("fhe_prio3_http_requests_total", &[("route", route), ("status", "200")]),
            1.0,
            "{route}"
        );
    }
    for phase in ["close", "count", "release"] {
        assert_eq!(leader.get("fhe_prio3_phase_duration_seconds_count", &[("phase", phase)]), 1.0, "{phase}");
    }
    assert_eq!(leader.sum("fhe_prio3_phase_failures_total", &[]), 0.0);
    assert_eq!(leader.get("fhe_prio3_batch", &[("field", "accepted")]), 4.0);
    assert_eq!(leader.get("fhe_prio3_batch", &[("field", "pending")]), 0.0);
    assert_eq!(leader.get("fhe_prio3_batch", &[("field", "closed")]), 1.0);
    for node in [&leader, &helper, &collector] {
        assert_eq!(node.sum("fhe_prio3_step_failures_total", &[]), 0.0);
        assert_eq!(node.get("fhe_prio3_lock_waiters", &[]), 0.0);
        assert_eq!(node.get("fhe_prio3_step_active_since_timestamp_seconds", &[]), 0.0);
        assert_eq!(node.get("fhe_prio3_http_requests_in_flight", &[]), 0.0);
        assert!(node.get("fhe_prio3_db_written_bytes_total", &[]) > 0.0);
        assert!(node.get("fhe_prio3_db_size_bytes", &[]) > 0.0);
        assert!(node.get("fhe_prio3_last_progress_timestamp_seconds", &[]) >= node.get("fhe_prio3_start_time_seconds", &[]));
        assert!(node.get("process_resident_memory_bytes", &[]) > 0.0);
    }
    assert_eq!(collector.get("fhe_prio3_batch", &[("field", "shares_received")]), 2.0);
    assert_eq!(collector.get("fhe_prio3_batch", &[("field", "result_ready")]), 1.0);
    assert_eq!(
        collector.get("fhe_prio3_http_requests_total", &[("route", "/v1/aggregate-share"), ("status", "200")]),
        2.0
    );
    assert_eq!(
        collector.get("fhe_prio3_http_requests_total", &[("route", "/v1/release-reveals"), ("status", "200")]),
        1.0
    );
    assert_eq!(
        collector.get(
            "fhe_prio3_build_info",
            &[
                ("version", env!("CARGO_PKG_VERSION")),
                ("role", "collector"),
                ("index", "0"),
                ("task_id", &hex::encode([10u8; 32])),
                ("mode", "Silent"),
                ("topology", "Aggregators"),
            ]
        ),
        1.0
    );
    // health on the public listener and on the metrics listener
    let http = https_client(&c.tls.ca_pem).unwrap();
    for url in [&c.agg_urls[0], &c.agg_urls[1], &c.col_urls[0]] {
        for path in ["/healthz", "/readyz"] {
            assert_eq!(http.get(format!("{url}{path}")).send().await.unwrap().status().as_u16(), 200, "{url}{path}");
        }
    }
    let ready = reqwest::get(format!("http://{}/readyz", c.agg_metrics[0].unwrap())).await.unwrap();
    assert_eq!(ready.status().as_u16(), 200);
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
    let _g = SERIAL.lock().await;
    let t = MeasurementType::BoundedSumVec { bounds: vec![100, 5, 15, 15] };
    let k0 = CollectorSealKey::generate();
    let k1 = CollectorSealKey::generate();
    let mut task = TaskConfig::new([11u8; 32], t.clone(), 2);
    task.moments = true;
    task.collectors = vec![
        CollectorPolicy {
            elements: vec![0, 1],
            moments: false,
            seal_key: k0.public_key(),
        },
        CollectorPolicy {
            elements: vec![2, 3],
            moments: true,
            seal_key: k1.public_key(),
        },
    ];
    task.validate().unwrap();
    let mut c = Cluster::with_seal_keys(
        task.clone(),
        vec![
            CollectorSealKey::from_secret_bytes(&k0.secret_bytes()),
            CollectorSealKey::from_secret_bytes(&k1.secret_bytes()),
        ],
    );
    c.start_all().await;
    let client = c.client();
    let rows = vec![vec![10u64, 1, 8, 8], vec![20, 5, 7, 6], vec![100, 3, 15, 15], vec![40, 1, 11, 12]];
    for r in &rows {
        assert_eq!(client.submit(&Measurement::SumVec(r.clone())).await.unwrap(), SubmitOutcome::Accepted);
    }
    let http = https_client(&c.tls.ca_pem).unwrap();
    // a helper refuses a collector id the task does not declare
    let r: anyhow::Result<fhe_prio3_node::wire::ShareReply> = http_post(
        &http,
        &format!("{}/v1/aggregate-share", c.agg_urls[1]),
        Some(&c.token),
        &fhe_prio3_node::wire::ShareRequest { collector: 7 },
    )
    .await;
    assert!(r.err().expect("unknown collector").to_string().contains("400"));
    // the leader closes: releases go to both collectors, no result comes back
    assert_eq!(c.close_policies().await.unwrap(), vec![0, 1]);
    let all = t
        .aggregate_plain(&rows.iter().map(|r| Measurement::SumVec(r.clone())).collect::<Vec<_>>())
        .unwrap();
    let AggregateResult::SumVec(all) = all else { panic!() };
    let r0 = c.result_of(0).await.unwrap().expect("collector 0 complete");
    assert_eq!(
        (r0.collector, &r0.elements, r0.aggregate.clone(), r0.report_count),
        (0, &vec![0, 1], AggregateResult::SumVec(vec![all[0], all[1], 0, 0]), 4)
    );
    assert!(r0.regression.is_none());
    let r1 = c.result_of(1).await.unwrap().expect("collector 1 complete");
    assert_eq!(
        (r1.collector, &r1.elements, r1.aggregate.clone()),
        (1, &vec![2, 3], AggregateResult::SumVec(vec![0, 0, all[2], all[3]]))
    );
    let reg = r1.regression.expect("collector 1 has moments");
    let plain = fhe_prio3::types::regression_plain(&rows.iter().map(|r| vec![r[2], r[3]]).collect::<Vec<_>>());
    assert_eq!((reg.n, &reg.first, &reg.second), (plain.n, &plain.first, &plain.second));
    // an envelope sealed for collector 1 is refused by collector 0
    let sealed1: fhe_prio3_node::wire::ShareReply = http_post(
        &http,
        &format!("{}/v1/aggregate-share", c.agg_urls[1]),
        Some(&c.token),
        &fhe_prio3_node::wire::ShareRequest { collector: 1 },
    )
    .await
    .unwrap();
    let fhe_prio3_node::wire::ShareReply::Sealed(sealed1) = sealed1 else {
        panic!("policy tasks seal")
    };
    assert!(
        fhe_prio3::seal::open(&sealed1, &k0).is_err(),
        "the leader-visible envelope is opaque to another key"
    );
    let r: anyhow::Result<fhe_prio3_node::wire::ShareReceipt> = http_post(
        &http,
        &format!("{}/v1/aggregate-share", c.col_urls[0]),
        Some(&c.token),
        &fhe_prio3_node::wire::SealedEnvelope { sealed: sealed1 },
    )
    .await;
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
        key_share: None,
    });
    assert!(bad.is_err());
    let none = CollectorNode::new(CollectorNodeConfig {
        task,
        material: c.material.clone(),
        collector_id: 0,
        seal_key: None,
        token: c.token.clone(),
        db: c.dir.path().join("bad2.db"),
        key_share: None,
    });
    assert!(none.is_err());
}

/// Three aggregators in verdict mode over TLS. Every internal request must
/// fit the body limit: the leader sends each helper the masks of the other
/// two aggregators in one request, which is larger than one report.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_aggregators_verdict_over_tls() {
    let _g = SERIAL.lock().await;
    let task = TaskConfig::new([12u8; 32], MeasurementType::Sum { max_measurement: 100 }, 3);
    let mut c = Cluster::new(task);
    c.start_all().await;
    let client = c.client();
    assert_eq!(client.submit(&Measurement::Sum(40)).await.unwrap(), SubmitOutcome::Accepted);
    assert_eq!(client.submit(&Measurement::Sum(2)).await.unwrap(), SubmitOutcome::Accepted);
    // out of range: 101 needs a non-bit slot (2 * 32 + 37)
    let bad = vec![0u64, 0, 0, 0, 0, 2, 1];
    match client.submit_report(&client.inner().shard_raw(&[bad]).unwrap()).await.unwrap() {
        SubmitOutcome::Rejected(r) => assert!(r.contains("ValidityCheckFailed"), "{r}"),
        o => panic!("expected rejection, got {o:?}"),
    }
    // Hostile chunks over the network: the leader parses them in safe Rust
    // and refuses them before any OpenFHE call; nothing is forwarded, and
    // the cluster keeps serving.
    let codec = client.inner().codec();
    let good = client.inner().shard(&Measurement::Sum(5)).unwrap();
    let legacy = codec
        .decode(&good.chunks[0], fhe_prio3::packed::Expect::Exactly(codec.fresh_meta()))
        .unwrap()
        .serialize()
        .unwrap();
    // OpenFHE's own encoding is larger than the packed one, so the public
    // body limit (packed report size plus 64 KiB) refuses it before it is
    // even decoded: 413, or a reset if the server closes while we upload.
    {
        let mut r = good.clone();
        r.chunks[0] = legacy;
        r.report_id = fhe_prio3::Report::compute_id(&r.task_id, r.group, &r.chunks);
        let body = fhe_prio3::messages::encode(&r).unwrap();
        let http = https_client(&c.tls.ca_pem).unwrap();
        match http.post(format!("{}/v1/submit", c.agg_urls[0])).body(body).send().await {
            Ok(resp) => assert_eq!(resp.status().as_u16(), 413, "legacy OpenFHE bytes"),
            Err(e) => assert!(e.is_request() || e.is_body() || e.is_connect(), "unexpected error: {e}"),
        }
        // A fresh client, i.e. a new connection: after a 413 the server
        // closes the refused connection, and a pooled client may race that
        // close. The question here is only whether the leader still serves.
        let fresh = https_client(&c.tls.ca_pem).unwrap();
        let st: fhe_prio3_node::wire::StatusReply = http_get(&fresh, &format!("{}/v1/status", c.agg_urls[0]), None).await.unwrap();
        assert_eq!((st.accepted, st.closed), (2, false));
    }
    let mut hostile: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut fp = good.chunks[0].clone();
    fp[40] ^= 0x80;
    hostile.push(("wrong fingerprint", fp));
    let mut top = good.chunks[0].clone();
    let last = top.len() - 1;
    top[last] = 0xFF; // the last residue of the last tower: all ones, at or above its modulus
    hostile.push(("residue above the modulus", top));
    let mut short = good.chunks[0].clone();
    short.pop();
    hostile.push(("one byte short", short));
    for (what, chunk) in hostile {
        let mut r = good.clone();
        r.chunks[0] = chunk;
        r.report_id = fhe_prio3::Report::compute_id(&r.task_id, r.group, &r.chunks);
        match client.submit_report(&r).await.unwrap() {
            SubmitOutcome::Rejected(reason) => {
                let expected = match what {
                    "wrong fingerprint" => "WrongParameters",
                    "residue above the modulus" => "ResidueOutOfRange",
                    _ => "BadLength",
                };
                assert!(reason.contains(expected), "{what}: {reason}");
            }
            o => panic!("{what}: expected rejection, got {o:?}"),
        }
    }
    assert_eq!(client.submit_report(&good).await.unwrap(), SubmitOutcome::Accepted);
    let r = c.close().await.unwrap();
    assert_eq!((r.aggregate, r.report_count, r.valid_count), (AggregateResult::Sum(47), 3, 3));
    c.stop_all();
}

/// One aggregator and the collector holding the two key shares, with small
/// cells suppressed: the gated release runs between the aggregator node and
/// the collector node over TLS (`/v1/gate-*`), the collector restarts from
/// its database and still serves the result, and a collector started
/// without its share refuses to run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn split_key_with_suppression_over_tls() {
    let _g = SERIAL.lock().await;
    let mut task = TaskConfig::new_split_key([31u8; 32], MeasurementType::Histogram { length: 4 });
    task.silent_batch_groups = 1;
    task.repetitions = 4;
    task.min_batch_size = 2;
    task.min_cell_count = 2;
    let mut c = Cluster::new(task.clone());
    // the collector of a split-key task needs its share
    let no_share = CollectorNode::new(CollectorNodeConfig {
        task: task.clone(),
        material: c.material.clone(),
        collector_id: 0,
        seal_key: None,
        token: c.token.clone(),
        db: c.dir.path().join("noshare.db"),
        key_share: None,
    });
    assert!(no_share.err().unwrap().to_string().contains("key share"));
    c.start_all().await;
    let client = c.client();
    for b in [0usize, 0, 1, 3, 3, 3] {
        assert_eq!(client.submit(&Measurement::Histogram(b)).await.unwrap(), SubmitOutcome::Accepted);
    }
    let r = c.close().await.unwrap();
    assert_eq!(r.aggregate, AggregateResult::Histogram(vec![2, 0, 0, 3]));
    assert_eq!(r.suppressed, vec![1, 2]);
    assert!(r.counts_withheld);
    c.stop_all();
    // the collector restarts from its database
    c.handles.clear();
    c.start_collector(0).await;
    let again = c.result_of(0).await.unwrap().expect("stored result");
    assert_eq!(again, r);
    c.stop_all();
}
