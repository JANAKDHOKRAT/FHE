//! Sharded deployment as separate OS processes of the node binary: per
//! shard two aggregators and a collector, plus one router; clients submit
//! concurrently through the router; the router closes every shard and
//! combines. Each process is pinned to a fixed number of OpenMP threads so
//! that the wall-clock comparison between one and two shards on this
//! machine measures real parallelism, not oversubscription.

use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use fhe_prio3_node::client::{ShardedClient, parse_aggregator_keys};
use fhe_prio3_node::wire::{SubmitOutcome, http_get, http_post, https_client};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Instant;

static SERIAL: Mutex<()> = Mutex::new(());
const SEAL_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const TOKEN: &str = "shard-t0k3n";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fhe-prio3-node")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Tls {
    ca_pem: Vec<u8>,
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

fn make_tls(dir: &Path) -> Tls {
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let cert = dir.join("server.pem");
    let key = dir.join("server.key");
    let ca_path = dir.join("ca.pem");
    std::fs::write(&cert, format!("{}{}", leaf.pem(), ca.pem())).unwrap();
    std::fs::write(&key, leaf_key.serialize_pem()).unwrap();
    std::fs::write(&ca_path, ca.pem()).unwrap();
    Tls { ca_pem: ca.pem().into_bytes(), ca: ca_path, cert, key }
}

struct Procs(Vec<Child>);
impl Drop for Procs {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn spawn(args: &[String], omp_threads: usize) -> Child {
    Command::new(bin())
        .args(args)
        .env("FHE_PRIO3_SEAL_KEY", SEAL_KEY)
        .env("OMP_NUM_THREADS", omp_threads.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn node")
}

async fn wait_ready(http: &reqwest::Client, url: &str) {
    let start = Instant::now();
    loop {
        if http.get(url).send().await.is_ok() {
            return;
        }
        assert!(start.elapsed().as_secs() < 120, "{url} did not come up");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

struct Deployment {
    _dir: tempfile::TempDir,
    tls: Tls,
    keys_dir: PathBuf,
    router_url: String,
    _procs: Procs,
}

/// Runs keygen for `shards` shards and starts every process. `threads` is
/// the OpenMP thread count per aggregator process.
async fn deploy(base: &TaskConfig, shards: usize, threads: usize) -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let tls = make_tls(dir.path());
    let task_path = dir.path().join("base.bin");
    std::fs::write(&task_path, encode(base).unwrap()).unwrap();
    let keys_dir = dir.path().join("keys");
    let st = Command::new(bin())
        .args(["keygen-shards", "--task", task_path.to_str().unwrap(), "--shards", &shards.to_string(), "--out-dir", keys_dir.to_str().unwrap()])
        .env("FHE_PRIO3_SEAL_KEY", SEAL_KEY)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "keygen-shards failed");

    let http = https_client(&tls.ca_pem).unwrap();
    let mut procs = Vec::new();
    let mut leaders = Vec::new();
    for s in 0..shards {
        let sdir = keys_dir.join(format!("shard-{s}"));
        let col_port = free_port();
        let agg_ports: Vec<u16> = (0..base.num_aggregators).map(|_| free_port()).collect();
        let agg_urls: Vec<String> = agg_ports.iter().map(|p| format!("https://localhost:{p}")).collect();
        let col_url = format!("https://localhost:{col_port}");
        procs.push(spawn(
            &[
                "collector".into(),
                "--task".into(), sdir.join("task.bin").to_str().unwrap().into(),
                "--material".into(), sdir.join("material.bin").to_str().unwrap().into(),
                "--db".into(), dir.path().join(format!("col{s}.db")).to_str().unwrap().into(),
                "--listen".into(), format!("127.0.0.1:{col_port}"),
                "--token".into(), TOKEN.into(),
                "--tls-cert".into(), tls.cert.to_str().unwrap().into(),
                "--tls-key".into(), tls.key.to_str().unwrap().into(),
            ],
            1,
        ));
        for i in 0..base.num_aggregators {
            procs.push(spawn(
                &[
                    "aggregator".into(),
                    "--index".into(), i.to_string(),
                    "--task".into(), sdir.join("task.bin").to_str().unwrap().into(),
                    "--material".into(), sdir.join("material.bin").to_str().unwrap().into(),
                    "--share".into(), sdir.join(format!("share-{i}.sealed")).to_str().unwrap().into(),
                    "--db".into(), dir.path().join(format!("agg{s}-{i}.db")).to_str().unwrap().into(),
                    "--listen".into(), format!("127.0.0.1:{}", agg_ports[i]),
                    "--aggregators".into(), agg_urls.join(","),
                    "--collector".into(), col_url.clone(),
                    "--token".into(), TOKEN.into(),
                    "--tls-cert".into(), tls.cert.to_str().unwrap().into(),
                    "--tls-key".into(), tls.key.to_str().unwrap().into(),
                    "--ca".into(), tls.ca.to_str().unwrap().into(),
                ],
                threads,
            ));
        }
        for u in &agg_urls {
            wait_ready(&http, &format!("{u}/v1/status")).await;
        }
        leaders.push(agg_urls[0].clone());
    }
    let router_port = free_port();
    procs.push(spawn(
        &[
            "router".into(),
            "--shards-dir".into(), keys_dir.to_str().unwrap().into(),
            "--leaders".into(), leaders.join(","),
            "--listen".into(), format!("127.0.0.1:{router_port}"),
            "--token".into(), TOKEN.into(),
            "--tls-cert".into(), tls.cert.to_str().unwrap().into(),
            "--tls-key".into(), tls.key.to_str().unwrap().into(),
            "--ca".into(), tls.ca.to_str().unwrap().into(),
        ],
        1,
    ));
    let router_url = format!("https://localhost:{router_port}");
    wait_ready(&http, &format!("{router_url}/v1/shards")).await;
    Deployment { _dir: dir, tls, keys_dir, router_url, _procs: Procs(procs) }
}

/// Submits `values` concurrently through the router; returns wall time.
async fn submit_all(d: &Deployment, values: &[u64]) -> std::time::Duration {
    let pinned = parse_aggregator_keys(&std::fs::read_to_string(d.keys_dir.join("aggregator-keys.txt")).unwrap()).unwrap();
    let client = std::sync::Arc::new(ShardedClient::new(d.router_url.clone(), &d.tls.ca_pem, None, pinned).unwrap());
    let t0 = Instant::now();
    let mut tasks = Vec::new();
    for &v in values {
        let c = client.clone();
        tasks.push(tokio::spawn(async move { c.submit(&Measurement::Sum(v)).await.unwrap() }));
    }
    let mut shards_used = std::collections::HashSet::new();
    for t in tasks {
        let (out, shard) = t.await.unwrap();
        assert_eq!(out, SubmitOutcome::Accepted);
        shards_used.insert(shard);
    }
    let elapsed = t0.elapsed();
    assert_eq!(shards_used.len(), std::cmp::min(values.len(), d._procs.0.len() / 3), "every shard received reports");
    elapsed
}

async fn close_all(d: &Deployment) -> BatchResult {
    let http = https_client(&d.tls.ca_pem).unwrap();
    http_post(&http, &format!("{}/v1/close-all", d.router_url), Some(TOKEN), &()).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_shards_as_processes_scale_and_combine() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let base = TaskConfig::new([21u8; 32], MeasurementType::Sum { max_measurement: 100 }, 2);
    let values: Vec<u64> = (0..16).map(|i| (i * 37) % 101).collect();
    let expected: u128 = values.iter().map(|&v| v as u128).sum();

    // (shards, OpenMP threads per aggregator process). The one-thread pair
    // measures the parallelism of sharding itself: 1 shard uses 2 cores, 2
    // shards use 4. The other pair keeps the total thread budget at 4 cores
    // and shows what sharding buys when one shard already uses every core.
    let configs = [(1usize, 1usize), (2, 1), (1, 4), (2, 2)];
    let mut timings = Vec::new();
    for (i, &(shards, threads)) in configs.iter().enumerate() {
        let d = deploy(&base, shards, threads).await;
        let t = submit_all(&d, &values).await;
        let r = close_all(&d).await;
        assert_eq!((r.aggregate.clone(), r.report_count, r.valid_count), (AggregateResult::Sum(expected), 16, 16), "config {shards}x{threads}");
        if i == configs.len() - 1 {
            // closing again is idempotent: every aggregator returns the share
            // it already released, so the combined result is byte-identical
            let http = https_client(&d.tls.ca_pem).unwrap();
            let again: BatchResult = http_post(&http, &format!("{}/v1/close-all", d.router_url), Some(TOKEN), &()).await.unwrap();
            assert_eq!(encode(&again).unwrap(), encode(&r).unwrap());
            // wrong token
            let bad: anyhow::Result<BatchResult> = http_post(&http, &format!("{}/v1/close-all", d.router_url), Some("x"), &()).await;
            assert!(bad.unwrap_err().to_string().contains("401"));
            let list: Vec<fhe_prio3_node::router::Assignment> = http_get(&http, &format!("{}/v1/shards", d.router_url), None).await.unwrap();
            assert_eq!(list.len(), 2);
            let m: PublicMaterial = http_get(&http, &format!("{}/v1/shard/1/material", d.router_url), None).await.unwrap();
            assert!(m.rotation_keys.is_empty() && m.eval_mult_key.is_empty(), "clients get no evaluation keys");
            // material served by the router carries every aggregator's attestation
            let pinned = parse_aggregator_keys(&std::fs::read_to_string(d.keys_dir.join("aggregator-keys.txt")).unwrap()).unwrap();
            let task1: TaskConfig = http_get(&http, &format!("{}/v1/shard/1/task", d.router_url), None).await.unwrap();
            fhe_prio3::attest::verify_material(&task1, &m, &pinned).unwrap();
            // a client pinning other aggregator keys refuses what the router serves
            let rogue = vec![AggregatorIdentity::generate().public_key(), pinned[1]];
            let c = ShardedClient::new(d.router_url.clone(), &d.tls.ca_pem, None, rogue).unwrap();
            let err = c.submit(&Measurement::Sum(1)).await.err().expect("unattested material must be refused");
            assert!(err.to_string().contains("pinned key") || err.to_string().contains("attest"), "{err}");
            // shard 0's attestations do not validate shard 1's material
            let task0: TaskConfig = http_get(&http, &format!("{}/v1/shard/0/task", d.router_url), None).await.unwrap();
            assert!(fhe_prio3::attest::verify_material(&task0, &m, &pinned).is_err());
            let missing: anyhow::Result<PublicMaterial> = http_get(&http, &format!("{}/v1/shard/7/material", d.router_url), None).await;
            assert!(missing.err().expect("shard 7 does not exist").to_string().contains("404"));
            let _ = decode::<TaskConfig>(&encode(&base).unwrap()).unwrap();
        }
        timings.push((shards, threads, t.as_secs_f64()));
        drop(d);
    }
    // A router whose leader list is misordered refuses to start.
    {
        let d = deploy(&base, 2, 1).await;
        let http = https_client(&d.tls.ca_pem).unwrap();
        let list: Vec<fhe_prio3_node::router::Assignment> = http_get(&http, &format!("{}/v1/shards", d.router_url), None).await.unwrap();
        let swapped = format!("{},{}", list[1].leader, list[0].leader);
        let st = Command::new(bin())
            .args([
                "router", "--shards-dir", d.keys_dir.to_str().unwrap(), "--leaders", &swapped,
                "--listen", &format!("127.0.0.1:{}", free_port()), "--token", TOKEN,
                "--tls-cert", d.tls.cert.to_str().unwrap(), "--tls-key", d.tls.key.to_str().unwrap(), "--ca", d.tls.ca.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!st.success(), "router must refuse a misordered leader list");
        drop(d);
    }
    let mut out = String::new();
    for (s, th, t) in &timings {
        out.push_str(&format!("SHARDING: 16 reports, {s} shard(s) x {th} thread(s): {t:.1} s\n"));
    }
    out.push_str(&format!("SHARDING: speedup 2 shards vs 1 at 1 thread: {:.2}x; at a 4-thread budget: {:.2}x\n", timings[0].2 / timings[1].2, timings[2].2 / timings[3].2));
    print!("{out}");
    std::fs::write(std::env::temp_dir().join("fhe_prio3_sharding_timing.txt"), out).unwrap();
}
