//! The distributed key ceremony as separate OS processes of the node
//! binary, one per aggregator, each with its own deployment seal key (its
//! own machine's KMS key), its own identity and its own output directory,
//! talking over TLS. The material they produce runs the protocol; a party
//! on another task configuration makes every party stop.

use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use fhe_prio3_node::client::parse_aggregator_keys;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());
const TOKEN: &str = "ceremony-t0k3n";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fhe-prio3-node")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A different 32-byte seal key per machine.
fn seal_key(i: usize) -> String {
    hex::encode([0x40 + i as u8; 32])
}

struct Tls {
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
    Tls { ca: ca_path, cert, key }
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

struct Machines {
    dir: tempfile::TempDir,
    tls: Tls,
    keys: PathBuf,
    pinned: Vec<[u8; 32]>,
}

/// One directory per aggregator with its sealed identity; the shared
/// `aggregator-keys.txt` assembled from what each printed.
fn machines(n: usize) -> Machines {
    let dir = tempfile::tempdir().unwrap();
    let tls = make_tls(dir.path());
    let mut text = String::from("# aggregator identity keys\n");
    for i in 0..n {
        let out = Command::new(bin())
            .args(["init-identity", "--index", &i.to_string(), "--out-dir", dir.path().join(format!("m{i}")).to_str().unwrap()])
            .env("FHE_PRIO3_SEAL_KEY", seal_key(i))
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        text.push_str(String::from_utf8(out.stdout).unwrap().trim());
        text.push('\n');
    }
    let keys = dir.path().join("aggregator-keys.txt");
    std::fs::write(&keys, &text).unwrap();
    let pinned = parse_aggregator_keys(&text).unwrap();
    Machines { dir, tls, keys, pinned }
}

/// Starts every party's `ceremony` process; `tasks[i]` is the task file party `i` uses.
fn start(m: &Machines, tasks: &[PathBuf], session: &str, timeout_secs: u64) -> Procs {
    let n = tasks.len();
    let ports: Vec<u16> = (0..n).map(|_| free_port()).collect();
    let urls = ports.iter().map(|p| format!("https://localhost:{p}")).collect::<Vec<_>>().join(",");
    let mut procs = Vec::new();
    for i in 0..n {
        let md = m.dir.path().join(format!("m{i}"));
        let log = std::fs::File::create(md.join("ceremony.log")).unwrap();
        procs.push(
            Command::new(bin())
                .args([
                    "ceremony",
                    "--task", tasks[i].to_str().unwrap(),
                    "--index", &i.to_string(),
                    "--identity", md.join(format!("aggregator-{i}.identity.sealed")).to_str().unwrap(),
                    "--aggregator-keys", m.keys.to_str().unwrap(),
                    "--session", session,
                    "--listen", &format!("127.0.0.1:{}", ports[i]),
                    "--aggregators", &urls,
                    "--token", TOKEN,
                    "--tls-cert", m.tls.cert.to_str().unwrap(),
                    "--tls-key", m.tls.key.to_str().unwrap(),
                    "--ca", m.tls.ca.to_str().unwrap(),
                    "--out-dir", md.to_str().unwrap(),
                    "--timeout-secs", &timeout_secs.to_string(),
                ])
                .env("FHE_PRIO3_SEAL_KEY", seal_key(i))
                .env("OMP_NUM_THREADS", "1")
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
    }
    Procs(procs)
}

fn wait_all(p: &mut Procs, limit: Duration) -> Vec<bool> {
    let start = Instant::now();
    let mut done: Vec<Option<bool>> = vec![None; p.0.len()];
    while done.iter().any(|d| d.is_none()) {
        for (i, c) in p.0.iter_mut().enumerate() {
            if done[i].is_none() {
                if let Some(st) = c.try_wait().unwrap() {
                    done[i] = Some(st.success());
                }
            }
        }
        assert!(start.elapsed() < limit, "ceremony processes did not finish");
        std::thread::sleep(Duration::from_millis(200));
    }
    done.into_iter().map(|d| d.unwrap()).collect()
}

fn log(m: &Machines, i: usize) -> String {
    std::fs::read_to_string(m.dir.path().join(format!("m{i}/ceremony.log"))).unwrap_or_default()
}

#[test]
fn three_machines_run_the_ceremony_over_tls_and_the_keys_work() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let n = 3;
    let m = machines(n);
    let cfg = TaskConfig::new([0x3c; 32], MeasurementType::Sum { max_measurement: 100 }, n);
    let task = m.dir.path().join("task.bin");
    std::fs::write(&task, encode(&cfg).unwrap()).unwrap();
    let mut p = start(&m, &vec![task; n], &hex::encode([7u8; 32]), 600);
    let ok = wait_all(&mut p, Duration::from_secs(900));
    for i in 0..n {
        assert!(ok[i], "party {i} failed:\n{}", log(&m, i));
    }

    // every machine holds the same attested material and transcript
    let read = |i: usize, f: &str| std::fs::read(m.dir.path().join(format!("m{i}/{f}"))).unwrap();
    for i in 1..n {
        assert_eq!(read(i, "material.bin"), read(0, "material.bin"));
        assert_eq!(read(i, "transcript.txt"), read(0, "transcript.txt"));
    }
    let material: PublicMaterial = decode(&read(0, "material.bin")).unwrap();
    attest::verify_material(&cfg, &material, &m.pinned).unwrap();
    // a machine's share opens only under its own seal key
    let label = |i: usize| format!("share:{i}:{}", hex::encode(cfg.task_id));
    let unseal = |i: usize, key: &str| {
        // SAFETY: tests in this file run serially
        unsafe { std::env::set_var("FHE_PRIO3_SEAL_KEY", key) };
        fhe_prio3_node::secret::unseal(label(i).as_bytes(), &read(i, &format!("share-{i}.sealed")))
    };
    assert!(unseal(1, &seal_key(0)).is_err());
    let shares: Vec<Vec<u8>> = (0..n).map(|i| unseal(i, &seal_key(i)).unwrap()).collect();
    for i in 0..n {
        assert!(!m.dir.path().join(format!("m{i}")).read_dir().unwrap().any(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.starts_with("share-") && name != format!("share-{i}.sealed")
        }), "machine {i} holds another share");
    }

    // the keys run the protocol
    let mut aggs: Vec<Aggregator> = shares.iter().enumerate().map(|(i, s)| Aggregator::new(cfg.clone(), &material, i, s, None).unwrap()).collect();
    let client = Client::new(cfg.clone(), &material.context, &material.public_key).unwrap();
    for v in [17u64, 100, 0, 42] {
        let report = client.shard(&Measurement::Sum(v)).unwrap();
        let masks: Vec<MaskMessage> = aggs.iter_mut().map(|a| a.prepare_init(&report).unwrap()).collect();
        let mut verifiers = Vec::new();
        for a in aggs.iter_mut() {
            let others: Vec<MaskMessage> = masks.iter().filter(|x| x.aggregator != a.index()).cloned().collect();
            verifiers.push(a.prepare_masks(&report.report_id, &others).unwrap());
        }
        for a in aggs.iter_mut() {
            let others: Vec<VerifierMessage> = verifiers.iter().filter(|x| x.aggregator != a.index()).cloned().collect();
            assert_eq!(a.prepare_finish(&report.report_id, &others).unwrap(), Verdict::Accepted);
        }
    }
    let released: Vec<AggregateShare> = aggs.iter_mut().map(|a| a.aggregate_share().unwrap()).collect();
    let result = Collector::new(cfg.clone(), &material).unwrap().unshard(&released).unwrap();
    assert_eq!(result.aggregate, AggregateResult::Sum(159));
}

#[test]
fn a_machine_on_another_task_stops_every_party() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let n = 3;
    let m = machines(n);
    let cfg = TaskConfig::new([0x3d; 32], MeasurementType::Count, n);
    let mut other = cfg.clone();
    other.min_batch_size = 5;
    let (a, b) = (m.dir.path().join("task.bin"), m.dir.path().join("other.bin"));
    std::fs::write(&a, encode(&cfg).unwrap()).unwrap();
    std::fs::write(&b, encode(&other).unwrap()).unwrap();
    let mut p = start(&m, &[a.clone(), b, a], &hex::encode([8u8; 32]), 120);
    let ok = wait_all(&mut p, Duration::from_secs(600));
    for i in 0..n {
        assert!(!ok[i], "party {i} completed:\n{}", log(&m, i));
        assert!(!m.dir.path().join(format!("m{i}/material.bin")).exists());
        assert!(!m.dir.path().join(format!("m{i}/share-{i}.sealed")).exists());
        let l = log(&m, i);
        assert!(l.contains("another task or session") || l.contains("aborted"), "party {i}:\n{l}");
    }
}
