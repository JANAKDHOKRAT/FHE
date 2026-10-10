//! `fhe-prio3-node`: key setup, aggregator, collector and client commands.
//!
//! Key material: in a deployment every aggregator runs `init-identity` once
//! and then `ceremony` on its own machine, together: the distributed
//! ceremony of `fhe_prio3::ceremony` over HTTPS, after which each machine
//! holds the attested public material and only its own sealed secret (its
//! key share and the task's verify key).
//! `keygen` runs every party in one process (a dealer that sees every
//! share) and exists for tests and trials.

use clap::{Parser, Subcommand};
use fhe_prio3::attest;
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use fhe_prio3_node::aggregator_node::{AggregatorNode, AggregatorNodeConfig};
use fhe_prio3_node::client::NetworkClient;
use fhe_prio3_node::collector_node::{CollectorNode, CollectorNodeConfig};
use fhe_prio3_node::secret;
use fhe_prio3_node::wire::ServerHandle;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "fhe-prio3-node", about = "fhe-prio3 network nodes")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create (or load) this aggregator's long-term identity, sealed under
    /// FHE_PRIO3_SEAL_KEY, and print its public key for `aggregator-keys.txt`.
    InitIdentity {
        #[arg(long)]
        index: usize,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Distributed key ceremony: run on every aggregator's own machine at
    /// the same time. Writes `material.bin` (attested by every aggregator),
    /// this aggregator's `share-<i>.sealed` (its key share and the task's
    /// verify key) and `transcript.txt`. No machine ever holds another
    /// aggregator's share.
    Ceremony {
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        index: usize,
        /// This aggregator's sealed identity (from `init-identity`).
        #[arg(long)]
        identity: PathBuf,
        /// Every aggregator's identity key, line i = aggregator i.
        #[arg(long)]
        aggregator_keys: PathBuf,
        /// 32 random bytes as hex, agreed by all aggregators for this run.
        #[arg(long)]
        session: String,
        #[arg(long)]
        listen: std::net::SocketAddr,
        /// Base URLs of every aggregator's ceremony server by index, comma separated.
        #[arg(long)]
        aggregators: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        tls_cert: PathBuf,
        #[arg(long)]
        tls_key: PathBuf,
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        /// Longest wait for any one peer message or blob, in seconds.
        #[arg(long, default_value_t = 3600)]
        timeout_secs: u64,
    },
    /// Single-machine ceremony for tests and trials: one process generates
    /// every aggregator's share (a dealer). Use `ceremony` for deployments.
    Keygen {
        /// Task configuration file (postcard, from `task-config`).
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        /// Directory of the aggregators' sealed long-term identities
        /// (`aggregator-<i>.identity.sealed`); created there when absent.
        /// Default: `<out_dir>/identities`.
        #[arg(long)]
        identities_dir: Option<PathBuf>,
    },
    /// Write the public material a client needs (context, joint public key,
    /// attestations) without the evaluation keys, which only the
    /// aggregators use (gigabytes in silent mode). Clients verify the
    /// attestations of this file as of the full one.
    ClientMaterial {
        #[arg(long)]
        material: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write a task configuration file.
    TaskConfig {
        #[arg(long)]
        out: PathBuf,
        /// count | sum:<max> | sumvec:<len>:<max> | bounded:<b1,b2,...> | histogram:<len> | multihot:<len>:<maxw>
        #[arg(long)]
        r#type: String,
        #[arg(long, default_value_t = 2)]
        aggregators: usize,
        #[arg(long, default_value = "verdict")]
        mode: String,
        #[arg(long, default_value_t = 1)]
        min_batch: usize,
        /// Require signed reports, at most this many per client per batch (0 = open).
        #[arg(long, default_value_t = 0)]
        auth_quota: u32,
        /// 32-byte task id as hex (default: derived from the type string).
        #[arg(long)]
        task_id: Option<String>,
        /// Release second moments for a regression (SumVec / bounded tasks).
        #[arg(long, default_value_t = false)]
        moments: bool,
        /// Largest batch (default: 2^20 verdict, 2^16 silent). With moments,
        /// a smaller batch allows wider digits and fewer multiplications per
        /// report (`TaskConfig::moment_digit_bits`).
        #[arg(long)]
        max_batch: Option<u64>,
        /// Release policy, repeatable, one per collector in id order:
        /// `<hex sealing public key>:<e0,e1,...>[:moments]`.
        #[arg(long = "collector")]
        collectors: Vec<String>,
        /// Who holds key shares: `aggregators` (n-of-n among
        /// `--aggregators`), or `split` (one aggregator and the collector,
        /// silent mode; the batch size is gated under encryption).
        #[arg(long, default_value = "aggregators")]
        topology: String,
        /// Small-cell suppression: cells below this are zeroed under
        /// encryption before release (0 = off; silent mode, count,
        /// histogram and multihot).
        #[arg(long, default_value_t = 0)]
        min_cell: u64,
    },
    Aggregator {
        #[arg(long)]
        index: usize,
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        material: PathBuf,
        #[arg(long)]
        share: PathBuf,
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        listen: std::net::SocketAddr,
        /// Base URLs of all aggregators by index, comma separated.
        #[arg(long)]
        aggregators: String,
        /// Collector base URLs by collector id, comma separated (one without policies).
        #[arg(long, alias = "collector")]
        collectors: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        tls_cert: PathBuf,
        #[arg(long)]
        tls_key: PathBuf,
        #[arg(long)]
        ca: PathBuf,
        /// File with one hex-encoded client public key per line (required with auth).
        #[arg(long)]
        clients: Option<PathBuf>,
        /// Serve Prometheus metrics (`/metrics`) and `/healthz`, `/readyz` on
        /// this address over plain HTTP. Bind it to a private interface.
        #[arg(long)]
        metrics_listen: Option<std::net::SocketAddr>,
    },
    Collector {
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        material: PathBuf,
        /// This collector's id in the task's release policies (0 without policies).
        #[arg(long, default_value_t = 0)]
        id: u32,
        /// Sealing secret file from `collector-identity` (required with policies).
        #[arg(long)]
        seal_secret: Option<PathBuf>,
        /// Split-key tasks: the collector's sealed key share
        /// (`share-<n>.sealed` from the ceremony, `n` = number of aggregators).
        #[arg(long)]
        key_share: Option<PathBuf>,
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long)]
        token: String,
        #[arg(long)]
        tls_cert: PathBuf,
        #[arg(long)]
        tls_key: PathBuf,
        /// Serve Prometheus metrics (`/metrics`) and `/healthz`, `/readyz` on
        /// this address over plain HTTP. Bind it to a private interface.
        #[arg(long)]
        metrics_listen: Option<std::net::SocketAddr>,
    },
    /// Load test of a running deployment: `--workers` client threads
    /// encrypt and submit `--reports` deterministic measurements, the batch
    /// is closed and the released result compared with the expected one;
    /// the nodes' metrics are scraped throughout. Writes a JSON report and
    /// exits non-zero unless the result is exactly the expected one.
    Loadtest {
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        material: PathBuf,
        #[arg(long)]
        leader: String,
        #[arg(long)]
        ca: PathBuf,
        /// Operator token (for the close).
        #[arg(long)]
        token: String,
        #[arg(long)]
        reports: u64,
        /// Client threads, one OpenFHE context each (set OMP_NUM_THREADS=1
        /// for one core per thread). Default: the available cores.
        #[arg(long)]
        workers: Option<usize>,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Every n-th report is invalid (a non-bit slot); 0 = none.
        #[arg(long, default_value_t = 0)]
        invalid_every: u64,
        /// A node's metrics listener, `name=http://host:port`, repeatable.
        #[arg(long = "metrics")]
        metrics: Vec<String>,
        #[arg(long, default_value_t = 5)]
        scrape_every_secs: u64,
        /// JSON lines of the scrapes.
        #[arg(long)]
        timeline: Option<PathBuf>,
        /// The JSON report.
        #[arg(long)]
        out: PathBuf,
        /// Submit only; leave the batch open.
        #[arg(long, default_value_t = false)]
        no_close: bool,
        #[arg(long, default_value_t = 4 * 3600)]
        close_timeout_secs: u64,
        /// Durable client state: a run stopped at any point (a restart)
        /// resumes from here, every report counted once.
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Submit one measurement to the leader.
    Submit {
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        material: PathBuf,
        #[arg(long)]
        leader: String,
        #[arg(long)]
        ca: PathBuf,
        /// Measurement: count:<0|1> | sum:<v> | sumvec:<a,b,c> (also for bounded tasks) | histogram:<i> | multihot:<0,1,0,...>
        #[arg(long)]
        value: String,
        /// Client signing key file (32 bytes hex) when the task requires authentication.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Aggregator identity keys (`aggregator-keys.txt` from keygen): when
        /// given, the material must be attested by every aggregator.
        #[arg(long)]
        aggregator_keys: Option<PathBuf>,
    },
    /// Close the batch (leader) and print the collector's result.
    Close {
        #[arg(long)]
        leader: String,
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        token: String,
    },
    /// Generate a client identity file and print its public key.
    ClientIdentity {
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate a collector sealing key file (sealed under FHE_PRIO3_SEAL_KEY)
    /// and print its public key, to be declared in the task's policy.
    CollectorIdentity {
        #[arg(long)]
        out: PathBuf,
    },
    /// Derive `shards` independent tasks from a base task and run each
    /// ceremony; writes `shard-<i>/{task.bin,material.bin,share-<j>.sealed}`.
    KeygenShards {
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        shards: usize,
        #[arg(long)]
        out_dir: PathBuf,
        /// See `keygen`. The same identities sign every shard's material.
        #[arg(long)]
        identities_dir: Option<PathBuf>,
    },
    /// Derive the `shards` shard tasks of a base task without any keys:
    /// writes `shard-<i>/task.bin`. Every aggregator machine then runs
    /// `ceremony` once per shard task (the distributed path).
    ShardTasks {
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        shards: usize,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Router for a sharded deployment.
    Router {
        /// Directory written by `keygen-shards`.
        #[arg(long)]
        shards_dir: PathBuf,
        /// Leader base URLs, one per shard, comma separated.
        #[arg(long)]
        leaders: String,
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long)]
        token: String,
        #[arg(long)]
        tls_cert: PathBuf,
        #[arg(long)]
        tls_key: PathBuf,
        #[arg(long)]
        ca: PathBuf,
        /// Serve Prometheus metrics (`/metrics`) and `/healthz`, `/readyz` on
        /// this address over plain HTTP. Bind it to a private interface.
        #[arg(long)]
        metrics_listen: Option<std::net::SocketAddr>,
    },
    /// Submit one measurement through a router.
    SubmitSharded {
        #[arg(long)]
        router: String,
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        value: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Aggregator identity keys (`aggregator-keys.txt` from keygen-shards), required:
        /// material served by the router is trusted only with their attestations.
        #[arg(long)]
        aggregator_keys: PathBuf,
    },
    /// Close every shard through the router and print the combined result.
    CloseAll {
        #[arg(long)]
        router: String,
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        token: String,
    },
}

fn parse_type(s: &str) -> anyhow::Result<MeasurementType> {
    let parts: Vec<&str> = s.split(':').collect();
    Ok(match parts.as_slice() {
        ["count"] => MeasurementType::Count,
        ["sum", m] => MeasurementType::Sum { max_measurement: m.parse()? },
        ["sumvec", l, m] => MeasurementType::SumVec {
            length: l.parse()?,
            max_measurement: m.parse()?,
        },
        ["bounded", bs] => MeasurementType::BoundedSumVec {
            bounds: bs.split(',').map(|x| x.parse::<u64>()).collect::<std::result::Result<Vec<u64>, _>>()?,
        },
        ["histogram", l] => MeasurementType::Histogram { length: l.parse()? },
        ["multihot", l, w] => MeasurementType::MultihotCountVec {
            length: l.parse()?,
            max_weight: w.parse()?,
        },
        _ => anyhow::bail!("unknown type {s}"),
    })
}

/// Loads the aggregators' sealed identities from `dir`, creating any that
/// are missing. Sealed under the deployment key like the shares, with the
/// aggregator index as associated data.
fn load_or_create_identities(dir: &PathBuf, n: usize) -> anyhow::Result<Vec<AggregatorIdentity>> {
    std::fs::create_dir_all(dir)?;
    (0..n).map(|i| load_or_create_identity(&dir.join(identity_file(i)), i)).collect()
}

fn identity_file(i: usize) -> String {
    format!("aggregator-{i}.identity.sealed")
}

fn load_or_create_identity(path: &std::path::Path, i: usize) -> anyhow::Result<AggregatorIdentity> {
    let label = format!("aggregator-identity:{i}");
    Ok(if path.exists() {
        let b = secret::unseal(label.as_bytes(), &std::fs::read(path)?)?;
        AggregatorIdentity::from_secret_bytes(b.as_slice().try_into().map_err(|_| anyhow::anyhow!("identity must be 32 bytes"))?)
    } else {
        let id = AggregatorIdentity::generate();
        std::fs::write(path, secret::seal(label.as_bytes(), &id.secret_bytes())?)?;
        id
    })
}

fn share_label(i: usize, cfg: &TaskConfig) -> String {
    format!("share:{i}:{}", hex::encode(cfg.task_id))
}

/// Writes `aggregator-keys.txt`: the public identity keys, one per line,
/// line `i` for aggregator `i`. This file is what clients pin.
fn write_aggregator_keys(out_dir: &std::path::Path, ids: &[AggregatorIdentity]) -> anyhow::Result<()> {
    let mut text = String::from("# fhe-prio3 key party identity keys, line i = aggregator i (then the collector of a split-key task)\n");
    for id in ids {
        text.push_str(&hex::encode(id.public_key()));
        text.push('\n');
    }
    std::fs::write(out_dir.join("aggregator-keys.txt"), text)?;
    Ok(())
}

/// `<hex sealing public key>:<e0,e1,...>[:moments]`
fn parse_policy(spec: &str) -> anyhow::Result<CollectorPolicy> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        anyhow::bail!("collector policy must be <hex key>:<elements>[:moments], got {spec}");
    }
    let key: [u8; 32] = hex::decode(parts[0])?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("sealing key must be 32 bytes"))?;
    let elements = parts[1]
        .split(',')
        .map(|x| x.trim().parse::<usize>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let moments = match parts.get(2) {
        None => false,
        Some(&"moments") => true,
        Some(other) => anyhow::bail!("unknown policy flag {other}"),
    };
    Ok(CollectorPolicy {
        elements,
        moments,
        seal_key: key,
    })
}

fn parse_measurement(s: &str) -> anyhow::Result<Measurement> {
    let (kind, v) = s.split_once(':').ok_or_else(|| anyhow::anyhow!("value must be kind:value"))?;
    Ok(match kind {
        "count" => Measurement::Count(v == "1"),
        "sum" => Measurement::Sum(v.parse()?),
        "sumvec" => Measurement::SumVec(v.split(',').map(|x| x.parse::<u64>()).collect::<std::result::Result<Vec<u64>, _>>()?),
        "histogram" => Measurement::Histogram(v.parse()?),
        "multihot" => Measurement::MultihotCountVec(v.split(',').map(|x| x == "1").collect()),
        _ => anyhow::bail!("unknown measurement kind {kind}"),
    })
}

fn read<T: serde::de::DeserializeOwned>(p: &PathBuf) -> anyhow::Result<T> {
    Ok(decode(&std::fs::read(p)?)?)
}

/// A task file, in the current format or one written before
/// `key_topology` and `min_cell_count` existed.
fn read_task(p: &PathBuf) -> anyhow::Result<TaskConfig> {
    Ok(TaskConfig::decode(&std::fs::read(p)?)?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::InitIdentity { index, out_dir } => {
            std::fs::create_dir_all(&out_dir)?;
            let path = out_dir.join(identity_file(index));
            let id = load_or_create_identity(&path, index)?;
            println!("{}", hex::encode(id.public_key()));
            eprintln!(
                "identity of aggregator {index} in {} (public key above, line {index} of aggregator-keys.txt)",
                path.display()
            );
        }
        Cmd::Ceremony {
            task,
            index,
            identity,
            aggregator_keys,
            session,
            listen,
            aggregators,
            token,
            tls_cert,
            tls_key,
            ca,
            out_dir,
            timeout_secs,
        } => {
            let cfg = read_task(&task)?;
            let label = format!("aggregator-identity:{index}");
            let secret_bytes = secret::unseal(label.as_bytes(), &std::fs::read(&identity)?)?;
            let identity = AggregatorIdentity::from_secret_bytes(secret_bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("identity must be 32 bytes"))?);
            let pinned = fhe_prio3_node::client::parse_aggregator_keys(&std::fs::read_to_string(&aggregator_keys)?)?;
            let session: [u8; 32] = hex::decode(session.trim())?
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("session must be 32 bytes of hex"))?;
            std::fs::create_dir_all(&out_dir)?;
            let started = std::time::Instant::now();
            let out = fhe_prio3_node::ceremony_node::run(fhe_prio3_node::ceremony_node::CeremonyNodeConfig {
                task: cfg.clone(),
                index,
                identity,
                pinned,
                session,
                listen,
                peers: aggregators.split(',').map(|s| s.trim().trim_end_matches('/').to_string()).collect(),
                token,
                tls_cert,
                tls_key,
                ca_pem: std::fs::read(&ca)?,
                work_dir: out_dir.join(format!("ceremony-{}", hex::encode(&session[..8]))),
                timeout: std::time::Duration::from_secs(timeout_secs),
            })
            .await?;
            // streamed: an in-memory encoding would double the gigabytes of
            // rotation keys at the process's peak (silent mode)
            let mut w = std::io::BufWriter::new(std::fs::File::create(out_dir.join("material.bin"))?);
            postcard::to_io(&out.material, &mut w)?;
            std::io::Write::flush(&mut w)?;
            drop(w);
            std::fs::write(
                out_dir.join(format!("share-{index}.sealed")),
                secret::seal(share_label(index, &cfg).as_bytes(), &out.secret)?,
            )?;
            std::fs::write(out_dir.join("transcript.txt"), format!("{}\n", hex::encode(out.transcript)))?;
            println!(
                "ceremony complete in {:.1} s: material.bin (attested by all {} key parties), share-{index}.sealed, transcript {}",
                started.elapsed().as_secs_f64(),
                cfg.num_key_parties(),
                hex::encode(out.transcript)
            );
        }
        Cmd::TaskConfig {
            out,
            r#type,
            aggregators,
            mode,
            min_batch,
            auth_quota,
            task_id,
            moments,
            max_batch,
            collectors,
            topology,
            min_cell,
        } => {
            let ty = parse_type(&r#type)?;
            let id: [u8; 32] = match task_id {
                Some(h) => hex::decode(h)?.as_slice().try_into().map_err(|_| anyhow::anyhow!("task id must be 32 bytes"))?,
                None => {
                    use sha2::Digest;
                    sha2::Sha256::digest(r#type.as_bytes()).into()
                }
            };
            let mut cfg = match mode.as_str() {
                "verdict" => TaskConfig::new(id, ty, aggregators),
                "silent" => TaskConfig::new_silent(id, ty, aggregators),
                other => anyhow::bail!("mode must be verdict or silent, got {other}"),
            };
            cfg.min_batch_size = min_batch;
            if auth_quota > 0 {
                cfg.auth = AuthPolicy::Required {
                    max_reports_per_client_per_batch: auth_quota,
                };
            }
            if moments {
                cfg.moments = true;
            }
            if let Some(n) = max_batch {
                cfg.max_batch_size = n;
            }
            for spec in &collectors {
                cfg.collectors.push(parse_policy(spec)?);
            }
            cfg.key_topology = match topology.as_str() {
                "aggregators" => KeyTopology::Aggregators,
                "split" => KeyTopology::AggregatorAndCollector,
                other => anyhow::bail!("topology must be aggregators or split, got {other}"),
            };
            cfg.min_cell_count = min_cell;
            cfg.validate()?;
            std::fs::write(&out, encode(&cfg)?)?;
            println!("wrote {} (digest {})", out.display(), hex::encode(cfg.digest()));
            if let Some(d) = cfg.moment_digit_bits() {
                println!("moments: {d}-bit digits for batches of up to {}", cfg.max_batch_size);
            }
        }
        Cmd::ClientMaterial { material, out } => {
            let m: PublicMaterial = read(&material)?;
            let stripped = fhe_prio3_node::router::client_material(&m);
            drop(m);
            std::fs::write(&out, encode(&stripped)?)?;
            println!("wrote {} ({} bytes)", out.display(), std::fs::metadata(&out)?.len());
        }
        Cmd::Keygen { task, out_dir, identities_dir } => {
            let cfg = read_task(&task)?;
            std::fs::create_dir_all(&out_dir)?;
            let ids = load_or_create_identities(&identities_dir.unwrap_or_else(|| out_dir.join("identities")), cfg.num_key_parties())?;
            write_aggregator_keys(&out_dir, &ids)?;
            let k = keys::run_local_key_ceremony(&cfg)?;
            let mut material = k.material;
            let mut shares = k.aggregator_secrets;
            // the collector's share of a split-key task is key party n's
            shares.extend(k.collector_secret);
            material.attestations = ids.iter().enumerate().map(|(i, id)| attest::attest(&cfg, &material, i, id)).collect();
            std::fs::write(out_dir.join("material.bin"), encode(&material)?)?;
            for (i, s) in shares.iter().enumerate() {
                let sealed = secret::seal(format!("share:{i}:{}", hex::encode(cfg.task_id)).as_bytes(), s)?;
                std::fs::write(out_dir.join(format!("share-{i}.sealed")), sealed)?;
            }
            println!("wrote material.bin and {} sealed shares to {}", shares.len(), out_dir.display());
        }
        Cmd::ClientIdentity { out } => {
            let id = ClientIdentity::generate();
            std::fs::write(&out, hex::encode(id.secret_bytes()))?;
            println!("{}", hex::encode(id.public_key()));
        }
        Cmd::CollectorIdentity { out } => {
            let k = CollectorSealKey::generate();
            std::fs::write(&out, secret::seal(b"collector-identity", &k.secret_bytes())?)?;
            println!("{}", hex::encode(k.public_key()));
        }
        Cmd::Aggregator {
            index,
            task,
            material,
            share,
            db,
            listen,
            aggregators,
            collectors,
            token,
            tls_cert,
            tls_key,
            ca,
            clients,
            metrics_listen,
        } => {
            let cfg = read_task(&task)?;
            let material: PublicMaterial = read(&material)?;
            let sealed = std::fs::read(&share)?;
            let share = secret::unseal(format!("share:{index}:{}", hex::encode(cfg.task_id)).as_bytes(), &sealed)?;
            let registry: Option<Arc<dyn ClientRegistry>> = match clients {
                Some(p) => {
                    let keys: Vec<[u8; 32]> = std::fs::read_to_string(p)?
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| {
                            hex::decode(l.trim())
                                .ok()
                                .and_then(|b| b.as_slice().try_into().ok())
                                .ok_or_else(|| anyhow::anyhow!("bad client key line"))
                        })
                        .collect::<anyhow::Result<Vec<[u8; 32]>>>()?;
                    Some(StaticRegistry::new(keys))
                }
                None => None,
            };
            let node = AggregatorNode::new(AggregatorNodeConfig {
                index,
                task: cfg,
                material,
                share,
                aggregators: aggregators.split(',').map(|s| s.trim().to_string()).collect(),
                collectors: collectors.split(',').map(|s| s.trim().to_string()).collect(),
                token,
                db,
                registry,
                ca_pem: std::fs::read(&ca)?,
            })?;
            let handle = ServerHandle::new();
            run_metrics(node.metrics(), metrics_listen)?;
            shutdown_on_signal(handle.clone());
            tracing::info!(%listen, index, "aggregator listening");
            let tls = AggregatorNode::tls_config(tls_cert, tls_key).await?;
            node.serve(listen, Some(tls), handle).await?;
        }
        Cmd::Collector {
            task,
            material,
            id,
            seal_secret,
            key_share,
            db,
            listen,
            token,
            tls_cert,
            tls_key,
            metrics_listen,
        } => {
            let cfg = read_task(&task)?;
            // the collector uses the context and the joint public key only:
            // drop the evaluation keys at once (gigabytes in silent mode) if
            // it was given the full material instead of `client-material`'s
            let full: PublicMaterial = read(&material)?;
            let material = fhe_prio3_node::router::client_material(&full);
            drop(full);
            let seal_key = match seal_secret {
                Some(p) => {
                    let b = secret::unseal(b"collector-identity", &std::fs::read(&p)?)?;
                    Some(CollectorSealKey::from_secret_bytes(
                        b.as_slice().try_into().map_err(|_| anyhow::anyhow!("sealing secret must be 32 bytes"))?,
                    ))
                }
                None => None,
            };
            let key_share = match (key_share, cfg.collector_party()) {
                (Some(p), Some(party)) => Some(secret::unseal(share_label(party, &cfg).as_bytes(), &std::fs::read(&p)?)?),
                (None, None) => None,
                (None, Some(_)) => anyhow::bail!("split-key task: pass the collector's key share (--key-share)"),
                (Some(_), None) => anyhow::bail!("this task gives the collector no key share"),
            };
            let node = CollectorNode::new(CollectorNodeConfig {
                task: cfg,
                material,
                collector_id: id,
                seal_key,
                token,
                db,
                key_share,
            })?;
            let handle = ServerHandle::new();
            run_metrics(node.metrics(), metrics_listen)?;
            shutdown_on_signal(handle.clone());
            tracing::info!(%listen, "collector listening");
            let tls = CollectorNode::tls_config(tls_cert, tls_key).await?;
            node.serve(listen, Some(tls), handle).await?;
        }
        Cmd::Loadtest {
            task,
            material,
            leader,
            ca,
            token,
            reports,
            workers,
            seed,
            invalid_every,
            metrics,
            scrape_every_secs,
            timeline,
            out,
            no_close,
            close_timeout_secs,
            state_dir,
        } => {
            let metrics = metrics
                .iter()
                .map(|m| {
                    m.split_once('=')
                        .map(|(n, u)| (n.to_string(), u.trim_end_matches('/').to_string()))
                        .ok_or_else(|| anyhow::anyhow!("--metrics takes name=url, got {m}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let workers = workers.unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
            let report = fhe_prio3_node::loadtest::run(fhe_prio3_node::loadtest::LoadConfig {
                task: read_task(&task)?,
                material: read(&material)?,
                leader,
                ca_pem: std::fs::read(&ca)?,
                token,
                reports,
                workers,
                seed,
                invalid_every,
                metrics,
                scrape_every: std::time::Duration::from_secs(scrape_every_secs),
                timeline,
                close: !no_close,
                close_timeout: std::time::Duration::from_secs(close_timeout_secs),
                state_dir,
            })
            .await?;
            std::fs::write(&out, serde_json::to_vec_pretty(&report)?)?;
            println!(
                "{} reports ({} answered before, {} resent) ({} bytes each) by {} workers in {:.1} s: {:.3} reports/s; accepted {}, rejected {:?}, failed {}, retries {}",
                report.reports,
                report.answered_before,
                report.resent,
                report.report_bytes,
                report.workers,
                report.submit_wall_seconds,
                report.reports_per_second,
                report.outcomes.accepted,
                report.outcomes.rejected,
                report.outcomes.failed,
                report.outcomes.retries
            );
            for (name, s) in [("encrypt", &report.encrypt), ("submit", &report.submit), ("group", &report.group_ticket)] {
                println!(
                    "{name:>8}: mean {:.3} s, p50 {:.3}, p90 {:.3}, p99 {:.3}, p99.9 {:.3}, max {:.3}",
                    s.mean, s.p50, s.p90, s.p99, s.p999, s.max
                );
            }
            if let Some(c) = report.close_seconds {
                println!("   close: {c:.1} s");
            }
            for (node, p) in &report.peaks {
                println!(
                    "{node:>10}: peak resident {:.2} GiB, peak database {:.1} MiB, peak lock waiters {}",
                    p.resident_memory_bytes / (1u64 << 30) as f64,
                    p.db_size_bytes / (1u64 << 20) as f64,
                    p.lock_waiters
                );
            }
            println!("report: {}", out.display());
            match &report.verdict {
                Ok(()) => println!("PASS: the released result is exactly the expected one"),
                Err(e) => {
                    println!("FAIL: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Submit {
            task,
            material,
            leader,
            ca,
            value,
            identity,
            aggregator_keys,
        } => {
            let cfg = read_task(&task)?;
            let material: PublicMaterial = read(&material)?;
            let id = match identity {
                Some(p) => {
                    let b = hex::decode(std::fs::read_to_string(p)?.trim())?;
                    Some(ClientIdentity::from_secret_bytes(
                        b.as_slice().try_into().map_err(|_| anyhow::anyhow!("identity must be 32 bytes"))?,
                    ))
                }
                None => None,
            };
            let pinned = match aggregator_keys {
                Some(p) => Some(fhe_prio3_node::client::parse_aggregator_keys(&std::fs::read_to_string(p)?)?),
                None => None,
            };
            let c = NetworkClient::new(cfg, &material, id, leader, &std::fs::read(&ca)?, pinned.as_deref())?;
            let out = c.submit(&parse_measurement(&value)?).await?;
            println!("{out:?}");
        }
        Cmd::Close { leader, ca, token } => {
            let http = fhe_prio3_node::wire::https_client(&std::fs::read(&ca)?)?;
            let r: fhe_prio3_node::wire::CloseReply = fhe_prio3_node::wire::http_post(&http, &format!("{leader}/v1/close"), Some(&token), &()).await?;
            match r.result {
                Some(res) => println!("{res:?}"),
                None => println!("released to collectors {:?}; each reads its result from its own collector", r.released_to),
            }
        }
        Cmd::KeygenShards {
            task,
            shards,
            out_dir,
            identities_dir,
        } => {
            let base = read_task(&task)?;
            let cfgs = fhe_prio3::sharding::shard_configs(&base, shards)?;
            std::fs::create_dir_all(&out_dir)?;
            let ids = load_or_create_identities(&identities_dir.unwrap_or_else(|| out_dir.join("identities")), base.num_aggregators)?;
            write_aggregator_keys(&out_dir, &ids)?;
            for (i, cfg) in cfgs.iter().enumerate() {
                let dir = out_dir.join(format!("shard-{i}"));
                std::fs::create_dir_all(&dir)?;
                let (mut material, shares) = keys::run_local_ceremony(cfg)?;
                material.attestations = ids.iter().enumerate().map(|(j, id)| attest::attest(cfg, &material, j, id)).collect();
                std::fs::write(dir.join("task.bin"), encode(cfg)?)?;
                std::fs::write(dir.join("material.bin"), encode(&material)?)?;
                for (j, s) in shares.iter().enumerate() {
                    let sealed = secret::seal(format!("share:{j}:{}", hex::encode(cfg.task_id)).as_bytes(), s)?;
                    std::fs::write(dir.join(format!("share-{j}.sealed")), sealed)?;
                }
                println!("shard {i}: task {} written to {}", hex::encode(cfg.task_id), dir.display());
            }
        }
        Cmd::ShardTasks { task, shards, out_dir } => {
            let base = read_task(&task)?;
            for (i, cfg) in fhe_prio3::sharding::shard_configs(&base, shards)?.iter().enumerate() {
                let dir = out_dir.join(format!("shard-{i}"));
                std::fs::create_dir_all(&dir)?;
                std::fs::write(dir.join("task.bin"), encode(cfg)?)?;
                println!("shard {i}: task {} written to {}", hex::encode(cfg.task_id), dir.display());
            }
        }
        Cmd::Router {
            shards_dir,
            leaders,
            listen,
            token,
            tls_cert,
            tls_key,
            ca,
            metrics_listen,
        } => {
            let leaders: Vec<String> = leaders.split(',').map(|s| s.trim().to_string()).collect();
            let mut shards = Vec::with_capacity(leaders.len());
            for (i, leader) in leaders.iter().enumerate() {
                let dir = shards_dir.join(format!("shard-{i}"));
                let task = read_task(&dir.join("task.bin"))?;
                let material: PublicMaterial = read(&dir.join("material.bin"))?;
                shards.push(fhe_prio3_node::router::ShardInfo {
                    task,
                    client_material: fhe_prio3_node::router::client_material(&material),
                    leader: leader.clone(),
                });
            }
            let node = fhe_prio3_node::router::RouterNode::new(fhe_prio3_node::router::RouterNodeConfig {
                shards,
                token,
                ca_pem: std::fs::read(&ca)?,
            })?;
            node.verify_leaders(std::time::Duration::from_secs(120)).await?;
            let handle = ServerHandle::new();
            run_metrics(node.metrics(), metrics_listen)?;
            shutdown_on_signal(handle.clone());
            tracing::info!(%listen, "router listening");
            let tls = fhe_prio3_node::router::RouterNode::tls_config(tls_cert, tls_key).await?;
            node.serve(listen, Some(tls), handle).await?;
        }
        Cmd::SubmitSharded {
            router,
            ca,
            value,
            identity,
            aggregator_keys,
        } => {
            let id = match identity {
                Some(p) => {
                    let b = hex::decode(std::fs::read_to_string(p)?.trim())?;
                    Some(ClientIdentity::from_secret_bytes(
                        b.as_slice().try_into().map_err(|_| anyhow::anyhow!("identity must be 32 bytes"))?,
                    ))
                }
                None => None,
            };
            let pinned = fhe_prio3_node::client::parse_aggregator_keys(&std::fs::read_to_string(aggregator_keys)?)?;
            let c = fhe_prio3_node::client::ShardedClient::new(router, &std::fs::read(&ca)?, id.as_ref(), pinned)?;
            let (out, shard) = c.submit(&parse_measurement(&value)?).await?;
            println!("shard {shard}: {out:?}");
        }
        Cmd::CloseAll { router, ca, token } => {
            let http = fhe_prio3_node::wire::https_client(&std::fs::read(&ca)?)?;
            let r: BatchResult = fhe_prio3_node::wire::http_post(&http, &format!("{router}/v1/close-all"), Some(&token), &()).await?;
            println!("{r:?}");
        }
    }
    Ok(())
}

/// Serves the node's metrics on `addr` when given; a listener that cannot
/// bind stops the node from starting.
fn run_metrics(m: Arc<fhe_prio3_node::metrics::NodeMetrics>, addr: Option<std::net::SocketAddr>) -> anyhow::Result<()> {
    if let Some(addr) = addr {
        let bound = fhe_prio3_node::metrics::spawn_metrics_server(m, addr)?;
        tracing::info!(%bound, "metrics listening");
    }
    Ok(())
}

/// Graceful shutdown on SIGINT or SIGTERM (what a container runtime sends):
/// requests in flight get 30 s to finish; every step is committed before it
/// answers, so an interrupted one is redone after the restart.
fn shutdown_on_signal(handle: ServerHandle) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(error = %e, "cannot listen for SIGTERM; stopping on SIGINT only");
                    let _ = tokio::signal::ctrl_c().await;
                    handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });
}
