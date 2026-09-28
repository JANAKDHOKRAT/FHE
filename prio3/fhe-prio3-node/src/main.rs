//! `fhe-prio3-node`: key setup, aggregator, collector and client commands.
//!
//! Key material: `keygen` runs the n-of-n ceremony and writes the public
//! material plus one sealed share file per aggregator. The ceremony messages
//! are the serialized objects of `fhe_prio3::keys`; running the parties on
//! separate machines uses the same functions with the files moved between
//! them.

use clap::{Parser, Subcommand};
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use fhe_prio3::attest;
use fhe_prio3_node::aggregator_node::{AggregatorNode, AggregatorNodeConfig};
use fhe_prio3_node::client::NetworkClient;
use fhe_prio3_node::collector_node::{CollectorNode, CollectorNodeConfig};
use fhe_prio3_node::secret;
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
    /// Run the key ceremony locally and write material + sealed shares.
    Keygen {
        /// Task configuration file (bincode, from `task-config`).
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
    /// Write a task configuration file.
    TaskConfig {
        #[arg(long)]
        out: PathBuf,
        /// count | sum:<max> | sumvec:<len>:<bits> | bounded:<b1,b2,...> | histogram:<len> | multihot:<len>:<maxw>
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
        #[arg(long)]
        collector: String,
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
    },
    Collector {
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        material: PathBuf,
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
        ["sumvec", l, b] => MeasurementType::SumVec { length: l.parse()?, bits: b.parse()? },
        ["bounded", bs] => MeasurementType::BoundedSumVec { bounds: bs.split(',').map(|x| x.parse::<u64>()).collect::<std::result::Result<Vec<u64>, _>>()? },
        ["histogram", l] => MeasurementType::Histogram { length: l.parse()? },
        ["multihot", l, w] => MeasurementType::MultihotCountVec { length: l.parse()?, max_weight: w.parse()? },
        _ => anyhow::bail!("unknown type {s}"),
    })
}

/// Loads the aggregators' sealed identities from `dir`, creating any that
/// are missing. Sealed under the deployment key like the shares, with the
/// aggregator index as associated data.
fn load_or_create_identities(dir: &PathBuf, n: usize) -> anyhow::Result<Vec<AggregatorIdentity>> {
    std::fs::create_dir_all(dir)?;
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let path = dir.join(format!("aggregator-{i}.identity.sealed"));
        let label = format!("aggregator-identity:{i}");
        let id = if path.exists() {
            let b = secret::unseal(label.as_bytes(), &std::fs::read(&path)?)?;
            AggregatorIdentity::from_secret_bytes(b.as_slice().try_into().map_err(|_| anyhow::anyhow!("identity must be 32 bytes"))?)
        } else {
            let id = AggregatorIdentity::generate();
            std::fs::write(&path, secret::seal(label.as_bytes(), &id.secret_bytes())?)?;
            id
        };
        ids.push(id);
    }
    Ok(ids)
}

/// Writes `aggregator-keys.txt`: the public identity keys, one per line,
/// line `i` for aggregator `i`. This file is what clients pin.
fn write_aggregator_keys(out_dir: &PathBuf, ids: &[AggregatorIdentity]) -> anyhow::Result<()> {
    let mut text = String::from("# fhe-prio3 aggregator identity keys, line i = aggregator i\n");
    for id in ids {
        text.push_str(&hex::encode(id.public_key()));
        text.push('\n');
    }
    std::fs::write(out_dir.join("aggregator-keys.txt"), text)?;
    Ok(())
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::TaskConfig { out, r#type, aggregators, mode, min_batch, auth_quota, task_id } => {
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
                cfg.auth = AuthPolicy::Required { max_reports_per_client_per_batch: auth_quota };
            }
            cfg.validate()?;
            std::fs::write(&out, encode(&cfg)?)?;
            println!("wrote {} (digest {})", out.display(), hex::encode(cfg.digest()));
        }
        Cmd::Keygen { task, out_dir, identities_dir } => {
            let cfg: TaskConfig = read(&task)?;
            std::fs::create_dir_all(&out_dir)?;
            let ids = load_or_create_identities(&identities_dir.unwrap_or_else(|| out_dir.join("identities")), cfg.num_aggregators)?;
            write_aggregator_keys(&out_dir, &ids)?;
            let (mut material, shares) = keys::run_local_ceremony(&cfg)?;
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
        Cmd::Aggregator { index, task, material, share, db, listen, aggregators, collector, token, tls_cert, tls_key, ca, clients } => {
            let cfg: TaskConfig = read(&task)?;
            let material: PublicMaterial = read(&material)?;
            let sealed = std::fs::read(&share)?;
            let share = secret::unseal(format!("share:{index}:{}", hex::encode(cfg.task_id)).as_bytes(), &sealed)?;
            let registry: Option<Arc<dyn ClientRegistry>> = match clients {
                Some(p) => {
                    let keys: Vec<[u8; 32]> = std::fs::read_to_string(p)?
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| hex::decode(l.trim()).ok().and_then(|b| b.as_slice().try_into().ok()).ok_or_else(|| anyhow::anyhow!("bad client key line")))
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
                collector,
                token,
                db,
                registry,
                ca_pem: std::fs::read(&ca)?,
            })?;
            let handle = axum_server::Handle::new();
            let h2 = handle.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                h2.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
            });
            tracing::info!(%listen, index, "aggregator listening");
            let tls = AggregatorNode::tls_config(tls_cert, tls_key).await?;
            node.serve(listen, Some(tls), handle).await?;
        }
        Cmd::Collector { task, material, db, listen, token, tls_cert, tls_key } => {
            let cfg: TaskConfig = read(&task)?;
            let material: PublicMaterial = read(&material)?;
            let node = CollectorNode::new(CollectorNodeConfig { task: cfg, material, token, db })?;
            let handle = axum_server::Handle::new();
            tracing::info!(%listen, "collector listening");
            let tls = CollectorNode::tls_config(tls_cert, tls_key).await?;
            node.serve(listen, Some(tls), handle).await?;
        }
        Cmd::Submit { task, material, leader, ca, value, identity, aggregator_keys } => {
            let cfg: TaskConfig = read(&task)?;
            let material: PublicMaterial = read(&material)?;
            let id = match identity {
                Some(p) => {
                    let b = hex::decode(std::fs::read_to_string(p)?.trim())?;
                    Some(ClientIdentity::from_secret_bytes(b.as_slice().try_into().map_err(|_| anyhow::anyhow!("identity must be 32 bytes"))?))
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
            let r: BatchResult = fhe_prio3_node::wire::http_post(&http, &format!("{leader}/v1/close"), Some(&token), &()).await?;
            println!("{r:?}");
        }
        Cmd::KeygenShards { task, shards, out_dir, identities_dir } => {
            let base: TaskConfig = read(&task)?;
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
        Cmd::Router { shards_dir, leaders, listen, token, tls_cert, tls_key, ca } => {
            let leaders: Vec<String> = leaders.split(',').map(|s| s.trim().to_string()).collect();
            let mut shards = Vec::with_capacity(leaders.len());
            for (i, leader) in leaders.iter().enumerate() {
                let dir = shards_dir.join(format!("shard-{i}"));
                let task: TaskConfig = read(&dir.join("task.bin"))?;
                let material: PublicMaterial = read(&dir.join("material.bin"))?;
                shards.push(fhe_prio3_node::router::ShardInfo { task, client_material: fhe_prio3_node::router::client_material(&material), leader: leader.clone() });
            }
            let node = fhe_prio3_node::router::RouterNode::new(fhe_prio3_node::router::RouterNodeConfig { shards, token, ca_pem: std::fs::read(&ca)? })?;
            node.verify_leaders(std::time::Duration::from_secs(120)).await?;
            let handle = axum_server::Handle::new();
            tracing::info!(%listen, "router listening");
            let tls = fhe_prio3_node::router::RouterNode::tls_config(tls_cert, tls_key).await?;
            node.serve(listen, Some(tls), handle).await?;
        }
        Cmd::SubmitSharded { router, ca, value, identity, aggregator_keys } => {
            let id = match identity {
                Some(p) => {
                    let b = hex::decode(std::fs::read_to_string(p)?.trim())?;
                    Some(ClientIdentity::from_secret_bytes(b.as_slice().try_into().map_err(|_| anyhow::anyhow!("identity must be 32 bytes"))?))
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
