//! Router: the single public entry point of a sharded deployment. It
//! assigns each client to a shard before the client encrypts, serves the
//! shard's public task and key material, and closes every shard and
//! combines their results for the operator. It holds no key material and
//! never sees a ciphertext.

use crate::wire::*;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use fhe_prio3::sharding::combine_results;
use fhe_prio3::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone)]
pub struct Assignment {
    pub shard: u32,
    pub leader: String,
}

#[derive(Clone)]
pub struct ShardInfo {
    pub task: TaskConfig,
    /// Public material with the evaluation keys stripped: what a client needs.
    pub client_material: PublicMaterial,
    pub leader: String,
}

pub struct RouterNodeConfig {
    pub shards: Vec<ShardInfo>,
    pub token: String,
    pub ca_pem: Vec<u8>,
}

struct Inner {
    shards: Vec<ShardInfo>,
    task_bytes: Vec<Vec<u8>>,
    material_bytes: Vec<Vec<u8>>,
    token: String,
    http: reqwest::Client,
    next: AtomicU64,
}

#[derive(Clone)]
pub struct RouterNode {
    inner: Arc<Inner>,
}

/// Strips evaluation keys from public material; clients only encrypt.
pub fn client_material(m: &PublicMaterial) -> PublicMaterial {
    PublicMaterial {
        context: m.context.clone(),
        public_key: m.public_key.clone(),
        joint_tag: m.joint_tag.clone(),
        eval_mult_key: Vec::new(),
        rotation_keys: Vec::new(),
        rotation_indices: m.rotation_indices.clone(),
        attestations: m.attestations.clone(),
    }
}

impl RouterNode {
    pub fn new(cfg: RouterNodeConfig) -> anyhow::Result<Self> {
        if cfg.shards.is_empty() {
            anyhow::bail!("router needs at least one shard");
        }
        let task_bytes = cfg.shards.iter().map(|s| fhe_prio3::messages::encode(&s.task)).collect::<Result<Vec<_>>>()?;
        let material_bytes = cfg.shards.iter().map(|s| fhe_prio3::messages::encode(&s.client_material)).collect::<Result<Vec<_>>>()?;
        Ok(Self {
            inner: Arc::new(Inner { shards: cfg.shards, task_bytes, material_bytes, token: cfg.token, http: https_client(&cfg.ca_pem)?, next: AtomicU64::new(0) }),
        })
    }

    /// Checks that leader `i` serves shard `i`'s task and is aggregator 0.
    /// Retries for up to `timeout` while a leader is still starting. A
    /// misordered leader list would otherwise send every client to a shard
    /// that rejects its reports with `WrongTask`.
    pub async fn verify_leaders(&self, timeout: std::time::Duration) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        for (i, s) in self.inner.shards.iter().enumerate() {
            loop {
                match http_get::<StatusReply>(&self.inner.http, &format!("{}/v1/status", s.leader), None).await {
                    Ok(st) => {
                        if st.task_id != hex::encode(s.task.task_id) {
                            anyhow::bail!("leader {} serves task {} but is listed for shard {} (task {})", s.leader, st.task_id, i, hex::encode(s.task.task_id));
                        }
                        if st.index != 0 {
                            anyhow::bail!("{} is aggregator {}, not the leader of shard {}", s.leader, st.index, i);
                        }
                        break;
                    }
                    Err(e) if start.elapsed() < timeout => {
                        tracing::warn!(leader = %s.leader, error = %e, "leader not reachable yet, retrying");
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                    Err(e) => anyhow::bail!("leader {} of shard {i} unreachable: {e}", s.leader),
                }
            }
        }
        Ok(())
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/assign", get(assign))
            .route("/v1/shard/:i/task", get(shard_task))
            .route("/v1/shard/:i/material", get(shard_material))
            .route("/v1/shards", get(shards))
            .route("/v1/close-all", post(close_all))
            .layer(DefaultBodyLimit::max(1 << 20))
            .with_state(self.clone())
    }

    pub async fn tls_config(cert: PathBuf, key: PathBuf) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
        init_crypto();
        Ok(axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?)
    }

    pub async fn serve(&self, addr: SocketAddr, tls: Option<axum_server::tls_rustls::RustlsConfig>, handle: axum_server::Handle) -> anyhow::Result<()> {
        init_crypto();
        let app = self.router();
        match tls {
            Some(cfg) => axum_server::bind_rustls(addr, cfg).handle(handle).serve(app.into_make_service()).await?,
            None => axum_server::bind(addr).handle(handle).serve(app.into_make_service()).await?,
        }
        Ok(())
    }
}

async fn assign(State(node): State<RouterNode>) -> std::result::Result<axum::response::Response, HttpError> {
    let n = node.inner.shards.len() as u64;
    let i = (node.inner.next.fetch_add(1, Ordering::Relaxed) % n) as usize;
    reply(&Assignment { shard: i as u32, leader: node.inner.shards[i].leader.clone() })
}

async fn shards(State(node): State<RouterNode>) -> std::result::Result<axum::response::Response, HttpError> {
    let list: Vec<Assignment> = node.inner.shards.iter().enumerate().map(|(i, s)| Assignment { shard: i as u32, leader: s.leader.clone() }).collect();
    reply(&list)
}

fn shard_index(node: &RouterNode, i: u32) -> std::result::Result<usize, HttpError> {
    let i = i as usize;
    if i >= node.inner.shards.len() {
        return Err(HttpError(StatusCode::NOT_FOUND, "no such shard".into()));
    }
    Ok(i)
}

async fn shard_task(State(node): State<RouterNode>, Path(i): Path<u32>) -> std::result::Result<axum::response::Response, HttpError> {
    let i = shard_index(&node, i)?;
    Ok(axum::response::IntoResponse::into_response(([(axum::http::header::CONTENT_TYPE, CONTENT_TYPE)], node.inner.task_bytes[i].clone())))
}

async fn shard_material(State(node): State<RouterNode>, Path(i): Path<u32>) -> std::result::Result<axum::response::Response, HttpError> {
    let i = shard_index(&node, i)?;
    Ok(axum::response::IntoResponse::into_response(([(axum::http::header::CONTENT_TYPE, CONTENT_TYPE)], node.inner.material_bytes[i].clone())))
}

/// Closes every shard through its leader and returns the combined result.
/// A shard that cannot close (for example below its minimum batch) fails the
/// whole call; nothing partial is returned.
async fn close_all(State(node): State<RouterNode>, headers: HeaderMap, _body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let mut results = Vec::with_capacity(node.inner.shards.len());
    for s in &node.inner.shards {
        let r: BatchResult = http_post(&node.inner.http, &format!("{}/v1/close", s.leader), Some(&node.inner.token), &()).await?;
        results.push(r);
    }
    let combined = combine_results(&results)?;
    reply(&combined)
}
