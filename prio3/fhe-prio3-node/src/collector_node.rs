//! Collector node: receives one aggregate share per aggregator, unshards
//! when all have arrived, and serves the result. Holds no key material.

use crate::store::Store;
use crate::wire::*;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct CollectorNodeConfig {
    pub task: TaskConfig,
    pub material: PublicMaterial,
    /// This collector's id in the task's policies (0 without policies).
    pub collector_id: u32,
    /// This collector's sealing key; required when the task has policies
    /// and must be the key the task declares for `collector_id`.
    pub seal_key: Option<CollectorSealKey>,
    pub token: String,
    pub db: PathBuf,
}

struct Inner {
    task: TaskConfig,
    collector_id: u32,
    seal_key: Option<CollectorSealKey>,
    collector: Mutex<Collector>,
    store: Mutex<Store>,
    shares: Mutex<BTreeMap<usize, AggregateShare>>,
    result: Mutex<Option<BatchResult>>,
    token: String,
}

#[derive(Clone)]
pub struct CollectorNode {
    inner: Arc<Inner>,
}

impl CollectorNode {
    pub fn new(cfg: CollectorNodeConfig) -> anyhow::Result<Self> {
        let collector = Collector::new(cfg.task.clone(), &cfg.material)?;
        let c = cfg.collector_id as usize;
        if cfg.task.collectors.is_empty() {
            if c != 0 {
                anyhow::bail!("task has a single collector, id 0");
            }
        } else {
            let declared = cfg.task.collectors.get(c).map(|p| p.seal_key).ok_or_else(|| anyhow::anyhow!("no collector {c} in the task"))?;
            let key = cfg.seal_key.as_ref().ok_or_else(|| anyhow::anyhow!("task has release policies: this collector needs its sealing key"))?;
            if key.public_key() != declared {
                anyhow::bail!("sealing key is not the one the task declares for collector {c}");
            }
        }
        let store = Store::open(&cfg.db)?;
        let mut shares = BTreeMap::new();
        for i in 0..cfg.task.num_aggregators {
            if let Some(b) = store.get(&format!("share:{i}"))? {
                shares.insert(i, decode::<AggregateShare>(&b)?);
            }
        }
        let result = match store.get("result")? {
            Some(b) => Some(decode::<BatchResult>(&b)?),
            None => None,
        };
        // Shares still waiting for the others will be unsharded: refuse to
        // start on shares stored before the packed format. A batch whose
        // result is already stored stays readable.
        if result.is_none() {
            for share in shares.values() {
                collector.check_stored_share(share)?;
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                task: cfg.task,
                collector_id: cfg.collector_id,
                seal_key: cfg.seal_key,
                collector: Mutex::new(collector),
                store: Mutex::new(store),
                shares: Mutex::new(shares),
                result: Mutex::new(result),
                token: cfg.token,
            }),
        })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/aggregate-share", post(receive_share))
            .route("/v1/result", get(result))
            .layer(DefaultBodyLimit::max(256 << 20))
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

/// Stores a share and, once every aggregator's share is present, unshards.
/// Without policies the body is a plain `ShareEnvelope` and the result is
/// returned to the leader; with policies the body is a `SealedEnvelope`
/// that only this collector can open, the share must be released to this
/// collector's id, and the result is served to this collector's operator
/// only.
async fn receive_share(State(node): State<CollectorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let inner = node.inner.clone();
    let share: AggregateShare = if inner.task.collectors.is_empty() {
        let env: ShareEnvelope = parse_body(&body)?;
        env.share
    } else {
        let env: SealedEnvelope = parse_body(&body)?;
        let key = inner.seal_key.as_ref().expect("checked at construction");
        if env.sealed.collector != inner.collector_id {
            return Err(HttpError(StatusCode::BAD_REQUEST, format!("share sealed for collector {}, this is collector {}", env.sealed.collector, inner.collector_id)));
        }
        fhe_prio3::seal::open(&env.sealed, key)?
    };
    if share.collector != inner.collector_id {
        return Err(HttpError(StatusCode::BAD_REQUEST, "share released to another collector".into()));
    }
    let out: ShareReceipt = tokio::task::spawn_blocking(move || -> std::result::Result<ShareReceipt, HttpError> {
        let n = inner.task.num_aggregators;
        if share.aggregator >= n {
            return Err(HttpError(StatusCode::BAD_REQUEST, "aggregator index out of range".into()));
        }
        let mut shares = inner.shares.lock().unwrap();
        let mut store = inner.store.lock().unwrap();
        store.put(&format!("share:{}", share.aggregator), &encode(&share)?)?;
        shares.insert(share.aggregator, share);
        if shares.len() < n {
            return Ok(ShareReceipt { complete: false, result: None });
        }
        let all: Vec<AggregateShare> = shares.values().cloned().collect();
        let collector = inner.collector.lock().unwrap();
        let r = collector.unshard_for(inner.collector_id as usize, &all)?;
        store.put("result", &encode(&r)?)?;
        *inner.result.lock().unwrap() = Some(r.clone());
        Ok(ShareReceipt { complete: true, result: if inner.task.collectors.is_empty() { Some(r) } else { None } })
    })
    .await
    .map_err(|e| HttpError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
    reply(&out)
}

async fn result(State(node): State<CollectorNode>, headers: HeaderMap) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let r = node.inner.result.lock().unwrap().clone();
    reply(&r)
}
