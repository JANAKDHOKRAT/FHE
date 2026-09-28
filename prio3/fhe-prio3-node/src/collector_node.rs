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
    pub token: String,
    pub db: PathBuf,
}

struct Inner {
    task: TaskConfig,
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
        Ok(Self {
            inner: Arc::new(Inner { task: cfg.task, collector: Mutex::new(collector), store: Mutex::new(store), shares: Mutex::new(shares), result: Mutex::new(result), token: cfg.token }),
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

/// Stores the share; returns the batch result once every aggregator's share
/// is present (and `None` before that).
async fn receive_share(State(node): State<CollectorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let env: ShareEnvelope = parse_body(&body)?;
    let inner = node.inner.clone();
    let out: Option<BatchResult> = tokio::task::spawn_blocking(move || -> std::result::Result<Option<BatchResult>, HttpError> {
        let n = inner.task.num_aggregators;
        if env.share.aggregator >= n {
            return Err(HttpError(StatusCode::BAD_REQUEST, "aggregator index out of range".into()));
        }
        let mut shares = inner.shares.lock().unwrap();
        let mut store = inner.store.lock().unwrap();
        store.put(&format!("share:{}", env.share.aggregator), &encode(&env.share)?)?;
        shares.insert(env.share.aggregator, env.share);
        if shares.len() < n {
            return Ok(None);
        }
        let all: Vec<AggregateShare> = shares.values().cloned().collect();
        let collector = inner.collector.lock().unwrap();
        let r = collector.unshard(&all)?;
        store.put("result", &encode(&r)?)?;
        *inner.result.lock().unwrap() = Some(r.clone());
        Ok(Some(r))
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
