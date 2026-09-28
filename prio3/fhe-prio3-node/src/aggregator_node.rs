//! Aggregator node: HTTPS server around one `Aggregator`, with the leader
//! (index 0) driving the per-report rounds and the batch close.
//!
//! Concurrency: OpenFHE work is CPU-bound and the `Aggregator` is `Send`
//! but not `Sync`, so it lives behind a `std::sync::Mutex` and every
//! homomorphic step runs on the blocking pool while holding the lock. That
//! serialises FHE work per node, which is also the throughput model an
//! operator sizes for (one node per core group).
//!
//! Persistence: after every state-changing step the aggregator's snapshot
//! and, for silent mode, the report bytes it still needs are committed to
//! SQLite in one transaction; a restarted node resumes from them.

use crate::store::Store;
use crate::wire::*;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

pub struct AggregatorNodeConfig {
    pub index: usize,
    pub task: TaskConfig,
    pub material: PublicMaterial,
    /// This node's unsealed key share bytes.
    pub share: Vec<u8>,
    /// Base URLs of every aggregator, by index (including this one).
    pub aggregators: Vec<String>,
    pub collector: String,
    /// Shared secret for aggregator-to-aggregator and aggregator-to-collector calls.
    pub token: String,
    pub db: PathBuf,
    pub registry: Option<Arc<dyn ClientRegistry>>,
    pub ca_pem: Vec<u8>,
}

struct Inner {
    index: usize,
    task: TaskConfig,
    agg: Mutex<Aggregator>,
    store: Mutex<Store>,
    aggregators: Vec<String>,
    collector: String,
    token: String,
    http: reqwest::Client,
    next_group: AtomicU32,
    groups: u32,
    max_report_bytes: usize,
}

#[derive(Clone)]
pub struct AggregatorNode {
    inner: Arc<Inner>,
}

const K_STATE: &str = "aggregator_state";
const K_TASK: &str = "task_config";

impl AggregatorNode {
    /// Builds the node, restoring persisted state if the database has any.
    pub fn new(cfg: AggregatorNodeConfig) -> anyhow::Result<Self> {
        let mut agg = Aggregator::new(cfg.task.clone(), &cfg.material, cfg.index, &cfg.share, cfg.registry.clone())?;
        let mut store = Store::open(&cfg.db)?;
        match store.get(K_TASK)? {
            Some(bytes) => {
                if bytes != encode(&cfg.task)? {
                    anyhow::bail!("database {} belongs to a different task configuration", cfg.db.display());
                }
            }
            None => store.put(K_TASK, &encode(&cfg.task)?)?,
        }
        if let Some(bytes) = store.get(K_STATE)? {
            let st: AggregatorState = decode(&bytes)?;
            let mut pending = Vec::with_capacity(st.silent_pending.len());
            for (_, id) in &st.silent_pending {
                let b = store.get(&format!("report:{}", hex::encode(id)))?.ok_or_else(|| anyhow::anyhow!("pending report missing from store"))?;
                pending.push(decode::<Report>(&b)?);
            }
            agg.restore(st, &pending)?;
            tracing::info!(index = cfg.index, accepted = agg.accepted_count(), "restored aggregator state");
        }
        let groups = agg.layout().groups as u32;
        let max_report_bytes = agg.max_report_bytes();
        let http = https_client(&cfg.ca_pem)?;
        Ok(Self {
            inner: Arc::new(Inner {
                index: cfg.index,
                task: cfg.task,
                agg: Mutex::new(agg),
                store: Mutex::new(store),
                aggregators: cfg.aggregators,
                collector: cfg.collector,
                token: cfg.token,
                http,
                next_group: AtomicU32::new(0),
                groups,
                max_report_bytes,
            }),
        })
    }

    pub fn is_leader(&self) -> bool {
        self.inner.index == 0
    }

    pub fn router(&self) -> Router {
        let limit = self.inner.max_report_bytes + (64 << 10);
        Router::new()
            .route("/v1/status", get(status))
            .route("/v1/group", get(group_ticket))
            .route("/v1/submit", post(submit))
            .route("/v1/close", post(close))
            .route("/v1/report", post(internal_report))
            .route("/v1/masks", post(internal_masks))
            .route("/v1/verifiers", post(internal_verifiers))
            .route("/v1/count-share", post(internal_count_share))
            .route("/v1/count-finish", post(internal_count_finish))
            .route("/v1/aggregate-share", post(internal_aggregate_share))
            .layer(DefaultBodyLimit::max(limit))
            .with_state(self.clone())
    }

    /// Loads the TLS configuration; errors surface here, before serving.
    pub async fn tls_config(cert: PathBuf, key: PathBuf) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
        init_crypto();
        Ok(axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?)
    }

    /// Serves until `handle` is shut down.
    pub async fn serve(&self, addr: SocketAddr, tls: Option<axum_server::tls_rustls::RustlsConfig>, handle: axum_server::Handle) -> anyhow::Result<()> {
        init_crypto();
        let app = self.router();
        match tls {
            Some(cfg) => axum_server::bind_rustls(addr, cfg).handle(handle).serve(app.into_make_service()).await?,
            None => axum_server::bind(addr).handle(handle).serve(app.into_make_service()).await?,
        }
        Ok(())
    }

    /// Runs `f` on the blocking pool with the aggregator and store locked,
    /// then commits the snapshot when `f` reports a state change.
    async fn with_agg<R: Send + 'static>(
        &self,
        event: &'static str,
        detail: String,
        extra: Vec<(String, Vec<u8>)>,
        f: impl FnOnce(&mut Aggregator) -> Result<(R, bool)> + Send + 'static,
    ) -> std::result::Result<R, HttpError> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || -> std::result::Result<R, HttpError> {
            let mut agg = inner.agg.lock().map_err(|_| HttpError(StatusCode::INTERNAL_SERVER_ERROR, "aggregator lock poisoned".into()))?;
            let (r, changed) = f(&mut agg)?;
            if changed {
                let snap = encode(&agg.snapshot()?)?;
                let mut entries: Vec<(&str, Vec<u8>)> = vec![(K_STATE, snap)];
                let names: Vec<String> = extra.iter().map(|(n, _)| n.clone()).collect();
                for (i, (_, b)) in extra.into_iter().enumerate() {
                    entries.push((names[i].as_str(), b));
                }
                let mut store = inner.store.lock().map_err(|_| HttpError(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned".into()))?;
                store.commit_step(&entries, event, &detail)?;
            }
            Ok(r)
        })
        .await
        .map_err(|e| HttpError(StatusCode::INTERNAL_SERVER_ERROR, format!("task join: {e}")))?
    }

    fn helpers(&self) -> Vec<(usize, String)> {
        self.inner.aggregators.iter().enumerate().filter(|(i, _)| *i != self.inner.index).map(|(i, u)| (i, u.clone())).collect()
    }

    // ---- leader orchestration ------------------------------------------

    /// Verdict mode: three rounds with every helper; silent mode: forward.
    async fn drive_report(&self, report: Report) -> std::result::Result<SubmitOutcome, HttpError> {
        let id = report.report_id;
        let detail = hex::encode(id);
        let report_bytes = encode(&report)?;
        if self.inner.task.mode == VerificationMode::Silent {
            // Local admission first: a report we refuse is not forwarded.
            let r = report.clone();
            let outcome = self
                .with_agg("silent_admit", detail.clone(), vec![(format!("report:{detail}"), report_bytes.clone())], move |agg| match agg.process_silent(&r) {
                    Ok(()) => Ok((SubmitOutcome::Accepted, true)),
                    Err(Error::Reject(reason)) => Ok((SubmitOutcome::Rejected(reason.to_string()), false)),
                    Err(e) => Err(e),
                })
                .await?;
            if outcome != SubmitOutcome::Accepted {
                return Ok(outcome);
            }
            for (_, url) in self.helpers() {
                let o: SubmitOutcome = http_post(&self.inner.http,&format!("{url}/v1/report"), Some(&self.inner.token), &report).await?;
                if o != SubmitOutcome::Accepted {
                    return Err(HttpError(StatusCode::CONFLICT, format!("helper disagrees on admission: {o:?}")));
                }
            }
            return Ok(SubmitOutcome::Accepted);
        }

        // Verdict mode, round 1: everyone's mask.
        let r = report.clone();
        let mine = self
            .with_agg("verdict_init", detail.clone(), vec![], move |agg| match agg.prepare_init(&r) {
                Ok(m) => Ok((Ok(m), false)),
                Err(Error::Reject(reason)) => Ok((Err(reason), false)),
                Err(e) => Err(e),
            })
            .await?;
        let my_mask = match mine {
            Ok(m) => m,
            Err(reason) => return Ok(SubmitOutcome::Rejected(reason.to_string())),
        };
        let mut masks = vec![my_mask];
        for (_, url) in self.helpers() {
            let m: std::result::Result<MaskMessage, String> = http_post(&self.inner.http,&format!("{url}/v1/report"), Some(&self.inner.token), &report).await?;
            match m {
                Ok(m) => masks.push(m),
                Err(reason) => return Err(HttpError(StatusCode::CONFLICT, format!("helper refused a report the leader admitted: {reason}"))),
            }
        }
        // Round 2: everyone's partial decryption of the masked check.
        let others_for_me: Vec<MaskMessage> = masks.iter().filter(|m| m.aggregator != self.inner.index).cloned().collect();
        let mut verifiers = vec![
            self.with_agg("verdict_masks", detail.clone(), vec![], move |agg| Ok((agg.prepare_masks(&id, &others_for_me)?, false))).await?,
        ];
        for (i, url) in self.helpers() {
            let req = MasksRequest { report_id: id, masks: masks.iter().filter(|m| m.aggregator != i).cloned().collect() };
            let v: VerifierMessage = http_post(&self.inner.http,&format!("{url}/v1/masks"), Some(&self.inner.token), &req).await?;
            verifiers.push(v);
        }
        // Round 3: verdicts.
        let others_for_me: Vec<VerifierMessage> = verifiers.iter().filter(|v| v.aggregator != self.inner.index).cloned().collect();
        let my_verdict = self
            .with_agg("verdict_finish", detail.clone(), vec![(format!("report:{detail}"), report_bytes)], move |agg| {
                let v = agg.prepare_finish(&id, &others_for_me)?;
                let changed = v == Verdict::Accepted;
                Ok((v, changed))
            })
            .await?;
        for (i, url) in self.helpers() {
            let req = VerifiersRequest { report_id: id, verifiers: verifiers.iter().filter(|v| v.aggregator != i).cloned().collect() };
            let o: SubmitOutcome = http_post(&self.inner.http,&format!("{url}/v1/verifiers"), Some(&self.inner.token), &req).await?;
            let mine = match &my_verdict {
                Verdict::Accepted => SubmitOutcome::Accepted,
                Verdict::Rejected(r) => SubmitOutcome::Rejected(r.to_string()),
            };
            if o != mine {
                return Err(HttpError(StatusCode::CONFLICT, format!("helper {i} verdict {o:?} differs from leader {mine:?}")));
            }
        }
        Ok(match my_verdict {
            Verdict::Accepted => SubmitOutcome::Accepted,
            Verdict::Rejected(r) => SubmitOutcome::Rejected(r.to_string()),
        })
    }

    /// Closes the batch on every aggregator and delivers the shares to the
    /// collector, which returns the batch result.
    async fn drive_close(&self) -> std::result::Result<BatchResult, HttpError> {
        if self.inner.task.mode == VerificationMode::Silent {
            let mut counts = vec![self.with_agg("count_share", String::new(), vec![], |agg| Ok((agg.count_share()?, true))).await?];
            for (_, url) in self.helpers() {
                let c: CountShare = http_post(&self.inner.http,&format!("{url}/v1/count-share"), Some(&self.inner.token), &()).await?;
                counts.push(c);
            }
            let req = CountFinishRequest { shares: counts };
            let shares = req.shares.clone();
            let mine: u64 = self.with_agg("count_finish", String::new(), vec![], move |agg| Ok((agg.count_finish(&shares)?, true))).await?;
            for (_, url) in self.helpers() {
                let n: u64 = http_post(&self.inner.http,&format!("{url}/v1/count-finish"), Some(&self.inner.token), &req).await?;
                if n != mine {
                    return Err(HttpError(StatusCode::CONFLICT, "aggregators disagree on the valid count".into()));
                }
            }
        }
        let mut shares = vec![self.with_agg("aggregate_share", String::new(), vec![], |agg| Ok((agg.aggregate_share()?, true))).await?];
        for (_, url) in self.helpers() {
            let s: AggregateShare = http_post(&self.inner.http,&format!("{url}/v1/aggregate-share"), Some(&self.inner.token), &()).await?;
            shares.push(s);
        }
        let mut result: Option<BatchResult> = None;
        for s in shares {
            let r: Option<BatchResult> =
                http_post(&self.inner.http, &format!("{}/v1/aggregate-share", self.inner.collector), Some(&self.inner.token), &ShareEnvelope { share: s }).await?;
            if r.is_some() {
                result = r;
            }
        }
        result.ok_or_else(|| HttpError(StatusCode::INTERNAL_SERVER_ERROR, "collector did not produce a result after all shares".into()))
    }
}

// ---- handlers ------------------------------------------------------------

async fn status(State(node): State<AggregatorNode>) -> std::result::Result<axum::response::Response, HttpError> {
    let inner = node.inner.clone();
    let (accepted, closed) = tokio::task::spawn_blocking(move || {
        let agg = inner.agg.lock().unwrap();
        (agg.accepted_count(), agg.is_closed())
    })
    .await
    .map_err(|e| HttpError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    reply(&StatusReply { index: node.inner.index, task_id: hex::encode(node.inner.task.task_id), accepted, closed, mode: format!("{:?}", node.inner.task.mode) })
}

async fn group_ticket(State(node): State<AggregatorNode>) -> std::result::Result<axum::response::Response, HttpError> {
    if !node.is_leader() {
        return Err(HttpError(StatusCode::NOT_FOUND, "only the leader hands out groups".into()));
    }
    let groups = node.inner.groups;
    let g = node.inner.next_group.fetch_add(1, Ordering::Relaxed) % groups;
    reply(&GroupTicket { group: g, groups })
}

async fn submit(State(node): State<AggregatorNode>, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    if !node.is_leader() {
        return Err(HttpError(StatusCode::NOT_FOUND, "submit to the leader".into()));
    }
    let report: Report = parse_body(&body)?;
    let outcome = node.drive_report(report).await?;
    reply(&outcome)
}

async fn close(State(node): State<AggregatorNode>, headers: HeaderMap) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    if !node.is_leader() {
        return Err(HttpError(StatusCode::NOT_FOUND, "close via the leader".into()));
    }
    let r = node.drive_close().await?;
    reply(&r)
}

async fn internal_report(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let report: Report = parse_body(&body)?;
    let detail = hex::encode(report.report_id);
    let bytes = body.to_vec();
    if node.inner.task.mode == VerificationMode::Silent {
        let out = node
            .with_agg("silent_admit", detail.clone(), vec![(format!("report:{detail}"), bytes)], move |agg| match agg.process_silent(&report) {
                Ok(()) => Ok((SubmitOutcome::Accepted, true)),
                Err(Error::Reject(r)) => Ok((SubmitOutcome::Rejected(r.to_string()), false)),
                Err(e) => Err(e),
            })
            .await?;
        return reply(&out);
    }
    let out: std::result::Result<MaskMessage, String> = node
        .with_agg("verdict_init", detail, vec![], move |agg| match agg.prepare_init(&report) {
            Ok(m) => Ok((Ok(m), false)),
            Err(Error::Reject(r)) => Ok((Err(r.to_string()), false)),
            Err(e) => Err(e),
        })
        .await?;
    reply(&out)
}

async fn internal_masks(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: MasksRequest = parse_body(&body)?;
    let v = node.with_agg("verdict_masks", hex::encode(req.report_id), vec![], move |agg| Ok((agg.prepare_masks(&req.report_id, &req.masks)?, false))).await?;
    reply(&v)
}

async fn internal_verifiers(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: VerifiersRequest = parse_body(&body)?;
    let detail = hex::encode(req.report_id);
    let out = node
        .with_agg("verdict_finish", detail, vec![], move |agg| {
            let v = agg.prepare_finish(&req.report_id, &req.verifiers)?;
            let changed = v == Verdict::Accepted;
            Ok((
                match v {
                    Verdict::Accepted => SubmitOutcome::Accepted,
                    Verdict::Rejected(r) => SubmitOutcome::Rejected(r.to_string()),
                },
                changed,
            ))
        })
        .await?;
    reply(&out)
}

async fn internal_count_share(State(node): State<AggregatorNode>, headers: HeaderMap) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let c = node.with_agg("count_share", String::new(), vec![], |agg| Ok((agg.count_share()?, true))).await?;
    reply(&c)
}

async fn internal_count_finish(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: CountFinishRequest = parse_body(&body)?;
    let n = node.with_agg("count_finish", String::new(), vec![], move |agg| Ok((agg.count_finish(&req.shares)?, true))).await?;
    reply(&n)
}

async fn internal_aggregate_share(State(node): State<AggregatorNode>, headers: HeaderMap) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let s = node.with_agg("aggregate_share", String::new(), vec![], |agg| Ok((agg.aggregate_share()?, true))).await?;
    reply(&s)
}
