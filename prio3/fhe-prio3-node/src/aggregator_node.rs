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

use crate::metrics::{BuildInfo, NodeMetrics};
use crate::store::{IdKind, Store};
use crate::wire::*;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
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
    /// Base URLs of the collectors, by collector id (one without policies).
    pub collectors: Vec<String>,
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
    collectors: Vec<String>,
    token: String,
    http: reqwest::Client,
    next_group: AtomicU32,
    groups: u32,
    max_report_bytes: usize,
    max_message_bytes: usize,
    metrics: Arc<NodeMetrics>,
    /// Accumulator generation of the last committed `K_ACC`; `None` until
    /// the first commit of this process, which always writes them.
    persisted_accumulators: Mutex<Option<u64>>,
    /// Report ids already in the store's `ids` table: (seen, accepted). The
    /// table holds a prefix of `Aggregator::id_logs`; a step appends the rest.
    persisted_ids: Mutex<(usize, usize)>,
}

#[derive(Clone)]
pub struct AggregatorNode {
    inner: Arc<Inner>,
}

const K_STATE: &str = "aggregator_state";
/// The encrypted accumulators, stored apart from `K_STATE` and written only
/// when they changed (`Aggregator::accumulator_generation`). A database
/// written before the split holds them inside `K_STATE` and none here.
const K_ACC: &str = "aggregator_accumulators";
const K_TASK: &str = "task_config";
const REPORT_PREFIX: &str = "report:";

fn report_key(id: &fhe_prio3::messages::ReportId) -> String {
    format!("{REPORT_PREFIX}{}", hex::encode(id))
}

impl AggregatorNode {
    /// Builds the node, restoring persisted state if the database has any.
    pub fn new(cfg: AggregatorNodeConfig) -> anyhow::Result<Self> {
        let mut agg = Aggregator::new(cfg.task.clone(), &cfg.material, cfg.index, &cfg.share, cfg.registry.clone())?;
        let mut store = Store::open(&cfg.db)?;
        match store.get(K_TASK)? {
            Some(bytes) => {
                // a database from before the task's last format change holds
                // the older encoding of the same task
                if TaskConfig::decode(&bytes).ok().as_ref() != Some(&cfg.task) {
                    anyhow::bail!("database {} belongs to a different task configuration", cfg.db.display());
                }
            }
            None => store.put(K_TASK, &encode(&cfg.task)?)?,
        }
        // report ids: a database written before the ids table holds them in
        // the snapshot and none in the table; since, the table holds them all
        let (stored_seen, stored_accepted) = (store.ids(IdKind::Seen)?, store.ids(IdKind::Accepted)?);
        let persisted_ids = (stored_seen.len(), stored_accepted.len());
        if let Some(bytes) = store.get(K_STATE)? {
            let mut st: AggregatorState = decode(&bytes)?;
            if let Some(acc) = store.get(K_ACC)? {
                st = st.with_accumulators(decode(&acc)?);
            }
            if persisted_ids != (0, 0) {
                if !st.seen.is_empty() || !st.accepted_ids.is_empty() {
                    anyhow::bail!("database {} holds report ids both in the snapshot and in the ids table", cfg.db.display());
                }
                st.seen = stored_seen;
                st.accepted_ids = stored_accepted;
            }
            let mut pending = Vec::with_capacity(st.silent_pending.len());
            for (_, id) in &st.silent_pending {
                let b = store
                    .get(&report_key(id))?
                    .ok_or_else(|| anyhow::anyhow!("pending report missing from store"))?;
                pending.push(decode::<Report>(&b)?);
            }
            agg.restore(st, &pending)?;
            tracing::info!(index = cfg.index, accepted = agg.accepted_count(), "restored aggregator state");
        }
        // Reports no restore needs: written by builds that kept every
        // report, or left by a crash between a flush and its commit (the
        // snapshot is authoritative). Deleted so the database stays bounded
        // by one verification ciphertext's reports.
        let pending: std::collections::HashSet<String> = agg.silent_pending_ids().map(report_key).collect();
        let stale: Vec<String> = store.names_with_prefix(REPORT_PREFIX)?.into_iter().filter(|n| !pending.contains(n)).collect();
        if !stale.is_empty() {
            tracing::info!(index = cfg.index, reports = stale.len(), "deleting stored reports no restore needs");
            store.commit_step(&[], &stale, &[], "prune_reports", &stale.len().to_string())?;
        }
        let groups = agg.layout().groups as u32;
        let max_report_bytes = agg.max_report_bytes();
        let max_message_bytes = agg.max_message_bytes();
        if cfg.collectors.len() != cfg.task.num_collectors() {
            anyhow::bail!(
                "task has {} collector(s) but {} collector URL(s) were given",
                cfg.task.num_collectors(),
                cfg.collectors.len()
            );
        }
        let http = https_client(&cfg.ca_pem)?;
        let metrics = NodeMetrics::new(BuildInfo {
            role: "aggregator",
            index: cfg.index,
            task: Some(&cfg.task),
        })?;
        metrics.set_batch(agg.accepted_count(), agg.pending_silent_reports(), agg.is_closed());
        metrics.set_db_size(store.size_bytes()?);
        metrics.set_ready(true);
        Ok(Self {
            inner: Arc::new(Inner {
                index: cfg.index,
                task: cfg.task,
                agg: Mutex::new(agg),
                store: Mutex::new(store),
                aggregators: cfg.aggregators,
                collectors: cfg.collectors,
                token: cfg.token,
                http,
                next_group: AtomicU32::new(0),
                groups,
                max_report_bytes,
                max_message_bytes,
                metrics,
                persisted_accumulators: Mutex::new(None),
                persisted_ids: Mutex::new(persisted_ids),
            }),
        })
    }

    /// This node's metrics (served by [`crate::metrics::serve_metrics`]).
    pub fn metrics(&self) -> Arc<NodeMetrics> {
        self.inner.metrics.clone()
    }

    /// POST to another node, timed and counted by peer and route.
    async fn peer_post<T: serde::Serialize, R: serde::de::DeserializeOwned>(&self, base: &str, path: &str, body: &T) -> std::result::Result<R, HttpError> {
        Ok(decode(&self.peer_post_raw(base, path, encode(body)?).await?)?)
    }

    async fn peer_post_raw(&self, base: &str, path: &str, body: Vec<u8>) -> std::result::Result<Vec<u8>, HttpError> {
        let t = std::time::Instant::now();
        let r = http_post_raw(&self.inner.http, &format!("{base}{path}"), Some(&self.inner.token), body).await;
        self.inner.metrics.peer(base, path, t.elapsed(), r.is_ok());
        Ok(r?)
    }

    /// Runs a batch phase, recording its duration and whether it failed.
    async fn phase<R>(&self, phase: &str, f: impl std::future::Future<Output = std::result::Result<R, HttpError>>) -> std::result::Result<R, HttpError> {
        let t = std::time::Instant::now();
        let r = f.await;
        self.inner.metrics.phase(phase, t.elapsed(), r.is_ok());
        r
    }

    pub fn is_leader(&self) -> bool {
        self.inner.index == 0
    }

    /// Body limits: the public submit endpoint accepts at most one report
    /// (its exact packed size plus 64 KiB for the envelope and signature);
    /// internal endpoints, reachable only with the token, accept the largest
    /// message another aggregator can legitimately send
    /// (`Aggregator::max_message_bytes`, e.g. the masks of every other
    /// aggregator in one request) plus the same slack.
    pub fn router(&self) -> Router {
        let public = DefaultBodyLimit::max(self.inner.max_report_bytes + (64 << 10));
        let internal = DefaultBodyLimit::max(self.inner.max_message_bytes + (64 << 10));
        // verifiable decryption: check ciphertexts of every aggregator (count
        // round) or of every released accumulator group (release)
        let verify = DefaultBodyLimit::max(256 << 20);
        let gate = DefaultBodyLimit::max(GATE_BODY_LIMIT);
        Router::new()
            .route("/v1/status", get(status))
            .route("/v1/group", get(group_ticket))
            .route("/v1/submit", post(submit).layer(public))
            .route("/v1/close", post(close).layer(public))
            .route("/v1/report", post(internal_report).layer(internal))
            .route("/v1/mask-commits", post(internal_mask_commits).layer(internal))
            .route("/v1/masks", post(internal_masks).layer(internal))
            .route("/v1/commits", post(internal_commits).layer(internal))
            .route("/v1/verifiers", post(internal_verifiers).layer(internal))
            .route("/v1/count-share", post(internal_count_share).layer(internal))
            .route("/v1/count-commit", post(internal_count_commit).layer(verify))
            .route("/v1/count-open", post(internal_count_open).layer(verify))
            .route("/v1/count-reveal", post(internal_count_reveal).layer(verify))
            .route("/v1/count-finish", post(internal_count_finish).layer(verify))
            .route("/v1/release-commit", post(internal_release_commit).layer(verify))
            .route("/v1/release-reveal", post(internal_release_reveal).layer(verify))
            .route("/v1/aggregate-share", post(internal_aggregate_share).layer(internal))
            .route("/v1/gate-start", post(internal_gate_start).layer(gate))
            .route("/v1/gate-contribute", post(internal_gate_contribute).layer(gate))
            .route("/v1/gate-share", post(internal_gate_share).layer(gate))
            .route("/v1/gate-check-commit", post(internal_gate_check_commit).layer(gate))
            .route("/v1/gate-open", post(internal_gate_open).layer(gate))
            .route("/v1/gate-reveal", post(internal_gate_reveal).layer(gate))
            .route("/v1/gate-finish", post(internal_gate_finish).layer(gate))
            .with_state(self.clone())
            .merge(crate::metrics::health_routes(self.inner.metrics.clone()))
            .layer(axum::middleware::from_fn_with_state(self.inner.metrics.clone(), crate::metrics::track))
    }

    /// Loads the TLS configuration; errors surface here, before serving.
    pub async fn tls_config(cert: PathBuf, key: PathBuf) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
        init_crypto();
        Ok(axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?)
    }

    /// Serves until `handle` is shut down.
    pub async fn serve(&self, addr: SocketAddr, tls: Option<axum_server::tls_rustls::RustlsConfig>, handle: ServerHandle) -> anyhow::Result<()> {
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
        let metrics = self.inner.metrics.clone();
        let joined = tokio::task::spawn_blocking(move || -> std::result::Result<R, HttpError> {
            let mut timer = inner.metrics.step(event);
            let mut agg = guard(&inner.agg, "aggregator").inspect_err(|_| inner.metrics.set_ready(false))?;
            timer.acquired();
            let pending_before: Vec<String> = agg.silent_pending_ids().map(report_key).collect();
            let (r, changed) = f(&mut agg)?;
            if changed {
                let snap = agg.snapshot_bookkeeping_without_ids()?;
                // A stored report is kept exactly while the snapshot lists it
                // as pending: once its verification ciphertext is flushed it
                // lives on only in the accumulators, so its bytes are not
                // written (flushed at once) or are deleted (flushed now) in
                // the same transaction as the snapshot that stops naming it.
                let pending: std::collections::HashSet<String> = snap.silent_pending.iter().map(|(_, id)| report_key(id)).collect();
                let deletes: Vec<String> = pending_before.into_iter().filter(|k| !pending.contains(k)).collect();
                let snap = encode(&snap)?;
                let mut entries: Vec<(&str, Vec<u8>)> = vec![(K_STATE, snap)];
                // the accumulators (tens of MiB) only when they changed
                let generation = agg.accumulator_generation();
                let mut persisted = guard(&inner.persisted_accumulators, "persisted accumulators")?;
                if *persisted != Some(generation) {
                    entries.push((K_ACC, encode(&agg.snapshot_accumulators()?)?));
                }
                for (name, b) in &extra {
                    if !name.starts_with(REPORT_PREFIX) || pending.contains(name) {
                        entries.push((name.as_str(), b.clone()));
                    }
                }
                // the report ids past those already stored (one or two per
                // report), not the whole lists
                let mut persisted_ids = guard(&inner.persisted_ids, "persisted ids")?;
                let (seen, accepted) = agg.id_logs();
                if seen.len() < persisted_ids.0 || accepted.len() < persisted_ids.1 {
                    return Err(HttpError(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "report id lists shorter than what the store holds".into(),
                    ));
                }
                let mut ids: Vec<(IdKind, [u8; 32])> = Vec::new();
                ids.extend(seen[persisted_ids.0..].iter().map(|id| (IdKind::Seen, *id)));
                ids.extend(accepted[persisted_ids.1..].iter().map(|id| (IdKind::Accepted, *id)));
                let next_ids = (seen.len(), accepted.len());
                let bytes: usize = entries.iter().map(|(_, b)| b.len()).sum::<usize>() + 32 * ids.len();
                let mut store = guard(&inner.store, "store").inspect_err(|_| inner.metrics.set_ready(false))?;
                let t = std::time::Instant::now();
                store.commit_step(&entries, &deletes, &ids, event, &detail)?;
                *persisted = Some(generation);
                *persisted_ids = next_ids;
                inner.metrics.committed(bytes, t.elapsed(), store.size_bytes().ok());
            }
            inner.metrics.set_batch(agg.accepted_count(), agg.pending_silent_reports(), agg.is_closed());
            timer.succeeded();
            Ok(r)
        })
        .await;
        match joined {
            Ok(r) => r,
            Err(e) => {
                // a panic inside the step: the state lock is poisoned and
                // every later step refuses until the node is restarted
                metrics.set_ready(false);
                Err(HttpError(StatusCode::INTERNAL_SERVER_ERROR, format!("task join: {e}")))
            }
        }
    }

    fn helpers(&self) -> Vec<(usize, String)> {
        self.inner
            .aggregators
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != self.inner.index)
            .map(|(i, u)| (i, u.clone()))
            .collect()
    }

    // ---- leader orchestration ------------------------------------------

    /// Verdict mode: three rounds with every helper; silent mode: forward.
    async fn drive_report(&self, report: Report) -> std::result::Result<SubmitOutcome, HttpError> {
        let id = report.report_id;
        let detail = hex::encode(id);
        if self.inner.task.mode == VerificationMode::Silent {
            // Local admission first: a report we refuse is not forwarded.
            let r = report.clone();
            let outcome = self
                .with_agg(
                    "silent_admit",
                    detail.clone(),
                    vec![(report_key(&id), encode(&report)?)],
                    move |agg| match agg.process_silent(&r) {
                        Ok(()) => Ok((SubmitOutcome::Accepted, true)),
                        Err(Error::Reject(reason)) => Ok((SubmitOutcome::Rejected(reason.to_string()), false)),
                        Err(e) => Err(e),
                    },
                )
                .await?;
            if outcome != SubmitOutcome::Accepted {
                return Ok(outcome);
            }
            for (_, url) in self.helpers() {
                let o: SubmitOutcome = self.peer_post(&url, "/v1/report", &report).await?;
                if o != SubmitOutcome::Accepted {
                    return Err(HttpError(StatusCode::CONFLICT, format!("helper disagrees on admission: {o:?}")));
                }
            }
            return Ok(SubmitOutcome::Accepted);
        }

        // Verdict mode, round 1: everyone commits to its mask.
        let r = report.clone();
        let mine = self
            .with_agg("verdict_init", detail.clone(), vec![], move |agg| match agg.prepare_init(&r) {
                Ok(m) => Ok((Ok(m), false)),
                Err(Error::Reject(reason)) => Ok((Err(reason), false)),
                Err(e) => Err(e),
            })
            .await?;
        let my_commit = match mine {
            Ok(m) => m,
            Err(reason) => return Ok(SubmitOutcome::Rejected(reason.to_string())),
        };
        let mut mask_commits = vec![my_commit];
        for (i, url) in self.helpers() {
            let m: std::result::Result<MaskCommit, String> = self.peer_post(&url, "/v1/report", &report).await?;
            match m {
                Ok(m) if m.aggregator == i => mask_commits.push(m),
                Ok(m) => return Err(HttpError(StatusCode::CONFLICT, format!("helper {i} answered as aggregator {}", m.aggregator))),
                Err(reason) => {
                    return Err(HttpError(
                        StatusCode::CONFLICT,
                        format!("helper refused a report the leader admitted: {reason}"),
                    ));
                }
            }
        }
        // Round 1b: every mask commitment is in; everyone reveals its mask.
        let others_for_me: Vec<MaskCommit> = mask_commits.iter().filter(|c| c.aggregator != self.inner.index).cloned().collect();
        let mut masks = vec![
            self.with_agg("verdict_mask_reveal", detail.clone(), vec![], move |agg| {
                Ok((agg.prepare_mask_reveal(&id, &others_for_me)?, false))
            })
            .await?,
        ];
        for (i, url) in self.helpers() {
            let req = MaskCommitsRequest {
                report_id: id,
                commits: mask_commits.iter().filter(|c| c.aggregator != i).cloned().collect(),
            };
            let m: MaskMessage = self.peer_post(&url, "/v1/mask-commits", &req).await?;
            masks.push(m);
        }
        // Round 2: everyone commits to its partial decryption of the masked check.
        let others_for_me: Vec<MaskMessage> = masks.iter().filter(|m| m.aggregator != self.inner.index).cloned().collect();
        let mut commits = vec![
            self.with_agg("verdict_masks", detail.clone(), vec![], move |agg| {
                Ok((agg.prepare_masks(&id, &others_for_me)?, false))
            })
            .await?,
        ];
        for (i, url) in self.helpers() {
            let req = MasksRequest {
                report_id: id,
                masks: masks.iter().filter(|m| m.aggregator != i).cloned().collect(),
            };
            let c: VerifierCommit = self.peer_post(&url, "/v1/masks", &req).await?;
            if c.aggregator != i {
                return Err(HttpError(StatusCode::CONFLICT, format!("helper {i} answered as aggregator {}", c.aggregator)));
            }
            commits.push(c);
        }
        // Round 2b: every commitment is in; everyone reveals its partial.
        let others_for_me: Vec<VerifierCommit> = commits.iter().filter(|c| c.aggregator != self.inner.index).cloned().collect();
        let mut verifiers = vec![
            self.with_agg("verdict_reveal", detail.clone(), vec![], move |agg| {
                Ok((agg.prepare_reveal(&id, &others_for_me)?, false))
            })
            .await?,
        ];
        for (i, url) in self.helpers() {
            let req = CommitsRequest {
                report_id: id,
                commits: commits.iter().filter(|c| c.aggregator != i).cloned().collect(),
            };
            let v: VerifierMessage = self.peer_post(&url, "/v1/commits", &req).await?;
            verifiers.push(v);
        }
        // Round 3: verdicts.
        let others_for_me: Vec<VerifierMessage> = verifiers.iter().filter(|v| v.aggregator != self.inner.index).cloned().collect();
        let my_verdict = self
            .with_agg("verdict_finish", detail.clone(), vec![], move |agg| {
                let v = agg.prepare_finish(&id, &others_for_me)?;
                let changed = v == Verdict::Accepted;
                Ok((v, changed))
            })
            .await?;
        for (i, url) in self.helpers() {
            let req = VerifiersRequest {
                report_id: id,
                verifiers: verifiers.iter().filter(|v| v.aggregator != i).cloned().collect(),
            };
            let o: SubmitOutcome = self.peer_post(&url, "/v1/verifiers", &req).await?;
            let mine = match &my_verdict {
                Verdict::Accepted => SubmitOutcome::Accepted,
                Verdict::Rejected(r) => SubmitOutcome::Rejected(r.to_string()),
            };
            if o != mine {
                return Err(HttpError(
                    StatusCode::CONFLICT,
                    format!("helper {i} verdict {o:?} differs from leader {mine:?}"),
                ));
            }
        }
        Ok(match my_verdict {
            Verdict::Accepted => SubmitOutcome::Accepted,
            Verdict::Rejected(r) => SubmitOutcome::Rejected(r.to_string()),
        })
    }

    /// Silent mode: the verified count round. Every aggregator checks the
    /// decrypted count with its own blinded checks before trusting it.
    async fn drive_count(&self) -> std::result::Result<(), HttpError> {
        let mut shares = vec![
            self.with_agg("count_share", String::new(), vec![], |agg| Ok((agg.count_share()?, true)))
                .await?,
        ];
        for (_, url) in self.helpers() {
            shares.push(decode(&self.peer_post_raw(&url, "/v1/count-share", encode(&())?).await?)?);
        }
        let req = encode(&CountSharesRequest { shares: shares.clone() })?;
        let mut commits = vec![
            self.with_agg("count_commit", String::new(), vec![], move |agg| Ok((agg.count_commit(&shares)?, true)))
                .await?,
        ];
        for (_, url) in self.helpers() {
            commits.push(decode(&self.peer_post_raw(&url, "/v1/count-commit", req.clone()).await?)?);
        }
        let req = encode(&CountCommitsRequest { commits: commits.clone() })?;
        let mut openings = vec![
            self.with_agg("count_open", String::new(), vec![], move |agg| Ok((agg.count_open(&commits)?, true)))
                .await?,
        ];
        for (_, url) in self.helpers() {
            openings.push(decode(&self.peer_post_raw(&url, "/v1/count-open", req.clone()).await?)?);
        }
        let req = encode(&CountOpeningsRequest { openings: openings.clone() })?;
        let mut reveals = vec![
            self.with_agg("count_reveal", String::new(), vec![], move |agg| Ok((agg.count_reveal(&openings)?, true)))
                .await?,
        ];
        for (_, url) in self.helpers() {
            reveals.push(decode(&self.peer_post_raw(&url, "/v1/count-reveal", req.clone()).await?)?);
        }
        let req = encode(&CountRevealsRequest { reveals: reveals.clone() })?;
        let mine: u64 = self
            .with_agg("count_finish", String::new(), vec![], move |agg| Ok((agg.count_finish(&reveals)?, true)))
            .await?;
        for (i, url) in self.helpers() {
            let n: u64 = decode(&self.peer_post_raw(&url, "/v1/count-finish", req.clone()).await?)?;
            if n != mine {
                return Err(HttpError(StatusCode::CONFLICT, format!("helper {i} verified another valid count")));
            }
        }
        Ok(())
    }

    /// Verified release to collector `c` of shares already delivered: relays
    /// the collector's checks, every aggregator's commitments, the opening
    /// and every aggregator's reveal (sealed with policies).
    async fn drive_release(&self, c: usize, challenge: ReleaseChallenge) -> std::result::Result<Option<BatchResult>, HttpError> {
        let url = self.inner.collectors[c].clone();
        let ch = challenge.clone();
        let mut commits = vec![
            self.with_agg("release_commit", format!("{c}"), vec![], move |agg| Ok((agg.release_commit(&ch)?, true)))
                .await?,
        ];
        for (_, h) in self.helpers() {
            let r: ReleaseCommit = self.peer_post(&h, "/v1/release-commit", &challenge).await?;
            commits.push(r);
        }
        let opening: ReleaseOpening = self.peer_post(&url, "/v1/release-commits", &ReleaseCommitsRequest { commits }).await?;
        let sealed = !self.inner.task.collectors.is_empty();
        let op = opening.clone();
        let mine = self
            .with_agg("release_reveal", format!("{c}"), vec![], move |agg| {
                Ok((
                    if sealed {
                        RevealEnvelope::Sealed(agg.sealed_release_reveal(&op)?)
                    } else {
                        RevealEnvelope::Plain(agg.release_reveal(&op)?)
                    },
                    true,
                ))
            })
            .await?;
        let mut reveals = vec![mine];
        for (_, h) in self.helpers() {
            let r: RevealEnvelope = self.peer_post(&h, "/v1/release-reveal", &opening).await?;
            reveals.push(r);
        }
        let done: FinishReceipt = self.peer_post(&url, "/v1/release-reveals", &ReleaseRevealsRequest { reveals }).await?;
        Ok(done.result)
    }

    /// The other key parties of the gated release: the helpers, then the
    /// collector of a split-key task.
    fn gate_peers(&self) -> Vec<String> {
        let mut v: Vec<String> = self.helpers().into_iter().map(|(_, u)| u).collect();
        if self.inner.task.collector_holds_key() {
            v.push(self.inner.collectors[0].clone());
        }
        v
    }

    /// Posts one round's request to every other key party; their replies.
    async fn gate_round<R: serde::de::DeserializeOwned>(&self, path: &str, body: Vec<u8>) -> std::result::Result<Vec<R>, HttpError> {
        let mut out = Vec::new();
        for url in self.gate_peers() {
            out.push(decode(&self.peer_post_raw(&url, path, body.clone()).await?)?);
        }
        Ok(out)
    }

    /// The gated release (`fhe_prio3::gate`) among the key parties, relayed
    /// by the leader: commitments, contributions, the verified joint
    /// decryption of the masked accumulators, then every aggregator
    /// computes the gates. Each party persists every step.
    async fn drive_gate(&self) -> std::result::Result<(), HttpError> {
        let mine = self
            .with_agg("gate_commit", String::new(), vec![], |agg| Ok((agg.gate_commit()?, true)))
            .await?;
        let mut commits = vec![mine.clone()];
        commits.extend(
            self.gate_round::<GateCommit>("/v1/gate-start", encode(&GateStartRequest { leader: mine })?)
                .await?,
        );
        let req = encode(&GateCommitsRequest { commits: commits.clone() })?;
        let mut contributions = vec![
            self.with_agg("gate_contribute", String::new(), vec![], move |agg| Ok((agg.gate_contribute(&commits)?, true)))
                .await?,
        ];
        contributions.extend(self.gate_round::<GateContribution>("/v1/gate-contribute", req).await?);
        let req = encode(&GateContributionsRequest {
            contributions: contributions.clone(),
        })?;
        let mut shares = vec![
            self.with_agg("gate_share", String::new(), vec![], move |agg| Ok((agg.gate_share(&contributions)?, true)))
                .await?,
        ];
        shares.extend(self.gate_round::<GateShare>("/v1/gate-share", req).await?);
        let req = encode(&GateSharesRequest { shares: shares.clone() })?;
        let mut cc = vec![
            self.with_agg("gate_check_commit", String::new(), vec![], move |agg| {
                Ok((agg.gate_check_commit(&shares)?, true))
            })
            .await?,
        ];
        cc.extend(self.gate_round::<GateCheckCommit>("/v1/gate-check-commit", req).await?);
        let req = encode(&GateCheckCommitsRequest { commits: cc.clone() })?;
        let mut openings = vec![
            self.with_agg("gate_open", String::new(), vec![], move |agg| Ok((agg.gate_open(&cc)?, true)))
                .await?,
        ];
        openings.extend(self.gate_round::<GateOpening>("/v1/gate-open", req).await?);
        let req = encode(&GateOpeningsRequest { openings: openings.clone() })?;
        let mut reveals = vec![
            self.with_agg("gate_reveal", String::new(), vec![], move |agg| Ok((agg.gate_reveal(&openings)?, true)))
                .await?,
        ];
        reveals.extend(self.gate_round::<GateReveal>("/v1/gate-reveal", req).await?);
        let req = encode(&GateRevealsRequest { reveals: reveals.clone() })?;
        self.with_agg("gate_finish", String::new(), vec![], move |agg| Ok((agg.gate_finish(&reveals)?, true)))
            .await?;
        self.gate_round::<()>("/v1/gate-finish", req).await?;
        Ok(())
    }

    /// Closes the batch on every aggregator, delivers the shares to the
    /// collector(s) and runs the verified release.
    async fn drive_close(&self) -> std::result::Result<CloseReply, HttpError> {
        if self.inner.task.mode == VerificationMode::Silent && !self.inner.task.collector_holds_key() {
            self.phase("count", self.drive_count()).await?;
        }
        if self.inner.task.gated() {
            self.phase("gate", self.drive_gate()).await?;
        }
        if self.inner.task.collectors.is_empty() {
            // single collector, plain shares relayed by the leader
            let mut shares = vec![
                self.with_agg("aggregate_share", String::new(), vec![], |agg| Ok((agg.aggregate_share()?, true)))
                    .await?,
            ];
            for (_, url) in self.helpers() {
                let r: ShareReply = self.peer_post(&url, "/v1/aggregate-share", &ShareRequest { collector: 0 }).await?;
                match r {
                    ShareReply::Plain(s) => shares.push(s),
                    ShareReply::Sealed(_) => {
                        return Err(HttpError(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "helper sealed a share on a task without policies".into(),
                        ));
                    }
                }
            }
            let mut challenge = None;
            for s in shares {
                let r: ShareReceipt = self
                    .peer_post(&self.inner.collectors[0], "/v1/aggregate-share", &ShareEnvelope { share: s })
                    .await?;
                if r.complete {
                    challenge = r.challenge;
                }
            }
            let challenge = challenge.ok_or_else(|| HttpError(StatusCode::INTERNAL_SERVER_ERROR, "collector sent no checks after all shares".into()))?;
            let result = self
                .phase("release", self.drive_release(0, challenge))
                .await?
                .ok_or_else(|| HttpError(StatusCode::INTERNAL_SERVER_ERROR, "collector returned no result".into()))?;
            return Ok(CloseReply {
                result: Some(result),
                released_to: vec![0],
            });
        }
        // release policies: every aggregator seals its share (and its check
        // partials) for collector c to c's key; the leader relays opaque
        // envelopes and learns nothing
        let mut released_to = Vec::new();
        for c in 0..self.inner.task.collectors.len() {
            let mut sealed = vec![
                self.with_agg("sealed_share_for", format!("{c}"), vec![], move |agg| Ok((agg.sealed_share_for(c)?, true)))
                    .await?,
            ];
            for (_, url) in self.helpers() {
                let r: ShareReply = self.peer_post(&url, "/v1/aggregate-share", &ShareRequest { collector: c as u32 }).await?;
                match r {
                    ShareReply::Sealed(s) => sealed.push(s),
                    ShareReply::Plain(_) => {
                        return Err(HttpError(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "helper returned a plain share on a task with policies".into(),
                        ));
                    }
                }
            }
            let mut challenge = None;
            for s in sealed {
                let r: ShareReceipt = self
                    .peer_post(&self.inner.collectors[c], "/v1/aggregate-share", &SealedEnvelope { sealed: s })
                    .await?;
                if r.complete {
                    challenge = r.challenge;
                }
            }
            let challenge = challenge.ok_or_else(|| HttpError(StatusCode::INTERNAL_SERVER_ERROR, format!("collector {c} sent no checks after all shares")))?;
            self.phase("release", self.drive_release(c, challenge)).await?;
            released_to.push(c as u32);
        }
        Ok(CloseReply { result: None, released_to })
    }
}

// ---- handlers ------------------------------------------------------------

async fn status(State(node): State<AggregatorNode>) -> std::result::Result<axum::response::Response, HttpError> {
    let inner = node.inner.clone();
    let (accepted, closed) = tokio::task::spawn_blocking(move || -> std::result::Result<(usize, bool), HttpError> {
        let agg = guard(&inner.agg, "aggregator")?;
        Ok((agg.accepted_count(), agg.is_closed()))
    })
    .await
    .map_err(|e| HttpError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
    reply(&StatusReply {
        index: node.inner.index,
        task_id: hex::encode(node.inner.task.task_id),
        accepted,
        closed,
        mode: format!("{:?}", node.inner.task.mode),
    })
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
    let report: Report = parse_body(&body).inspect_err(|_| node.inner.metrics.report("error", "Undecodable"))?;
    let m = &node.inner.metrics;
    match node.drive_report(report).await {
        Ok(outcome) => {
            match &outcome {
                SubmitOutcome::Accepted => m.report("accepted", "none"),
                SubmitOutcome::Rejected(r) => m.report("rejected", crate::metrics::reject_label(r)),
            }
            reply(&outcome)
        }
        Err(e) => {
            m.report("error", "none");
            Err(e)
        }
    }
}

async fn close(State(node): State<AggregatorNode>, headers: HeaderMap) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    if !node.is_leader() {
        return Err(HttpError(StatusCode::NOT_FOUND, "close via the leader".into()));
    }
    let r = node.phase("close", node.drive_close()).await?;
    reply(&r)
}

async fn internal_report(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let report: Report = parse_body(&body)?;
    let detail = hex::encode(report.report_id);
    let bytes = body.to_vec();
    if node.inner.task.mode == VerificationMode::Silent {
        let out = node
            .with_agg(
                "silent_admit",
                detail.clone(),
                vec![(report_key(&report.report_id), bytes)],
                move |agg| match agg.process_silent(&report) {
                    Ok(()) => Ok((SubmitOutcome::Accepted, true)),
                    Err(Error::Reject(r)) => Ok((SubmitOutcome::Rejected(r.to_string()), false)),
                    Err(e) => Err(e),
                },
            )
            .await?;
        return reply(&out);
    }
    let out: std::result::Result<MaskCommit, String> = node
        .with_agg("verdict_init", detail, vec![], move |agg| match agg.prepare_init(&report) {
            Ok(m) => Ok((Ok(m), false)),
            Err(Error::Reject(r)) => Ok((Err(r.to_string()), false)),
            Err(e) => Err(e),
        })
        .await?;
    reply(&out)
}

async fn internal_mask_commits(
    State(node): State<AggregatorNode>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: MaskCommitsRequest = parse_body(&body)?;
    let m = node
        .with_agg("verdict_mask_reveal", hex::encode(req.report_id), vec![], move |agg| {
            Ok((agg.prepare_mask_reveal(&req.report_id, &req.commits)?, false))
        })
        .await?;
    reply(&m)
}

async fn internal_masks(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: MasksRequest = parse_body(&body)?;
    let v = node
        .with_agg("verdict_masks", hex::encode(req.report_id), vec![], move |agg| {
            Ok((agg.prepare_masks(&req.report_id, &req.masks)?, false))
        })
        .await?;
    reply(&v)
}

async fn internal_commits(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: CommitsRequest = parse_body(&body)?;
    let v = node
        .with_agg("verdict_reveal", hex::encode(req.report_id), vec![], move |agg| {
            Ok((agg.prepare_reveal(&req.report_id, &req.commits)?, false))
        })
        .await?;
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
    let c = node
        .with_agg("count_share", String::new(), vec![], |agg| Ok((agg.count_share()?, true)))
        .await?;
    reply(&c)
}

async fn internal_count_commit(
    State(node): State<AggregatorNode>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: CountSharesRequest = parse_body(&body)?;
    reply(
        &node
            .with_agg("count_commit", String::new(), vec![], move |agg| Ok((agg.count_commit(&req.shares)?, true)))
            .await?,
    )
}

async fn internal_count_open(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: CountCommitsRequest = parse_body(&body)?;
    reply(
        &node
            .with_agg("count_open", String::new(), vec![], move |agg| Ok((agg.count_open(&req.commits)?, true)))
            .await?,
    )
}

async fn internal_count_reveal(
    State(node): State<AggregatorNode>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: CountOpeningsRequest = parse_body(&body)?;
    reply(
        &node
            .with_agg("count_reveal", String::new(), vec![], move |agg| Ok((agg.count_reveal(&req.openings)?, true)))
            .await?,
    )
}

async fn internal_count_finish(
    State(node): State<AggregatorNode>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: CountRevealsRequest = parse_body(&body)?;
    let n = node
        .with_agg("count_finish", String::new(), vec![], move |agg| Ok((agg.count_finish(&req.reveals)?, true)))
        .await?;
    reply(&n)
}

async fn internal_release_commit(
    State(node): State<AggregatorNode>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let ch: ReleaseChallenge = parse_body(&body)?;
    reply(
        &node
            .with_agg("release_commit", format!("{}", ch.collector), vec![], move |agg| {
                Ok((agg.release_commit(&ch)?, true))
            })
            .await?,
    )
}

async fn internal_release_reveal(
    State(node): State<AggregatorNode>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let op: ReleaseOpening = parse_body(&body)?;
    let sealed = !node.inner.task.collectors.is_empty();
    let r = node
        .with_agg("release_reveal", format!("{}", op.collector), vec![], move |agg| {
            Ok((
                if sealed {
                    RevealEnvelope::Sealed(agg.sealed_release_reveal(&op)?)
                } else {
                    RevealEnvelope::Plain(agg.release_reveal(&op)?)
                },
                true,
            ))
        })
        .await?;
    reply(&r)
}

/// A helper releases only what the task's policy for the named collector
/// allows, and seals it to that collector; the leader cannot widen it.
async fn internal_aggregate_share(
    State(node): State<AggregatorNode>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: ShareRequest = parse_body(&body)?;
    let c = req.collector as usize;
    if node.inner.task.collectors.is_empty() {
        if c != 0 {
            return Err(HttpError(StatusCode::BAD_REQUEST, "task has a single collector, id 0".into()));
        }
        let s = node
            .with_agg("aggregate_share", String::new(), vec![], |agg| Ok((agg.aggregate_share()?, true)))
            .await?;
        return reply(&ShareReply::Plain(s));
    }
    if c >= node.inner.task.collectors.len() {
        return Err(HttpError(StatusCode::BAD_REQUEST, format!("no collector {c} in the task")));
    }
    let s = node
        .with_agg("sealed_share_for", format!("{c}"), vec![], move |agg| Ok((agg.sealed_share_for(c)?, true)))
        .await?;
    reply(&ShareReply::Sealed(s))
}

// ---- gated release, helper side ------------------------------------------

async fn internal_gate_start(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let _req: GateStartRequest = parse_body(&body)?;
    reply(
        &node
            .with_agg("gate_commit", String::new(), vec![], |agg| Ok((agg.gate_commit()?, true)))
            .await?,
    )
}
async fn internal_gate_contribute(
    State(node): State<AggregatorNode>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: GateCommitsRequest = parse_body(&body)?;
    reply(
        &node
            .with_agg("gate_contribute", String::new(), vec![], move |agg| {
                Ok((agg.gate_contribute(&req.commits)?, true))
            })
            .await?,
    )
}
async fn internal_gate_share(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: GateContributionsRequest = parse_body(&body)?;
    reply(
        &node
            .with_agg("gate_share", String::new(), vec![], move |agg| Ok((agg.gate_share(&req.contributions)?, true)))
            .await?,
    )
}
async fn internal_gate_check_commit(
    State(node): State<AggregatorNode>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: GateSharesRequest = parse_body(&body)?;
    reply(
        &node
            .with_agg("gate_check_commit", String::new(), vec![], move |agg| {
                Ok((agg.gate_check_commit(&req.shares)?, true))
            })
            .await?,
    )
}
async fn internal_gate_open(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: GateCheckCommitsRequest = parse_body(&body)?;
    reply(
        &node
            .with_agg("gate_open", String::new(), vec![], move |agg| Ok((agg.gate_open(&req.commits)?, true)))
            .await?,
    )
}
async fn internal_gate_reveal(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: GateOpeningsRequest = parse_body(&body)?;
    reply(
        &node
            .with_agg("gate_reveal", String::new(), vec![], move |agg| Ok((agg.gate_reveal(&req.openings)?, true)))
            .await?,
    )
}
async fn internal_gate_finish(State(node): State<AggregatorNode>, headers: HeaderMap, body: Bytes) -> std::result::Result<axum::response::Response, HttpError> {
    check_token(&headers, &node.inner.token)?;
    let req: GateRevealsRequest = parse_body(&body)?;
    node.with_agg("gate_finish", String::new(), vec![], move |agg| Ok((agg.gate_finish(&req.reveals)?, true)))
        .await?;
    reply(&())
}
