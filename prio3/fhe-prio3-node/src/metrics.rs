//! Prometheus metrics and health endpoints of every node.
//!
//! Each node owns one [`NodeMetrics`] (its own registry, so several nodes
//! in one test process do not mix their series) and serves it on a
//! separate plain-HTTP listener (`--metrics-listen`, normally bound to a
//! private interface) as `GET /metrics` in the Prometheus text format,
//! next to `GET /healthz` (the process answers) and `GET /readyz` (the
//! node can serve: its state is not poisoned by a panic). The public TLS
//! listener carries `/healthz` and `/readyz` too, for load balancers.
//!
//! What the series are for (alert rules: `deploy/prometheus/alerts.yml`):
//!
//! * *stuck*: `fhe_prio3_step_active_since_timestamp_seconds` is the start
//!   time of the homomorphic step holding the node's state lock (0 when
//!   idle) and `fhe_prio3_lock_waiters` the requests queued behind it;
//!   `fhe_prio3_last_progress_timestamp_seconds` is the last committed
//!   state change;
//! * *slow*: `fhe_prio3_step_duration_seconds{step}`,
//!   `fhe_prio3_lock_wait_seconds`, `fhe_prio3_phase_duration_seconds{phase}`
//!   (close, count round, gated release, release to the collector),
//!   `fhe_prio3_http_request_duration_seconds{route}`,
//!   `fhe_prio3_peer_request_duration_seconds{peer,route}`,
//!   `fhe_prio3_db_commit_duration_seconds`;
//! * *failing*: `fhe_prio3_http_requests_total{route,status}`,
//!   `fhe_prio3_step_failures_total{step}`,
//!   `fhe_prio3_phase_failures_total{phase}`,
//!   `fhe_prio3_peer_requests_total{peer,route,outcome}`,
//!   `fhe_prio3_reports_total{outcome,reason}`;
//! * *capacity*: `fhe_prio3_db_size_bytes`, `fhe_prio3_db_written_bytes_total`,
//!   the batch gauges, and the process collector's
//!   `process_resident_memory_bytes`, `process_cpu_seconds_total`,
//!   `process_open_fds`.
//!
//! Every label takes values from a fixed set: routes are the router's
//! matched path templates, steps and phases are names in the code, peers
//! are the configured peer base URLs, reasons are `RejectReason` variant
//! names. Nothing a client sends becomes a label value.

use axum::Router;
use axum::extract::{MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use prometheus::{Encoder, Gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Buckets for anything that can be a homomorphic step: from a millisecond
/// (a status read) to half an hour (a gated release at a large threshold).
const SLOW_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0,
];
/// Buckets for SQLite commits (a snapshot of tens of MiB with
/// `synchronous=FULL`).
const DB_BUCKETS: &[f64] = &[0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

/// Reject reasons as label values: the `RejectReason` variant names, and
/// `Other` for anything else, so a label never carries free text.
const REJECT_REASONS: &[&str] = &[
    "WrongTask",
    "ReportIdMismatch",
    "Replay",
    "WrongChunkCount",
    "MalformedCiphertext",
    "ValidityCheckFailed",
    "BatchFull",
    "BatchClosed",
    "TooLarge",
    "Unauthenticated",
    "UnknownClient",
    "QuotaExceeded",
    "BadGroup",
    "WrongParameters",
];

/// The variant name at the start of a rejection message (`Display` of
/// `RejectReason` is its `Debug` form, e.g. `TooLarge { limit: .. }`), or
/// `Other`.
pub fn reject_label(reason: &str) -> &'static str {
    let name: String = reason.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
    REJECT_REASONS.iter().find(|r| **r == name).copied().unwrap_or("Other")
}

pub fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

pub struct NodeMetrics {
    registry: Registry,
    ready: AtomicBool,
    ready_gauge: IntGauge,
    http_requests: IntCounterVec,
    http_duration: HistogramVec,
    http_in_flight: IntGauge,
    step_duration: HistogramVec,
    step_failures: IntCounterVec,
    lock_wait: Histogram,
    lock_waiters: IntGauge,
    step_active_since: Gauge,
    last_progress: Gauge,
    db_commit_duration: Histogram,
    db_written: IntCounter,
    db_size: IntGauge,
    reports: IntCounterVec,
    batch: IntGaugeVec,
    phase_duration: HistogramVec,
    phase_failures: IntCounterVec,
    peer_requests: IntCounterVec,
    peer_duration: HistogramVec,
}

/// Labels of `fhe_prio3_build_info`. The router serves several shard
/// tasks and passes no task (its task labels are empty).
pub struct BuildInfo<'a> {
    pub role: &'a str,
    pub index: usize,
    pub task: Option<&'a fhe_prio3::TaskConfig>,
}

fn hist(name: &str, help: &str, buckets: &[f64]) -> HistogramOpts {
    HistogramOpts::new(name, help).buckets(buckets.to_vec())
}

impl NodeMetrics {
    pub fn new(info: BuildInfo<'_>) -> anyhow::Result<Arc<Self>> {
        let registry = Registry::new();
        let build = IntGaugeVec::new(
            Opts::new("fhe_prio3_build_info", "Constant 1, labelled with what this node runs."),
            &["version", "role", "index", "task_id", "mode", "topology"],
        )?;
        build
            .with_label_values(&[
                env!("CARGO_PKG_VERSION"),
                info.role,
                &info.index.to_string(),
                &info.task.map(|t| hex::encode(t.task_id)).unwrap_or_default(),
                &info.task.map(|t| format!("{:?}", t.mode)).unwrap_or_default(),
                &info.task.map(|t| format!("{:?}", t.key_topology)).unwrap_or_default(),
            ])
            .set(1);
        let m = Self {
            ready: AtomicBool::new(false),
            ready_gauge: IntGauge::new(
                "fhe_prio3_ready",
                "1 when the node can serve; 0 before start-up completes or after a panic poisoned its state (restart it).",
            )?,
            http_requests: IntCounterVec::new(
                Opts::new("fhe_prio3_http_requests_total", "HTTP requests answered, by route template and status code."),
                &["route", "status"],
            )?,
            http_duration: HistogramVec::new(
                hist(
                    "fhe_prio3_http_request_duration_seconds",
                    "Time from request to response, by route template.",
                    SLOW_BUCKETS,
                ),
                &["route"],
            )?,
            http_in_flight: IntGauge::new("fhe_prio3_http_requests_in_flight", "HTTP requests being served.")?,
            step_duration: HistogramVec::new(
                hist(
                    "fhe_prio3_step_duration_seconds",
                    "Time a protocol step held the node's state lock, including its database commit, by step.",
                    SLOW_BUCKETS,
                ),
                &["step"],
            )?,
            step_failures: IntCounterVec::new(
                Opts::new("fhe_prio3_step_failures_total", "Protocol steps that returned an error, by step."),
                &["step"],
            )?,
            lock_wait: Histogram::with_opts(hist(
                "fhe_prio3_lock_wait_seconds",
                "Time a request waited for the node's state lock (another step held it).",
                SLOW_BUCKETS,
            ))?,
            lock_waiters: IntGauge::new("fhe_prio3_lock_waiters", "Requests waiting for the node's state lock.")?,
            step_active_since: Gauge::new(
                "fhe_prio3_step_active_since_timestamp_seconds",
                "Unix time the step now holding the state lock started; 0 when no step runs.",
            )?,
            last_progress: Gauge::new(
                "fhe_prio3_last_progress_timestamp_seconds",
                "Unix time of the last committed state change (report admitted, round completed).",
            )?,
            db_commit_duration: Histogram::with_opts(hist(
                "fhe_prio3_db_commit_duration_seconds",
                "Time of one SQLite transaction committing a step (synchronous=FULL).",
                DB_BUCKETS,
            ))?,
            db_written: IntCounter::new(
                "fhe_prio3_db_written_bytes_total",
                "Bytes of entries written to the database by committed steps.",
            )?,
            db_size: IntGauge::new("fhe_prio3_db_size_bytes", "Size of the node's database file, after the last commit.")?,
            reports: IntCounterVec::new(
                Opts::new(
                    "fhe_prio3_reports_total",
                    "Client reports answered by the leader: outcome accepted, rejected (with the reason) or error.",
                ),
                &["outcome", "reason"],
            )?,
            batch: IntGaugeVec::new(
                Opts::new(
                    "fhe_prio3_batch",
                    "Current batch: accepted (reports admitted), pending (in the open verification ciphertext), closed (0/1).",
                ),
                &["field"],
            )?,
            phase_duration: HistogramVec::new(
                hist(
                    "fhe_prio3_phase_duration_seconds",
                    "Duration of a batch phase driven by the leader (close, count, gate, release).",
                    SLOW_BUCKETS,
                ),
                &["phase"],
            )?,
            phase_failures: IntCounterVec::new(Opts::new("fhe_prio3_phase_failures_total", "Batch phases that failed, by phase."), &["phase"])?,
            peer_requests: IntCounterVec::new(
                Opts::new(
                    "fhe_prio3_peer_requests_total",
                    "Calls to other nodes (helpers, collectors), by peer base URL, route and outcome (ok, error).",
                ),
                &["peer", "route", "outcome"],
            )?,
            peer_duration: HistogramVec::new(
                hist(
                    "fhe_prio3_peer_request_duration_seconds",
                    "Duration of calls to other nodes, by peer base URL and route.",
                    SLOW_BUCKETS,
                ),
                &["peer", "route"],
            )?,
            registry,
        };
        let start = Gauge::new("fhe_prio3_start_time_seconds", "Unix time the node started.")?;
        start.set(unix_now());
        let r = &m.registry;
        r.register(Box::new(build))?;
        r.register(Box::new(start))?;
        r.register(Box::new(m.ready_gauge.clone()))?;
        r.register(Box::new(m.http_requests.clone()))?;
        r.register(Box::new(m.http_duration.clone()))?;
        r.register(Box::new(m.http_in_flight.clone()))?;
        r.register(Box::new(m.step_duration.clone()))?;
        r.register(Box::new(m.step_failures.clone()))?;
        r.register(Box::new(m.lock_wait.clone()))?;
        r.register(Box::new(m.lock_waiters.clone()))?;
        r.register(Box::new(m.step_active_since.clone()))?;
        r.register(Box::new(m.last_progress.clone()))?;
        r.register(Box::new(m.db_commit_duration.clone()))?;
        r.register(Box::new(m.db_written.clone()))?;
        r.register(Box::new(m.db_size.clone()))?;
        r.register(Box::new(m.reports.clone()))?;
        r.register(Box::new(m.batch.clone()))?;
        r.register(Box::new(m.phase_duration.clone()))?;
        r.register(Box::new(m.phase_failures.clone()))?;
        r.register(Box::new(m.peer_requests.clone()))?;
        r.register(Box::new(m.peer_duration.clone()))?;
        #[cfg(target_os = "linux")]
        r.register(Box::new(prometheus::process_collector::ProcessCollector::for_self()))?;
        Ok(Arc::new(m))
    }

    /// The text exposition of every series.
    pub fn render(&self) -> anyhow::Result<String> {
        let mut buf = Vec::new();
        TextEncoder::new().encode(&self.registry.gather(), &mut buf)?;
        Ok(String::from_utf8(buf)?)
    }

    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
        self.ready_gauge.set(ready as i64);
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    // ---- protocol steps (one per state-lock section) ----------------------

    /// Call before waiting for the state lock; the returned guard records the
    /// wait when [`StepTimer::acquired`] is called and the step when dropped.
    pub fn step(self: &Arc<Self>, step: &'static str) -> StepTimer {
        self.lock_waiters.inc();
        StepTimer {
            m: self.clone(),
            step,
            queued: Instant::now(),
            acquired: None,
            failed: true,
        }
    }

    pub fn committed(&self, bytes: usize, took: Duration, db_size: Option<u64>) {
        self.db_commit_duration.observe(took.as_secs_f64());
        self.db_written.inc_by(bytes as u64);
        if let Some(s) = db_size {
            self.db_size.set(s as i64);
        }
        self.last_progress.set(unix_now());
    }

    pub fn set_batch(&self, accepted: usize, pending: usize, closed: bool) {
        self.batch.with_label_values(&["accepted"]).set(accepted as i64);
        self.batch.with_label_values(&["pending"]).set(pending as i64);
        self.batch.with_label_values(&["closed"]).set(closed as i64);
    }

    /// One field of `fhe_prio3_batch` (the collector's `shares_received`
    /// and `result_ready`).
    pub fn set_batch_field(&self, field: &str, value: i64) {
        self.batch.with_label_values(&[field]).set(value);
    }

    pub fn set_db_size(&self, bytes: u64) {
        self.db_size.set(bytes as i64);
    }

    // ---- leader-side events ----------------------------------------------

    pub fn report(&self, outcome: &str, reason: &str) {
        self.reports.with_label_values(&[outcome, reason]).inc();
    }

    pub fn phase(&self, phase: &str, took: Duration, ok: bool) {
        self.phase_duration.with_label_values(&[phase]).observe(took.as_secs_f64());
        if !ok {
            self.phase_failures.with_label_values(&[phase]).inc();
        }
    }

    pub fn peer(&self, peer: &str, route: &str, took: Duration, ok: bool) {
        self.peer_duration.with_label_values(&[peer, route]).observe(took.as_secs_f64());
        self.peer_requests.with_label_values(&[peer, route, if ok { "ok" } else { "error" }]).inc();
    }
}

/// Times one protocol step: the wait for the state lock, then the step.
/// Dropping it without [`StepTimer::succeeded`] counts a failure (an error
/// return or a panic inside the step).
pub struct StepTimer {
    m: Arc<NodeMetrics>,
    step: &'static str,
    queued: Instant,
    acquired: Option<Instant>,
    failed: bool,
}

impl StepTimer {
    /// The state lock is held: the step starts now.
    pub fn acquired(&mut self) {
        let now = Instant::now();
        self.m.lock_waiters.dec();
        self.m.lock_wait.observe((now - self.queued).as_secs_f64());
        self.m.step_active_since.set(unix_now());
        self.acquired = Some(now);
    }

    pub fn succeeded(mut self) {
        self.failed = false;
    }
}

impl Drop for StepTimer {
    fn drop(&mut self) {
        match self.acquired {
            Some(t) => {
                self.m.step_active_since.set(0.0);
                self.m.step_duration.with_label_values(&[self.step]).observe(t.elapsed().as_secs_f64());
            }
            // never got the lock (poisoned, or the task was cancelled)
            None => self.m.lock_waiters.dec(),
        }
        if self.failed {
            self.m.step_failures.with_label_values(&[self.step]).inc();
        }
    }
}

// ---- HTTP ----------------------------------------------------------------

/// Middleware recording every request by matched route template.
pub async fn track(State(m): State<Arc<NodeMetrics>>, req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    m.http_in_flight.inc();
    let t = Instant::now();
    let resp = next.run(req).await;
    m.http_in_flight.dec();
    m.http_duration.with_label_values(&[route.as_str()]).observe(t.elapsed().as_secs_f64());
    m.http_requests.with_label_values(&[route.as_str(), resp.status().as_str()]).inc();
    resp
}

/// `/healthz` and `/readyz`, merged into a node's public router.
pub fn health_routes(m: Arc<NodeMetrics>) -> Router {
    Router::new().route("/healthz", get(healthz)).route("/readyz", get(readyz)).with_state(m)
}

/// The metrics listener's router: `/metrics`, `/healthz`, `/readyz`.
pub fn metrics_router(m: Arc<NodeMetrics>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(m)
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn readyz(State(m): State<Arc<NodeMetrics>>) -> Response {
    if m.is_ready() {
        (StatusCode::OK, "ready\n").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response()
    }
}

async fn metrics(State(m): State<Arc<NodeMetrics>>) -> Response {
    match m.render() {
        Ok(body) => ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], body).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Binds the metrics listener now (so a taken or invalid address fails the
/// node's start instead of leaving it unmonitored) and serves the metrics
/// router on it, plain HTTP: bind it to a private interface.
pub fn spawn_metrics_server(m: Arc<NodeMetrics>, addr: std::net::SocketAddr) -> anyhow::Result<std::net::SocketAddr> {
    let listener = std::net::TcpListener::bind(addr).map_err(|e| anyhow::anyhow!("metrics listener {addr}: {e}"))?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?;
    let server = axum_server::from_tcp(listener)?;
    tokio::spawn(async move {
        if let Err(e) = server.serve(metrics_router(m).into_make_service()).await {
            tracing::error!(%bound, error = %e, "metrics server stopped");
        }
    });
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> fhe_prio3::TaskConfig {
        fhe_prio3::TaskConfig::new([1; 32], fhe_prio3::MeasurementType::Count, 2)
    }

    /// Every `fhe_prio3_*` series the alert rules name is one a node
    /// exports (a histogram's `_sum`, `_count` and `_bucket` included), so a
    /// renamed metric cannot silently disable an alert.
    #[test]
    fn every_series_the_alert_rules_name_is_exported() {
        let t = task();
        let m = NodeMetrics::new(BuildInfo {
            role: "aggregator",
            index: 0,
            task: Some(&t),
        })
        .unwrap();
        // labelled families appear once they have a child
        let mut step = m.step("s");
        step.acquired();
        step.succeeded();
        drop(m.step("f"));
        m.report("accepted", "none");
        m.phase("close", Duration::from_secs(1), false);
        m.peer("https://p", "/v1/report", Duration::from_secs(1), true);
        m.set_batch(1, 0, false);
        m.committed(1, Duration::from_millis(1), Some(1));
        let mut exported = std::collections::BTreeSet::new();
        for f in m.registry.gather() {
            let name = f.name().to_string();
            if f.get_field_type() == prometheus::proto::MetricType::HISTOGRAM {
                for suffix in ["_sum", "_count", "_bucket"] {
                    exported.insert(format!("{name}{suffix}"));
                }
            }
            exported.insert(name);
        }
        let rules = include_str!("../deploy/prometheus/alerts.yml");
        let mut named = std::collections::BTreeSet::new();
        for (i, _) in rules.match_indices("fhe_prio3_") {
            let name: String = rules[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            named.insert(name);
        }
        assert!(named.len() >= 10, "{named:?}");
        let missing: Vec<&String> = named.iter().filter(|n| !exported.contains(*n)).collect();
        assert!(missing.is_empty(), "alert rules name series no node exports: {missing:?}");
        #[cfg(target_os = "linux")]
        assert!(exported.contains("process_resident_memory_bytes"));
    }

    #[test]
    fn reject_reasons_map_to_variant_names_only() {
        assert_eq!(reject_label("Replay"), "Replay");
        assert_eq!(reject_label("TooLarge { limit: 3, got: 4 }"), "TooLarge");
        assert_eq!(reject_label("MalformedCiphertext(\"x\")"), "MalformedCiphertext");
        assert_eq!(reject_label("anything a client wrote"), "Other");
        assert_eq!(reject_label(""), "Other");
    }

    #[test]
    fn a_step_records_wait_duration_and_failure() {
        let t = task();
        let m = NodeMetrics::new(BuildInfo {
            role: "aggregator",
            index: 0,
            task: Some(&t),
        })
        .unwrap();
        let mut ok = m.step("silent_admit");
        assert_eq!(m.lock_waiters.get(), 1);
        ok.acquired();
        assert_eq!(m.lock_waiters.get(), 0);
        assert!(m.step_active_since.get() > 0.0);
        ok.succeeded();
        assert_eq!(m.step_active_since.get(), 0.0);
        let mut bad = m.step("count_share");
        bad.acquired();
        drop(bad);
        let never = m.step("gate_commit");
        drop(never);
        assert_eq!(m.lock_waiters.get(), 0);
        assert_eq!(m.step_failures.with_label_values(&["count_share"]).get(), 1);
        assert_eq!(m.step_failures.with_label_values(&["gate_commit"]).get(), 1);
        assert_eq!(m.step_failures.with_label_values(&["silent_admit"]).get(), 0);
        assert_eq!(m.step_duration.with_label_values(&["silent_admit"]).get_sample_count(), 1);
        // a step that never got the lock has no duration
        assert_eq!(m.step_duration.with_label_values(&["gate_commit"]).get_sample_count(), 0);
        let text = m.render().unwrap();
        assert!(text.contains("fhe_prio3_build_info{"), "{text}");
        assert!(text.contains(r#"fhe_prio3_step_failures_total{step="count_share"} 1"#), "{text}");
        #[cfg(target_os = "linux")]
        assert!(text.contains("process_resident_memory_bytes"), "{text}");
    }
}
