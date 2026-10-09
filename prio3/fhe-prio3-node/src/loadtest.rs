//! Load test of a running deployment (`fhe-prio3-node loadtest`).
//!
//! Drives real clients against a leader over TLS: each worker thread holds
//! its own client (its own OpenFHE context), takes a group ticket when the
//! task batches, encrypts a measurement, submits it, and records how long
//! each step took. The measurements are a deterministic function of a seed,
//! so the exact aggregate is known in advance; after the batch is closed the
//! released result is compared with it, including the small cells that must
//! be suppressed and a batch below the minimum that must be refused. While
//! it runs, the nodes' `/metrics` are scraped into a timeline (resident
//! memory, database size, queue depth, batch gauges), and the final scrape
//! of every node goes into the report.
//!
//! Nothing here estimates: every number in the report is a measurement of
//! this run, and the run fails (non-zero exit) when the result is not the
//! expected one or a report could not be delivered.

use crate::wire::*;
use fhe_prio3::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Result<T, E = String> = std::result::Result<T, E>;

pub struct LoadConfig {
    pub task: TaskConfig,
    pub material: PublicMaterial,
    pub leader: String,
    pub ca_pem: Vec<u8>,
    /// Operator token, for the close.
    pub token: String,
    pub reports: u64,
    /// Encryption threads, one client (and OpenFHE context) each.
    pub workers: usize,
    pub seed: u64,
    /// Every `invalid_every`-th report is invalid (a non-bit slot); 0: none.
    pub invalid_every: u64,
    /// `(name, base URL)` of each node's metrics listener.
    pub metrics: Vec<(String, String)>,
    pub scrape_every: Duration,
    /// JSON lines of the scrapes, one per node and scrape.
    pub timeline: Option<PathBuf>,
    /// Close the batch at the end and check the released result.
    pub close: bool,
    /// Longest wait for the close (a gated release at a large threshold
    /// runs for minutes).
    pub close_timeout: Duration,
}

/// splitmix64: a fixed, seedable generator, so a run is reproducible.
fn mix(seed: u64, i: u64) -> u64 {
    let mut z = seed ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The `i`-th measurement of a run. Histograms are skewed (bucket `b` with
/// probability `2^-(b+1)`, the last bucket taking the rest) so that a run of
/// any size has both large cells and cells below a suppression threshold.
pub fn measurement(ty: &MeasurementType, seed: u64, i: u64) -> anyhow::Result<Measurement> {
    let r = mix(seed, i);
    Ok(match ty {
        MeasurementType::Count => Measurement::Count(r & 1 == 1),
        MeasurementType::Sum { max_measurement } => Measurement::Sum(r % (max_measurement + 1)),
        MeasurementType::Histogram { length } => {
            let b = (r.trailing_zeros() as usize).min(length - 1);
            Measurement::Histogram(b)
        }
        other => anyhow::bail!("loadtest generates count, sum and histogram measurements, not {other:?}"),
    })
}

pub fn is_invalid(invalid_every: u64, i: u64) -> bool {
    invalid_every > 0 && i % invalid_every == invalid_every - 1
}

/// The aggregate of the valid measurements of a run, kept per element.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Expected {
    pub elements: Vec<u128>,
    pub valid: u64,
    pub invalid: u64,
}

impl Expected {
    pub fn of(ty: &MeasurementType, seed: u64, reports: u64, invalid_every: u64) -> anyhow::Result<Self> {
        let mut e = Expected {
            elements: vec![0; ty.num_elements()],
            valid: 0,
            invalid: 0,
        };
        for i in 0..reports {
            if is_invalid(invalid_every, i) {
                e.invalid += 1;
                continue;
            }
            e.valid += 1;
            match measurement(ty, seed, i)? {
                Measurement::Count(b) => e.elements[0] += b as u128,
                Measurement::Sum(v) => e.elements[0] += v as u128,
                Measurement::Histogram(b) => e.elements[b] += 1,
                _ => unreachable!("measurement() makes only these"),
            }
        }
        Ok(e)
    }

    /// Compares a released result (or the close's refusal) with what the
    /// task's rules say this run must release. `admitted`: reports the
    /// leader accepted (silent mode admits invalid reports too).
    pub fn check(&self, task: &TaskConfig, admitted: u64, outcome: &Result<BatchResult, String>) -> Result<(), String> {
        let gated_count = task.collector_holds_key();
        if (gated_count || task.mode == VerificationMode::Verdict) && self.valid < task.min_batch_size as u64 {
            // two refusals: fewer reports admitted than the minimum (the
            // leader refuses before any decryption: "batch has n admitted
            // reports, minimum is k"), or enough admitted but too few valid
            // (only the encrypted gate knows: "batch below minimum size")
            let want = if admitted < task.min_batch_size as u64 {
                format!("minimum is {}", task.min_batch_size)
            } else {
                "batch below minimum size".to_string()
            };
            return match outcome {
                Err(e) if e.contains(&want) => Ok(()),
                Err(e) => Err(format!("batch below the minimum: expected a refusal with \"{want}\", got error {e}")),
                Ok(r) => Err(format!(
                    "batch below the minimum ({} < {}) was released: {r:?}",
                    self.valid, task.min_batch_size
                )),
            };
        }
        let r = outcome.as_ref().map_err(|e| format!("close failed: {e}"))?;
        let got: Vec<u128> = match &r.aggregate {
            AggregateResult::Count(c) => vec![*c as u128],
            AggregateResult::Sum(s) => vec![*s],
            AggregateResult::Histogram(h) => h.iter().map(|&c| c as u128).collect(),
            other => return Err(format!("unexpected aggregate kind {other:?}")),
        };
        if task.min_cell_count > 0 {
            let k = task.min_cell_count as u128;
            let want_suppressed: Vec<usize> = (0..self.elements.len()).filter(|&e| self.elements[e] < k).collect();
            let want: Vec<u128> = self.elements.iter().map(|&c| if c < k { 0 } else { c }).collect();
            if r.suppressed != want_suppressed {
                return Err(format!("suppressed cells {:?}, expected {want_suppressed:?}", r.suppressed));
            }
            if got != want {
                return Err(format!("released cells {got:?}, expected {want:?}"));
            }
            if !r.counts_withheld || r.report_count != 0 || r.valid_count != 0 {
                return Err("small-cell suppression must withhold the counts".into());
            }
            return Ok(());
        }
        if got != self.elements {
            return Err(format!("aggregate {got:?}, expected {:?}", self.elements));
        }
        if r.valid_count != self.valid {
            return Err(format!("valid count {}, expected {}", r.valid_count, self.valid));
        }
        if r.report_count != admitted {
            return Err(format!("report count {}, expected {admitted} admitted", r.report_count));
        }
        Ok(())
    }
}

/// Order statistics of a sample of durations, in seconds.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Stats {
    pub n: usize,
    pub mean: f64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
}

impl Stats {
    /// Nearest-rank percentiles (the smallest value with at least `q` of the
    /// sample at or below it).
    pub fn of(mut v: Vec<f64>) -> Self {
        if v.is_empty() {
            return Self::default();
        }
        v.sort_by(|a, b| a.total_cmp(b));
        let rank = |q: f64| v[((q * v.len() as f64).ceil() as usize).clamp(1, v.len()) - 1];
        Stats {
            n: v.len(),
            mean: v.iter().sum::<f64>() / v.len() as f64,
            p50: rank(0.50),
            p90: rank(0.90),
            p99: rank(0.99),
            p999: rank(0.999),
            max: v[v.len() - 1],
        }
    }
}

#[derive(Default)]
struct Sample {
    group: f64,
    encrypt: f64,
    submit: f64,
    retries: u32,
    done_at: f64,
}

#[derive(Debug, Default, Serialize)]
pub struct Outcomes {
    pub accepted: u64,
    pub rejected: BTreeMap<String, u64>,
    /// Reports that could not be delivered after the retries.
    pub failed: u64,
    /// Transport retries (a retried report the leader had already admitted
    /// answers `Replay`, which counts as accepted).
    pub retries: u64,
}

#[derive(Debug, Serialize)]
pub struct NodePeaks {
    pub resident_memory_bytes: f64,
    pub db_size_bytes: f64,
    pub lock_waiters: f64,
}

#[derive(Debug, Serialize)]
pub struct LoadReport {
    pub task_digest: String,
    pub measurement_type: String,
    pub mode: String,
    pub topology: String,
    pub min_batch_size: usize,
    pub min_cell_count: u64,
    pub reports: u64,
    pub workers: usize,
    pub seed: u64,
    pub invalid_every: u64,
    pub report_bytes: usize,
    pub outcomes: Outcomes,
    /// Wall time from the first ticket to the last answered submission.
    pub submit_wall_seconds: f64,
    pub reports_per_second: f64,
    /// Completed submissions per minute of the run.
    pub per_minute: Vec<u64>,
    pub group_ticket: Stats,
    pub encrypt: Stats,
    /// Client-observed submit round trip (upload and the leader's admission).
    pub submit: Stats,
    pub close_seconds: Option<f64>,
    pub expected: Expected,
    pub result: Option<BatchResult>,
    pub close_error: Option<String>,
    /// `Ok` when the released result is exactly what the run must release.
    pub verdict: Result<(), String>,
    pub peaks: BTreeMap<String, NodePeaks>,
    /// The last scrape of every node, as served.
    pub final_metrics: BTreeMap<String, String>,
}

/// Parsed Prometheus text: series (name with labels, as written) to value.
pub fn parse_metrics(text: &str) -> BTreeMap<String, f64> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let (series, value) = l.rsplit_once(' ')?;
            Some((series.to_string(), value.parse().ok()?))
        })
        .collect()
}

/// The series a timeline line keeps.
fn timeline_value(series: &str) -> bool {
    [
        "process_resident_memory_bytes",
        "process_cpu_seconds_total",
        "fhe_prio3_db_size_bytes",
        "fhe_prio3_lock_waiters",
        "fhe_prio3_batch{",
        "fhe_prio3_step_active_since_timestamp_seconds",
        "fhe_prio3_http_requests_in_flight",
        "fhe_prio3_ready",
    ]
    .iter()
    .any(|p| series.starts_with(p))
}

struct Scraper {
    peaks: Mutex<BTreeMap<String, NodePeaks>>,
    last: Mutex<BTreeMap<String, String>>,
}

impl Scraper {
    async fn scrape_once(&self, http: &reqwest::Client, nodes: &[(String, String)], timeline: &mut Option<std::fs::File>, t0: Instant) {
        for (name, base) in nodes {
            let text = match http.get(format!("{base}/metrics")).send().await {
                Ok(r) => match r.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!(node = %name, error = %e, "metrics body");
                        continue;
                    }
                },
                Err(e) => {
                    tracing::warn!(node = %name, error = %e, "metrics scrape");
                    continue;
                }
            };
            let values = parse_metrics(&text);
            {
                let mut peaks = self.peaks.lock().expect("scraper peaks");
                let p = peaks.entry(name.clone()).or_insert(NodePeaks {
                    resident_memory_bytes: 0.0,
                    db_size_bytes: 0.0,
                    lock_waiters: 0.0,
                });
                let get = |k: &str| values.get(k).copied().unwrap_or(0.0);
                p.resident_memory_bytes = p.resident_memory_bytes.max(get("process_resident_memory_bytes"));
                p.db_size_bytes = p.db_size_bytes.max(get("fhe_prio3_db_size_bytes"));
                p.lock_waiters = p.lock_waiters.max(get("fhe_prio3_lock_waiters"));
            }
            if let Some(f) = timeline.as_mut() {
                let kept: BTreeMap<&String, &f64> = values.iter().filter(|(k, _)| timeline_value(k)).collect();
                let line = serde_json::json!({ "t": t0.elapsed().as_secs_f64(), "node": name, "values": kept });
                let _ = writeln!(f, "{line}");
            }
            self.last.lock().expect("scraper last").insert(name.clone(), text);
        }
    }
}

/// Runs the load test; the report says whether it passed.
pub async fn run(cfg: LoadConfig) -> anyhow::Result<LoadReport> {
    let expected = Expected::of(&cfg.task.measurement_type, cfg.seed, cfg.reports, cfg.invalid_every)?;
    let batched = cfg.task.mode == VerificationMode::Silent && cfg.task.silent_batch_groups > 1;
    let http = https_client(&cfg.ca_pem)?;
    let plain = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
    let t0 = Instant::now();

    // scraper
    let scraper = Arc::new(Scraper {
        peaks: Mutex::new(BTreeMap::new()),
        last: Mutex::new(BTreeMap::new()),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let scrape_task = {
        let (scraper, stop, nodes, every) = (scraper.clone(), stop.clone(), cfg.metrics.clone(), cfg.scrape_every);
        let mut timeline = match &cfg.timeline {
            Some(p) => Some(std::fs::File::create(p)?),
            None => None,
        };
        let plain = plain.clone();
        tokio::spawn(async move {
            while !stop.load(Ordering::SeqCst) {
                scraper.scrape_once(&plain, &nodes, &mut timeline, t0).await;
                let mut slept = Duration::ZERO;
                while slept < every && !stop.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    slept += Duration::from_millis(200);
                }
            }
            scraper.scrape_once(&plain, &nodes, &mut timeline, t0).await;
        })
    };

    // workers: one OS thread and one client each; network calls run on the
    // runtime through its handle
    let rt = tokio::runtime::Handle::current();
    let next = Arc::new(AtomicU64::new(0));
    let samples: Arc<Mutex<Vec<Sample>>> = Arc::new(Mutex::new(Vec::with_capacity(cfg.reports as usize)));
    let outcomes = Arc::new(Mutex::new(Outcomes::default()));
    let report_bytes = Arc::new(AtomicU64::new(0));
    let progress = Arc::new(AtomicU64::new(0));
    let submit_start = Instant::now();
    let mut threads = Vec::new();
    for w in 0..cfg.workers {
        let client = Client::new(cfg.task.clone(), &cfg.material.context, &cfg.material.public_key)?;
        let (rt, next, samples, outcomes, report_bytes, progress) = (
            rt.clone(),
            next.clone(),
            samples.clone(),
            outcomes.clone(),
            report_bytes.clone(),
            progress.clone(),
        );
        let (http, leader, task, n, seed, invalid_every) = (http.clone(), cfg.leader.clone(), cfg.task.clone(), cfg.reports, cfg.seed, cfg.invalid_every);
        threads.push(std::thread::Builder::new().name(format!("loadtest-{w}")).spawn(move || -> anyhow::Result<()> {
            loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= n {
                    return Ok(());
                }
                let mut s = Sample::default();
                let t = Instant::now();
                let group = if batched {
                    let ticket: GroupTicket = rt.block_on(http_get(&http, &format!("{leader}/v1/group"), None))?;
                    ticket.group
                } else {
                    0
                };
                s.group = t.elapsed().as_secs_f64();
                let t = Instant::now();
                let m = measurement(&task.measurement_type, seed, i)?;
                let report = if is_invalid(invalid_every, i) {
                    // a valid encoding with its first element set to 2: not
                    // a bit, so the validity check zeroes or rejects it
                    let mut enc = task.measurement_type.encode(&m)?;
                    enc[0] = 2;
                    let layout = client.layout();
                    let chunks: Vec<Vec<u64>> = (0..layout.num_chunks).map(|c| enc[layout.chunk_range(c)].to_vec()).collect();
                    client.shard_raw_elements_in_group(&chunks, group)?
                } else {
                    client.shard_in_group(&m, group)?
                };
                s.encrypt = t.elapsed().as_secs_f64();
                let body = fhe_prio3::messages::encode(&report)?;
                report_bytes.store(body.len() as u64, Ordering::Relaxed);
                let t = Instant::now();
                let mut answer = None;
                for attempt in 0..4u32 {
                    match rt.block_on(http_post_raw(&http, &format!("{leader}/v1/submit"), None, body.clone())) {
                        Ok(bytes) => {
                            let o: SubmitOutcome = fhe_prio3::messages::decode(&bytes)?;
                            answer = Some(match o {
                                // a retry of a report the leader admitted
                                SubmitOutcome::Rejected(r) if attempt > 0 && r.starts_with("Replay") => SubmitOutcome::Accepted,
                                o => o,
                            });
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(report = i, attempt, error = %e, "submit failed, retrying");
                            s.retries += 1;
                            std::thread::sleep(Duration::from_millis(500 << attempt));
                        }
                    }
                }
                s.submit = t.elapsed().as_secs_f64();
                s.done_at = submit_start.elapsed().as_secs_f64();
                {
                    let mut o = outcomes.lock().expect("outcomes");
                    o.retries += s.retries as u64;
                    match answer {
                        Some(SubmitOutcome::Accepted) => o.accepted += 1,
                        Some(SubmitOutcome::Rejected(r)) => *o.rejected.entry(crate::metrics::reject_label(&r).to_string()).or_default() += 1,
                        None => o.failed += 1,
                    }
                }
                samples.lock().expect("samples").push(s);
                let done = progress.fetch_add(1, Ordering::SeqCst) + 1;
                if done % 256 == 0 || done == n {
                    let el = submit_start.elapsed().as_secs_f64();
                    tracing::info!(done, total = n, elapsed_s = el as u64, rate = format!("{:.3}/s", done as f64 / el), "submitted");
                }
            }
        })?);
    }
    let mut worker_error = None;
    for t in threads {
        // join on the blocking pool: a worker blocks inside `block_on`
        let r = tokio::task::spawn_blocking(move || t.join()).await?;
        match r {
            Ok(Ok(())) => {}
            Ok(Err(e)) => worker_error = Some(e.to_string()),
            Err(_) => worker_error = Some("a worker thread panicked".into()),
        }
    }
    let submit_wall = submit_start.elapsed().as_secs_f64();
    if let Some(e) = &worker_error {
        tracing::error!(error = %e, "worker failed");
    }

    // close and check
    let outcomes = Arc::try_unwrap(outcomes)
        .map_err(|_| anyhow::anyhow!("outcomes still shared"))?
        .into_inner()
        .expect("outcomes");
    let (mut close_seconds, mut result, mut close_error) = (None, None, None);
    let mut verdict = match (&worker_error, outcomes.failed) {
        (Some(e), _) => Err(format!("worker failed: {e}")),
        (None, f) if f > 0 => Err(format!("{f} report(s) could not be delivered")),
        _ => Ok(()),
    };
    if cfg.close && verdict.is_ok() {
        let closer = reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(reqwest::Certificate::from_pem(&cfg.ca_pem)?)
            .tls_built_in_root_certs(false)
            .timeout(cfg.close_timeout)
            .build()?;
        let t = Instant::now();
        let r: anyhow::Result<CloseReply> = http_post(&closer, &format!("{}/v1/close", cfg.leader), Some(&cfg.token), &()).await;
        close_seconds = Some(t.elapsed().as_secs_f64());
        let outcome = match r {
            Ok(CloseReply { result: Some(res), .. }) => Ok(res),
            Ok(CloseReply { result: None, .. }) => Err("close returned no result (release policies)".to_string()),
            Err(e) => Err(e.to_string()),
        };
        verdict = expected.check(&cfg.task, outcomes.accepted, &outcome);
        match outcome {
            Ok(r) => result = Some(r),
            Err(e) => close_error = Some(e),
        }
    }
    stop.store(true, Ordering::SeqCst);
    scrape_task.await?;

    let samples = Arc::try_unwrap(samples)
        .map_err(|_| anyhow::anyhow!("samples still shared"))?
        .into_inner()
        .expect("samples");
    let mut per_minute = vec![0u64; (submit_wall / 60.0).ceil().max(1.0) as usize];
    for s in &samples {
        let m = ((s.done_at / 60.0) as usize).min(per_minute.len() - 1);
        per_minute[m] += 1;
    }
    let scraper = Arc::try_unwrap(scraper).map_err(|_| anyhow::anyhow!("scraper still shared"))?;
    Ok(LoadReport {
        task_digest: hex::encode(cfg.task.digest()),
        measurement_type: format!("{:?}", cfg.task.measurement_type),
        mode: format!("{:?}", cfg.task.mode),
        topology: format!("{:?}", cfg.task.key_topology),
        min_batch_size: cfg.task.min_batch_size,
        min_cell_count: cfg.task.min_cell_count,
        reports: cfg.reports,
        workers: cfg.workers,
        seed: cfg.seed,
        invalid_every: cfg.invalid_every,
        report_bytes: report_bytes.load(Ordering::Relaxed) as usize,
        submit_wall_seconds: submit_wall,
        reports_per_second: samples.len() as f64 / submit_wall,
        per_minute,
        group_ticket: Stats::of(samples.iter().map(|s| s.group).collect()),
        encrypt: Stats::of(samples.iter().map(|s| s.encrypt).collect()),
        submit: Stats::of(samples.iter().map(|s| s.submit).collect()),
        outcomes,
        close_seconds,
        expected,
        result,
        close_error,
        verdict,
        peaks: scraper.peaks.into_inner().expect("peaks"),
        final_metrics: scraper.last.into_inner().expect("last"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_are_nearest_rank() {
        let s = Stats::of((1..=1000).map(|x| x as f64).collect());
        assert_eq!((s.n, s.p50, s.p90, s.p99, s.p999, s.max), (1000, 500.0, 900.0, 990.0, 999.0, 1000.0));
        assert_eq!(s.mean, 500.5);
        let one = Stats::of(vec![3.0]);
        assert_eq!((one.p50, one.p999, one.max), (3.0, 3.0, 3.0));
        assert_eq!(Stats::of(vec![]), Stats::default());
    }

    #[test]
    fn measurements_are_reproducible_and_skewed() {
        let ty = MeasurementType::Histogram { length: 16 };
        let e = Expected::of(&ty, 7, 65536, 0).unwrap();
        assert_eq!(e, Expected::of(&ty, 7, 65536, 0).unwrap());
        assert_eq!(e.elements.iter().sum::<u128>(), 65536);
        // about half in bucket 0, a quarter in bucket 1, ...: large cells and
        // cells of a handful of reports in one run
        assert!((30000..36000).contains(&e.elements[0]), "{:?}", e.elements);
        assert!(e.elements[14] < 16, "{:?}", e.elements);
        let sum = MeasurementType::Sum { max_measurement: 100 };
        for i in 0..1000 {
            match measurement(&sum, 1, i).unwrap() {
                Measurement::Sum(v) => assert!(v <= 100),
                _ => unreachable!(),
            }
        }
        let with_invalid = Expected::of(&ty, 7, 100, 10).unwrap();
        assert_eq!((with_invalid.valid, with_invalid.invalid), (90, 10));
    }

    fn result(cells: Vec<u64>, suppressed: Vec<usize>, withheld: bool, report_count: u64, valid: u64) -> BatchResult {
        BatchResult {
            collector: 0,
            elements: (0..cells.len()).collect(),
            aggregate: AggregateResult::Histogram(cells),
            report_count,
            valid_count: valid,
            regression: None,
            counts_withheld: withheld,
            suppressed,
        }
    }

    #[test]
    fn the_check_applies_suppression_minimum_and_counts() {
        let e = Expected {
            elements: vec![10, 2, 0, 5],
            valid: 17,
            invalid: 1,
        };
        let mut t = TaskConfig::new_split_key([1; 32], MeasurementType::Histogram { length: 4 });
        t.min_batch_size = 3;
        t.min_cell_count = 3;
        assert_eq!(e.check(&t, 18, &Ok(result(vec![10, 0, 0, 5], vec![1, 2], true, 0, 0))), Ok(()));
        // a small cell released, a wrong suppression list, counts not withheld
        assert!(e.check(&t, 18, &Ok(result(vec![10, 2, 0, 5], vec![2], true, 0, 0))).is_err());
        assert!(e.check(&t, 18, &Ok(result(vec![10, 0, 0, 5], vec![1], true, 0, 0))).is_err());
        assert!(e.check(&t, 18, &Ok(result(vec![10, 0, 0, 5], vec![1, 2], false, 18, 17))).is_err());
        // no suppression: exact cells and counts
        t.min_cell_count = 0;
        assert_eq!(e.check(&t, 18, &Ok(result(vec![10, 2, 0, 5], vec![], false, 18, 17))), Ok(()));
        assert!(e.check(&t, 18, &Ok(result(vec![10, 2, 0, 5], vec![], false, 17, 17))).is_err());
        assert!(e.check(&t, 18, &Err("boom".into())).is_err());
        // below the minimum the close must refuse: 18 admitted, 17 valid
        // against a minimum of 18 is the encrypted gate's refusal
        t.min_batch_size = 18;
        assert_eq!(e.check(&t, 18, &Err("collector: batch below minimum size".into())), Ok(()));
        assert!(e.check(&t, 18, &Err("HTTP 409: batch has 18 admitted reports, minimum is 18".into())).is_err());
        assert!(e.check(&t, 18, &Ok(result(vec![10, 2, 0, 5], vec![], false, 18, 17))).is_err());
        // fewer admitted than the minimum: the leader's refusal
        t.min_batch_size = 20;
        assert_eq!(
            e.check(&t, 18, &Err("HTTP 409 Conflict: batch has 18 admitted reports, minimum is 20".into())),
            Ok(())
        );
        assert!(e.check(&t, 18, &Err("collector: batch below minimum size".into())).is_err());
    }

    #[test]
    fn metrics_text_parses_into_series() {
        let m = parse_metrics("# HELP x y\n# TYPE x gauge\nx 3\nfhe_prio3_batch{field=\"accepted\"} 42\n\nbad line\n");
        assert_eq!(m.get("x"), Some(&3.0));
        assert_eq!(m.get("fhe_prio3_batch{field=\"accepted\"}"), Some(&42.0));
        assert_eq!(m.len(), 2);
    }
}
