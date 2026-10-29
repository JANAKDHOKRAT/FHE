//! Measurements of the paper's architecture (`fhe-paper-core`): one
//! configuration per process (the peak memory is the process's VmHWM).
//!
//!   paper_core_eval exact --type histogram:3 --reports 100 --batches 6 --out exact-histogram-3.json
//!   paper_core_eval randomised --type sumvec:100:1 --reports 100 --batches 6 [--groups 64]
//!
//! Per report: client encryption, evaluator admission. Per verification
//! ciphertext: the validity circuit (with the decoding `A_T`). Per batch:
//! the evaluator's finish and the collector's decryption. Setup (the
//! collector's key generation) is reported apart. Every batch's decrypted
//! output is compared with the plaintext. Medians come with
//! distribution-free 95% confidence intervals from order statistics (exact
//! binomial ranks).

use fhe_paper_core::*;
use fhe_prio3::config::SilentCheck;
use fhe_prio3::{Measurement, MeasurementType, Report, messages};
use rand::{Rng, SeedableRng};
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Args {
    batch_limit: Option<u64>,
    native: bool,
    profile: NativeParameters,
    check: SilentCheck,
    ty: MeasurementType,
    ty_str: String,
    reports: usize,
    batches: usize,
    seed: u64,
    /// Randomised check: reports per verification ciphertext (0 = the most).
    groups: usize,
    out: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: paper_core_eval (exact|randomised) --type T [--reports N] [--batches B] [--groups G] [--seed S] [--out FILE] [--key-mode single --plain-mod P --attempts Q --soundness-bits B --digits D]\n  T: count | sum:<max> | sumvec:<len>:<max> | histogram:<len>"
    );
    std::process::exit(2)
}

fn parse_type(s: &str) -> MeasurementType {
    let p: Vec<&str> = s.split(':').collect();
    let n = |i: usize| -> u64 { p.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage()) };
    match p[0] {
        "count" => MeasurementType::Count,
        "sum" => MeasurementType::Sum { max_measurement: n(1) },
        "histogram" => MeasurementType::Histogram { length: n(1) as usize },
        "sumvec" => MeasurementType::SumVec {
            length: n(1) as usize,
            max_measurement: n(2),
        },
        _ => usage(),
    }
}

fn parse() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    parse_args(&argv)
}

fn parse_args(argv: &[String]) -> Args {
    let check = match argv.first().map(String::as_str) {
        Some("exact") => SilentCheck::Exact,
        Some("randomised") => SilentCheck::Randomised,
        _ => usage(),
    };
    let mut a = Args {
        batch_limit: None,
        native: false,
        profile: NativeParameters::default(),
        check,
        ty: MeasurementType::Count,
        ty_str: String::new(),
        reports: 100,
        batches: 6,
        seed: 1,
        groups: 0,
        out: None,
    };
    let mut i = 1;
    let mut native_options = false;
    while i < argv.len() {
        native_options |= matches!(
            argv[i].as_str(),
            "--plain-mod" | "--attempts" | "--soundness-bits" | "--digits" | "--count-projection"
        );
        let v = argv.get(i + 1).cloned().unwrap_or_else(|| usage());
        match argv[i].as_str() {
            "--count-projection" => {
                a.profile.count_projection = match v.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => usage(),
                }
            }
            "--batch-limit" => a.batch_limit = Some(v.parse().unwrap_or_else(|_| usage())),
            "--key-mode" => {
                a.native = match v.as_str() {
                    "single" => true,
                    "threshold" => false,
                    _ => usage(),
                }
            }
            "--plain-mod" => a.profile.plain_mod = v.parse().unwrap_or_else(|_| usage()),
            "--attempts" => a.profile.invalid_attempts = v.parse().unwrap_or_else(|_| usage()),
            "--soundness-bits" => a.profile.target_bits = v.parse().unwrap_or_else(|_| usage()),
            "--digits" => a.profile.key_switch_digits = v.parse().unwrap_or_else(|_| usage()),
            "--type" => {
                a.ty = parse_type(&v);
                a.ty_str = v;
            }
            "--reports" => a.reports = v.parse().unwrap_or_else(|_| usage()),
            "--batches" => a.batches = v.parse().unwrap_or_else(|_| usage()),
            "--groups" => a.groups = v.parse().unwrap_or_else(|_| usage()),
            "--seed" => a.seed = v.parse().unwrap_or_else(|_| usage()),
            "--out" => a.out = Some(v),
            _ => usage(),
        }
        i += 2;
    }
    if a.ty_str.is_empty() || a.reports == 0 || a.batches == 0 {
        usage();
    }
    if !a.native && native_options {
        usage();
    }
    a
}

// ---- statistics ------------------------------------------------------

/// Minimal unsigned big integer (little-endian base 2^32), enough for
/// exact binomial sums.
#[derive(Clone, PartialEq, Eq)]
struct Big(Vec<u32>);

impl Big {
    fn from(v: u64) -> Self {
        let mut b = Big(vec![v as u32, (v >> 32) as u32]);
        b.trim();
        b
    }
    fn trim(&mut self) {
        while self.0.len() > 1 && *self.0.last().unwrap() == 0 {
            self.0.pop();
        }
    }
    fn add(&self, o: &Big) -> Big {
        let n = self.0.len().max(o.0.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry = 0u64;
        for i in 0..n {
            let s = *self.0.get(i).unwrap_or(&0) as u64 + *o.0.get(i).unwrap_or(&0) as u64 + carry;
            out.push(s as u32);
            carry = s >> 32;
        }
        out.push(carry as u32);
        let mut b = Big(out);
        b.trim();
        b
    }
    fn mul_small(&self, m: u32) -> Big {
        let mut out = Vec::with_capacity(self.0.len() + 1);
        let mut carry = 0u64;
        for &d in &self.0 {
            let s = d as u64 * m as u64 + carry;
            out.push(s as u32);
            carry = s >> 32;
        }
        out.push(carry as u32);
        let mut b = Big(out);
        b.trim();
        b
    }
    /// Exact division (the caller guarantees no remainder).
    fn div_small(&self, d: u32) -> Big {
        let mut out = vec![0u32; self.0.len()];
        let mut rem = 0u64;
        for i in (0..self.0.len()).rev() {
            let cur = (rem << 32) | self.0[i] as u64;
            out[i] = (cur / d as u64) as u32;
            rem = cur % d as u64;
        }
        assert_eq!(rem, 0, "binomial coefficients divide exactly");
        let mut b = Big(out);
        b.trim();
        b
    }
    fn pow2(n: usize) -> Big {
        let mut v = vec![0u32; n / 32 + 1];
        v[n / 32] = 1 << (n % 32);
        Big(v)
    }
    fn le(&self, o: &Big) -> bool {
        if self.0.len() != o.0.len() {
            return self.0.len() < o.0.len();
        }
        for i in (0..self.0.len()).rev() {
            if self.0[i] != o.0[i] {
                return self.0[i] < o.0[i];
            }
        }
        true
    }
}

/// The largest `k` with `P(Bin(n, 1/2) < k) <= 0.025`, i.e.
/// `40 * sum_{i<k} C(n, i) <= 2^n`, computed exactly: `[x_(k), x_(n+1-k)]`
/// covers the median with probability at least 95% for any continuous
/// distribution. `None` when `n` is too small for a 95% interval.
fn median_ci_rank(n: usize) -> Option<usize> {
    let two_n = Big::pow2(n);
    let mut c = Big::from(1);
    let mut cum = Big::from(0);
    let mut k = 0usize;
    for i in 0..n {
        cum = cum.add(&c);
        if cum.mul_small(40).le(&two_n) {
            k = i + 1;
        } else {
            break;
        }
        c = c.mul_small((n - i) as u32).div_small((i + 1) as u32);
    }
    if k == 0 { None } else { Some(k) }
}

fn stat_json(name: &str, mut xs: Vec<f64>) -> String {
    xs.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let n = xs.len();
    let median = if n % 2 == 1 { xs[n / 2] } else { (xs[n / 2 - 1] + xs[n / 2]) / 2.0 };
    let rank = |q: f64| xs[((q * n as f64).ceil() as usize).clamp(1, n) - 1];
    let (lo, hi) = match median_ci_rank(n) {
        Some(k) => (format!("{:.3}", xs[k - 1]), format!("{:.3}", xs[n - k])),
        None => ("null".into(), "null".into()),
    };
    format!(
        "\"{name}\": {{\"n\": {n}, \"median_ms\": {median:.3}, \"ci95_low_ms\": {lo}, \"ci95_high_ms\": {hi}, \"p5_ms\": {:.3}, \"p95_ms\": {:.3}, \"min_ms\": {:.3}, \"max_ms\": {:.3}}}",
        rank(0.05),
        rank(0.95),
        xs[0],
        xs[n - 1]
    )
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn peak_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}

fn machine_json() -> String {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        })
        .unwrap_or_default();
    let mem_kb: u64 = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0);
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    let omp = std::env::var("OMP_NUM_THREADS").unwrap_or_else(|_| "unset".into());
    let libs = openfhe_tbgv_rs::loaded_openfhe_libraries().unwrap_or_default().join(", ");
    format!(
        "{{\"cpu\": \"{cpu}\", \"logical_cpus\": {threads}, \"mem_total_kb\": {mem_kb}, \"omp_num_threads\": \"{omp}\", \"openfhe\": \"{}\"}}",
        libs.replace('"', "'")
    )
}

// ---- measurements -----------------------------------------------------

fn random_measurement(t: &MeasurementType, rng: &mut impl Rng) -> Measurement {
    match t {
        MeasurementType::Count => Measurement::Count(rng.gen_bool(0.5)),
        MeasurementType::Sum { max_measurement } => Measurement::Sum(rng.gen_range(0..=*max_measurement)),
        MeasurementType::SumVec { length, max_measurement } => Measurement::SumVec((0..*length).map(|_| rng.gen_range(0..=*max_measurement)).collect()),
        MeasurementType::BoundedSumVec { bounds } => Measurement::SumVec(bounds.iter().map(|&b| rng.gen_range(0..=b)).collect()),
        MeasurementType::Histogram { length } => Measurement::Histogram(rng.gen_range(0..*length)),
        MeasurementType::MultihotCountVec { length, max_weight } => {
            let mut v = vec![false; *length];
            let mut set = 0;
            for x in v.iter_mut() {
                if set < *max_weight && rng.gen_bool(0.5) {
                    *x = true;
                    set += 1;
                }
            }
            Measurement::MultihotCountVec(v)
        }
    }
}

/// Plaintext slot sums of the encodings: what every run must decrypt.
fn plain_sums(t: &MeasurementType, ms: &[Measurement]) -> Vec<u64> {
    let mut s = vec![0u64; t.input_len()];
    for m in ms {
        for (a, v) in s.iter_mut().zip(t.encode(m).expect("valid measurement")) {
            *a += v;
        }
    }
    s
}

struct Out {
    fields: Vec<String>,
}

impl Out {
    fn kv(&mut self, k: &str, v: impl std::fmt::Display) {
        self.fields.push(format!("\"{k}\": {v}"));
    }
    fn s(&mut self, k: &str, v: &str) {
        self.fields.push(format!("\"{k}\": \"{v}\""));
    }
    fn raw(&mut self, v: String) {
        self.fields.push(v);
    }
}

fn run(a: &Args, o: &mut Out) -> Result<()> {
    let mut task = if a.native {
        let mut profile = a.profile.clone();
        profile.groups = if a.groups > 0 { Some(a.groups) } else { None };
        PaperTask::new_native([0xC0; 32], a.ty.clone(), a.check, profile)?
    } else {
        let t = PaperTask::new([0xC0; 32], a.ty.clone(), a.check)?;
        if a.groups > 0 { t.with_groups(a.groups)? } else { t }
    };
    if let Some(limit) = a.batch_limit {
        task = task.with_batch_limit(limit)?;
    }
    if a.reports as u128 > task.max_batch() as u128 {
        return Err("requested reports exceed the task's arithmetic batch bound".into());
    }
    let cfg = task.config().clone();
    o.s("key_mode", if a.native { "native-single" } else { "threshold-one-party" });
    o.kv("count_projection", a.profile.count_projection);
    o.kv("plain_mod", cfg.plain_mod);
    o.kv("security_bits", cfg.security_bits);
    if a.native {
        o.kv("invalid_attempt_budget", a.profile.invalid_attempts);
        o.kv("global_soundness_target_bits", a.profile.target_bits);
    }
    o.kv("mult_depth", task.mult_depth());
    o.kv(
        "key_switch_digits",
        if a.native { a.profile.key_switch_digits } else { cfg.key_switch_digits() },
    );
    o.kv("reports_per_verification_ciphertext", task.groups());
    o.kv("max_batch", task.max_batch());
    if cfg.exact_check() {
        o.s("soundness", "exact (no soundness error)");
    } else {
        o.kv("repetitions", cfg.repetitions);
        o.kv("soundness_bits", format!("{:.1}", cfg.soundness_bits()));
    }
    let t0 = Instant::now();
    let (em, cm, key) = setup(&task)?;
    o.kv("setup_ms", format!("{:.1}", ms(t0)));
    o.kv("rotation_keys", em.rotation_indices.len());
    o.kv("rotation_key_bytes", em.rotation_key_bytes());
    o.kv("eval_mult_key_bytes", em.eval_mult_key.len());
    o.kv("public_key_bytes", cm.public_key.len());
    o.kv("context_bytes", cm.context.len());
    let ctx = task.make_context()?;
    o.kv("ring_dim", ctx.ring_dim());
    o.kv("log2_q", format!("{:.1}", ctx.log2_q()));
    o.kv("towers", ctx.num_towers());
    o.kv("key_switch_digits_actual", ctx.key_num_parts()?);
    let qp = ctx.key_basis_moduli(openfhe_tbgv_rs::KeyBasis::KeySwitch)?;
    o.kv("log2_qp", format!("{:.6}", qp.iter().map(|&q| (q as f64).log2()).sum::<f64>()));
    for (name, primes) in [
        ("q_moduli_decimal", ctx.moduli()?),
        ("public_key_moduli_decimal", ctx.key_basis_moduli(openfhe_tbgv_rs::KeyBasis::PublicKey)?),
        ("key_switch_moduli_decimal", qp.clone()),
    ] {
        o.raw(format!(
            "\"{name}\": [{}]",
            primes.iter().map(|p| format!("\"{p}\"")).collect::<Vec<_>>().join(",")
        ));
    }
    o.s("secret_distribution", "UNIFORM_TERNARY");
    let widths: u32 = ctx.moduli()?.iter().map(|q| 64 - (q - 1).leading_zeros()).sum();
    o.kv("wire_header_bytes", fhe_prio3::packed::HEADER_LEN);
    o.kv("wire_residue_fixed_width_bits_per_coefficient", widths);
    // Approximate coding headroom for arbitrary residue tuples, NOT a
    // ciphertext-entropy claim or an implemented compressed wire format.
    o.kv(
        "wire_generic_radix_headroom_bytes_estimate",
        format!("{:.1}", (widths as f64 - ctx.log2_q()).max(0.0) * 2.0 * ctx.ring_dim() as f64 / 8.0),
    );
    let client = PaperClient::new(&task, &cm)?;
    let collector = PaperCollector::new(task.clone(), &cm, &key)?;
    let groups = task.groups();
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(a.seed);
    let (mut c_t, mut admit_t, mut flush_t, mut finish_t, mut dec_t) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut evaluator_t = Vec::new();
    let (mut aggregate_bytes, mut report_bytes) = (0usize, 0usize);
    let mut serialized_report_bytes = 0usize;
    for b in 0..a.batches {
        let mut evaluator_ms = 0.0;
        let mut ev = PaperEvaluator::new(task.clone(), &em)?;
        let ms_: Vec<Measurement> = (0..a.reports).map(|_| random_measurement(&a.ty, &mut rng)).collect();
        let want = plain_sums(&a.ty, &ms_);
        for (i, meas) in ms_.iter().enumerate() {
            let t = Instant::now();
            let r = client.report(meas, (i % groups) as u32)?;
            c_t.push(ms(t));
            report_bytes = r.chunks[0].len();
            let encoded = messages::encode(&r)?;
            serialized_report_bytes = encoded.len();
            let r: Report = messages::decode(&encoded)?;
            let before = ev.pending();
            let t = Instant::now();
            ev.admit(&r)?;
            let dt = ms(t);
            evaluator_ms += dt;
            if ev.pending() <= before {
                // this report completed or reopened a verification
                // ciphertext: the call ran the circuit
                flush_t.push(dt);
            } else {
                admit_t.push(dt);
            }
        }
        if ev.pending() > 0 {
            let t = Instant::now();
            ev.flush()?;
            let dt = ms(t);
            evaluator_ms += dt;
            flush_t.push(dt);
        }
        let t = Instant::now();
        let agg = ev.finish()?;
        let dt = ms(t);
        evaluator_ms += dt;
        finish_t.push(dt);
        evaluator_t.push(evaluator_ms);
        aggregate_bytes = agg.output.len();
        let agg: PaperAggregate = messages::decode(&messages::encode(&agg)?)?;
        let t = Instant::now();
        let res = collector.decrypt_aggregate(&agg)?;
        dec_t.push(ms(t));
        let expect = a.ty.decode_aggregate(&want)?;
        if res.aggregate != expect || res.reports != a.reports as u64 {
            return Err(format!("batch {b}: decrypted {:?}, expected {expect:?}", res.aggregate).into());
        }
        eprintln!(
            "batch {}/{} verified: evaluator {:.3} ms over {} reports",
            b + 1,
            a.batches,
            evaluator_ms,
            a.reports
        );
    }
    o.kv("report_bytes", report_bytes);
    o.kv("serialized_report_bytes", serialized_report_bytes);
    o.kv("aggregate_bytes", aggregate_bytes);
    o.kv("evaluator_total_per_batch_ms", format!("{evaluator_t:?}"));
    o.raw(stat_json(
        "evaluator_total_per_report",
        evaluator_t.iter().map(|t| t / a.reports as f64).collect(),
    ));
    o.raw(stat_json("evaluator_total_per_batch", evaluator_t));
    o.raw(stat_json("client_encrypt_per_report", c_t));
    o.raw(stat_json("evaluator_admit_per_report", admit_t));
    o.raw(stat_json("validity_circuit_per_verification_ciphertext", flush_t));
    o.raw(stat_json("evaluator_finish_per_batch", finish_t));
    o.raw(stat_json("collector_decrypt_per_batch", dec_t));
    Ok(())
}

fn main() {
    let a = parse();
    let mut o = Out { fields: Vec::new() };
    o.s(
        "check",
        match a.check {
            SilentCheck::Exact => "exact",
            SilentCheck::Randomised => "randomised",
        },
    );
    o.s("type", &a.ty_str);
    o.kv("input_len", a.ty.input_len());
    o.kv("reports_per_batch", a.reports);
    o.kv("batches", a.batches);
    o.kv("seed", a.seed);
    o.raw(format!("\"machine\": {}", machine_json()));
    let started = Instant::now();
    if let Err(e) = run(&a, &mut o) {
        eprintln!("paper_core_eval: {e}");
        std::process::exit(1);
    }
    o.kv("wall_s", format!("{:.1}", started.elapsed().as_secs_f64()));
    o.kv("peak_rss_kb", peak_rss_kb());
    let json = format!("{{\n  {}\n}}\n", o.fields.join(",\n  "));
    print!("{json}");
    if let Some(path) = &a.out {
        std::fs::write(path, &json).expect("write --out");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_modes_select_the_requested_circuit() {
        for (mode, check, groups, depth) in [("exact", SilentCheck::Exact, 32768, 24), ("randomised", SilentCheck::Randomised, 4096, 28)] {
            let argv = [mode, "--type", "count"].map(String::from);
            let args = parse_args(&argv);
            assert_eq!(args.check, check);
            let task = PaperTask::new([0xC0; 32], args.ty, args.check).unwrap();
            assert_eq!(task.check_kind(), check);
            assert_eq!((task.groups(), task.mult_depth()), (groups, depth));
        }
    }

    /// The exact rank against the binomial tail computed in floating point
    /// for small `n`, and the known values for `n = 6` (smallest with a 95%
    /// interval), 100 and 600.
    #[test]
    fn ci_rank_is_the_binomial_quantile() {
        assert_eq!(median_ci_rank(5), None);
        assert_eq!(median_ci_rank(6), Some(1));
        for n in 6..=60usize {
            let k = median_ci_rank(n).unwrap();
            let tail = |k: usize| -> f64 {
                let mut c = 1f64;
                let mut s = 0f64;
                for i in 0..k {
                    s += c;
                    c = c * (n - i) as f64 / (i + 1) as f64;
                }
                s / 2f64.powi(n as i32)
            };
            assert!(tail(k) <= 0.025 && tail(k + 1) > 0.025, "n={n} k={k}");
        }
        assert_eq!(median_ci_rank(100), Some(40));
        assert_eq!(median_ci_rank(600), Some(276));
    }
}
