//! Prio3 baseline: the reference Rust implementation of Prio3 (crate `prio`
//! 0.18.1, which implements draft-irtf-cfrg-vdaf-18) run on this machine
//! with two aggregators, for the tasks `fhe-prio3` measures.
//!
//! For every report it runs the protocol as the specification defines it:
//! the client shards, each aggregator decodes its input share and runs
//! `verify_init`, the verifier shares are combined into the verifier
//! message, each aggregator runs `verify_next` to its output share; the
//! output shares are aggregated and the collector unshards. Each step is
//! timed on its own, and the encoded size of every object that crosses the
//! network is recorded. The aggregate is compared with the plaintext sum of
//! the measurements; a mismatch stops the run.
//!
//! Timing statistics are the median over the reports with its exact 95%
//! confidence interval from order statistics (distribution-free: it assumes
//! only independent samples), plus the 5th and 95th percentiles.
//!
//! Usage: prio3-baseline [--reports N] [--seed S] [--out FILE]

use anyhow::{Context, Result, bail, ensure};
use prio::codec::{Encode, ParameterizedDecode};
use prio::vdaf::prio3::{Prio3, Prio3Count, Prio3Histogram, Prio3MultihotCountVec, Prio3Sum, Prio3SumVec, optimal_chunk_length};
use prio::vdaf::{Aggregatable, Aggregator, Client, Collector, VerifyTransition};
use rand::{Rng, RngCore, SeedableRng};
use serde::Serialize;
use std::time::Instant;

const NUM_AGGREGATORS: u8 = 2;
const CTX: &[u8] = b"fhe-prio3 baseline";

/// Median with its exact distribution-free 95% confidence interval, and the
/// 5th and 95th percentiles (nearest rank), in milliseconds.
#[derive(Serialize, Clone, Debug)]
struct Stat {
    n: usize,
    median_ms: f64,
    ci95_low_ms: f64,
    ci95_high_ms: f64,
    p5_ms: f64,
    p95_ms: f64,
}

/// Largest k with P(B <= k - 1) <= 0.025 for B ~ Binomial(n, 1/2), computed
/// exactly in integers: 40 * sum_{i<k} C(n, i) <= 2^n. The interval
/// [x_(k), x_(n-k+1)] then covers the median with probability >= 95%.
fn median_ci_rank(n: usize) -> Option<usize> {
    if n > 120 {
        return None;
    }
    let two_n: u128 = 1u128 << n;
    let mut c: u128 = 1; // C(n, 0)
    let mut cum: u128 = 0;
    let mut k = 0usize;
    for i in 0..n {
        // cum = sum_{j < i+1} C(n, j) after adding C(n, i)
        cum += c;
        if 40 * cum <= two_n {
            k = i + 1;
        } else {
            break;
        }
        c = c * (n - i) as u128 / (i + 1) as u128;
    }
    if k == 0 { None } else { Some(k) }
}

fn stat(mut xs: Vec<f64>) -> Stat {
    xs.sort_by(|a, b| a.partial_cmp(b).expect("finite durations"));
    let n = xs.len();
    let rank = |q: f64| xs[((q * n as f64).ceil() as usize).clamp(1, n) - 1];
    let median = if n % 2 == 1 { xs[n / 2] } else { (xs[n / 2 - 1] + xs[n / 2]) / 2.0 };
    let (lo, hi) = match median_ci_rank(n) {
        Some(k) => (xs[k - 1], xs[n - k]),
        None => (f64::NAN, f64::NAN),
    };
    Stat {
        n,
        median_ms: median,
        ci95_low_ms: lo,
        ci95_high_ms: hi,
        p5_ms: rank(0.05),
        p95_ms: rank(0.95),
    }
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

#[derive(Serialize, Debug)]
struct TaskResult {
    task: String,
    prio_version: &'static str,
    vdaf_draft: &'static str,
    aggregators: u8,
    reports: usize,
    chunk_length: Option<usize>,
    /// Bytes: public share plus every input share, as encoded.
    report_bytes: usize,
    public_share_bytes: usize,
    input_share_bytes: Vec<usize>,
    /// Bytes each aggregator sends in the one verification round.
    verifier_share_bytes: usize,
    verifier_message_bytes: usize,
    aggregate_share_bytes: usize,
    client_shard: Stat,
    /// Per aggregator: decode the input share, verify_init.
    aggregator_verify_init: Vec<Stat>,
    /// The leader combines the verifier shares into the verifier message.
    verifier_shares_to_message: Stat,
    /// Per aggregator: verify_next to the output share.
    aggregator_verify_next: Vec<Stat>,
    /// Per aggregator total per report (verify_init + verify_next, plus the
    /// message combination for the leader).
    aggregator_total: Vec<Stat>,
    /// Per batch: accumulating every output share into the aggregate share,
    /// per aggregator; then the collector's unshard.
    aggregate_batch_ms: Vec<f64>,
    unshard_ms: f64,
    aggregate_matches_reference: bool,
}

/// Runs `reports` measurements through Prio3 and measures every step.
#[allow(clippy::too_many_arguments)]
fn run<V, const SEED: usize>(
    name: &str,
    vdaf: &V,
    agg_param: &V::AggregationParam,
    chunk_length: Option<usize>,
    measurements: &[V::Measurement],
    reference: V::AggregateResult,
    rng: &mut impl RngCore,
) -> Result<TaskResult>
where
    V: Client<16> + Aggregator<SEED, 16> + Collector,
    V::AggregateResult: PartialEq + std::fmt::Debug,
{
    let mut verify_key = [0u8; SEED];
    rng.fill_bytes(&mut verify_key);
    let n_agg = vdaf.num_aggregators();
    let (mut t_shard, mut t_msg) = (Vec::new(), Vec::new());
    let mut t_init = vec![Vec::new(); n_agg];
    let mut t_next = vec![Vec::new(); n_agg];
    let mut t_total = vec![Vec::new(); n_agg];
    let mut out_shares: Vec<Vec<V::OutputShare>> = vec![Vec::new(); n_agg];
    let (mut report_bytes, mut public_bytes, mut input_bytes, mut vshare_bytes, mut vmsg_bytes) = (0, 0, Vec::new(), 0, 0);
    for m in measurements {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        let t = Instant::now();
        let (public_share, input_shares) = vdaf.shard(CTX, m, &nonce)?;
        t_shard.push(ms(t));
        let public_enc = public_share.get_encoded()?;
        let inputs_enc: Vec<Vec<u8>> = input_shares.iter().map(|s| s.get_encoded()).collect::<Result<_, _>>()?;
        public_bytes = public_enc.len();
        input_bytes = inputs_enc.iter().map(Vec::len).collect();
        report_bytes = public_bytes + input_bytes.iter().sum::<usize>();

        // each aggregator decodes what it received, then verify_init
        let mut states = Vec::with_capacity(n_agg);
        let mut vshares = Vec::with_capacity(n_agg);
        let mut init_ms = vec![0.0; n_agg];
        for (agg_id, enc) in inputs_enc.iter().enumerate() {
            let t = Instant::now();
            let public = V::PublicShare::get_decoded_with_param(vdaf, &public_enc)?;
            let input = V::InputShare::get_decoded_with_param(&(vdaf, agg_id), enc)?;
            let (state, vshare) = vdaf.verify_init(&verify_key, CTX, agg_id, agg_param, &nonce, &public, &input)?;
            init_ms[agg_id] = ms(t);
            vshare_bytes = vshare.get_encoded()?.len();
            states.push(state);
            vshares.push(vshare);
        }
        let t = Instant::now();
        let vmsg = vdaf.verifier_shares_to_message(CTX, agg_param, vshares)?;
        let msg_ms = ms(t);
        vmsg_bytes = vmsg.get_encoded()?.len();
        for (agg_id, state) in states.into_iter().enumerate() {
            let t = Instant::now();
            let out = match vdaf.verify_next(CTX, state, vmsg.clone())? {
                VerifyTransition::Finish(out) => out,
                VerifyTransition::Continue(..) => bail!("{name}: Prio3 finishes in one round"),
            };
            let next_ms = ms(t);
            out_shares[agg_id].push(out);
            t_init[agg_id].push(init_ms[agg_id]);
            t_next[agg_id].push(next_ms);
            t_total[agg_id].push(init_ms[agg_id] + next_ms + if agg_id == 0 { msg_ms } else { 0.0 });
        }
        t_msg.push(msg_ms);
    }
    let mut agg_ms = Vec::with_capacity(n_agg);
    let mut agg_shares = Vec::with_capacity(n_agg);
    for shares in out_shares {
        let t = Instant::now();
        let mut acc = vdaf.aggregate_init(agg_param);
        for s in shares {
            acc.accumulate(&s)?;
        }
        agg_ms.push(ms(t));
        agg_shares.push(acc);
    }
    let aggregate_share_bytes = agg_shares[0].get_encoded()?.len();
    let t = Instant::now();
    let result = vdaf.unshard(agg_param, agg_shares, measurements.len())?;
    let unshard_ms = ms(t);
    ensure!(
        result == reference,
        "{name}: aggregate {result:?} differs from the plaintext reference {reference:?}"
    );
    Ok(TaskResult {
        task: name.to_string(),
        prio_version: "0.18.1",
        vdaf_draft: "draft-irtf-cfrg-vdaf-18",
        aggregators: n_agg as u8,
        reports: measurements.len(),
        chunk_length,
        report_bytes,
        public_share_bytes: public_bytes,
        input_share_bytes: input_bytes,
        verifier_share_bytes: vshare_bytes,
        verifier_message_bytes: vmsg_bytes,
        aggregate_share_bytes,
        client_shard: stat(t_shard),
        aggregator_verify_init: t_init.into_iter().map(stat).collect(),
        verifier_shares_to_message: stat(t_msg),
        aggregator_verify_next: t_next.into_iter().map(stat).collect(),
        aggregator_total: t_total.into_iter().map(stat).collect(),
        aggregate_batch_ms: agg_ms,
        unshard_ms,
        aggregate_matches_reference: true,
    })
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let reports: usize = arg(&args, "--reports").map(|s| s.parse()).transpose()?.unwrap_or(100);
    let seed: u64 = arg(&args, "--seed").map(|s| s.parse()).transpose()?.unwrap_or(1);
    let out = arg(&args, "--out");
    ensure!(reports >= 6, "at least 6 reports are needed for a 95% interval on the median");
    // measurements from a seeded generator (reproducible); the protocol's own
    // randomness (nonces, verify key, shares) comes from it too
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut results = Vec::new();

    {
        let v = Prio3Count::new_count(NUM_AGGREGATORS)?;
        let ms: Vec<bool> = (0..reports).map(|_| rng.r#gen()).collect();
        let reference = ms.iter().filter(|&&b| b).count() as u64;
        results.push(run::<_, 32>("Count", &v, &(), None, &ms, reference, &mut rng)?);
    }
    {
        let v = Prio3Sum::new_sum(NUM_AGGREGATORS, 100)?;
        let ms: Vec<u64> = (0..reports).map(|_| rng.gen_range(0..=100)).collect();
        let reference: u64 = ms.iter().sum();
        results.push(run::<_, 32>("Sum(100)", &v, &(), None, &ms, reference, &mut rng)?);
    }
    for length in [16usize, 64] {
        let chunk = optimal_chunk_length(length);
        let v = Prio3Histogram::new_histogram(NUM_AGGREGATORS, length, chunk)?;
        let ms: Vec<usize> = (0..reports).map(|_| rng.gen_range(0..length)).collect();
        let mut reference = vec![0u128; length];
        for &b in &ms {
            reference[b] += 1;
        }
        results.push(run::<_, 32>(&format!("Histogram({length})"), &v, &(), Some(chunk), &ms, reference, &mut rng)?);
    }
    for (len, max) in [(8usize, 255u128), (1200, 15), (100, 1)] {
        // SumVec's measurement length is len * bits(max)
        let bits = (128 - max.leading_zeros()) as usize;
        let chunk = optimal_chunk_length(len * bits);
        let v = Prio3SumVec::new_sum_vec(NUM_AGGREGATORS, max, len, chunk)?;
        let ms: Vec<Vec<u128>> = (0..reports).map(|_| (0..len).map(|_| rng.gen_range(0..=max)).collect()).collect();
        let mut reference = vec![0u128; len];
        for m in &ms {
            for (r, x) in reference.iter_mut().zip(m) {
                *r += x;
            }
        }
        results.push(run::<_, 32>(
            &format!("SumVec({len}, max {max})"),
            &v,
            &(),
            Some(chunk),
            &ms,
            reference,
            &mut rng,
        )?);
    }
    {
        let (buckets, max_weight) = (32usize, 4usize);
        // measurement: the buckets plus the weight's bits
        let weight_bits = (usize::BITS - max_weight.leading_zeros()) as usize;
        let chunk = optimal_chunk_length(buckets + weight_bits);
        let v: Prio3MultihotCountVec = Prio3::new_multihot_count_vec(NUM_AGGREGATORS, buckets, max_weight, chunk)?;
        let ms: Vec<Vec<bool>> = (0..reports)
            .map(|_| {
                let w = rng.gen_range(0..=max_weight);
                let mut m = vec![false; buckets];
                let mut set = 0;
                while set < w {
                    let i = rng.gen_range(0..buckets);
                    if !m[i] {
                        m[i] = true;
                        set += 1;
                    }
                }
                m
            })
            .collect();
        let mut reference = vec![0u128; buckets];
        for m in &ms {
            for (r, &b) in reference.iter_mut().zip(m) {
                *r += b as u128;
            }
        }
        results.push(run::<_, 32>(
            &format!("MultihotCountVec({buckets}, {max_weight})"),
            &v,
            &(),
            Some(chunk),
            &ms,
            reference,
            &mut rng,
        )?);
    }

    for r in &results {
        println!(
            "{:<28} report {:>7} B (public {} + inputs {:?}); verifier share {} B, message {} B; client {:.3} ms [{:.3}, {:.3}]; aggregator 0 {:.3} ms [{:.3}, {:.3}], aggregator 1 {:.3} ms [{:.3}, {:.3}]",
            r.task,
            r.report_bytes,
            r.public_share_bytes,
            r.input_share_bytes,
            r.verifier_share_bytes,
            r.verifier_message_bytes,
            r.client_shard.median_ms,
            r.client_shard.ci95_low_ms,
            r.client_shard.ci95_high_ms,
            r.aggregator_total[0].median_ms,
            r.aggregator_total[0].ci95_low_ms,
            r.aggregator_total[0].ci95_high_ms,
            r.aggregator_total[1].median_ms,
            r.aggregator_total[1].ci95_low_ms,
            r.aggregator_total[1].ci95_high_ms,
        );
    }
    if let Some(path) = out {
        std::fs::write(&path, serde_json::to_vec_pretty(&results)?).with_context(|| format!("writing {path}"))?;
        println!("wrote {path}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rank against a direct evaluation of the binomial tail.
    #[test]
    fn median_interval_rank_is_the_exact_binomial_bound() {
        fn tail(n: usize, k: usize) -> f64 {
            // P(B <= k - 1) for B ~ Bin(n, 1/2), in f64 with log-gamma-free products
            let mut c = 1f64;
            let mut s = 0f64;
            for i in 0..k {
                s += c;
                c = c * (n - i) as f64 / (i + 1) as f64;
            }
            s / 2f64.powi(n as i32)
        }
        assert_eq!(median_ci_rank(5), None); // even x_(1)..x_(5) covers with prob 1 - 2/32 < 0.95
        for n in 6..=120 {
            let k = median_ci_rank(n).unwrap();
            assert!(tail(n, k) <= 0.025 + 1e-12, "n={n} k={k}");
            assert!(tail(n, k + 1) > 0.025 - 1e-12, "n={n} k={k}");
        }
        // known values: n = 100 -> [x_(40), x_(61)]
        assert_eq!(median_ci_rank(100), Some(40));
    }

    #[test]
    fn stats_on_a_known_sample() {
        let s = stat((1..=100).map(|x| x as f64).collect());
        assert_eq!((s.n, s.median_ms, s.p5_ms, s.p95_ms), (100, 50.5, 5.0, 95.0));
        assert_eq!((s.ci95_low_ms, s.ci95_high_ms), (40.0, 61.0));
    }
}
