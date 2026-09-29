//! Every party of a round in one process, for tests and simulations: the
//! same steps a deployment runs over the network (`fhe-prio3-node`), with
//! each message passed by value.

use crate::aggregator::{Aggregator, Verdict};
use crate::collector::Collector;
use crate::error::{Error, Result};
use crate::messages::{AggregateShare, MaskCommit, MaskMessage, Report, VerifierCommit, VerifierMessage};
use crate::types::BatchResult;

/// Verdict mode: mask commitments, masks, partial commitments, partials, verdicts.
pub fn verdict(aggs: &mut [Aggregator], report: &Report) -> Result<Vec<Verdict>> {
    let mask_commits: Vec<MaskCommit> = aggs.iter_mut().map(|a| a.prepare_init(report)).collect::<Result<_>>()?;
    let masks: Vec<MaskMessage> = aggs
        .iter_mut()
        .map(|a| {
            let o: Vec<MaskCommit> = mask_commits.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
            a.prepare_mask_reveal(&report.report_id, &o)
        })
        .collect::<Result<_>>()?;
    let others = |i: usize| -> Vec<MaskMessage> { masks.iter().filter(|m| m.aggregator != i).cloned().collect() };
    let commits: Vec<VerifierCommit> = aggs.iter_mut().map(|a| { let o = others(a.index()); a.prepare_masks(&report.report_id, &o) }).collect::<Result<_>>()?;
    let verifiers: Vec<VerifierMessage> = aggs
        .iter_mut()
        .map(|a| {
            let o: Vec<VerifierCommit> = commits.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
            a.prepare_reveal(&report.report_id, &o)
        })
        .collect::<Result<_>>()?;
    aggs.iter_mut()
        .map(|a| {
            let o: Vec<VerifierMessage> = verifiers.iter().filter(|v| v.aggregator != a.index()).cloned().collect();
            a.prepare_finish(&report.report_id, &o)
        })
        .collect()
}

/// Silent mode: the verified count round; returns the count every
/// aggregator verified (they must agree).
pub fn count(aggs: &mut [Aggregator]) -> Result<u64> {
    let shares: Vec<_> = aggs.iter_mut().map(|a| a.count_share()).collect::<Result<_>>()?;
    let commits: Vec<_> = aggs.iter_mut().map(|a| a.count_commit(&shares)).collect::<Result<_>>()?;
    let openings: Vec<_> = aggs.iter_mut().map(|a| a.count_open(&commits)).collect::<Result<_>>()?;
    let reveals: Vec<_> = aggs.iter_mut().map(|a| a.count_reveal(&openings)).collect::<Result<_>>()?;
    let counts: Vec<u64> = aggs.iter_mut().map(|a| a.count_finish(&reveals)).collect::<Result<_>>()?;
    if counts.windows(2).any(|w| w[0] != w[1]) {
        return Err(Error::Protocol("aggregators verified different counts".into()));
    }
    Ok(counts[0])
}

/// The verified release of shares already released to collector `c`.
pub fn finish_release(aggs: &mut [Aggregator], collector: &Collector, c: usize, shares: Vec<AggregateShare>) -> Result<BatchResult> {
    let mut pending = collector.release_challenge(c, shares)?;
    let commits: Vec<_> = aggs.iter_mut().map(|a| a.release_commit(&pending.challenge)).collect::<Result<_>>()?;
    let opening = collector.release_open(&mut pending, commits)?;
    let reveals: Vec<_> = aggs.iter_mut().map(|a| a.release_reveal(&opening)).collect::<Result<_>>()?;
    collector.release_finish(&pending, &reveals)
}

/// Count round (silent mode), shares for collector `c`, verified release.
pub fn release(aggs: &mut [Aggregator], collector: &Collector, c: usize) -> Result<BatchResult> {
    if aggs.first().map(|a| a.is_silent()).unwrap_or(false) {
        count(aggs)?;
    }
    let shares: Vec<AggregateShare> = aggs.iter_mut().map(|a| a.aggregate_share_for(c)).collect::<Result<_>>()?;
    finish_release(aggs, collector, c, shares)
}
