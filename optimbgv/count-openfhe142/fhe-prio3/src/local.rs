//! Every party of a round in one process, for tests and simulations: the
//! same steps a deployment runs over the network (`fhe-prio3-node`), with
//! each message passed by value.

use crate::aggregator::{Aggregator, Verdict};
use crate::collector::Collector;
use crate::error::{Error, Result};
use crate::messages::{
    AggregateShare, GateCheckCommit, GateCommit, GateContribution, GateOpening, GateReveal, GateShare, MaskCommit, MaskMessage, ProvenReport, Report,
    VerifierCommit, VerifierMessage,
};
use crate::types::BatchResult;

/// Verdict mode: mask commitments, masks, partial commitments, partials, verdicts.
pub fn verdict(aggs: &mut [Aggregator], report: &Report) -> Result<Vec<Verdict>> {
    let mask_commits: Vec<MaskCommit> = aggs.iter_mut().map(|a| a.prepare_init(report)).collect::<Result<_>>()?;
    verdict_after_init(aggs, report, mask_commits)
}

/// [`verdict`] for a task with client proofs: every aggregator verifies the
/// proofs itself in [`Aggregator::prepare_init_proven`].
pub fn verdict_proven(aggs: &mut [Aggregator], report: &ProvenReport) -> Result<Vec<Verdict>> {
    let mask_commits: Vec<MaskCommit> = aggs.iter_mut().map(|a| a.prepare_init_proven(report)).collect::<Result<_>>()?;
    verdict_after_init(aggs, &report.report, mask_commits)
}

fn verdict_after_init(aggs: &mut [Aggregator], report: &Report, mask_commits: Vec<MaskCommit>) -> Result<Vec<Verdict>> {
    let masks: Vec<MaskMessage> = aggs
        .iter_mut()
        .map(|a| {
            let o: Vec<MaskCommit> = mask_commits.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
            a.prepare_mask_reveal(&report.report_id, &o)
        })
        .collect::<Result<_>>()?;
    let others = |i: usize| -> Vec<MaskMessage> { masks.iter().filter(|m| m.aggregator != i).cloned().collect() };
    let commits: Vec<VerifierCommit> = aggs
        .iter_mut()
        .map(|a| {
            let o = others(a.index());
            a.prepare_masks(&report.report_id, &o)
        })
        .collect::<Result<_>>()?;
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
/// Gated tasks use [`gated_release`].
pub fn release(aggs: &mut [Aggregator], collector: &Collector, c: usize) -> Result<BatchResult> {
    if aggs.first().is_some_and(|a| a.config().gated()) {
        return Err(Error::Protocol("gated task: use local::gated_release".into()));
    }
    if aggs.first().map(|a| a.is_silent()).unwrap_or(false) {
        count(aggs)?;
    }
    let shares: Vec<AggregateShare> = aggs.iter_mut().map(|a| a.aggregate_share_for(c)).collect::<Result<_>>()?;
    finish_release(aggs, collector, c, shares)
}

/// Gated release (`gate.rs`): the count round first when the aggregators
/// hold every key share (suppression), then rounds 0 to 6 among the key
/// parties (the aggregators, and the collector of a split-key task), then
/// the verified release to the collector.
pub fn gated_release(aggs: &mut [Aggregator], collector: &mut Collector) -> Result<BatchResult> {
    let split = collector_holds_key(aggs);
    if !split {
        count(aggs)?;
    }
    let mut commits: Vec<GateCommit> = aggs.iter_mut().map(|a| a.gate_commit()).collect::<Result<_>>()?;
    if split {
        let c = collector.gate_commit(&commits[0])?;
        commits.push(c);
    }
    let mut contributions: Vec<GateContribution> = aggs.iter_mut().map(|a| a.gate_contribute(&commits)).collect::<Result<_>>()?;
    if split {
        contributions.push(collector.gate_contribute(&commits)?);
    }
    let mut shares: Vec<GateShare> = aggs.iter_mut().map(|a| a.gate_share(&contributions)).collect::<Result<_>>()?;
    if split {
        shares.push(collector.gate_share(&contributions)?);
    }
    let mut check_commits: Vec<GateCheckCommit> = aggs.iter_mut().map(|a| a.gate_check_commit(&shares)).collect::<Result<_>>()?;
    if split {
        check_commits.push(collector.gate_check_commit(&shares)?);
    }
    let mut openings: Vec<GateOpening> = aggs.iter_mut().map(|a| a.gate_open(&check_commits)).collect::<Result<_>>()?;
    if split {
        openings.push(collector.gate_open(&check_commits)?);
    }
    let mut reveals: Vec<GateReveal> = aggs.iter_mut().map(|a| a.gate_reveal(&openings)).collect::<Result<_>>()?;
    if split {
        reveals.push(collector.gate_reveal(&openings)?);
    }
    for a in aggs.iter_mut() {
        a.gate_finish(&reveals)?;
    }
    if split {
        collector.gate_finish(&reveals)?;
    }
    let released: Vec<AggregateShare> = aggs.iter_mut().map(|a| a.aggregate_share_for(0)).collect::<Result<_>>()?;
    finish_release(aggs, collector, 0, released)
}

fn collector_holds_key(aggs: &[Aggregator]) -> bool {
    aggs.first().is_some_and(|a| a.config().collector_holds_key())
}
