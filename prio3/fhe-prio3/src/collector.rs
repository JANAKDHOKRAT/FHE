//! Collector: fuses the aggregators' partial decryptions of the batch sums
//! and checks the result is consistent with a batch of valid reports. Holds
//! no key material.

use crate::config::{TaskConfig, VerificationMode};
use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::messages::{AggregateShare, PublicMaterial};
use crate::types::{AggregateResult, BatchResult, RegressionResult};
use openfhe_tbgv_rs::{Context, PartialDecryption};

pub struct Collector {
    cfg: TaskConfig,
    ctx: Context,
    layout: Layout,
}

impl Collector {
    pub fn new(cfg: TaskConfig, material: &PublicMaterial) -> Result<Self> {
        cfg.validate()?;
        let ctx = Context::deserialize(&material.context)?;
        let layout = cfg.layout(ctx.row_slots())?;
        Ok(Self { cfg, ctx, layout })
    }

    /// Single-collector tasks: [`Self::unshard_for`] with collector 0.
    pub fn unshard(&self, shares: &[AggregateShare]) -> Result<BatchResult> {
        if !self.cfg.collectors.is_empty() {
            return Err(Error::Protocol("task has release policies: use unshard_for(collector)".into()));
        }
        self.unshard_for(0, shares)
    }

    /// Opens sealed shares with this collector's key and unshards them.
    pub fn unshard_sealed(&self, collector: usize, key: &crate::seal::CollectorSealKey, sealed: &[crate::seal::SealedShare]) -> Result<BatchResult> {
        let expected = self.cfg.collectors.get(collector).map(|p| p.seal_key).ok_or_else(|| Error::Config(format!("no collector {collector} in the task")))?;
        if key.public_key() != expected {
            return Err(Error::Config(format!("sealing key is not the one the task declares for collector {collector}")));
        }
        let shares = sealed.iter().map(|s| crate::seal::open(s, key)).collect::<Result<Vec<_>>>()?;
        self.unshard_for(collector, &shares)
    }

    /// Requires one share from every aggregator, all released to
    /// `collector` and agreeing on the batch, and a decrypted aggregate that
    /// passes the type's consistency check over the slots this collector
    /// sees. The result carries the collector's elements; the others are
    /// zero. Second moments, if the policy grants them, cover the
    /// collector's elements only and the regression is fitted on those,
    /// the last of them being the target.
    pub fn unshard_for(&self, collector: usize, shares: &[AggregateShare]) -> Result<BatchResult> {
        let n = self.cfg.num_aggregators;
        let elements = self.cfg.collector_elements(collector)?;
        let chunks = self.cfg.collector_chunks(&self.layout, collector);
        let pairs = self.cfg.collector_moment_pairs(collector)?;
        if shares.len() != n {
            return Err(Error::Protocol(format!("expected {n} aggregate shares, got {}", shares.len())));
        }
        let mut seen = vec![false; n];
        for s in shares {
            if s.task_id != self.cfg.task_id {
                return Err(Error::Protocol("aggregate share for a different task".into()));
            }
            if s.collector != collector as u32 {
                return Err(Error::Protocol(format!("aggregate share released to collector {}, not {collector}", s.collector)));
            }
            if s.aggregator >= n || std::mem::replace(&mut seen[s.aggregator], true) {
                return Err(Error::Protocol("duplicate or out-of-range aggregator in shares".into()));
            }
            if s.batch_digest != shares[0].batch_digest || s.report_count != shares[0].report_count {
                return Err(Error::Protocol("aggregators disagree on the batch".into()));
            }
            if s.partials.len() != chunks.len() {
                return Err(Error::Protocol("wrong number of chunk partials for this collector".into()));
            }
            if s.moment_partials.len() != pairs.len() {
                return Err(Error::Protocol("wrong number of moment partials for this collector".into()));
            }
        }
        let count = shares[0].report_count;
        let valid = match self.cfg.mode {
            VerificationMode::Verdict => count,
            VerificationMode::Silent => {
                let partials: Vec<PartialDecryption> = shares
                    .iter()
                    .map(|s| {
                        let b = s.valid_count_partial.as_ref().ok_or_else(|| Error::Protocol("silent mode share lacks the valid-count partial".into()))?;
                        PartialDecryption::deserialize(&self.ctx, b, s.aggregator == 0).map_err(Into::into)
                    })
                    .collect::<Result<_>>()?;
                let refs: Vec<&PartialDecryption> = partials.iter().collect();
                self.ctx.fuse(&refs, 1)?[0]
            }
        };
        if valid > count {
            return Err(Error::Protocol("aggregate inconsistent: valid count exceeds report count".into()));
        }
        if valid < self.cfg.min_batch_size as u64 {
            return Err(Error::Protocol("batch below minimum size".into()));
        }
        let m = self.layout.input_len;
        let mut slot_sums = vec![0u64; m];
        let mut visible = vec![false; m];
        for (pi, &k) in chunks.iter().enumerate() {
            let partials: Vec<PartialDecryption> = shares
                .iter()
                .map(|s| PartialDecryption::deserialize(&self.ctx, &s.partials[pi], s.aggregator == 0))
                .collect::<std::result::Result<_, _>>()?;
            let refs: Vec<&PartialDecryption> = partials.iter().collect();
            let fused = self.ctx.fuse(&refs, self.layout.chunk_span(k))?;
            for (i, g) in self.layout.chunk_range(k).enumerate() {
                slot_sums[g] = fused[self.layout.client_slot(i)];
                visible[g] = true;
            }
        }
        let full = elements.len() == self.cfg.measurement_type.num_elements();
        self.cfg.measurement_type.check_aggregate_consistency_visible(&slot_sums, valid, if full { None } else { Some(&visible) })?;
        let aggregate = self.cfg.measurement_type.decode_aggregate(&slot_sums)?;
        let regression = if pairs.is_empty() {
            None
        } else {
            let map = self.layout.moments.as_ref().ok_or_else(|| Error::Protocol("moments released but not laid out".into()))?;
            let all: Vec<u128> = match &aggregate {
                AggregateResult::SumVec(v) => v.clone(),
                _ => return Err(Error::Protocol("moments require a vector aggregate".into())),
            };
            // values of this collector, in ascending element order
            let values: Vec<usize> = elements.clone();
            let l = values.len();
            let pos = |e: usize| values.iter().position(|&x| x == e).expect("pair within elements");
            let mut second = vec![vec![0u128; l]; l];
            for (idx, &(a, b)) in pairs.iter().enumerate() {
                let partials: Vec<PartialDecryption> = shares
                    .iter()
                    .map(|s| PartialDecryption::deserialize(&self.ctx, &s.moment_partials[idx], s.aggregator == 0).map_err(Into::into))
                    .collect::<Result<_>>()?;
                let refs: Vec<&PartialDecryption> = partials.iter().collect();
                let v = self.ctx.fuse(&refs, 1)?[0] as u128;
                // Each second moment (a, b) is a sum of `valid` products each at
                // most (2^bits_a - 1)(2^bits_b - 1); anything larger means a
                // corrupted contribution.
                let cap = (valid as u128) * ((1u128 << map[a].1) - 1) * ((1u128 << map[b].1) - 1);
                if v > cap {
                    return Err(Error::Protocol(format!("aggregate inconsistent: second moment ({a},{b}) exceeds its bound")));
                }
                second[pos(a)][pos(b)] = v;
                second[pos(b)][pos(a)] = v;
            }
            let first: Vec<u128> = values.iter().map(|&e| all[e]).collect();
            Some(RegressionResult::from_moments(valid, first, second))
        };
        Ok(BatchResult { collector: collector as u32, elements, aggregate, report_count: count, valid_count: valid, regression })
    }
}
