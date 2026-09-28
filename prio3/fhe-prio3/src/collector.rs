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

    /// Requires one share from every aggregator, all agreeing on the batch,
    /// and a decrypted aggregate that passes the type's consistency check.
    pub fn unshard(&self, shares: &[AggregateShare]) -> Result<BatchResult> {
        let n = self.cfg.num_aggregators;
        if shares.len() != n {
            return Err(Error::Protocol(format!("expected {n} aggregate shares, got {}", shares.len())));
        }
        let mut seen = vec![false; n];
        for s in shares {
            if s.task_id != self.cfg.task_id {
                return Err(Error::Protocol("aggregate share for a different task".into()));
            }
            if s.aggregator >= n || std::mem::replace(&mut seen[s.aggregator], true) {
                return Err(Error::Protocol("duplicate or out-of-range aggregator in shares".into()));
            }
            if s.batch_digest != shares[0].batch_digest || s.report_count != shares[0].report_count {
                return Err(Error::Protocol("aggregators disagree on the batch".into()));
            }
            if s.partials.len() != self.layout.num_chunks {
                return Err(Error::Protocol("wrong number of chunk partials".into()));
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
        let mut slot_sums = Vec::with_capacity(self.layout.input_len);
        for c in 0..self.layout.num_chunks {
            let partials: Vec<PartialDecryption> = shares
                .iter()
                .map(|s| PartialDecryption::deserialize(&self.ctx, &s.partials[c], s.aggregator == 0))
                .collect::<std::result::Result<_, _>>()?;
            let refs: Vec<&PartialDecryption> = partials.iter().collect();
            let fused = self.ctx.fuse(&refs, self.layout.chunk_span(c))?;
            for i in 0..self.layout.chunk_len(c) {
                slot_sums.push(fused[self.layout.client_slot(i)]);
            }
        }
        self.cfg.measurement_type.check_aggregate_consistency(&slot_sums, valid)?;
        let aggregate = self.cfg.measurement_type.decode_aggregate(&slot_sums)?;
        let regression = match &self.layout.moments {
            None => None,
            Some(map) => {
                let length = map.len();
                let pairs = self.layout.moment_pairs();
                let mut second = vec![vec![0u128; length]; length];
                let mut idx = 0;
                for a in 0..length {
                    for b in a..length {
                        let partials: Vec<PartialDecryption> = shares
                            .iter()
                            .map(|s| {
                                let bytes = s.moment_partials.get(idx).ok_or_else(|| Error::Protocol("missing moment partial".into()))?;
                                PartialDecryption::deserialize(&self.ctx, bytes, s.aggregator == 0).map_err(Into::into)
                            })
                            .collect::<Result<_>>()?;
                        let refs: Vec<&PartialDecryption> = partials.iter().collect();
                        let v = self.ctx.fuse(&refs, 1)?[0] as u128;
                        second[a][b] = v;
                        second[b][a] = v;
                        idx += 1;
                    }
                }
                debug_assert_eq!(idx, pairs);
                let first: Vec<u128> = match &aggregate {
                    AggregateResult::SumVec(v) => v.clone(),
                    _ => return Err(Error::Protocol("moments require a SumVec aggregate".into())),
                };
                // Each second moment (a, b) is a sum of `valid` products each at
                // most (2^bits_a - 1)(2^bits_b - 1); anything larger means a
                // corrupted contribution.
                for a in 0..length {
                    for b in 0..length {
                        let cap = (valid as u128) * ((1u128 << map[a].1) - 1) * ((1u128 << map[b].1) - 1);
                        if second[a][b] > cap {
                            return Err(Error::Protocol(format!("aggregate inconsistent: second moment ({a},{b}) exceeds its bound")));
                        }
                    }
                }
                Some(RegressionResult::from_moments(valid, first, second))
            }
        };
        Ok(BatchResult { aggregate, report_count: count, valid_count: valid, regression })
    }
}
