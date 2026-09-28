//! Collector: fuses the aggregators' partial decryptions of the batch sums.
//! Holds no key material.

use crate::config::TaskConfig;
use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::messages::{AggregateShare, PublicMaterial};
use crate::types::AggregateResult;
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

    /// Requires one share from every aggregator, all agreeing on the batch.
    pub fn unshard(&self, shares: &[AggregateShare]) -> Result<(AggregateResult, u64)> {
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
        if count < self.cfg.min_batch_size as u64 {
            return Err(Error::Protocol("batch below minimum size".into()));
        }
        let mut slot_sums = Vec::with_capacity(self.layout.input_len);
        for c in 0..self.layout.num_chunks {
            let partials: Vec<PartialDecryption> = shares
                .iter()
                .map(|s| PartialDecryption::deserialize(&self.ctx, &s.partials[c], s.aggregator == 0))
                .collect::<std::result::Result<_, _>>()?;
            let refs: Vec<&PartialDecryption> = partials.iter().collect();
            let len = self.layout.chunk_len(c);
            let fused = self.ctx.fuse(&refs, len)?;
            slot_sums.extend_from_slice(&fused[..len]);
        }
        Ok((self.cfg.measurement_type.decode_aggregate(&slot_sums)?, count))
    }
}
