//! Client side: encode a measurement and encrypt it under the joint key.

use crate::config::TaskConfig;
use crate::error::Result;
use crate::layout::Layout;
use crate::messages::Report;
use crate::types::Measurement;
use openfhe_tbgv_rs::{Context, PublicKey};

pub struct Client {
    cfg: TaskConfig,
    ctx: Context,
    pk: PublicKey,
    layout: Layout,
}

impl Client {
    /// Needs only the context and the joint public key, not the evaluation keys.
    pub fn new(cfg: TaskConfig, context: &[u8], public_key: &[u8]) -> Result<Self> {
        cfg.validate()?;
        let ctx = Context::deserialize(context)?;
        if ctx.plain_mod() != cfg.plain_mod {
            return Err(crate::Error::Config("context plaintext modulus does not match task".into()));
        }
        let pk = ctx.deserialize_public_key(public_key)?;
        let layout = cfg.layout(ctx.row_slots())?;
        Ok(Self { cfg, ctx, pk, layout })
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Encodes and encrypts `m`. Unlike Prio3 there is one report, not one
    /// share per aggregator: the same bytes go to every aggregator.
    pub fn shard(&self, m: &Measurement) -> Result<Report> {
        let encoded = self.cfg.measurement_type.encode(m)?;
        let mut chunks = Vec::with_capacity(self.layout.num_chunks);
        for c in 0..self.layout.num_chunks {
            let slots = &encoded[self.layout.chunk_range(c)];
            let ct = self.ctx.encrypt(&self.pk, &self.ctx.plaintext(slots)?)?;
            chunks.push(ct.serialize()?);
        }
        let report_id = Report::compute_id(&self.cfg.task_id, &chunks);
        Ok(Report { task_id: self.cfg.task_id, report_id, chunks })
    }

    /// Encrypts arbitrary field elements as a report, bypassing encoding.
    /// This is how a malicious client is modelled in tests; it is not part
    /// of the honest protocol.
    pub fn shard_raw(&self, slots_per_chunk: &[Vec<u64>]) -> Result<Report> {
        let mut chunks = Vec::with_capacity(slots_per_chunk.len());
        for slots in slots_per_chunk {
            let ct = self.ctx.encrypt(&self.pk, &self.ctx.plaintext(slots)?)?;
            chunks.push(ct.serialize()?);
        }
        let report_id = Report::compute_id(&self.cfg.task_id, &chunks);
        Ok(Report { task_id: self.cfg.task_id, report_id, chunks })
    }
}
