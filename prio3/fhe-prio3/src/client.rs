//! Client side: encode a measurement, encrypt it under the joint key, and
//! sign the report when the task requires authentication.

use crate::auth::ClientIdentity;
use crate::config::{AuthPolicy, TaskConfig};
use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::messages::Report;
use crate::types::Measurement;
use openfhe_tbgv_rs::{Context, PublicKey};

pub struct Client {
    cfg: TaskConfig,
    ctx: Context,
    pk: PublicKey,
    layout: Layout,
    identity: Option<ClientIdentity>,
}

impl Client {
    /// Needs only the context and the joint public key, not the evaluation keys.
    pub fn new(cfg: TaskConfig, context: &[u8], public_key: &[u8]) -> Result<Self> {
        cfg.validate()?;
        let ctx = Context::deserialize(context)?;
        if ctx.plain_mod() != cfg.plain_mod {
            return Err(Error::Config("context plaintext modulus does not match task".into()));
        }
        let pk = ctx.deserialize_public_key(public_key)?;
        let layout = cfg.layout(ctx.row_slots())?;
        Ok(Self { cfg, ctx, pk, layout, identity: None })
    }

    /// Attaches the signing identity used when the task requires authentication.
    pub fn with_identity(mut self, identity: ClientIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    fn finish(&self, chunks: Vec<Vec<u8>>) -> Result<Report> {
        let report_id = Report::compute_id(&self.cfg.task_id, &chunks);
        let auth = match (&self.cfg.auth, &self.identity) {
            (AuthPolicy::Open, _) => None,
            (AuthPolicy::Required { .. }, Some(id)) => Some(id.sign(&self.cfg.task_id, &report_id)),
            (AuthPolicy::Required { .. }, None) => return Err(Error::Config("task requires authentication but the client has no identity".into())),
        };
        Ok(Report { task_id: self.cfg.task_id, report_id, chunks, auth })
    }

    /// Encodes and encrypts `m`. Unlike Prio3 there is one report, not one
    /// share per aggregator: the same bytes go to every aggregator.
    pub fn shard(&self, m: &Measurement) -> Result<Report> {
        let encoded = self.cfg.measurement_type.encode(m)?;
        let mut chunks = Vec::with_capacity(self.layout.num_chunks);
        for c in 0..self.layout.num_chunks {
            let elems = &encoded[self.layout.chunk_range(c)];
            let mut slots = vec![0u64; self.layout.chunk_span(c)];
            for (i, &v) in elems.iter().enumerate() {
                slots[self.layout.client_slot(i)] = v;
            }
            let ct = self.ctx.encrypt(&self.pk, &self.ctx.plaintext(&slots)?)?;
            chunks.push(ct.serialize()?);
        }
        self.finish(chunks)
    }

    /// Encrypts arbitrary slot vectors as a report, bypassing encoding. This
    /// is how a malicious client is modelled in tests; it is not part of the
    /// honest protocol. Slot `i` of `slots` goes to physical slot `i`.
    pub fn shard_raw(&self, slots_per_chunk: &[Vec<u64>]) -> Result<Report> {
        let mut chunks = Vec::with_capacity(slots_per_chunk.len());
        for slots in slots_per_chunk {
            let ct = self.ctx.encrypt(&self.pk, &self.ctx.plaintext(slots)?)?;
            chunks.push(ct.serialize()?);
        }
        self.finish(chunks)
    }

    /// Like `shard_raw` but places element `i` at `client_slot(i)`, i.e. the
    /// layout-correct position, so tests can craft invalid *encodings*.
    pub fn shard_raw_elements(&self, elements_per_chunk: &[Vec<u64>]) -> Result<Report> {
        let mut chunks = Vec::with_capacity(elements_per_chunk.len());
        for elems in elements_per_chunk {
            let mut slots = vec![0u64; self.layout.client_slot(elems.len().max(1) - 1) + 1];
            for (i, &v) in elems.iter().enumerate() {
                slots[self.layout.client_slot(i)] = v;
            }
            let ct = self.ctx.encrypt(&self.pk, &self.ctx.plaintext(&slots)?)?;
            chunks.push(ct.serialize()?);
        }
        self.finish(chunks)
    }

    /// TEST HOOK: a report whose ciphertexts carry extra noise of the given
    /// magnitude (see `Context::add_noise_for_tests`).
    pub fn shard_noisy_for_tests(&self, m: &Measurement, log2_magnitude: u32, seed: u64) -> Result<Report> {
        let clean = self.shard(m)?;
        let mut chunks = Vec::with_capacity(clean.chunks.len());
        for (i, bytes) in clean.chunks.iter().enumerate() {
            let ct = self.ctx.deserialize_ciphertext(bytes)?;
            chunks.push(self.ctx.add_noise_for_tests(&ct, log2_magnitude, seed + i as u64)?.serialize()?);
        }
        self.finish(chunks)
    }
}
