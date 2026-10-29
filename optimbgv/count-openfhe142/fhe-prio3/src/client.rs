//! Client side: encode a measurement, encrypt it under the joint key, and
//! sign the report when the task requires authentication.

use crate::auth::ClientIdentity;
use crate::config::{AuthPolicy, TaskConfig};
use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::messages::{ProvenReport, Report};
use crate::packed::{Codec, Expect};
use crate::types::Measurement;
use crate::wfe::{self, SlotCodec};
use openfhe_tbgv_rs::{Context, PublicKey};
use rand::rngs::OsRng;

pub struct Client {
    cfg: TaskConfig,
    ctx: Context,
    pk: PublicKey,
    layout: Layout,
    identity: Option<ClientIdentity>,
    codec: Codec,
    /// [`TaskConfig::client_proofs`]: slot vectors to raw plaintext
    /// polynomials, for the proven encryptions.
    slot_codec: Option<SlotCodec>,
}

impl Client {
    /// Needs only the context and the joint public key, not the evaluation keys.
    pub fn new(cfg: TaskConfig, context: &[u8], public_key: &[u8]) -> Result<Self> {
        cfg.validate()?;
        Self::construct(cfg, context, public_key, false)
    }
    /// Explicit native single-key profile; threshold constructor stays strict.
    pub fn new_native(cfg: TaskConfig, context: &[u8], public_key: &[u8]) -> Result<Self> {
        Self::construct(cfg, context, public_key, true)
    }
    fn construct(cfg: TaskConfig, context: &[u8], public_key: &[u8], native: bool) -> Result<Self> {
        let ctx = Context::deserialize(context)?;
        if native {
            if !ctx.is_single_mode()? {
                return Err(Error::Config("native client requires native context".into()));
            }
            cfg.validate_native(ctx.row_slots())?;
        }
        if ctx.plain_mod() != cfg.plain_mod {
            return Err(Error::Config("context plaintext modulus does not match task".into()));
        }
        let pk = ctx.deserialize_public_key(public_key)?;
        let layout = if native {
            cfg.layout_native(ctx.row_slots())?
        } else {
            cfg.layout(ctx.row_slots())?
        };
        let codec = Codec::new(&ctx, &pk, public_key)?;
        let slot_codec = if cfg.client_proofs { Some(SlotCodec::new(&ctx)?) } else { None };
        Ok(Self {
            cfg,
            ctx,
            pk,
            layout,
            identity: None,
            codec,
            slot_codec,
        })
    }

    /// One chunk's slots encrypted the plain way (no proof). Refused for a
    /// task that requires proofs: its aggregators reject such reports.
    fn encrypt_unproven(&self, slots: &[u64]) -> Result<Vec<u8>> {
        if self.cfg.client_proofs {
            return Err(Error::Config(
                "this task requires client proofs (TaskConfig::client_proofs): use shard_proven".into(),
            ));
        }
        let ct = self.ctx.encrypt(&self.pk, &self.ctx.plaintext(slots)?)?;
        self.codec.encode(&ct)
    }

    /// The slot vector of one chunk of `group`: element `i` at its layout
    /// position.
    fn chunk_slots(&self, elems: &[u64], group: u32) -> Vec<u64> {
        let mut slots = vec![0u64; self.layout.group_slot(group as usize, elems.len().max(1) - 1) + 1];
        for (i, &v) in elems.iter().enumerate() {
            slots[self.layout.group_slot(group as usize, i)] = v;
        }
        slots
    }

    /// Encrypts each chunk's slots so that its effective ciphertext `2C`
    /// decodes to them, computes the report id over the chunks, then proves
    /// every chunk well formed under a context bound to the task, the
    /// report id and the chunk's position ([`ProvenReport::proof_context`]).
    fn prove_chunks(&self, slots_per_chunk: &[Vec<u64>], group: u32) -> Result<ProvenReport> {
        let sc = self
            .slot_codec
            .as_ref()
            .ok_or_else(|| Error::Config("this task does not use client proofs (TaskConfig::client_proofs)".into()))?;
        let n = self.ctx.ring_dim() as usize;
        let reference = self.codec.reference();
        let sf = reference.meta()?.scaling_factor_int;
        let mut encrypted = Vec::with_capacity(slots_per_chunk.len());
        let mut chunks = Vec::with_capacity(slots_per_chunk.len());
        for slots in slots_per_chunk {
            if slots.len() > n {
                return Err(Error::Config(format!("{} slots for a ring of dimension {n}", slots.len())));
            }
            let mut full = vec![0u64; n];
            full[..slots.len()].copy_from_slice(slots);
            let coeffs = sc.contribution_plaintext(&full, sf);
            let (ct, witness) = wfe::encrypt_with_witness(&self.ctx, &self.pk, reference, &coeffs, &mut OsRng)?;
            chunks.push(self.codec.encode(&ct)?);
            encrypted.push((ct, witness));
        }
        let report = self.finish(chunks, group)?;
        let digest = self.cfg.digest();
        let num_chunks = encrypted.len();
        let mut proofs = Vec::with_capacity(num_chunks);
        for (i, (ct, witness)) in encrypted.iter().enumerate() {
            let context = ProvenReport::proof_context(&digest, &report.report_id, i, num_chunks);
            proofs.push(wfe::prove(&self.ctx, &self.pk, reference, ct, witness, &context, &mut OsRng)?);
        }
        Ok(ProvenReport { report, proofs })
    }

    /// [`TaskConfig::client_proofs`]: encodes `m` and encrypts each chunk
    /// with a proof of well-formed encryption.
    pub fn shard_proven(&self, m: &Measurement) -> Result<ProvenReport> {
        let encoded = self.cfg.measurement_type.encode(m)?;
        let slots: Vec<Vec<u64>> = (0..self.layout.num_chunks)
            .map(|c| self.chunk_slots(&encoded[self.layout.chunk_range(c)], 0))
            .collect();
        self.prove_chunks(&slots, 0)
    }

    /// Like [`Self::shard_raw_elements`], with proofs: a client that
    /// proves its encryptions but encodes an invalid measurement (tests).
    pub fn shard_raw_elements_proven(&self, elements_per_chunk: &[Vec<u64>]) -> Result<ProvenReport> {
        let slots: Vec<Vec<u64>> = elements_per_chunk.iter().map(|e| self.chunk_slots(e, 0)).collect();
        self.prove_chunks(&slots, 0)
    }

    /// Like [`Self::shard_raw`], with proofs (arbitrary slot vectors).
    pub fn shard_raw_proven(&self, slots_per_chunk: &[Vec<u64>]) -> Result<ProvenReport> {
        self.prove_chunks(slots_per_chunk, 0)
    }

    /// Attaches the signing identity used when the task requires authentication.
    pub fn with_identity(mut self, identity: ClientIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Replaces the signing identity: one client submitting on behalf of
    /// several enrolled senders signs each report as its sender.
    pub fn set_identity(&mut self, identity: ClientIdentity) {
        self.identity = Some(identity);
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The packed-ciphertext codec for this task's parameters and joint key.
    pub fn codec(&self) -> &Codec {
        &self.codec
    }

    fn finish(&self, chunks: Vec<Vec<u8>>, group: u32) -> Result<Report> {
        if group as usize >= self.layout.groups {
            return Err(Error::Config(format!("group {group} out of range (layout has {} groups)", self.layout.groups)));
        }
        let report_id = Report::compute_id(&self.cfg.task_id, group, &chunks);
        let auth = match (&self.cfg.auth, &self.identity) {
            (AuthPolicy::Open, _) => None,
            (AuthPolicy::Required { .. }, Some(id)) => Some(id.sign(&self.cfg.task_id, &report_id)),
            (AuthPolicy::Required { .. }, None) => return Err(Error::Config("task requires authentication but the client has no identity".into())),
        };
        Ok(Report {
            task_id: self.cfg.task_id,
            report_id,
            group,
            chunks,
            auth,
        })
    }

    /// Encodes and encrypts `m` in group 0. Unlike Prio3 there is one
    /// report, not one share per aggregator: the same bytes go to every
    /// aggregator.
    pub fn shard(&self, m: &Measurement) -> Result<Report> {
        self.shard_in_group(m, 0)
    }

    /// Batched silent mode: encodes and encrypts `m` at the slots of the
    /// group the aggregators assigned to this report.
    pub fn shard_in_group(&self, m: &Measurement, group: u32) -> Result<Report> {
        if group as usize >= self.layout.groups {
            return Err(Error::Protocol("report group outside layout".into()));
        }
        let encoded = self.cfg.measurement_type.encode(m)?;
        let mut chunks = Vec::with_capacity(self.layout.num_chunks);
        for c in 0..self.layout.num_chunks {
            let elems = &encoded[self.layout.chunk_range(c)];
            let last = self.layout.group_slot(group as usize, elems.len() - 1);
            let mut slots = vec![0u64; last + 1];
            for (i, &v) in elems.iter().enumerate() {
                slots[self.layout.group_slot(group as usize, i)] = v;
            }
            chunks.push(self.encrypt_unproven(&slots)?);
        }
        self.finish(chunks, group)
    }

    /// Encrypts arbitrary slot vectors as a report, bypassing encoding. This
    /// is how a malicious client is modelled in tests; it is not part of the
    /// honest protocol. Slot `i` of `slots` goes to physical slot `i`.
    pub fn shard_raw(&self, slots_per_chunk: &[Vec<u64>]) -> Result<Report> {
        let mut chunks = Vec::with_capacity(slots_per_chunk.len());
        for slots in slots_per_chunk {
            chunks.push(self.encrypt_unproven(slots)?);
        }
        self.finish(chunks, 0)
    }

    /// Raw slots claimed for `group` (tests of cross-group injection).
    pub fn shard_raw_in_group(&self, slots_per_chunk: &[Vec<u64>], group: u32) -> Result<Report> {
        let mut chunks = Vec::with_capacity(slots_per_chunk.len());
        for slots in slots_per_chunk {
            chunks.push(self.encrypt_unproven(slots)?);
        }
        self.finish(chunks, group)
    }

    /// Like `shard_raw` but places element `i` at the layout-correct position
    /// of `group`, so tests can craft invalid *encodings*.
    pub fn shard_raw_elements(&self, elements_per_chunk: &[Vec<u64>]) -> Result<Report> {
        self.shard_raw_elements_in_group(elements_per_chunk, 0)
    }

    pub fn shard_raw_elements_in_group(&self, elements_per_chunk: &[Vec<u64>], group: u32) -> Result<Report> {
        if group as usize >= self.layout.groups {
            return Err(Error::Protocol("report group outside layout".into()));
        }
        let mut chunks = Vec::with_capacity(elements_per_chunk.len());
        for elems in elements_per_chunk {
            chunks.push(self.encrypt_unproven(&self.chunk_slots(elems, group))?);
        }
        self.finish(chunks, group)
    }

    /// TEST HOOK: a report whose ciphertexts carry extra noise of the given
    /// magnitude (see `Context::add_noise_for_tests`).
    pub fn shard_noisy_for_tests(&self, m: &Measurement, log2_magnitude: u32, seed: u64) -> Result<Report> {
        self.shard_noisy_in_group_for_tests(m, 0, log2_magnitude, seed)
    }

    pub fn shard_noisy_in_group_for_tests(&self, m: &Measurement, group: u32, log2_magnitude: u32, seed: u64) -> Result<Report> {
        let clean = self.shard_in_group(m, group)?;
        let mut chunks = Vec::with_capacity(clean.chunks.len());
        for (i, bytes) in clean.chunks.iter().enumerate() {
            let ct = self.codec.decode(bytes, Expect::Exactly(self.codec.fresh_meta()))?;
            let noisy = self.ctx.add_noise_for_tests(&ct, log2_magnitude, seed + i as u64)?;
            chunks.push(self.codec.encode(&noisy)?);
        }
        self.finish(chunks, group)
    }
}
