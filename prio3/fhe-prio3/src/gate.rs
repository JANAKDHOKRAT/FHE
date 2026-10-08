//! Gated release: the release decisions are taken under encryption, so no
//! party has to decrypt anything to take them.
//!
//! Two decisions use it:
//! * **Batch-size gate** (tasks where the collector holds a key share,
//!   [`KeyTopology::AggregatorAndCollector`]): with one aggregator there is
//!   no second aggregator to run the count round with, and a count round
//!   with the collector would be a decryption oracle for the aggregator.
//!   Instead the release is multiplied by
//!   `Z_v = Π_{j < min_batch_size} (count - j) · Π r_a`, zero exactly when
//!   fewer than `min_batch_size` reports were valid and a uniform nonzero
//!   value otherwise (`r_a` are the aggregators' secret random factors).
//! * **Cell gate** (small-cell suppression, `min_cell_count = k`): each
//!   released cell is multiplied by `Z_c = Π_{j < k} (cell - j) · Π r_a`,
//!   zero exactly when the cell is below `k`.
//!
//! The collector decrypts `R = X · Z_v · Z_c`, `Z_v` and `Z_c` and divides:
//! it learns a released value only where every gate is nonzero, and of a
//! suppressed cell only that it was suppressed. The aggregators never fuse
//! a decryption of `R` or `Z`.
//!
//! Refresh. The validity circuit uses the whole chain, so the gates cannot
//! run on the accumulators directly (depth 32 does not fit in 15 GiB at
//! ring dimension 65536; measured). Every key party `p` publishes a mask
//! `M_p` per accumulator (round 0 commits, round 1 reveals); everyone forms
//! `Y = X + Σ_p M_p` and decrypts it jointly, verifiably (`vdec`, as the
//! count round: rounds 2 to 5), so everyone learns `y = x + Σ_p m_p`, which
//! is uniform to anyone missing one party's mask. Then
//! `X' = y - Σ_p M_p`, an encryption of `x` at the top of the chain, and
//! the gates run on `X'`.
//!
//! Why the masks and factors must be proven well formed (`wfe.rs`): their
//! noise enters `X'` and every gate. A party that inflates it can make the
//! noise of `R` depend on the plaintexts it multiplies, which the fuser
//! reads at full precision. Every contribution is therefore a fresh
//! encryption with a proof of short randomness, bound to its party, batch
//! and position, and the protocol uses its effective form `2C`.
//!
//! Who may decrypt what. A key party partially decrypts, for the others,
//! only `Y`, which it computed itself from accumulators fixed before its
//! own mask was revealed (the commitments of round 0) plus its own uniform
//! mask, and the others' checks of `Y` rebuilt from its own `Y`. In a
//! split-key task the collector partially decrypts nothing else for the
//! aggregator, so a ciphertext the aggregator chooses (say, a raw report)
//! comes back to it masked by the collector's uniform mask. The collector
//! fuses `R` and `Z` alone, with its own partials, after verifying the
//! aggregator's partials with the release checks (`Collector::release_*`).

use crate::config::{KeyTopology, TaskConfig};
use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::messages::{GateCheckCommit, GateCommit, GateContribution, GateOpening, GateReveal, GateShare};
use crate::packed::{Codec, Expect};
use crate::vdec;
use crate::wfe;
use openfhe_tbgv_rs::{Ciphertext, CiphertextMeta, Context, PartialDecryption, PublicKey, SecretShare};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// A value the gated release refreshes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refreshed {
    /// The chunk accumulator `c`.
    Chunk(usize),
    /// The valid count at every element slot of group 0 (batch-size gate input).
    SpreadCount,
    /// Second-moment accumulator `i` (`Layout::moment_terms` order).
    Moment(usize),
}

/// A released ciphertext of the gated release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    /// `X'_i · Z_v · Z_c` of refreshed value `i`.
    Gated(usize),
    /// The batch-size gate.
    CountGate,
    /// The cell gate of chunk `c`.
    CellGate(usize),
}

/// What a task's gated release refreshes, gates and releases. Every party
/// derives it from the task alone.
#[derive(Debug, Clone)]
pub struct GatePlan {
    pub refreshed: Vec<Refreshed>,
    pub count_gate: bool,
    pub cell_gate: bool,
    pub outputs: Vec<Output>,
    /// Slots where the batch-size gate's factor is nonzero: every element
    /// slot of group 0 (where every released value lives).
    pub spread_slots: Vec<usize>,
    /// Per chunk: the slots of its cells (cell gate factors are nonzero
    /// there only, so constraint slots are never released).
    pub cell_slots: Vec<Vec<usize>>,
}

impl GatePlan {
    pub fn new(cfg: &TaskConfig, layout: &Layout) -> Result<Self> {
        if !cfg.gated() {
            return Err(Error::Config("task does not use the gated release".into()));
        }
        let count_gate = cfg.collector_holds_key();
        let cell_gate = cfg.min_cell_count > 0;
        let mut refreshed: Vec<Refreshed> = (0..layout.num_chunks).map(Refreshed::Chunk).collect();
        if count_gate {
            refreshed.push(Refreshed::SpreadCount);
            if layout.moments.is_some() {
                refreshed.extend((0..layout.moment_terms().len()).map(Refreshed::Moment));
            }
        }
        let mut outputs = Vec::new();
        for (i, r) in refreshed.iter().enumerate() {
            // the count is withheld when cells are suppressed (with it, the
            // collector would recover the suppressed total)
            if !(cell_gate && *r == Refreshed::SpreadCount) {
                outputs.push(Output::Gated(i));
            }
        }
        if count_gate {
            outputs.push(Output::CountGate);
        }
        if cell_gate {
            outputs.extend((0..layout.num_chunks).map(Output::CellGate));
        }
        let spread_slots = (0..layout.block).map(|i| layout.group_slot(0, i)).collect();
        let cells = cfg.measurement_type.cell_slots();
        let cell_slots = (0..layout.num_chunks)
            .map(|c| match &cells {
                Some(cells) => layout
                    .chunk_range(c)
                    .enumerate()
                    .filter(|(_, g)| cells.contains(g))
                    .map(|(i, _)| layout.client_slot(i))
                    .collect(),
                None => Vec::new(),
            })
            .collect();
        Ok(Self {
            refreshed,
            count_gate,
            cell_gate,
            outputs,
            spread_slots,
            cell_slots,
        })
    }

    pub fn num_masks(&self) -> usize {
        self.refreshed.len()
    }

    /// Random factors an aggregator contributes: one for the batch-size
    /// gate, one per chunk for the cell gate. The collector contributes none
    /// (the factors hide the gates' values from it).
    pub fn num_factors(&self) -> usize {
        self.count_gate as usize + if self.cell_gate { self.cell_slots.len() } else { 0 }
    }

    /// Slots where factor `f` is nonzero.
    pub fn factor_slots(&self, f: usize) -> &[usize] {
        if self.count_gate && f == 0 {
            &self.spread_slots
        } else {
            &self.cell_slots[f - self.count_gate as usize]
        }
    }

    fn spread_index(&self) -> Option<usize> {
        self.refreshed.iter().position(|r| *r == Refreshed::SpreadCount)
    }
}

/// What a party computing or checking the gated release needs.
pub struct GateEnv<'a> {
    pub cfg: &'a TaskConfig,
    pub layout: &'a Layout,
    pub ctx: &'a Context,
    pub pk: &'a PublicKey,
    pub codec: &'a Codec,
    pub share: &'a SecretShare,
    /// Key-party index: aggregators `0..num_aggregators`, then the collector.
    pub party: usize,
}

/// Everything a key party keeps between the rounds of the gated release,
/// persisted so that a restarted party answers a repeated round with the
/// same bytes and never decrypts a second set of `Y` or checks.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct GateState {
    pub batch_digest: Option<[u8; 32]>,
    pub own_contribution: Option<GateContribution>,
    /// Every party's commitment (round 0), in party order.
    pub commits: Vec<GateCommit>,
    /// Every party's contribution (round 1), checked, in party order.
    pub contributions: Vec<GateContribution>,
    /// This party's checks of `Y`, secret until round 3.
    pub opening: Option<vdec::Opening>,
    pub own_share: Option<GateShare>,
    /// Every party's share (round 2), in party order.
    pub shares: Vec<GateShare>,
    /// This party's partials of the others' checks, by verifier.
    pub check_partials: Vec<(usize, Vec<Vec<u8>>)>,
    /// The others' commitments to their partials of this party's checks.
    pub check_commits: Vec<GateCheckCommit>,
    /// The verified decryption of `Y`, all slots, per refreshed value.
    pub y: Option<Vec<Vec<u64>>>,
    /// Aggregators: the released ciphertexts, packed, in [`GatePlan::outputs`] order.
    pub outputs: Option<Vec<Vec<u8>>>,
}

fn proof_context(cfg: &TaskConfig, batch: &[u8; 32], party: usize, kind: &[u8], index: usize) -> Vec<u8> {
    let mut c = b"gate".to_vec();
    c.extend_from_slice(&cfg.digest());
    c.extend_from_slice(batch);
    c.extend_from_slice(&(party as u64).to_le_bytes());
    c.extend_from_slice(kind);
    c.extend_from_slice(&(index as u64).to_le_bytes());
    c
}

fn check_context(cfg: &TaskConfig, batch: &[u8; 32], verifier: usize, check: usize, committer: usize) -> Vec<u8> {
    let mut c = b"gate check".to_vec();
    c.extend_from_slice(&cfg.task_id);
    c.extend_from_slice(batch);
    for x in [verifier, check, committer] {
        c.extend_from_slice(&(x as u64).to_le_bytes());
    }
    c
}

/// A fresh encryption of zero: the shape every contribution must have.
fn reference(env: &GateEnv) -> Result<Ciphertext> {
    Ok(env.ctx.encrypt(env.pk, &env.ctx.plaintext(&[0])?)?)
}

fn partial_meta(ct: &Ciphertext) -> Result<CiphertextMeta> {
    Ok(CiphertextMeta { num_elements: 1, ..ct.meta()? })
}

fn is_aggregator(cfg: &TaskConfig, party: usize) -> bool {
    party < cfg.num_aggregators
}

/// Whether `party` sends the accumulators with its contribution: the
/// aggregator of a split-key task (the collector does not compute them).
fn sends_accumulators(cfg: &TaskConfig, party: usize) -> bool {
    cfg.key_topology == KeyTopology::AggregatorAndCollector && party == 0
}

/// Round 0: draws this party's contribution (masks, and factors for an
/// aggregator, each proven well formed) and returns the commitment to it.
/// `accumulators` are the values to refresh, sent along by the aggregator
/// of a split-key task (empty otherwise). Repeated calls return the same
/// commitment.
pub fn commit(env: &GateEnv, st: &mut GateState, batch: [u8; 32], accumulators: &[Ciphertext], rng: &mut impl Rng) -> Result<GateCommit> {
    let plan = GatePlan::new(env.cfg, env.layout)?;
    if let Some(c) = &st.own_contribution {
        if st.batch_digest != Some(batch) {
            return Err(Error::Protocol("gated release already started for another batch".into()));
        }
        return Ok(GateCommit {
            task_id: env.cfg.task_id,
            party: env.party,
            batch_digest: batch,
            digest: c.digest(),
        });
    }
    if sends_accumulators(env.cfg, env.party) == accumulators.is_empty() {
        return Err(Error::Protocol("only the aggregator of a split-key task sends its accumulators".into()));
    }
    let reference = reference(env)?;
    let sf = reference.meta()?.scaling_factor_int;
    let n = env.ctx.ring_dim() as usize;
    let t = env.ctx.plain_mod();
    let mut masks = Vec::with_capacity(plan.num_masks());
    let mut proofs = Vec::new();
    for i in 0..plan.num_masks() {
        let m: Vec<u64> = (0..n).map(|_| rng.gen_range(0..t)).collect();
        let (c, p) = wfe::encrypt_proven(env.ctx, env.pk, &reference, &m, &proof_context(env.cfg, &batch, env.party, b"mask", i), rng)?;
        masks.push(env.codec.encode(&c)?);
        proofs.push(p);
    }
    let mut factors = Vec::new();
    if is_aggregator(env.cfg, env.party) {
        let slots = wfe::SlotCodec::new(env.ctx)?;
        for f in 0..plan.num_factors() {
            let mut v = vec![0u64; n];
            for &s in plan.factor_slots(f) {
                v[s] = rng.gen_range(1..t);
            }
            let m = slots.contribution_plaintext(&v, sf);
            let (c, p) = wfe::encrypt_proven(env.ctx, env.pk, &reference, &m, &proof_context(env.cfg, &batch, env.party, b"factor", f), rng)?;
            factors.push(env.codec.encode(&c)?);
            proofs.push(p);
        }
    }
    let contribution = GateContribution {
        task_id: env.cfg.task_id,
        party: env.party,
        batch_digest: batch,
        accumulators: accumulators.iter().map(|c| env.codec.encode(c)).collect::<Result<_>>()?,
        masks,
        factors,
        proofs,
    };
    let digest = contribution.digest();
    st.batch_digest = Some(batch);
    st.own_contribution = Some(contribution);
    Ok(GateCommit {
        task_id: env.cfg.task_id,
        party: env.party,
        batch_digest: batch,
        digest,
    })
}

fn batch(st: &GateState) -> Result<[u8; 32]> {
    st.batch_digest.ok_or_else(|| Error::Protocol("gated release not started".into()))
}

/// Round 1: with every party's commitment in, reveals this party's contribution.
pub fn contribute(env: &GateEnv, st: &mut GateState, commits: &[GateCommit]) -> Result<GateContribution> {
    let n = env.cfg.num_key_parties();
    let b = batch(st)?;
    let own = st
        .own_contribution
        .clone()
        .ok_or_else(|| Error::Protocol("gate contribute before commit".into()))?;
    let mut sorted: Vec<GateCommit> = commits.to_vec();
    sorted.sort_by_key(|c| c.party);
    if sorted.len() != n || sorted.iter().enumerate().any(|(i, c)| c.party != i) {
        return Err(Error::Protocol(format!("expected one gate commitment from each of {n} key parties")));
    }
    for c in &sorted {
        if c.task_id != env.cfg.task_id || c.batch_digest != b {
            return Err(Error::Protocol("gate commitment for another task or batch".into()));
        }
    }
    if sorted[env.party].digest != own.digest() {
        return Err(Error::Protocol("the gate commitments do not carry this party's own".into()));
    }
    if st.commits.is_empty() {
        st.commits = sorted;
    } else if st.commits != sorted {
        return Err(Error::Protocol("a key party changed its gate commitment".into()));
    }
    Ok(own)
}

/// Decoded contributions: per party, effective masks and factors.
struct Decoded {
    masks: Vec<Vec<Ciphertext>>,
    factors: Vec<Vec<Ciphertext>>,
    /// The split-key aggregator's accumulators.
    accumulators: Option<Vec<Ciphertext>>,
}

/// Checks every other party's contribution against its commitment and
/// verifies its proofs (this party's own is trusted), then decodes all.
fn decode_all(env: &GateEnv, st: &GateState, contributions: &[GateContribution], verify: bool) -> Result<Decoded> {
    let plan = GatePlan::new(env.cfg, env.layout)?;
    let n = env.cfg.num_key_parties();
    let b = batch(st)?;
    let reference = reference(env)?;
    let fresh = env.codec.fresh_meta();
    let mut out = Decoded {
        masks: Vec::with_capacity(n),
        factors: Vec::with_capacity(n),
        accumulators: None,
    };
    for (p, c) in contributions.iter().enumerate() {
        if c.party != p || c.task_id != env.cfg.task_id || c.batch_digest != b {
            return Err(Error::Protocol(format!("gate contribution {p} is for another party, task or batch")));
        }
        if c.digest() != st.commits[p].digest {
            return Err(Error::Protocol(format!("key party {p}'s gate contribution is not the one it committed to")));
        }
        let want_factors = if is_aggregator(env.cfg, p) { plan.num_factors() } else { 0 };
        let want_accs = if sends_accumulators(env.cfg, p) { plan.num_masks() } else { 0 };
        if c.masks.len() != plan.num_masks()
            || c.factors.len() != want_factors
            || c.proofs.len() != plan.num_masks() + want_factors
            || c.accumulators.len() != want_accs
        {
            return Err(Error::Protocol(format!("key party {p}'s gate contribution has the wrong shape")));
        }
        let check = |bytes: &[u8], kind: &[u8], i: usize, proof: &wfe::Proof| -> Result<Ciphertext> {
            let ct = env
                .codec
                .decode(bytes, Expect::Exactly(fresh))
                .map_err(|e| Error::Protocol(format!("key party {p}'s gate {} {i}: {e}", String::from_utf8_lossy(kind))))?;
            if verify && p != env.party {
                wfe::verify(env.ctx, env.pk, &reference, &ct, proof, &proof_context(env.cfg, &b, p, kind, i))
                    .map_err(|e| Error::Protocol(format!("key party {p}'s gate {} {i}: {e}", String::from_utf8_lossy(kind))))?;
            }
            wfe::effective(env.ctx, &ct)
        };
        let masks = c
            .masks
            .iter()
            .enumerate()
            .map(|(i, m)| check(m, b"mask", i, &c.proofs[i]))
            .collect::<Result<Vec<_>>>()?;
        let factors = c
            .factors
            .iter()
            .enumerate()
            .map(|(f, m)| check(m, b"factor", f, &c.proofs[plan.num_masks() + f]))
            .collect::<Result<Vec<_>>>()?;
        if want_accs > 0 {
            out.accumulators = Some(
                c.accumulators
                    .iter()
                    .enumerate()
                    .map(|(i, a)| {
                        env.codec
                            .decode(a, Expect::Any)
                            .map_err(|e| Error::Protocol(format!("accumulator {i} to refresh: {e}")))
                    })
                    .collect::<Result<_>>()?,
            );
        }
        out.masks.push(masks);
        out.factors.push(factors);
    }
    Ok(out)
}

/// `Y_i = X_i + Σ_p M_p,i`.
fn masked(env: &GateEnv, xs: &[Ciphertext], d: &Decoded) -> Result<Vec<Ciphertext>> {
    xs.iter()
        .enumerate()
        .map(|(i, x)| {
            let mut y = x.try_clone()?;
            for masks in &d.masks {
                y = env.ctx.add(&y, &masks[i])?;
            }
            if y.meta()?.num_elements != 2 {
                return Err(Error::Protocol(format!("refreshed value {i} is not a relinearized ciphertext")));
            }
            Ok(y)
        })
        .collect()
}

/// The values whose masked sum this party decrypts: an aggregator's own
/// accumulators, or (the collector) those the aggregator committed to.
fn values(xs_own: Option<&[Ciphertext]>, d: &Decoded) -> Result<Vec<Ciphertext>> {
    match (xs_own, &d.accumulators) {
        (Some(x), _) => x.iter().map(|c| c.try_clone().map_err(Into::into)).collect(),
        (None, Some(a)) => a.iter().map(|c| c.try_clone().map_err(Into::into)).collect(),
        (None, None) => Err(Error::Protocol("no accumulators to refresh".into())),
    }
}

/// Recomputes `Y` from the stored contributions.
pub fn masked_values(env: &GateEnv, st: &GateState, xs_own: Option<&[Ciphertext]>) -> Result<Vec<Ciphertext>> {
    let d = decode_all(env, st, &st.contributions, false)?;
    masked(env, &values(xs_own, &d)?, &d)
}

/// Round 2: checks every contribution, forms `Y`, partially decrypts it
/// and draws this party's checks of it. `xs_own` are an aggregator's own
/// accumulators (`None` for the collector, which takes the aggregator's).
pub fn share(env: &GateEnv, st: &mut GateState, contributions: &[GateContribution], xs_own: Option<&[Ciphertext]>, rng: &mut impl Rng) -> Result<GateShare> {
    let n = env.cfg.num_key_parties();
    let b = batch(st)?;
    if st.commits.len() != n {
        return Err(Error::Protocol("gate share before contribute".into()));
    }
    if let Some(s) = &st.own_share {
        let same = contributions.len() == st.contributions.len()
            && contributions
                .iter()
                .all(|c| st.contributions.iter().any(|d| d.party == c.party && d.digest() == c.digest()));
        if !same {
            return Err(Error::Protocol(
                "different gate contributions than those this party already decrypted with".into(),
            ));
        }
        return Ok(s.clone());
    }
    let mut sorted = contributions.to_vec();
    sorted.sort_by_key(|c| c.party);
    if sorted.len() != n {
        return Err(Error::Protocol(format!("expected {n} gate contributions, got {}", contributions.len())));
    }
    let d = decode_all(env, st, &sorted, true)?;
    let xs = values(xs_own, &d)?;
    let ys = masked(env, &xs, &d)?;
    let refs: Vec<&Ciphertext> = ys.iter().collect();
    let opening = vdec::draw(env.ctx, &refs, rng)?;
    let checks = vdec::build(env.ctx, env.pk, &refs, &opening)?
        .iter()
        .map(|c| env.codec.encode(c))
        .collect::<Result<Vec<_>>>()?;
    let partials = ys
        .iter()
        .map(|y| env.codec.encode(env.share.partial_decrypt(y, env.party == 0)?.ciphertext()))
        .collect::<Result<Vec<_>>>()?;
    let s = GateShare {
        task_id: env.cfg.task_id,
        party: env.party,
        batch_digest: b,
        partials,
        checks,
    };
    st.contributions = sorted;
    st.opening = Some(opening);
    st.own_share = Some(s.clone());
    Ok(s)
}

/// Party `j`'s checks of `Y`, decoded to the shapes of this party's `Y`.
fn checks_of(env: &GateEnv, st: &GateState, ys: &[Ciphertext], j: usize) -> Result<Vec<Ciphertext>> {
    let refs: Vec<&Ciphertext> = ys.iter().collect();
    let groups = vdec::groups(&refs)?;
    let per = vdec::check_count(env.ctx.ring_dim() as usize);
    let s = st
        .shares
        .iter()
        .find(|s| s.party == j)
        .ok_or_else(|| Error::Protocol(format!("no gate share from party {j}")))?;
    if s.checks.len() != groups.len() * per {
        return Err(Error::Protocol(format!(
            "party {j} published {} checks, expected {}",
            s.checks.len(),
            groups.len() * per
        )));
    }
    s.checks
        .iter()
        .enumerate()
        .map(|(l, b)| {
            env.codec
                .decode(b, Expect::Exactly(ys[groups[l / per][0]].meta()?))
                .map_err(|e| Error::Protocol(format!("party {j}'s check {l} of Y: {e}")))
        })
        .collect()
}

/// Round 3: takes every party's share, partially decrypts every other
/// party's checks and commits to those partials.
pub fn check_commit(env: &GateEnv, st: &mut GateState, shares: &[GateShare], ys: &[Ciphertext]) -> Result<GateCheckCommit> {
    let n = env.cfg.num_key_parties();
    let b = batch(st)?;
    let own = st.own_share.clone().ok_or_else(|| Error::Protocol("gate check commit before share".into()))?;
    if st.check_partials.is_empty() {
        let mut sorted = shares.to_vec();
        sorted.sort_by_key(|s| s.party);
        if sorted.len() != n || sorted.iter().enumerate().any(|(i, s)| s.party != i) {
            return Err(Error::Protocol(format!("expected one gate share from each of {n} key parties")));
        }
        for s in &sorted {
            if s.task_id != env.cfg.task_id || s.batch_digest != b {
                return Err(Error::Protocol("gate share for another task or batch".into()));
            }
            if s.partials.len() != ys.len() || s.checks.len() != own.checks.len() {
                return Err(Error::Protocol(format!("party {}'s gate share has the wrong shape", s.party)));
            }
        }
        if sorted[env.party].partials != own.partials || sorted[env.party].checks != own.checks {
            return Err(Error::Protocol("the gate shares do not carry this party's own".into()));
        }
        // every partial must parse to the shape of this party's own
        for s in &sorted {
            for (i, (p, y)) in s.partials.iter().zip(ys).enumerate() {
                env.codec
                    .decode(p, Expect::Exactly(partial_meta(y)?))
                    .map_err(|e| Error::Protocol(format!("party {}'s partial of Y {i}: {e}", s.party)))?;
            }
        }
        st.shares = sorted;
        let mut all = Vec::new();
        for j in (0..n).filter(|&j| j != env.party) {
            let mut mine = Vec::new();
            for c in checks_of(env, st, ys, j)? {
                mine.push(env.codec.encode(env.share.partial_decrypt(&c, env.party == 0)?.ciphertext())?);
            }
            all.push((j, mine));
        }
        st.check_partials = all;
    } else {
        let same = shares.len() == n
            && shares
                .iter()
                .all(|s| st.shares.iter().any(|t| t.party == s.party && t.partials == s.partials && t.checks == s.checks));
        if !same {
            return Err(Error::Protocol("different gate shares than those this party already committed on".into()));
        }
    }
    let digests = st
        .check_partials
        .iter()
        .map(|(j, ps)| {
            (
                *j,
                ps.iter()
                    .enumerate()
                    .map(|(l, p)| vdec::commit(&check_context(env.cfg, &b, *j, l, env.party), p))
                    .collect(),
            )
        })
        .collect();
    Ok(GateCheckCommit {
        task_id: env.cfg.task_id,
        party: env.party,
        batch_digest: b,
        digests,
    })
}

/// Round 4: once every other party has committed to its partials of this
/// party's checks, reveals the checks.
pub fn open(env: &GateEnv, st: &mut GateState, commits: &[GateCheckCommit]) -> Result<GateOpening> {
    let n = env.cfg.num_key_parties();
    let b = batch(st)?;
    let opening = st.opening.clone().ok_or_else(|| Error::Protocol("gate open before share".into()))?;
    if st.check_partials.is_empty() {
        return Err(Error::Protocol("gate open before check commit".into()));
    }
    let mut others: Vec<GateCheckCommit> = commits.iter().filter(|c| c.party != env.party).cloned().collect();
    others.sort_by_key(|c| c.party);
    let expect: Vec<usize> = (0..n).filter(|&j| j != env.party).collect();
    if others.iter().map(|c| c.party).collect::<Vec<_>>() != expect {
        return Err(Error::Protocol(format!(
            "expected one check commitment from each of the other {} key parties",
            n - 1
        )));
    }
    for c in &others {
        if c.task_id != env.cfg.task_id || c.batch_digest != b {
            return Err(Error::Protocol("check commitment for another task or batch".into()));
        }
        let mine = c
            .digests
            .iter()
            .find(|(v, _)| *v == env.party)
            .ok_or_else(|| Error::Protocol(format!("party {} did not commit to this party's checks", c.party)))?;
        if mine.1.len() != opening.checks.len() {
            return Err(Error::Protocol(format!(
                "party {} committed to {} checks, expected {}",
                c.party,
                mine.1.len(),
                opening.checks.len()
            )));
        }
    }
    if st.check_commits.is_empty() {
        st.check_commits = others;
    } else if st.check_commits != others {
        return Err(Error::Protocol("a key party changed its check commitments".into()));
    }
    Ok(GateOpening {
        task_id: env.cfg.task_id,
        party: env.party,
        batch_digest: b,
        opening,
    })
}

/// Round 5: rebuilds every other party's checks from this party's own `Y`
/// and reveals its partials only if each is exactly what was published.
pub fn reveal(env: &GateEnv, st: &mut GateState, openings: &[GateOpening], ys: &[Ciphertext]) -> Result<GateReveal> {
    let n = env.cfg.num_key_parties();
    let b = batch(st)?;
    if st.check_commits.len() != n - 1 {
        return Err(Error::Protocol("gate reveal before open".into()));
    }
    let refs: Vec<&Ciphertext> = ys.iter().collect();
    for j in (0..n).filter(|&j| j != env.party) {
        let o = openings
            .iter()
            .find(|o| o.party == j)
            .ok_or_else(|| Error::Protocol(format!("no gate opening from party {j}")))?;
        if o.task_id != env.cfg.task_id || o.batch_digest != b {
            return Err(Error::Protocol("gate opening for another task or batch".into()));
        }
        let rebuilt = vdec::build(env.ctx, env.pk, &refs, &o.opening)?;
        let published = checks_of(env, st, ys, j)?;
        if rebuilt.len() != published.len() || rebuilt.iter().zip(&published).any(|(a, b)| !vdec::same(a, b).unwrap_or(false)) {
            return Err(Error::Protocol(format!(
                "party {j}'s checks of Y are not what it opened: refusing to decrypt them"
            )));
        }
    }
    Ok(GateReveal {
        task_id: env.cfg.task_id,
        party: env.party,
        batch_digest: b,
        partials: st.check_partials.clone(),
    })
}

/// Round 6 (local): verifies this party's checks with every other party's
/// revealed partials, fuses `Y` (every fusion bounded, `vdec::fuse_checked`)
/// and records the verified `y`.
pub fn finish(env: &GateEnv, st: &mut GateState, reveals: &[GateReveal], ys: &[Ciphertext]) -> Result<Vec<Vec<u64>>> {
    if let Some(y) = &st.y {
        return Ok(y.clone());
    }
    let n = env.cfg.num_key_parties();
    let b = batch(st)?;
    let opening = st.opening.clone().ok_or_else(|| Error::Protocol("gate finish before share".into()))?;
    if st.check_commits.len() != n - 1 {
        return Err(Error::Protocol("gate finish before open".into()));
    }
    let refs: Vec<&Ciphertext> = ys.iter().collect();
    let groups = vdec::groups(&refs)?;
    let my_checks = vdec::build(env.ctx, env.pk, &refs, &opening)?;
    let mut check_parts: Vec<Vec<PartialDecryption>> = (0..my_checks.len()).map(|_| Vec::with_capacity(n)).collect();
    let mut y_parts: Vec<Vec<PartialDecryption>> = (0..ys.len()).map(|_| Vec::with_capacity(n)).collect();
    for j in 0..n {
        let s = &st.shares[j];
        for (i, (p, y)) in s.partials.iter().zip(ys).enumerate() {
            y_parts[i].push(PartialDecryption::from_ciphertext(
                env.codec.decode(p, Expect::Exactly(partial_meta(y)?))?,
                j == 0,
            ));
        }
        if j == env.party {
            for (l, c) in my_checks.iter().enumerate() {
                check_parts[l].push(env.share.partial_decrypt(c, env.party == 0)?);
            }
            continue;
        }
        let r = reveals
            .iter()
            .find(|r| r.party == j)
            .ok_or_else(|| Error::Protocol(format!("no gate reveal from party {j}")))?;
        if r.task_id != env.cfg.task_id || r.batch_digest != b {
            return Err(Error::Protocol("gate reveal for another task or batch".into()));
        }
        let ps = &r
            .partials
            .iter()
            .find(|(v, _)| *v == env.party)
            .ok_or_else(|| Error::Protocol(format!("party {j} revealed nothing for this party's checks")))?
            .1;
        let committed = &st.check_commits.iter().find(|c| c.party == j).expect("n - 1 commitments").digests;
        let committed = &committed.iter().find(|(v, _)| *v == env.party).expect("checked in open").1;
        if ps.len() != my_checks.len() {
            return Err(Error::Protocol(format!(
                "party {j} revealed {} partials, expected {}",
                ps.len(),
                my_checks.len()
            )));
        }
        for (l, (p, c)) in ps.iter().zip(&my_checks).enumerate() {
            if vdec::commit(&check_context(env.cfg, &b, env.party, l, j), p) != committed[l] {
                return Err(Error::Protocol(format!("party {j}'s partial of check {l} is not the one it committed to")));
            }
            check_parts[l].push(PartialDecryption::from_ciphertext(
                env.codec.decode(p, Expect::Exactly(partial_meta(c)?))?,
                j == 0,
            ));
        }
    }
    let fused_y = y_parts
        .iter()
        .enumerate()
        .map(|(i, ps)| vdec::fuse_checked(env.ctx, &ps.iter().collect::<Vec<_>>(), &format!("masked value {i}")))
        .collect::<Result<Vec<_>>>()?;
    let fused_checks = check_parts
        .iter()
        .enumerate()
        .map(|(l, ps)| vdec::fuse_checked(env.ctx, &ps.iter().collect::<Vec<_>>(), &format!("check {l} of Y")))
        .collect::<Result<Vec<_>>>()?;
    vdec::verify(&vdec::SlotPowers::new(env.ctx)?, &groups, &fused_y, &fused_checks, &opening)?;
    st.y = Some(fused_y.clone());
    Ok(fused_y)
}

/// Product of ciphertexts, as a balanced tree (depth `ceil(log2(len))`),
/// in a fixed order so that every aggregator computes the same bytes.
fn product(ctx: &Context, mut v: Vec<Ciphertext>) -> Result<Ciphertext> {
    if v.is_empty() {
        return Err(Error::Protocol("empty product".into()));
    }
    while v.len() > 1 {
        let mut next = Vec::with_capacity(v.len().div_ceil(2));
        let mut it = v.into_iter();
        while let Some(a) = it.next() {
            match it.next() {
                Some(b) => next.push(ctx.mult(&a, &b)?),
                None => next.push(a),
            }
        }
        v = next;
    }
    Ok(v.pop().expect("one left"))
}

/// `Π_{j < k} (x - j) · Π factors`: zero where `x < k`, a product of the
/// factors with a nonzero value elsewhere.
fn gate(ctx: &Context, x: &Ciphertext, k: u64, factors: Vec<Ciphertext>) -> Result<Ciphertext> {
    let n = ctx.ring_dim() as usize;
    let mut terms = Vec::with_capacity(k as usize + factors.len());
    terms.push(x.try_clone()?);
    for j in 1..k {
        terms.push(ctx.sub_plain(x, &ctx.plaintext(&vec![j % ctx.plain_mod(); n])?)?);
    }
    terms.extend(factors);
    product(ctx, terms)
}

/// After the refresh (aggregators only): `X' = y - Σ_p M_p` for every
/// refreshed value, the gates, and the released ciphertexts in
/// [`GatePlan::outputs`] order. Deterministic in its inputs.
pub fn outputs(env: &GateEnv, st: &GateState) -> Result<Vec<Ciphertext>> {
    let plan = GatePlan::new(env.cfg, env.layout)?;
    let y =
        st.y.as_ref()
            .ok_or_else(|| Error::Protocol("gate outputs before the refresh finished".into()))?;
    let d = decode_all(env, st, &st.contributions, false)?;
    let ctx = env.ctx;
    let mut fresh = Vec::with_capacity(plan.num_masks());
    for (i, yi) in y.iter().enumerate() {
        let mut dsum = d.masks[0][i].try_clone()?;
        for masks in &d.masks[1..] {
            dsum = ctx.add(&dsum, &masks[i])?;
        }
        fresh.push(ctx.add_plain(&ctx.negate(&dsum)?, &ctx.plaintext(yi)?)?);
    }
    let aggregators = env.cfg.num_aggregators;
    let factor = |f: usize| -> Result<Vec<Ciphertext>> { (0..aggregators).map(|a| d.factors[a][f].try_clone().map_err(Into::into)).collect() };
    let zv = if plan.count_gate {
        let s = plan.spread_index().expect("count gate refreshes the spread count");
        Some(gate(ctx, &fresh[s], env.cfg.min_batch_size as u64, factor(0)?)?)
    } else {
        None
    };
    let mut zc = Vec::new();
    if plan.cell_gate {
        for (c, x) in fresh.iter().enumerate().take(env.layout.num_chunks) {
            zc.push(gate(ctx, x, env.cfg.min_cell_count, factor(plan.count_gate as usize + c)?)?);
        }
    }
    let mut out = Vec::with_capacity(plan.outputs.len());
    for o in &plan.outputs {
        out.push(match *o {
            Output::Gated(i) => {
                let g = match (&zv, plan.refreshed[i]) {
                    (Some(v), Refreshed::Chunk(c)) if plan.cell_gate => ctx.mult(v, &zc[c])?,
                    (None, Refreshed::Chunk(c)) => zc[c].try_clone()?,
                    (Some(v), _) => v.try_clone()?,
                    (None, _) => return Err(Error::Protocol("ungated output".into())),
                };
                ctx.mult(&fresh[i], &g)?
            }
            Output::CountGate => zv.as_ref().expect("count gate").try_clone()?,
            Output::CellGate(c) => zc[c].try_clone()?,
        });
    }
    Ok(out)
}

fn inv(x: u64, p: u64) -> u64 {
    let mut r = 1u64;
    let (mut b, mut e) = (x % p, p - 2);
    while e > 0 {
        if e & 1 == 1 {
            r = ((r as u128 * b as u128) % p as u128) as u64;
        }
        b = ((b as u128 * b as u128) % p as u128) as u64;
        e >>= 1;
    }
    r
}

/// The collector's reading of the fused outputs.
pub struct Ungated {
    /// Per refreshed value: its slots where every gate is nonzero (divided
    /// out), zero elsewhere.
    pub values: Vec<Vec<u64>>,
    /// Per chunk (cell gate): whether each of its cell slots was suppressed.
    pub suppressed: Vec<Vec<bool>>,
}

/// Divides the gates out of the fused outputs. Refuses outputs that are not
/// consistent with honest gates: a batch-size gate that is zero (the batch
/// is below the minimum) or zero at some of its slots only; a gate nonzero
/// outside its slots; a gated value nonzero where its gate is zero.
pub fn ungate(cfg: &TaskConfig, layout: &Layout, p: u64, fused: &[Vec<u64>]) -> Result<Ungated> {
    let plan = GatePlan::new(cfg, layout)?;
    if fused.len() != plan.outputs.len() {
        return Err(Error::Protocol(format!("{} gated outputs, expected {}", fused.len(), plan.outputs.len())));
    }
    let at = |o: Output| plan.outputs.iter().position(|x| *x == o).map(|i| &fused[i]);
    let slots = fused[0].len();
    let inside = |allowed: &[usize], v: &[u64], what: &str| -> Result<()> {
        let mut ok = vec![false; slots];
        for &s in allowed {
            ok[s] = true;
        }
        if v.iter().enumerate().any(|(s, &x)| x != 0 && !ok[s]) {
            return Err(Error::Protocol(format!("aggregate inconsistent: {what} is nonzero outside its slots")));
        }
        Ok(())
    };
    if let Some(zv) = at(Output::CountGate) {
        inside(&plan.spread_slots, zv, "the batch-size gate")?;
        let zero = plan.spread_slots.iter().filter(|&&s| zv[s] == 0).count();
        if zero == plan.spread_slots.len() {
            return Err(Error::Protocol("batch below minimum size".into()));
        }
        if zero != 0 {
            return Err(Error::Protocol(
                "aggregate inconsistent: the batch-size gate is zero at some of its slots only".into(),
            ));
        }
    }
    let mut suppressed = Vec::new();
    if plan.cell_gate {
        for c in 0..layout.num_chunks {
            let zc = at(Output::CellGate(c)).expect("cell gate output");
            inside(&plan.cell_slots[c], zc, "a cell gate")?;
            suppressed.push(plan.cell_slots[c].iter().map(|&s| zc[s] == 0).collect());
        }
    }
    let mut values = vec![Vec::new(); plan.refreshed.len()];
    for (i, r) in plan.refreshed.iter().enumerate() {
        let Some(gated) = at(Output::Gated(i)) else { continue };
        let mut v = vec![0u64; slots];
        for s in 0..slots {
            let mut g = 1u64;
            if let Some(zv) = at(Output::CountGate) {
                g = ((g as u128 * zv[s] as u128) % p as u128) as u64;
            }
            if let (true, Refreshed::Chunk(c)) = (plan.cell_gate, r) {
                g = ((g as u128 * at(Output::CellGate(*c)).expect("cell gate")[s] as u128) % p as u128) as u64;
            }
            if g == 0 {
                if gated[s] != 0 {
                    return Err(Error::Protocol(
                        "aggregate inconsistent: a gated value is nonzero where its gate is zero".into(),
                    ));
                }
            } else {
                v[s] = ((gated[s] as u128 * inv(g, p) as u128) % p as u128) as u64;
            }
        }
        values[i] = v;
    }
    Ok(Ungated { values, suppressed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MeasurementType;
    use rand::{Rng, SeedableRng};

    /// Row slots of the silent-mode ring (dimension 65536).
    const ROW: usize = 32768;

    fn task(t: MeasurementType, split: bool, k: u64) -> (TaskConfig, Layout) {
        let mut c = if split {
            TaskConfig::new_split_key([3; 32], t)
        } else {
            TaskConfig::new_silent([3; 32], t, 2)
        };
        c.min_cell_count = k;
        c.validate().unwrap();
        let l = c.layout(ROW).unwrap();
        (c, l)
    }

    #[test]
    fn plans_follow_the_topology_and_the_suppression() {
        let h = MeasurementType::Histogram { length: 8 };
        // ungated tasks have no plan
        let (plain, l) = task(h.clone(), false, 0);
        assert!(GatePlan::new(&plain, &l).is_err());
        // split key without suppression: chunks and the count refreshed and released
        let (c, l) = task(h.clone(), true, 0);
        let p = GatePlan::new(&c, &l).unwrap();
        assert_eq!(p.refreshed, vec![Refreshed::Chunk(0), Refreshed::SpreadCount]);
        assert_eq!(p.outputs, vec![Output::Gated(0), Output::Gated(1), Output::CountGate]);
        assert!((p.count_gate, p.cell_gate) == (true, false));
        assert_eq!((p.num_masks(), p.num_factors()), (2, 1));
        assert_eq!(p.factor_slots(0), &p.spread_slots[..]);
        assert_eq!(p.spread_slots.len(), l.block);
        // with suppression the count is refreshed (the gate needs it) but withheld
        let (c, l) = task(h.clone(), true, 3);
        let p = GatePlan::new(&c, &l).unwrap();
        assert_eq!(p.outputs, vec![Output::Gated(0), Output::CountGate, Output::CellGate(0)]);
        assert_eq!(p.num_factors(), 2);
        assert_eq!(p.factor_slots(1), &(0..8).map(|i| l.client_slot(i)).collect::<Vec<_>>()[..]);
        // aggregators with suppression: chunks only, cell gates only
        let (c, l) = task(h, false, 3);
        let p = GatePlan::new(&c, &l).unwrap();
        assert_eq!(p.refreshed, vec![Refreshed::Chunk(0)]);
        assert_eq!(p.outputs, vec![Output::Gated(0), Output::CellGate(0)]);
        assert_eq!((p.num_factors(), p.factor_slots(0).len()), (1, 8));
        // multihot: the weight's range-check slots are not cells, their factor is zero
        let (c, l) = task(MeasurementType::MultihotCountVec { length: 5, max_weight: 3 }, false, 2);
        let p = GatePlan::new(&c, &l).unwrap();
        assert_eq!(c.measurement_type.input_len(), 7);
        assert_eq!(p.cell_slots[0], (0..5).map(|i| l.client_slot(i)).collect::<Vec<_>>());
    }

    /// Honest gated outputs for a split-key task with suppression: what the
    /// collector fuses when the batch passes, with gate factors drawn at random.
    fn honest(cfg: &TaskConfig, l: &Layout, cells: &[u64], rng: &mut impl Rng) -> Vec<Vec<u64>> {
        let p = cfg.plain_mod;
        let plan = GatePlan::new(cfg, l).unwrap();
        let n = 2 * ROW;
        let mul = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;
        let mut zv = vec![0u64; n];
        for &s in &plan.spread_slots {
            zv[s] = rng.gen_range(1..p);
        }
        let mut zc = vec![0u64; n];
        let mut x = vec![0u64; n];
        for (e, &s) in plan.cell_slots[0].iter().enumerate() {
            x[s] = cells[e];
            if cells[e] >= cfg.min_cell_count {
                zc[s] = rng.gen_range(1..p);
            }
        }
        let r: Vec<u64> = (0..n).map(|s| mul(x[s], mul(zv[s], zc[s]))).collect();
        vec![r, zv, zc]
    }

    #[test]
    fn ungate_recovers_released_cells_and_flags_suppressed_ones() {
        let (c, l) = task(MeasurementType::Histogram { length: 6 }, true, 3);
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let cells = [2u64, 3, 4, 0, 1, 9];
        let fused = honest(&c, &l, &cells, &mut rng);
        let u = ungate(&c, &l, c.plain_mod, &fused).unwrap();
        let slots = &GatePlan::new(&c, &l).unwrap().cell_slots[0];
        let released: Vec<u64> = slots.iter().map(|&s| u.values[0][s]).collect();
        assert_eq!(released, vec![0, 3, 4, 0, 0, 9]);
        assert_eq!(u.suppressed[0], vec![true, false, false, true, true, false]);
        assert!(u.values[1].is_empty(), "the count is not released with suppression");
    }

    #[test]
    fn ungate_refuses_outputs_no_honest_gate_produces() {
        let (c, l) = task(MeasurementType::Histogram { length: 6 }, true, 3);
        let p = c.plain_mod;
        let mut rng = rand::rngs::StdRng::seed_from_u64(12);
        let fused = honest(&c, &l, &[5, 5, 0, 5, 5, 5], &mut rng);
        let plan = GatePlan::new(&c, &l).unwrap();
        let err = |f: &[Vec<u64>]| ungate(&c, &l, p, f).err().unwrap().to_string();
        // a batch below the minimum: the batch-size gate is zero everywhere
        let mut below = fused.clone();
        below[1] = vec![0; 2 * ROW];
        below[0] = vec![0; 2 * ROW];
        assert!(err(&below).contains("batch below minimum size"));
        // zero at some of its slots only
        let mut partial = fused.clone();
        partial[1][plan.spread_slots[3]] = 0;
        assert!(err(&partial).contains("zero at some of its slots only"));
        // a gate nonzero outside its slots (it would release a constraint or
        // another group's slot)
        let mut outside = fused.clone();
        outside[2][1] = 7;
        assert!(err(&outside).contains("nonzero outside its slots"));
        let mut outside_v = fused.clone();
        outside_v[1][1] = 7;
        assert!(err(&outside_v).contains("nonzero outside its slots"));
        // a released value where the cell gate is zero (a suppressed cell leaking)
        let mut leak = fused.clone();
        leak[0][plan.cell_slots[0][2]] = 1;
        assert!(err(&leak).contains("nonzero where its gate is zero"));
        // the wrong number of outputs
        assert!(err(&fused[..2]).contains("expected 3"));
    }
}
