//! Collector: fuses the aggregators' partial decryptions of the batch sums
//! and checks the result is consistent with a batch of valid reports. Holds
//! no key material.
//!
//! A release is verified (`vdec`): the collector receives every
//! aggregator's share with the accumulators it decrypted (which must be
//! identical across aggregators), sends blinded checks of them
//! ([`Collector::release_challenge`]), collects every aggregator's
//! commitments to its partials of the checks and opens them
//! ([`Collector::release_open`]), then fuses and accepts the batch only if
//! every check holds ([`Collector::release_finish`]). A malicious
//! aggregator's shifted partial decryption is caught with probability at
//! least `1 - 2^-80`; there is no unverified path.

use crate::config::{TaskConfig, VerificationMode};
use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::messages::{AggregateShare, PublicMaterial, ReleaseChallenge, ReleaseCommit, ReleaseOpening, ReleaseReveal};
use crate::packed::{Codec, Expect, check_stored};
use crate::types::{AggregateResult, BatchResult, RegressionResult};
use crate::vdec;
use openfhe_tbgv_rs::{Ciphertext, CiphertextMeta, Context, PartialDecryption, PublicKey};

/// A release in progress at the collector: the shares, the checks sent and
/// their opening (secret until every commitment is in), and the
/// commitments. Serializable, so that a collector node can persist it.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingRelease {
    pub collector: u32,
    pub shares: Vec<AggregateShare>,
    pub challenge: ReleaseChallenge,
    pub opening: vdec::Opening,
    pub commits: Vec<ReleaseCommit>,
}

pub struct Collector {
    cfg: TaskConfig,
    ctx: Context,
    pk: PublicKey,
    layout: Layout,
    /// Partial decryptions arrive packed and are rebuilt through this
    /// codec, never through OpenFHE's deserializer.
    codec: Codec,
}

impl Collector {
    pub fn new(cfg: TaskConfig, material: &PublicMaterial) -> Result<Self> {
        cfg.validate()?;
        let ctx = Context::deserialize(&material.context)?;
        // Partial decryptions are rebuilt from residues and metadata; refuse
        // to run on an OpenFHE that does not rebuild them exactly.
        openfhe_tbgv_rs::verify_rebuild_once(&ctx, cfg.mult_depth())?;
        let layout = cfg.layout(ctx.row_slots())?;
        let pk = ctx.deserialize_public_key(&material.public_key)?;
        let codec = Codec::new(&ctx, &pk, &material.public_key)?;
        Ok(Self { cfg, ctx, pk, layout, codec })
    }

    /// Checks that a stored aggregate share (one a collector node kept while
    /// waiting for the others) is in the packed format, so that a node
    /// restarted on state from before it refuses to start with a clear
    /// reason instead of failing when the last share arrives.
    pub fn check_stored_share(&self, share: &AggregateShare) -> Result<()> {
        let what = format!("stored aggregate share from aggregator {}", share.aggregator);
        for p in share.partials.iter().chain(&share.moment_partials).chain(share.valid_count_partial.as_ref()) {
            check_stored(self.codec.format(), p, Expect::Partial, &what)?;
        }
        for a in &share.accumulators {
            check_stored(self.codec.format(), a, Expect::Any, &what)?;
        }
        Ok(())
    }

    /// Checks the shares' structure: one per aggregator, all released to
    /// `collector`, agreeing on the batch, each with exactly the partials
    /// and accumulators the collector's policy covers, and identical
    /// accumulators.
    fn check_shares(&self, collector: usize, shares: &[AggregateShare]) -> Result<()> {
        let n = self.cfg.num_aggregators;
        let chunks = self.cfg.collector_chunks(&self.layout, collector);
        let terms = self.collector_terms(collector)?;
        let expect_accs = chunks.len() + (self.cfg.mode == VerificationMode::Silent) as usize + terms.len();
        if shares.len() != n {
            return Err(Error::Protocol(format!("expected {n} aggregate shares, got {}", shares.len())));
        }
        let mut seen = vec![false; n];
        for s in shares {
            if s.task_id != self.cfg.task_id {
                return Err(Error::Protocol("aggregate share for a different task".into()));
            }
            if s.collector != collector as u32 {
                return Err(Error::Protocol(format!(
                    "aggregate share released to collector {}, not {collector}",
                    s.collector
                )));
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
            if s.moment_partials.len() != terms.len() {
                return Err(Error::Protocol("wrong number of moment partials for this collector".into()));
            }
            if s.valid_count_partial.is_some() != (self.cfg.mode == VerificationMode::Silent) {
                return Err(Error::Protocol("valid-count partial present in the wrong mode".into()));
            }
            if s.accumulators.len() != expect_accs {
                return Err(Error::Protocol(format!(
                    "share carries {} accumulators, expected {expect_accs}",
                    s.accumulators.len()
                )));
            }
            if s.accumulators != shares[0].accumulators {
                return Err(Error::Protocol(format!(
                    "aggregator {} computed other accumulators than aggregator {}",
                    s.aggregator, shares[0].aggregator
                )));
            }
        }
        if shares[0].report_count > self.cfg.max_batch_size {
            // every bound below (and the digit width) assumes at most
            // max_batch_size reports; aggregators admit no more
            return Err(Error::Protocol("aggregate inconsistent: report count exceeds max_batch_size".into()));
        }
        Ok(())
    }

    fn collector_terms(&self, collector: usize) -> Result<Vec<crate::layout::MomentTerm>> {
        let pairs = self.cfg.collector_moment_pairs(collector)?;
        Ok(if pairs.is_empty() {
            Vec::new()
        } else {
            // terms are over pieces; a collector's pairs are over elements
            let el = |i: usize| self.layout.moment_pieces[i].0;
            self.layout.moment_terms().into_iter().filter(|t| pairs.contains(&(el(t.a), el(t.b)))).collect()
        })
    }

    fn accumulators(&self, share: &AggregateShare) -> Result<Vec<Ciphertext>> {
        share
            .accumulators
            .iter()
            .enumerate()
            .map(|(i, b)| self.codec.decode(b, Expect::Any).map_err(|e| Error::Protocol(format!("accumulator {i}: {e}"))))
            .collect()
    }

    /// Every share's partials in accumulator order (chunks, count, moments).
    fn share_partials(s: &AggregateShare) -> Vec<&[u8]> {
        s.partials
            .iter()
            .chain(s.valid_count_partial.as_ref())
            .chain(&s.moment_partials)
            .map(|v| v.as_slice())
            .collect()
    }

    /// Release step 1: checks the shares and draws blinded checks of the
    /// accumulators. The returned state holds the opening; send
    /// `pending.challenge` to every aggregator.
    pub fn release_challenge(&self, collector: usize, shares: Vec<AggregateShare>) -> Result<PendingRelease> {
        self.check_shares(collector, &shares)?;
        let accs = self.accumulators(&shares[0])?;
        // every partial must be of exactly its accumulator's shape
        for s in &shares {
            for (i, (p, acc)) in Self::share_partials(s).into_iter().zip(&accs).enumerate() {
                let meta = CiphertextMeta {
                    num_elements: 1,
                    ..acc.meta()?
                };
                self.codec
                    .decode(p, Expect::Exactly(meta))
                    .map_err(|e| Error::Protocol(format!("aggregator {}'s partial decryption of accumulator {i}: {e}", s.aggregator)))?;
            }
        }
        let refs: Vec<&Ciphertext> = accs.iter().collect();
        let opening = vdec::draw(&self.ctx, &refs, &mut rand::rngs::OsRng)?;
        let checks = vdec::build(&self.ctx, &self.pk, &refs, &opening)?
            .iter()
            .map(|c| self.codec.encode(c))
            .collect::<Result<Vec<_>>>()?;
        let challenge = ReleaseChallenge {
            task_id: self.cfg.task_id,
            collector: collector as u32,
            batch_digest: shares[0].batch_digest,
            checks,
        };
        Ok(PendingRelease {
            collector: collector as u32,
            shares,
            challenge,
            opening,
            commits: Vec::new(),
        })
    }

    /// [`Self::release_challenge`] for sealed shares (tasks with policies).
    pub fn release_challenge_sealed(
        &self,
        collector: usize,
        key: &crate::seal::CollectorSealKey,
        sealed: &[crate::seal::SealedShare],
    ) -> Result<PendingRelease> {
        self.check_seal_key(collector, key)?;
        let shares = sealed.iter().map(|s| crate::seal::open(s, key)).collect::<Result<Vec<_>>>()?;
        self.release_challenge(collector, shares)
    }

    fn check_seal_key(&self, collector: usize, key: &crate::seal::CollectorSealKey) -> Result<()> {
        let expected = self
            .cfg
            .collectors
            .get(collector)
            .map(|p| p.seal_key)
            .ok_or_else(|| Error::Config(format!("no collector {collector} in the task")))?;
        if key.public_key() != expected {
            return Err(Error::Config(format!("sealing key is not the one the task declares for collector {collector}")));
        }
        Ok(())
    }

    /// Release step 2: once every aggregator has committed to its partials
    /// of the checks, returns the opening to send to all of them.
    pub fn release_open(&self, p: &mut PendingRelease, commits: Vec<ReleaseCommit>) -> Result<ReleaseOpening> {
        let n = self.cfg.num_aggregators;
        let digest = p.challenge.digest();
        if commits.len() != n {
            return Err(Error::Protocol(format!("expected {n} commitments, got {}", commits.len())));
        }
        let mut seen = vec![false; n];
        for c in &commits {
            if c.task_id != self.cfg.task_id || c.collector != p.collector || c.challenge != digest {
                return Err(Error::Protocol("commitment for another challenge".into()));
            }
            if c.aggregator >= n || std::mem::replace(&mut seen[c.aggregator], true) {
                return Err(Error::Protocol("duplicate or out-of-range aggregator in commitments".into()));
            }
            if c.digests.len() != p.challenge.checks.len() {
                return Err(Error::Protocol(format!(
                    "aggregator {} committed to {} checks, expected {}",
                    c.aggregator,
                    c.digests.len(),
                    p.challenge.checks.len()
                )));
            }
        }
        if !p.commits.is_empty()
            && p.commits
                .iter()
                .any(|old| commits.iter().find(|c| c.aggregator == old.aggregator).map(|c| &c.digests) != Some(&old.digests))
        {
            return Err(Error::Protocol("an aggregator changed its commitments".into()));
        }
        p.commits = commits;
        Ok(ReleaseOpening {
            task_id: self.cfg.task_id,
            collector: p.collector,
            challenge: digest,
            opening: p.opening.clone(),
        })
    }

    fn release_context(&self, p: &PendingRelease, check: usize, aggregator: usize) -> Vec<u8> {
        let mut c = b"release".to_vec();
        c.extend_from_slice(&self.cfg.task_id);
        c.extend_from_slice(&p.challenge.batch_digest);
        c.extend_from_slice(&p.collector.to_le_bytes());
        for x in [check, aggregator] {
            c.extend_from_slice(&(x as u64).to_le_bytes());
        }
        c
    }

    /// Release step 3: verifies every aggregator's revealed partials of the
    /// checks against its commitments, fuses the accumulators and the checks
    /// (every fusion bounded below `q0 / 4`), accepts only if every check
    /// holds, then decodes and checks the aggregate.
    pub fn release_finish(&self, p: &PendingRelease, reveals: &[ReleaseReveal]) -> Result<BatchResult> {
        let n = self.cfg.num_aggregators;
        if p.commits.len() != n {
            return Err(Error::Protocol("release_finish before release_open".into()));
        }
        let digest = p.challenge.digest();
        let accs = self.accumulators(&p.shares[0])?;
        let refs: Vec<&Ciphertext> = accs.iter().collect();
        let groups = vdec::groups(&refs)?;
        let checks: Vec<Ciphertext> = vdec::build(&self.ctx, &self.pk, &refs, &p.opening)?;
        // partials in aggregator order (aggregator 0 leads)
        let mut shares: Vec<&AggregateShare> = p.shares.iter().collect();
        shares.sort_by_key(|s| s.aggregator);
        let mut fused_accs = Vec::with_capacity(accs.len());
        for (i, acc) in accs.iter().enumerate() {
            let meta = CiphertextMeta {
                num_elements: 1,
                ..acc.meta()?
            };
            let parts = shares
                .iter()
                .map(|s| {
                    Ok(PartialDecryption::from_ciphertext(
                        self.codec.decode(Self::share_partials(s)[i], Expect::Exactly(meta))?,
                        s.aggregator == 0,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            fused_accs.push(vdec::fuse_checked(&self.ctx, &parts.iter().collect::<Vec<_>>(), &format!("accumulator {i}"))?);
        }
        let mut fused_checks = Vec::with_capacity(checks.len());
        for (l, c) in checks.iter().enumerate() {
            let meta = CiphertextMeta { num_elements: 1, ..c.meta()? };
            let mut parts = Vec::with_capacity(n);
            for j in 0..n {
                let r = reveals
                    .iter()
                    .find(|r| r.aggregator == j)
                    .ok_or_else(|| Error::Protocol(format!("no reveal from aggregator {j}")))?;
                if r.task_id != self.cfg.task_id || r.collector != p.collector || r.challenge != digest || r.partials.len() != checks.len() {
                    return Err(Error::Protocol(format!("aggregator {j}'s reveal is for another challenge")));
                }
                let committed = &p.commits.iter().find(|c| c.aggregator == j).expect("n commitments").digests;
                if vdec::commit(&self.release_context(p, l, j), &r.partials[l]) != committed[l] {
                    return Err(Error::Protocol(format!("aggregator {j}'s partial of check {l} is not the one it committed to")));
                }
                parts.push(PartialDecryption::from_ciphertext(
                    self.codec.decode(&r.partials[l], Expect::Exactly(meta))?,
                    j == 0,
                ));
            }
            fused_checks.push(vdec::fuse_checked(&self.ctx, &parts.iter().collect::<Vec<_>>(), &format!("check {l}"))?);
        }
        vdec::verify(&vdec::SlotPowers::new(&self.ctx)?, &groups, &fused_accs, &fused_checks, &p.opening)?;
        self.result_from(p.collector as usize, &p.shares[0], &fused_accs)
    }

    /// [`Self::release_finish`] for sealed reveals (tasks with policies).
    pub fn release_finish_sealed(&self, p: &PendingRelease, key: &crate::seal::CollectorSealKey, sealed: &[crate::seal::SealedShare]) -> Result<BatchResult> {
        self.check_seal_key(p.collector as usize, key)?;
        let reveals = sealed.iter().map(|s| crate::seal::open_reveal(s, key)).collect::<Result<Vec<_>>>()?;
        self.release_finish(p, &reveals)
    }

    /// The batch result from verified fused accumulators (all slots, in the
    /// order chunks, valid count, moments). The result carries the
    /// collector's elements; the others are zero. Second moments, if the
    /// policy grants them, cover the collector's elements only and the
    /// regression is fitted on those, the last of them being the target.
    fn result_from(&self, collector: usize, share: &AggregateShare, fused: &[Vec<u64>]) -> Result<BatchResult> {
        let elements = self.cfg.collector_elements(collector)?;
        let chunks = self.cfg.collector_chunks(&self.layout, collector);
        let pairs = self.cfg.collector_moment_pairs(collector)?;
        let terms = self.collector_terms(collector)?;
        let count = share.report_count;
        let valid = match self.cfg.mode {
            VerificationMode::Verdict => count,
            VerificationMode::Silent => fused[chunks.len()][0],
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
            for (i, g) in self.layout.chunk_range(k).enumerate() {
                slot_sums[g] = fused[pi][self.layout.client_slot(i)];
                visible[g] = true;
            }
        }
        let full = elements.len() == self.cfg.measurement_type.num_elements();
        self.cfg
            .measurement_type
            .check_aggregate_consistency_visible(&slot_sums, valid, if full { None } else { Some(&visible) })?;
        let aggregate = self.cfg.measurement_type.decode_aggregate(&slot_sums)?;
        let regression = if pairs.is_empty() {
            None
        } else {
            let map = self
                .layout
                .moments
                .as_ref()
                .ok_or_else(|| Error::Protocol("moments released but not laid out".into()))?;
            let all: Vec<u128> = match &aggregate {
                AggregateResult::SumVec(v) => v.clone(),
                _ => return Err(Error::Protocol("moments require a vector aggregate".into())),
            };
            // values of this collector, in ascending element order
            let values: Vec<usize> = elements.clone();
            let l = values.len();
            let pos = |e: usize| values.iter().position(|&x| x == e).expect("pair within elements");
            let mut second = vec![vec![0u128; l]; l];
            let base = chunks.len() + (self.cfg.mode == VerificationMode::Silent) as usize;
            let bounds = self.cfg.measurement_type.value_bounds().expect("vector type");
            let pieces = &self.layout.moment_pieces;
            if pieces.len() != map.len() {
                return Err(Error::Protocol("moment pieces not laid out".into()));
            }
            // v_a v_b = sum over piece pairs (i in a, j in b) of m_i m_j S(i, j);
            // within one element the pair {i, j}, i < j, is one accumulator
            // but occurs twice in v^2.
            for (idx, &t) in terms.iter().enumerate() {
                let span = self.layout.moment_term_span(t);
                let acc = self
                    .layout
                    .moment_term_sum(t, &fused[base + idx][..span], valid)
                    .map_err(|e| Error::Protocol(format!("aggregate inconsistent: {e}")))?;
                let ((ea, ma), (eb, mb)) = (pieces[t.a], pieces[t.b]);
                let (pa, pb) = (pos(ea), pos(eb));
                let twice = if ea == eb && t.a != t.b { 2u128 } else { 1 };
                second[pa][pb] += twice * acc * ma as u128 * mb as u128;
                if pa != pb {
                    second[pb][pa] = second[pa][pb];
                }
            }
            for &(a, b) in &pairs {
                // the recombined sum of `valid` products of values bounded by B_a and B_b
                let cap = (valid as u128) * (bounds[a] as u128) * (bounds[b] as u128);
                if second[pos(a)][pos(b)] > cap {
                    return Err(Error::Protocol(format!("aggregate inconsistent: second moment ({a},{b}) exceeds its bound")));
                }
            }
            let first: Vec<u128> = values.iter().map(|&e| all[e]).collect();
            Some(RegressionResult::from_moments(valid, first, second))
        };
        Ok(BatchResult {
            collector: collector as u32,
            elements,
            aggregate,
            report_count: count,
            valid_count: valid,
            regression,
        })
    }
}
