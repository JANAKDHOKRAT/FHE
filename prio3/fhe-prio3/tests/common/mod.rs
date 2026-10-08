//! In-process network: every message crosses postcard serialization.
#![allow(dead_code)]

use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use std::sync::{Arc, Mutex};

/// OpenFHE keeps evaluation keys in unsynchronised process-global tables.
pub static SERIAL: Mutex<()> = Mutex::new(());

/// Serialises tests; a panic in one test must not poison the rest.
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// The messages of one round of the gated release, for tests to tamper with.
pub enum GateStage<'a> {
    Commits(&'a mut Vec<GateCommit>),
    Contributions(&'a mut Vec<GateContribution>),
    /// With the masked values `Y` (aggregator 0's; every honest key party has the same).
    Shares(&'a mut Vec<GateShare>, &'a [openfhe_tbgv_rs::Ciphertext]),
    CheckCommits(&'a mut Vec<GateCheckCommit>),
    Openings(&'a mut Vec<GateOpening>),
    Reveals(&'a mut Vec<GateReveal>),
    Released(&'a mut Vec<AggregateShare>),
}

pub struct Net {
    pub cfg: TaskConfig,
    /// Only what clients need: the evaluation keys are dropped once the
    /// aggregators have installed them (they are gigabytes in silent mode).
    pub material: PublicMaterial,
    pub aggs: Vec<Aggregator>,
    pub client: Client,
    pub collector: Collector,
}

pub fn task_id(seed: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = seed;
    id[31] = 0xA5;
    id
}

impl Net {
    pub fn new(cfg: TaskConfig) -> Self {
        Self::with_registry(cfg, None)
    }

    pub fn with_registry(cfg: TaskConfig, registry: Option<Arc<dyn ClientRegistry>>) -> Self {
        let k = keys::run_local_key_ceremony(&cfg).expect("ceremony");
        let mut net = Self::with_keys(cfg.clone(), k.material, &k.aggregator_secrets, registry);
        if let Some(secret) = &k.collector_secret {
            net.collector = Collector::with_key_share(cfg, &net.material, secret).expect("collector with key share");
        }
        net
    }

    /// From keys made once for several tests: a task with the same depth and
    /// layout as the one the keys were made for (the batch-size and cell
    /// thresholds do not enter the keys).
    pub fn from_local_keys(cfg: TaskConfig, k: &keys::LocalKeys) -> Self {
        let mut net = Self::with_keys(cfg.clone(), k.material.clone(), &k.aggregator_secrets, None);
        if let Some(secret) = &k.collector_secret {
            net.collector = Collector::with_key_share(cfg, &net.material, secret).expect("collector with key share");
        }
        net
    }

    /// From material and shares made elsewhere (e.g. the distributed ceremony).
    pub fn with_keys(cfg: TaskConfig, full: PublicMaterial, shares: &[Vec<u8>], registry: Option<Arc<dyn ClientRegistry>>) -> Self {
        let mut full: PublicMaterial = {
            let bytes = encode(&full).unwrap();
            drop(full);
            decode(&bytes).unwrap()
        };
        let aggs = shares
            .iter()
            .enumerate()
            .map(|(i, s)| Aggregator::new(cfg.clone(), &full, i, s, registry.clone()).expect("aggregator"))
            .collect();
        // Keep only the public parameters clients and the collector need.
        full.rotation_keys.clear();
        full.eval_mult_key.clear();
        let material = full;
        let client = Client::new(cfg.clone(), &material.context, &material.public_key).expect("client");
        let collector = Collector::new(cfg.clone(), &material).expect("collector");
        Self {
            cfg,
            material,
            aggs,
            client,
            collector,
        }
    }

    /// Runs the three preparation steps for one report on every aggregator.
    /// Returns one verdict per aggregator (a rejection at step 1 is reported
    /// as a verdict too).
    pub fn run_report(&mut self, report: &Report) -> Vec<Verdict> {
        let report: Report = decode(&encode(report).unwrap()).unwrap();
        if self.cfg.mode == VerificationMode::Silent {
            let verdicts: Vec<Verdict> = self
                .aggs
                .iter_mut()
                .map(|a| match a.process_silent(&report) {
                    Ok(()) => Verdict::Accepted,
                    Err(Error::Reject(r)) => Verdict::Rejected(r),
                    Err(e) => panic!("process_silent failed: {e}"),
                })
                .collect();
            return verdicts;
        }
        let mut mask_commits: Vec<MaskCommit> = Vec::new();
        let mut early = Vec::new();
        for a in self.aggs.iter_mut() {
            match a.prepare_init(&report) {
                Ok(m) => mask_commits.push(decode(&encode(&m).unwrap()).unwrap()),
                Err(Error::Reject(r)) => early.push(Verdict::Rejected(r)),
                Err(e) => panic!("prepare_init failed: {e}"),
            }
        }
        if !early.is_empty() {
            assert_eq!(early.len(), self.aggs.len(), "aggregators must agree on structural rejections");
            return early;
        }
        let mut masks: Vec<MaskMessage> = Vec::new();
        for a in self.aggs.iter_mut() {
            let others: Vec<MaskCommit> = mask_commits.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
            let m = a.prepare_mask_reveal(&report.report_id, &others).expect("prepare_mask_reveal");
            masks.push(decode(&encode(&m).unwrap()).unwrap());
        }
        let mut commits: Vec<VerifierCommit> = Vec::new();
        for a in self.aggs.iter_mut() {
            let others: Vec<MaskMessage> = masks.iter().filter(|m| m.aggregator != a.index()).cloned().collect();
            let c = a.prepare_masks(&report.report_id, &others).expect("prepare_masks");
            commits.push(decode(&encode(&c).unwrap()).unwrap());
        }
        let mut verifiers: Vec<VerifierMessage> = Vec::new();
        for a in self.aggs.iter_mut() {
            let others: Vec<VerifierCommit> = commits.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
            let v = a.prepare_reveal(&report.report_id, &others).expect("prepare_reveal");
            verifiers.push(decode(&encode(&v).unwrap()).unwrap());
        }
        let mut verdicts = Vec::new();
        for a in self.aggs.iter_mut() {
            let others: Vec<VerifierMessage> = verifiers.iter().filter(|v| v.aggregator != a.index()).cloned().collect();
            verdicts.push(a.prepare_finish(&report.report_id, &others).expect("prepare_finish"));
        }
        verdicts
    }

    pub fn expect_accept(&mut self, report: &Report) {
        let v = self.run_report(report);
        assert!(v.iter().all(|v| *v == Verdict::Accepted), "expected acceptance, got {v:?}");
    }

    pub fn expect_reject(&mut self, report: &Report, reason: RejectReason) {
        let v = self.run_report(report);
        assert!(v.iter().all(|v| *v == Verdict::Rejected(reason.clone())), "expected {reason:?}, got {v:?}");
    }

    /// Closes the batch (with the silent-mode count round when needed) and
    /// returns `(aggregate, valid_count)` from the collector.
    pub fn collect(&mut self) -> Result<(AggregateResult, u64)> {
        let r = self.collect_full()?;
        Ok((r.aggregate, r.valid_count))
    }

    /// Runs the verified count round in silent mode (idempotent per batch).
    pub fn count_round(&mut self) -> Result<()> {
        if self.cfg.mode != VerificationMode::Silent {
            return Ok(());
        }
        fn wire<T: serde::Serialize + serde::de::DeserializeOwned>(v: Vec<T>) -> Vec<T> {
            v.into_iter().map(|x| decode(&encode(&x).unwrap()).unwrap()).collect()
        }
        let shares = wire(self.aggs.iter_mut().map(|a| a.count_share()).collect::<Result<Vec<_>>>()?);
        let commits = wire(self.aggs.iter_mut().map(|a| a.count_commit(&shares)).collect::<Result<Vec<_>>>()?);
        let openings = wire(self.aggs.iter_mut().map(|a| a.count_open(&commits)).collect::<Result<Vec<_>>>()?);
        let reveals = wire(self.aggs.iter_mut().map(|a| a.count_reveal(&openings)).collect::<Result<Vec<_>>>()?);
        let mut seen = None;
        for a in self.aggs.iter_mut() {
            let v = a.count_finish(&reveals)?;
            assert!(seen.is_none() || seen == Some(v), "aggregators must agree on the valid count");
            seen = Some(v);
        }
        Ok(())
    }

    /// Verified release to collector `c` through the sealed path: every
    /// aggregator seals its share and its check partials to the collector's
    /// key. `key` must be the collector's declared sealing key.
    pub fn collect_sealed_for(&mut self, c: usize, key: &CollectorSealKey) -> Result<BatchResult> {
        self.count_round()?;
        let sealed: Vec<SealedShare> = self.aggs.iter_mut().map(|a| a.sealed_share_for(c)).collect::<Result<Vec<_>>>()?;
        let sealed: Vec<SealedShare> = sealed.into_iter().map(|s| decode(&encode(&s).unwrap()).unwrap()).collect();
        let mut pending = self.collector.release_challenge_sealed(c, key, &sealed)?;
        let commits = self.aggs.iter_mut().map(|a| a.release_commit(&pending.challenge)).collect::<Result<Vec<_>>>()?;
        let opening = self.collector.release_open(&mut pending, commits)?;
        let reveals: Vec<SealedShare> = self.aggs.iter_mut().map(|a| a.sealed_release_reveal(&opening)).collect::<Result<Vec<_>>>()?;
        self.collector.release_finish_sealed(&pending, key, &reveals)
    }

    /// Gated release (`gate.rs`), every message across postcard: the count
    /// round when the aggregators hold every share, rounds 0 to 6 among the
    /// key parties, then the verified release.
    pub fn gated_collect(&mut self) -> Result<BatchResult> {
        self.gated_collect_with(|_| {})
    }

    /// [`Self::gated_collect`], with `hook` seeing (and able to change)
    /// every round's messages before they are delivered: what a malicious
    /// party or network can do.
    pub fn gated_collect_with(&mut self, mut hook: impl FnMut(GateStage)) -> Result<BatchResult> {
        fn wire<T: serde::Serialize + serde::de::DeserializeOwned>(v: Vec<T>) -> Vec<T> {
            v.into_iter().map(|x| decode(&encode(&x).unwrap()).unwrap()).collect()
        }
        let split = self.cfg.collector_holds_key();
        if !split {
            self.count_round()?;
        }
        let mut commits = self.aggs.iter_mut().map(|a| a.gate_commit()).collect::<Result<Vec<_>>>()?;
        if split {
            let c = self.collector.gate_commit(&commits[0])?;
            commits.push(c);
        }
        let mut commits = wire(commits);
        hook(GateStage::Commits(&mut commits));
        let mut contributions = self.aggs.iter_mut().map(|a| a.gate_contribute(&commits)).collect::<Result<Vec<_>>>()?;
        if split {
            contributions.push(self.collector.gate_contribute(&commits)?);
        }
        let mut contributions = wire(contributions);
        hook(GateStage::Contributions(&mut contributions));
        let mut shares = self.aggs.iter_mut().map(|a| a.gate_share(&contributions)).collect::<Result<Vec<_>>>()?;
        if split {
            shares.push(self.collector.gate_share(&contributions)?);
        }
        let mut shares = wire(shares);
        let ys = self.aggs[0].gate_masked_values_for_tests()?;
        hook(GateStage::Shares(&mut shares, &ys));
        // a party whose share the hook changed sends that share to everyone
        // and keeps it as its own (what a malicious party does)
        for a in self.aggs.iter_mut() {
            let i = a.index();
            a.gate_state_for_tests().own_share = Some(shares[i].clone());
        }
        if split {
            let c = self.cfg.num_aggregators;
            self.collector.gate_state_for_tests().own_share = Some(shares[c].clone());
        }
        let mut cc = self.aggs.iter_mut().map(|a| a.gate_check_commit(&shares)).collect::<Result<Vec<_>>>()?;
        if split {
            cc.push(self.collector.gate_check_commit(&shares)?);
        }
        let mut cc = wire(cc);
        hook(GateStage::CheckCommits(&mut cc));
        let mut openings = self.aggs.iter_mut().map(|a| a.gate_open(&cc)).collect::<Result<Vec<_>>>()?;
        if split {
            openings.push(self.collector.gate_open(&cc)?);
        }
        let mut openings = wire(openings);
        hook(GateStage::Openings(&mut openings));
        let mut reveals = self.aggs.iter_mut().map(|a| a.gate_reveal(&openings)).collect::<Result<Vec<_>>>()?;
        if split {
            reveals.push(self.collector.gate_reveal(&openings)?);
        }
        let mut reveals = wire(reveals);
        hook(GateStage::Reveals(&mut reveals));
        for a in self.aggs.iter_mut() {
            a.gate_finish(&reveals)?;
        }
        if split {
            self.collector.gate_finish(&reveals)?;
        }
        let mut released = wire(self.aggs.iter_mut().map(|a| a.aggregate_share_for(0)).collect::<Result<Vec<_>>>()?);
        hook(GateStage::Released(&mut released));
        self.finish_release(0, released)
    }

    /// Verified release to collector `c` unsealed (library-level tests of policies).
    pub fn collect_for(&mut self, c: usize) -> Result<BatchResult> {
        if self.cfg.gated() {
            assert_eq!(c, 0);
            return self.gated_collect();
        }
        self.count_round()?;
        let shares: Vec<AggregateShare> = self
            .aggs
            .iter_mut()
            .map(|a| a.aggregate_share_for(c))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|s| decode(&encode(&s).unwrap()).unwrap())
            .collect();
        let mut pending = self.collector.release_challenge(c, shares)?;
        let commits = self.aggs.iter_mut().map(|a| a.release_commit(&pending.challenge)).collect::<Result<Vec<_>>>()?;
        let opening = self.collector.release_open(&mut pending, commits)?;
        let reveals = self.aggs.iter_mut().map(|a| a.release_reveal(&opening)).collect::<Result<Vec<_>>>()?;
        self.collector.release_finish(&pending, &reveals)
    }

    /// The verified release steps for shares already released to collector `c`.
    pub fn finish_release(&mut self, c: usize, shares: Vec<AggregateShare>) -> Result<BatchResult> {
        let mut pending = self.collector.release_challenge(c, shares)?;
        let commits = self.aggs.iter_mut().map(|a| a.release_commit(&pending.challenge)).collect::<Result<Vec<_>>>()?;
        let opening = self.collector.release_open(&mut pending, commits)?;
        let reveals = self.aggs.iter_mut().map(|a| a.release_reveal(&opening)).collect::<Result<Vec<_>>>()?;
        self.collector.release_finish(&pending, &reveals)
    }

    pub fn collect_full(&mut self) -> Result<BatchResult> {
        self.collect_for(0)
    }
}
