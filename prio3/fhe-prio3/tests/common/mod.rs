//! In-process network: every message crosses bincode serialization.
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
        let (full, shares) = keys::run_local_ceremony(&cfg).expect("ceremony");
        Self::with_keys(cfg, full, &shares, registry)
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
        Self { cfg, material, aggs, client, collector }
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

    /// Verified release to collector `c` unsealed (library-level tests of policies).
    pub fn collect_for(&mut self, c: usize) -> Result<BatchResult> {
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
