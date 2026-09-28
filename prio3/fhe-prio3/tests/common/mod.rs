//! In-process network: every message crosses bincode serialization.
#![allow(dead_code)]

use fhe_prio3::messages::{decode, encode};
use fhe_prio3::*;
use std::sync::Mutex;

/// OpenFHE keeps evaluation keys in unsynchronised process-global tables.
pub static SERIAL: Mutex<()> = Mutex::new(());

/// Serialises tests; a panic in one test must not poison the rest.
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct Net {
    pub cfg: TaskConfig,
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
        let (material, shares) = keys::run_local_ceremony(&cfg).expect("ceremony");
        let material: PublicMaterial = decode(&encode(&material).unwrap()).unwrap();
        let aggs = shares
            .iter()
            .enumerate()
            .map(|(i, s)| Aggregator::new(cfg.clone(), &material, i, s).expect("aggregator"))
            .collect();
        let client = Client::new(cfg.clone(), &material.context, &material.public_key).expect("client");
        let collector = Collector::new(cfg.clone(), &material).expect("collector");
        Self { cfg, material, aggs, client, collector }
    }

    /// Runs the three preparation steps for one report on every aggregator.
    /// Returns one verdict per aggregator (a rejection at step 1 is reported
    /// as a verdict too).
    pub fn run_report(&mut self, report: &Report) -> Vec<Verdict> {
        let report: Report = decode(&encode(report).unwrap()).unwrap();
        let mut masks: Vec<MaskMessage> = Vec::new();
        let mut early = Vec::new();
        for a in self.aggs.iter_mut() {
            match a.prepare_init(&report) {
                Ok(m) => masks.push(decode(&encode(&m).unwrap()).unwrap()),
                Err(Error::Reject(r)) => early.push(Verdict::Rejected(r)),
                Err(e) => panic!("prepare_init failed: {e}"),
            }
        }
        if !early.is_empty() {
            assert_eq!(early.len(), self.aggs.len(), "aggregators must agree on structural rejections");
            return early;
        }
        let mut verifiers: Vec<VerifierMessage> = Vec::new();
        for a in self.aggs.iter_mut() {
            let others: Vec<MaskMessage> = masks.iter().filter(|m| m.aggregator != a.index()).cloned().collect();
            let v = a.prepare_masks(&report.report_id, &others).expect("prepare_masks");
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

    pub fn collect(&self) -> Result<(AggregateResult, u64)> {
        let shares: Vec<AggregateShare> = self
            .aggs
            .iter()
            .map(|a| a.aggregate_share())
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|s| decode(&encode(&s).unwrap()).unwrap())
            .collect();
        self.collector.unshard(&shares)
    }
}
