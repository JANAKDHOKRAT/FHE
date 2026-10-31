//! One-aggregator protocol: evaluator + collector holding the whole key.
use fhe_flp::bitvec::BitVec;
use fhe_flp::single::{Evaluator, SingleClient, SingleCollector, SingleTask};
use fhe_flp::{Field, PLAIN_MOD, VerifierMap};
use prio::field::FieldElement;
use prio::flp::types::Count;
use prio::flp::{Flp, Type};

const VK: [u8; 32] = [42u8; 32];

/// Runs a batch end to end; returns (verdict bits, verifiers, aggregate or None).
fn run<T: VerifierMap<Field>>(task: &SingleTask<Field, T>, reports: &[Vec<u8>]) -> (Vec<bool>, Vec<Vec<Field>>, Option<T::AggregateResult>) {
    let (mut collector, pk) = SingleCollector::new(task).unwrap();
    let mut ev = Evaluator::new(task, &pk, VK).unwrap();
    for r in reports {
        ev.ingest(r).unwrap();
    }
    let req = ev.check_request().unwrap();
    assert_eq!(req.len(), task.check_request_len(reports.len()));
    let (verdicts, verifiers) = collector.check_with_verifiers(&req).unwrap();
    let bits: Vec<bool> = (0..reports.len()).map(|i| verdicts[i / 8] >> (i % 8) & 1 == 1).collect();
    let agg = if bits.iter().any(|&b| b) {
        let a = ev.aggregate_request(&verdicts).unwrap();
        assert_eq!(a.len(), task.aggregate_request_len());
        Some(collector.unshard(&a).unwrap())
    } else {
        None
    };
    (bits, verifiers, agg)
}

/// Clients need the collector's public key; tests make reports under a key
/// created by the same collector the batch then uses.
struct Batch<'a, T: VerifierMap<Field>> {
    task: &'a SingleTask<Field, T>,
    collector: SingleCollector<'a, Field, T>,
    pk: openfhe_tbgv_rs::PublicKey,
}

impl<'a, T: VerifierMap<Field>> Batch<'a, T> {
    fn new(task: &'a SingleTask<Field, T>) -> Self {
        let (collector, pk) = SingleCollector::new(task).unwrap();
        Self { task, collector, pk }
    }
    fn client(&self) -> SingleClient<'_, Field, T> {
        SingleClient::new(self.task, &self.pk)
    }
    fn run(&mut self, reports: &[Vec<u8>]) -> (Vec<bool>, Vec<Vec<Field>>, Option<T::AggregateResult>) {
        let mut ev = Evaluator::new(self.task, &self.pk, VK).unwrap();
        for r in reports {
            ev.ingest(r).unwrap();
        }
        let req = ev.check_request().unwrap();
        assert_eq!(req.len(), self.task.check_request_len(reports.len()));
        let (verdicts, verifiers) = self.collector.check_with_verifiers(&req).unwrap();
        let bits: Vec<bool> = (0..reports.len()).map(|i| verdicts[i / 8] >> (i % 8) & 1 == 1).collect();
        let agg = if bits.iter().any(|&b| b) {
            let a = ev.aggregate_request(&verdicts).unwrap();
            assert_eq!(a.len(), self.task.aggregate_request_len());
            Some(self.collector.unshard(&a).unwrap())
        } else {
            None
        };
        (bits, verifiers, agg)
    }
}

#[test]
fn count_end_to_end() {
    let task = SingleTask::new(Count::<Field>::new(), [1u8; 32], 5).unwrap();
    assert_eq!(task.context().ring_dim(), 8192);
    let mut b = Batch::new(&task);
    let ms = [true, false, true, true, false, true, true];
    let reports: Vec<Vec<u8>> = ms.iter().map(|m| b.client().shard(m).unwrap()).collect();
    assert_eq!(reports[0].len(), task.report_len());
    let (bits, _, agg) = b.run(&reports);
    assert!(bits.iter().all(|&x| x));
    assert_eq!(agg, Some(5));
}

#[test]
fn decrypted_verifier_is_exactly_prio_query() {
    let task = SingleTask::new(Count::<Field>::new(), [2u8; 32], 4).unwrap();
    let mut b = Batch::new(&task);
    let typ = Count::<Field>::new();
    let mut reports = Vec::new();
    let mut witnesses = Vec::new();
    for m in [false, true] {
        let input = typ.encode_measurement(&m).unwrap();
        let (r, z) = b.client().shard_with_witness(&input).unwrap();
        reports.push(r);
        witnesses.push((input, z));
    }
    let (bits, verifiers, _) = b.run(&reports);
    assert_eq!(bits, vec![true, true]);
    let (il, pl, vl) = (typ.input_len(), typ.proof_len(), typ.verifier_len());
    for ((r, (input, z)), v) in reports.iter().zip(&witnesses).zip(&verifiers) {
        for (p, qr) in task.query_rands(&VK, r).unwrap().iter().enumerate() {
            let plain = typ.query(input, &z[il + p * pl..il + (p + 1) * pl], qr, &[], 1).unwrap();
            assert_eq!(&v[p * vl..(p + 1) * vl], &plain[..], "proof {p}");
        }
    }
}

#[test]
fn invalid_inputs_and_tampered_proofs_are_rejected_and_not_counted() {
    let task = SingleTask::new(Count::<Field>::new(), [3u8; 32], 5).unwrap();
    let mut b = Batch::new(&task);
    let c = b.client();
    let mut reports = vec![c.shard(&true).unwrap()];
    for bad in [2u32, 3, (PLAIN_MOD - 1) as u32, 1 << 31] {
        reports.push(c.shard_with_witness(&[Field::from(bad)]).unwrap().0);
    }
    let (_, z) = c.shard_with_witness(&[Field::one()]).unwrap();
    for i in 1..z.len() {
        let mut t = z.clone();
        t[i] += Field::one();
        reports.push(c.report_from_coefficients(&t).unwrap());
    }
    reports.push(c.shard(&true).unwrap());
    let (bits, _, agg) = b.run(&reports);
    let accepted: Vec<usize> = bits.iter().enumerate().filter(|(_, x)| **x).map(|(i, _)| i).collect();
    assert_eq!(accepted, vec![0, reports.len() - 1]);
    assert_eq!(agg, Some(2));
}

#[test]
fn bitvec100_end_to_end_and_rejects_a_single_non_bit() {
    let task = SingleTask::new(BitVec::<Field>::new(100).unwrap(), [4u8; 32], 6).unwrap();
    let mut b = Batch::new(&task);
    let c = b.client();
    let mut want = vec![0u32; 100];
    let mut reports = Vec::new();
    for s in 0..3u32 {
        let m: Vec<bool> = (0..100).map(|i| (i * 7 + s * 3) % 5 < 2).collect();
        for (w, &x) in want.iter_mut().zip(&m) {
            *w += x as u32;
        }
        reports.push(c.shard(&m).unwrap());
    }
    let mut bad = vec![Field::zero(); 100];
    bad[57] = Field::from(2u32);
    reports.push(c.shard_with_witness(&bad).unwrap().0);
    let (bits, _, agg) = b.run(&reports);
    assert_eq!(bits, vec![true, true, true, false]);
    assert_eq!(agg, Some(want));
}

#[test]
fn malformed_replayed_and_flipped_reports() {
    let task = SingleTask::new(Count::<Field>::new(), [5u8; 32], 2).unwrap();
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let c = SingleClient::new(&task, &pk);
    let mut ev = Evaluator::new(&task, &pk, VK).unwrap();
    let r = c.shard(&true).unwrap();
    assert!(ev.ingest(&r[1..]).is_err());
    let mut ones = r.clone();
    ones[16..40].fill(0xff);
    assert!(ev.ingest(&ones).is_err());
    ev.ingest(&r).unwrap();
    assert!(ev.ingest(&r).is_err(), "replayed nonce accepted");
    // flipped ciphertext bits: parsed reports are rejected by the FLP
    let mut flipped = 0;
    for pos in [100usize, 50_000, 200_000, 340_000] {
        let mut f = c.shard(&true).unwrap();
        f[pos] ^= 1;
        if ev.ingest(&f).is_ok() {
            flipped += 1;
        }
    }
    let verdicts = collector.check(&ev.check_request().unwrap()).unwrap();
    let bits: Vec<bool> = (0..ev.len()).map(|i| verdicts[i / 8] >> (i % 8) & 1 == 1).collect();
    assert_eq!(bits.len(), 1 + flipped);
    assert!(bits[0] && bits[1..].iter().all(|&x| !x), "{bits:?}");
}

#[test]
fn collector_refuses_inconsistent_requests() {
    let task = SingleTask::new(Count::<Field>::new(), [6u8; 32], 2).unwrap();
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let c = SingleClient::new(&task, &pk);
    let mut ev = Evaluator::new(&task, &pk, VK).unwrap();
    for m in [true, true] {
        ev.ingest(&c.shard(&m).unwrap()).unwrap();
    }
    // an invalid input: the collector accepts two of three
    ev.ingest(&c.shard_with_witness(&[Field::from(2u32)]).unwrap().0).unwrap();
    let req = ev.check_request().unwrap();
    assert!(collector.check(&req[..req.len() - 1]).is_err());
    let verdicts = collector.check(&req).unwrap();
    // an aggregate over more reports than the collector accepted
    let lie = ev.aggregate_request(&[0b0000_0111]).unwrap();
    assert!(collector.unshard(&lie).is_err());
    assert!(ev.aggregate_request(&[0u8; 2]).is_err());
    let a = ev.aggregate_request(&verdicts).unwrap();
    assert_eq!(collector.unshard(&a).unwrap(), 2);
}

#[test]
fn check_requests_are_freshly_masked_and_flooded() {
    let task = SingleTask::new(Count::<Field>::new(), [7u8; 32], 2).unwrap();
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let mut ev = Evaluator::new(&task, &pk, VK).unwrap();
    ev.ingest(&SingleClient::new(&task, &pk).shard(&true).unwrap()).unwrap();
    let a = ev.check_request().unwrap();
    let b = ev.check_request().unwrap();
    assert_ne!(a, b);
    assert_eq!(collector.check_with_verifiers(&a).unwrap(), collector.check_with_verifiers(&b).unwrap());
}

#[test]
fn a_report_under_another_key_is_rejected() {
    let task = SingleTask::new(Count::<Field>::new(), [8u8; 32], 2).unwrap();
    let (_, pk) = SingleCollector::new(&task).unwrap();
    // reports under another collector's key do not decrypt to valid verifiers
    let r = SingleClient::new(&task, &pk).shard(&true).unwrap();
    let (bits, _, agg) = run(&task, &[r]);
    assert_eq!(bits, vec![false]);
    assert_eq!(agg, None);
}
