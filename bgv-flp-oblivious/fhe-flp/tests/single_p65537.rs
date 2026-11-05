//! The one-aggregator protocol with p = 65537 (`Field65537` as the FLP field
//! and the BGV plaintext modulus).
use fhe_flp::FheField;
use fhe_flp::bitvec::BitVec;
use fhe_flp::f65537::Field65537 as F;
use fhe_flp::single::{Evaluator, SingleClient, SingleCollector, SingleTask};
use fhe_flp::soundness::{log2_error, proofs_for};
use fhe_flp::{Error, VerifierMap};
use prio::field::{FieldElement, FieldElementWithInteger, NttFriendlyFieldElement};
use prio::flp::types::Count;
use prio::flp::{Flp, Type};

const VK: [u8; 32] = [11u8; 32];

fn k_for<T: Flp>(typ: &T) -> usize
where
    T::Field: prio::field::NttFriendlyFieldElement,
{
    proofs_for(typ, F::PLAIN_MOD as f64, 128.0)
}

/// Ingests `reports`, runs the batch; returns verdict bits, verifiers, aggregate.
fn batch<T: VerifierMap<F>>(
    task: &SingleTask<F, T>,
    collector: &mut SingleCollector<F, T>,
    pk: &openfhe_tbgv_rs::PublicKey,
    reports: &[Vec<u8>],
) -> (Vec<bool>, Vec<Vec<F>>, Option<T::AggregateResult>) {
    let mut ev = Evaluator::new(task, pk, VK).unwrap();
    for r in reports {
        ev.ingest(r).unwrap();
    }
    let (verdicts, verifiers) = collector.check_with_verifiers(&ev.check_request().unwrap()).unwrap();
    let bits: Vec<bool> = (0..reports.len()).map(|i| verdicts[i / 8] >> (i % 8) & 1 == 1).collect();
    let agg = bits
        .iter()
        .any(|&b| b)
        .then(|| collector.unshard(&ev.aggregate_request(&verdicts).unwrap()).unwrap());
    (bits, verifiers, agg)
}

#[test]
fn proofs_for_2_to_the_minus_128() {
    let count = Count::<F>::new();
    assert_eq!(k_for(&count), 9);
    assert!(log2_error(&count, F::PLAIN_MOD as f64, 9) <= -128.0);
    assert_eq!(k_for(&BitVec::<F>::new(100).unwrap()), 16);
    // the padded-degree bound used here is never below the draft script's
    for len in [1usize, 10, 25, 50, 100] {
        let t = BitVec::<F>::new(len).unwrap();
        let p = F::PLAIN_MOD as f64;
        assert!(fhe_flp::soundness::log2_per_proof(&t, p) >= fhe_flp::soundness::log2_per_proof_draft(&t, p));
    }
    // and it is the one that decides: BitVec(50) needs 15 proofs, not 14
    let bv50 = BitVec::<F>::new(50).unwrap();
    assert_eq!(k_for(&bv50), 15);
    assert!(log2_error(&bv50, F::PLAIN_MOD as f64, 14) > -128.0);
    assert!(log2_error(&bv50, F::PLAIN_MOD as f64, 15) <= -128.0);
}

#[test]
fn count_end_to_end_with_exact_prio_verifiers() {
    let typ = Count::<F>::new();
    let task = SingleTask::new(typ.clone(), [1u8; 32], k_for(&typ)).unwrap();
    assert_eq!(task.context().ring_dim(), 8192);
    assert_eq!(task.context().plain_mod(), 65_537);
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let c = SingleClient::new(&task, &pk);
    let ms = [true, false, true, true, false];
    let mut reports = Vec::new();
    let mut witnesses = Vec::new();
    for m in ms {
        let input = typ.encode_measurement(&m).unwrap();
        let (r, z) = c.shard_with_witness(&input).unwrap();
        assert_eq!(r.len(), task.report_len());
        reports.push(r);
        witnesses.push((input, z));
    }
    let (bits, verifiers, agg) = batch(&task, &mut collector, &pk, &reports);
    assert!(bits.iter().all(|&b| b));
    assert_eq!(agg, Some(3));
    let (il, pl, vl) = (typ.input_len(), typ.proof_len(), typ.verifier_len());
    for ((r, (input, z)), v) in reports.iter().zip(&witnesses).zip(&verifiers) {
        for (p, qr) in task.query_rands(&VK, r).unwrap().iter().enumerate() {
            let plain = typ.query(input, &z[il + p * pl..il + (p + 1) * pl], qr, &[], 1).unwrap();
            assert_eq!(&v[p * vl..(p + 1) * vl], &plain[..], "proof {p}");
        }
    }
}

#[test]
fn invalid_and_tampered_reports_are_rejected() {
    let typ = Count::<F>::new();
    let task = SingleTask::new(typ.clone(), [2u8; 32], k_for(&typ)).unwrap();
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let c = SingleClient::new(&task, &pk);
    let mut reports = vec![c.shard(&true).unwrap()];
    for bad in [2u32, 3, 65_536, 1 << 15] {
        reports.push(c.shard_with_witness(&[F::from(bad)]).unwrap().0);
    }
    let (_, z) = c.shard_with_witness(&[F::one()]).unwrap();
    for i in 1..z.len() {
        let mut t = z.clone();
        t[i] += F::one();
        reports.push(c.report_from_coefficients(&t).unwrap());
    }
    let (bits, _, agg) = batch(&task, &mut collector, &pk, &reports);
    let accepted: Vec<usize> = bits.iter().enumerate().filter(|(_, b)| **b).map(|(i, _)| i).collect();
    assert_eq!(accepted, vec![0]);
    assert_eq!(agg, Some(1));
}

#[test]
fn bitvec_end_to_end_and_rejects_a_non_bit() {
    for len in [10usize, 100] {
        let typ = BitVec::<F>::new(len).unwrap();
        let task = SingleTask::new(typ.clone(), [3u8; 32], k_for(&typ)).unwrap();
        let (mut collector, pk) = SingleCollector::new(&task).unwrap();
        let c = SingleClient::new(&task, &pk);
        let mut want = vec![0u32; len];
        let mut reports = Vec::new();
        for s in 0..2u32 {
            let m: Vec<bool> = (0..len as u32).map(|i| (i * 7 + s * 3) % 5 < 2).collect();
            for (w, &x) in want.iter_mut().zip(&m) {
                *w += x as u32;
            }
            reports.push(c.shard(&m).unwrap());
        }
        let mut bad = vec![F::zero(); len];
        bad[len / 2] = F::from(2);
        reports.push(c.shard_with_witness(&bad).unwrap().0);
        let (bits, _, agg) = batch(&task, &mut collector, &pk, &reports);
        assert_eq!(bits, vec![true, true, false], "len {len}");
        assert_eq!(agg, Some(want), "len {len}");
    }
}

#[test]
fn circuits_beyond_the_fields_roots_are_refused_not_panicking() {
    // 2^15 calls: W = 2^16 needs roots of order 2^17, which GF(65537) lacks
    // (prio's NTT panics there); 2^15 - 1 calls (W = 2^15) passes the root
    // check and is refused only because it does not fit the ring.
    let typ = BitVec::<F>::new(1 << 15).unwrap();
    match SingleTask::new(typ, [4u8; 32], 1) {
        Err(Error::Protocol(m)) => assert!(m.contains("roots of unity"), "{m}"),
        Err(e) => panic!("unexpected error {e}"),
        Ok(_) => panic!("accepted a circuit prio's NTT cannot handle in this field"),
    }
    match SingleTask::new(BitVec::<F>::new((1 << 15) - 1).unwrap(), [4u8; 32], 1) {
        Err(Error::Protocol(m)) => assert!(m.contains("coefficients"), "{m}"),
        Err(e) => panic!("unexpected error {e}"),
        Ok(_) => panic!("accepted input and proofs larger than the ring"),
    }
}

#[test]
fn batches_are_capped_so_sums_never_wrap_modulo_p() {
    let count = SingleTask::new(Count::<F>::new(), [5u8; 32], 9).unwrap();
    assert_eq!(count.max_batch(), 65_536);
    let bv = SingleTask::new(BitVec::<F>::new(10).unwrap(), [5u8; 32], 12).unwrap();
    assert_eq!(bv.max_batch(), 65_536);
    let prio2 = SingleTask::new(Count::<fhe_flp::Field>::new(), [5u8; 32], 5).unwrap();
    assert_eq!(prio2.max_batch(), 1 << 24);
}

/// In a 17-bit field the gadget query point lands on a 2W-th root of unity
/// with probability 2W/p (not negligible): the closed form must still equal
/// prio's query there, and W-th roots must never be drawn.
#[test]
fn closed_form_at_roots_of_unity_in_gf65537() {
    use fhe_flp::bitvec::mul_bits_map;
    for len in [1usize, 10, 100] {
        let typ = BitVec::<F>::new(len).unwrap();
        let w = (len + 1).next_power_of_two();
        let r = F::root((2 * w).trailing_zeros() as usize).unwrap().pow(3); // r^W = -1
        assert_eq!(r.pow(w as u32), -F::one());
        let mut qr: Vec<F> = (0..typ.query_rand_len() as u32 - 1).map(|i| F::from(17 + i)).collect();
        qr.push(r);
        let z = F::random_vector(typ.input_len() + typ.proof_len());
        let want = typ.query(&z[..len], &z[len..], &qr, &[], 1).unwrap();
        let (rows, c) = mul_bits_map(len, len > 1, &qr);
        for (k, row) in rows.iter().enumerate() {
            assert_eq!(row.iter().zip(&z).fold(c[k], |a, (&x, &y)| a + x * y), want[k], "len {len} row {k}");
        }
    }
    // the evaluator's query randomness never contains a W-th root of unity
    let typ = BitVec::<F>::new(100).unwrap();
    let task = SingleTask::new(typ, [6u8; 32], 16).unwrap();
    for i in 0..200u32 {
        let mut report = vec![0u8; 64];
        report[..4].copy_from_slice(&i.to_le_bytes());
        for qr in task.query_rands(&VK, &report).unwrap() {
            assert_ne!(qr.last().unwrap().pow(128), F::one());
        }
    }
}
