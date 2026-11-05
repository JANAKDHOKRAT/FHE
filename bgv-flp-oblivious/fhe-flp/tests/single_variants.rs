//! Prio3's Sum, SumVec, Histogram and MultihotCountVec in the one-aggregator
//! protocol: prio's types, encodings and FLP unchanged, p = 65537 (and
//! FieldPrio2), one evaluator, a collector holding the whole key.
use fhe_flp::FheField;
use fhe_flp::VerifierMap;
use fhe_flp::f65537::Field65537 as F;
use fhe_flp::protocol::NONCE_LEN;
use fhe_flp::single::{Evaluator, SingleClient, SingleCollector, SingleTask};
use fhe_flp::soundness::proofs_for_with_joint_rand;
use prio::field::{FieldElement, FieldElementWithInteger, FieldPrio2};
use prio::flp::gadgets::{Mul, ParallelSum};
use prio::flp::types::{Histogram, MultihotCountVec, Sum, SumVec};
use prio::flp::{Flp, Type};
use prio::vdaf::prio3::optimal_chunk_length;
use rand::RngCore;
use rand::rngs::OsRng;

const VK: [u8; 32] = [21u8; 32];
type Ps<G> = ParallelSum<G, Mul>;

/// The fewest proofs reaching 2^-128, joint randomness included.
fn k_for<G: FheField, T: VerifierMap<G>>(typ: &T) -> usize {
    proofs_for_with_joint_rand(typ, G::PLAIN_MOD as f64, 128.0, typ.joint_rand_degree())
}

/// Ingests `reports`, runs the batch; returns verdict bits, verifiers, aggregate.
fn batch<G: FheField, T: VerifierMap<G>>(
    task: &SingleTask<G, T>,
    collector: &mut SingleCollector<G, T>,
    pk: &openfhe_tbgv_rs::PublicKey,
    reports: &[Vec<u8>],
) -> (Vec<bool>, Vec<Vec<G>>, Option<T::AggregateResult>) {
    let mut ev = Evaluator::new(task, pk, VK).unwrap();
    for r in reports {
        ev.ingest(r).unwrap();
    }
    let request = ev.check_request().unwrap();
    assert_eq!(request.len(), task.check_request_len(reports.len()));
    let (verdicts, verifiers) = collector.check_with_verifiers(&request).unwrap();
    let bits: Vec<bool> = (0..reports.len()).map(|i| verdicts[i / 8] >> (i % 8) & 1 == 1).collect();
    let agg = bits.iter().any(|&b| b).then(|| {
        let request = ev.aggregate_request(&verdicts).unwrap();
        assert_eq!(request.len(), task.aggregate_request_len());
        collector.unshard(&request).unwrap()
    });
    (bits, verifiers, agg)
}

/// The collector's verifier of every report is exactly prio's `query` on
/// the report's input and proofs, with the evaluator's query randomness and
/// the joint randomness bound to the input ciphertext.
fn assert_verifiers_are_prio_query<G: FheField, T: VerifierMap<G>>(
    task: &SingleTask<G, T>,
    reports: &[Vec<u8>],
    witnesses: &[(Vec<G>, Vec<G>)],
    verifiers: &[Vec<G>],
) {
    let typ = task.typ();
    let (il, pl, vl) = (typ.input_len(), typ.proof_len(), typ.verifier_len());
    for ((r, (input, z)), v) in reports.iter().zip(witnesses).zip(verifiers) {
        let jrs = task.joint_rands(r).unwrap();
        for (p, qr) in task.query_rands(&VK, r).unwrap().iter().enumerate() {
            let plain = typ.query(input, &z[il + p * pl..il + (p + 1) * pl], qr, &jrs[p], 1).unwrap();
            assert_eq!(&v[p * vl..(p + 1) * vl], &plain[..], "proof {p}");
        }
    }
}

#[test]
fn sum_end_to_end_one_ciphertext() {
    let typ = Sum::<F>::new(100).unwrap();
    let k = k_for(&typ);
    let task = SingleTask::new(typ.clone(), [1u8; 32], k).unwrap();
    assert_eq!(task.ciphertexts_per_report(), 1);
    assert_eq!(task.report_len(), 245_776);
    assert!(task.log2_soundness() <= -128.0);
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let c = SingleClient::new(&task, &pk);
    let ms = [0u32, 7, 100, 55, 1, 64];
    let mut reports = Vec::new();
    let mut witnesses = Vec::new();
    for m in ms {
        let input = typ.encode_measurement(&m).unwrap();
        let (r, z) = c.shard_with_witness(&input).unwrap();
        reports.push(r);
        witnesses.push((input, z));
    }
    // invalid: a coordinate that is not a bit, honestly proved
    let mut bad = typ.encode_measurement(&5).unwrap();
    bad[2] = F::from(2);
    reports.push(c.shard_with_witness(&bad).unwrap().0);
    // tampered: one proof coefficient changed
    let (_, mut z) = c.shard_with_witness(&typ.encode_measurement(&9).unwrap()).unwrap();
    let last = z.len() - 1;
    z[last] += F::one();
    reports.push(c.report_from_coefficients(&z).unwrap());

    let (bits, verifiers, agg) = batch(&task, &mut collector, &pk, &reports);
    assert_eq!(bits, [vec![true; ms.len()], vec![false, false]].concat());
    assert_eq!(agg, Some(ms.iter().sum::<u32>()));
    assert_verifiers_are_prio_query(&task, &reports[..ms.len()], &witnesses, &verifiers[..ms.len()]);
}

#[test]
fn sumvec_end_to_end_two_ciphertexts_with_joint_randomness() {
    let (max, len) = (3u32, 10usize);
    let bits = 2;
    let typ = SumVec::<F, Ps<F>>::new(max, len, optimal_chunk_length(len * bits)).unwrap();
    assert!(typ.joint_rand_len() > 0);
    let k = k_for(&typ);
    let task = SingleTask::new(typ.clone(), [2u8; 32], k).unwrap();
    assert_eq!(task.ciphertexts_per_report(), 2);
    assert_eq!(task.report_len(), NONCE_LEN + 2 * 245_760);
    assert!(task.log2_soundness() <= -128.0);
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let c = SingleClient::new(&task, &pk);
    let ms: Vec<Vec<u32>> = (0..4u32).map(|s| (0..len as u32).map(|i| (i * 5 + s * 3) % (max + 1)).collect()).collect();
    let mut want = vec![0u32; len];
    let mut reports = Vec::new();
    let mut witnesses = Vec::new();
    for m in &ms {
        for (w, x) in want.iter_mut().zip(m) {
            *w += x;
        }
        let input = typ.encode_measurement(m).unwrap();
        let (r, z) = c.shard_with_witness(&input).unwrap();
        assert_eq!(r.len(), task.report_len());
        reports.push(r);
        witnesses.push((input, z));
    }
    let mut bad = typ.encode_measurement(&vec![1; len]).unwrap();
    bad[7] = F::from(2);
    reports.push(c.shard_with_witness(&bad).unwrap().0);
    let (_, mut z) = c.shard_with_witness(&typ.encode_measurement(&vec![2; len]).unwrap()).unwrap();
    let il = typ.input_len();
    z[il + 1] += F::one();
    reports.push(c.report_from_coefficients(&z).unwrap());

    let (bits, verifiers, agg) = batch(&task, &mut collector, &pk, &reports);
    assert_eq!(bits, vec![true, true, true, true, false, false]);
    assert_eq!(agg, Some(want));
    assert_verifiers_are_prio_query(&task, &reports[..4], &witnesses, &verifiers[..4]);
}

/// The input that fixed the joint randomness is the input that is checked
/// and aggregated: the proof ciphertext cannot change it, and the joint
/// randomness follows the input ciphertext.
#[test]
fn the_proofs_cannot_change_the_input_that_fixed_the_joint_randomness() {
    let len = 8usize;
    let typ = SumVec::<F, Ps<F>>::new(1, len, optimal_chunk_length(len)).unwrap();
    let k = k_for(&typ);
    let task = SingleTask::new(typ.clone(), [3u8; 32], k).unwrap();
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let c = SingleClient::new(&task, &pk);
    let il = typ.input_len();
    let good = typ.encode_measurement(&vec![1, 0, 1, 1, 0, 0, 1, 0]).unwrap();
    let mut bad = good.clone();
    bad[1] = F::from(5);

    // A report built part by part: the input ciphertext of `input`, then
    // `extra` at the input coefficients of the proof ciphertext and proofs
    // of `proved` under the joint randomness of that input ciphertext.
    let build = |input: &[F], extra: &[F], proved: &[F]| -> Vec<u8> {
        let mut nonce = vec![0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let c_in = c.encrypt_coefficients(input).unwrap();
        let placeholder = [nonce.clone(), c_in.clone(), c_in.clone()].concat();
        let jrs = task.joint_rands(&placeholder).unwrap();
        let mut pf = extra.to_vec();
        pf.resize(il, F::zero());
        for jr in &jrs {
            pf.extend(typ.prove(proved, &F::random_vector(typ.prove_rand_len()), jr).unwrap());
        }
        [nonce, c_in, c.encrypt_coefficients(&pf).unwrap()].concat()
    };
    let zero = vec![F::zero(); il];
    let delta: Vec<F> = good.iter().zip(&bad).map(|(&g, &b)| g - b).collect();
    let honest = build(&good, &zero, &good);
    // proofs for `good` with the input coefficients of the proof ciphertext
    // turning `bad` into `good`: the sum of the two plaintexts is a valid z
    let attack = build(&bad, &delta, &good);
    // proofs for `bad` itself
    let invalid = build(&bad, &zero, &bad);
    // a valid report whose input ciphertext is swapped for another's
    let other = c.shard(&vec![0, 1, 0, 0, 1, 1, 0, 1]).unwrap();
    let fl = (task.report_len() - NONCE_LEN) / 2;
    let mut swapped = other.clone();
    swapped[NONCE_LEN..NONCE_LEN + fl].copy_from_slice(&honest[NONCE_LEN..NONCE_LEN + fl]);

    let (bits, _, agg) = batch(&task, &mut collector, &pk, &[honest, attack, invalid, swapped]);
    assert_eq!(bits, vec![true, false, false, false]);
    assert_eq!(agg, Some(vec![1, 0, 1, 1, 0, 0, 1, 0]));
}

#[test]
fn histogram_end_to_end_rejects_two_hot_and_zero_vectors() {
    let len = 20usize;
    let typ = Histogram::<F, Ps<F>>::new(len, optimal_chunk_length(len)).unwrap();
    let k = k_for(&typ);
    let task = SingleTask::new(typ.clone(), [4u8; 32], k).unwrap();
    assert_eq!(task.ciphertexts_per_report(), 2);
    assert_eq!(task.max_batch(), 65_536);
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let c = SingleClient::new(&task, &pk);
    let ms = [3usize, 3, 19, 0, 7];
    let mut want = vec![0u32; len];
    let mut reports = Vec::new();
    let mut witnesses = Vec::new();
    for &m in &ms {
        want[m] += 1;
        let input = typ.encode_measurement(&m).unwrap();
        let (r, z) = c.shard_with_witness(&input).unwrap();
        reports.push(r);
        witnesses.push((input, z));
    }
    let mut two_hot = typ.encode_measurement(&2).unwrap();
    two_hot[11] = F::one();
    reports.push(c.shard_with_witness(&two_hot).unwrap().0);
    reports.push(c.shard_with_witness(&vec![F::zero(); len]).unwrap().0);
    let (bits, verifiers, agg) = batch(&task, &mut collector, &pk, &reports);
    assert_eq!(bits, [vec![true; ms.len()], vec![false, false]].concat());
    assert_eq!(agg, Some(want));
    assert_verifiers_are_prio_query(&task, &reports[..ms.len()], &witnesses, &verifiers[..ms.len()]);
}

#[test]
fn multihot_end_to_end_in_field_prio2_rejects_overweight() {
    type G = FieldPrio2;
    let (len, max_weight) = (10usize, 3usize);
    let typ = MultihotCountVec::<G, Ps<G>>::new(len, max_weight, optimal_chunk_length(len + 2)).unwrap();
    let k = k_for(&typ);
    let task = SingleTask::new(typ.clone(), [5u8; 32], k).unwrap();
    assert_eq!(task.ciphertexts_per_report(), 2);
    assert!(task.log2_soundness() <= -128.0);
    let (mut collector, pk) = SingleCollector::new(&task).unwrap();
    let c = SingleClient::new(&task, &pk);
    let ms: Vec<Vec<bool>> = vec![
        (0..len).map(|i| i == 2 || i == 5).collect(),
        (0..len).map(|i| i == 5).collect(),
        vec![false; len],
        (0..len).map(|i| i % 4 == 1).collect(),
    ];
    let mut want = vec![0u32; len];
    let mut reports = Vec::new();
    for m in &ms {
        for (w, &b) in want.iter_mut().zip(m) {
            *w += b as u32;
        }
        reports.push(c.shard(m).unwrap());
    }
    // a fourth bucket set without updating the encoded weight
    let mut over = typ.encode_measurement(&(0..len).map(|i| i % 4 == 1).collect()).unwrap();
    over[0] = G::one();
    reports.push(c.shard_with_witness(&over).unwrap().0);
    let (bits, _, agg) = batch(&task, &mut collector, &pk, &reports);
    assert_eq!(bits, vec![true, true, true, true, false]);
    assert_eq!(agg, Some(want));
}

#[test]
fn batches_are_capped_by_the_largest_output() {
    let sum = SingleTask::new(Sum::<F>::new(100).unwrap(), [6u8; 32], 9).unwrap();
    assert_eq!(sum.max_batch(), 655);
    let sv = SingleTask::new(SumVec::<F, Ps<F>>::new(3, 10, 4).unwrap(), [6u8; 32], 9).unwrap();
    assert_eq!(sv.max_batch(), 21_845);
    let sum2 = SingleTask::new(Sum::<FieldPrio2>::new(1000).unwrap(), [6u8; 32], 5).unwrap();
    assert_eq!(sum2.max_batch(), 4_293_918_720 / 1000);
    // a full batch is refused by the evaluator
    let typ = Sum::<F>::new(65_535).unwrap();
    let task = SingleTask::new(typ.clone(), [7u8; 32], 9).unwrap();
    assert_eq!(task.max_batch(), 1);
    let (_collector, pk) = SingleCollector::new(&task).unwrap();
    let c = SingleClient::new(&task, &pk);
    let mut ev = Evaluator::new(&task, &pk, VK).unwrap();
    ev.ingest(&c.shard(&65_535).unwrap()).unwrap();
    assert!(ev.ingest(&c.shard(&1).unwrap()).is_err());
}

/// Measurement encodings and aggregate decodings are prio's own.
#[test]
fn encodings_are_prio3s() {
    let typ = SumVec::<F, Ps<F>>::new(3, 4, 2).unwrap();
    let input = typ.encode_measurement(&vec![3, 0, 2, 1]).unwrap();
    assert_eq!(input.iter().map(|x| x.to_u64()).collect::<Vec<_>>(), vec![1, 1, 0, 0, 0, 1, 1, 0]);
    let typ = Sum::<F>::new(100).unwrap();
    assert_eq!(typ.input_len(), 7);
    assert_eq!(
        <F as FieldElementWithInteger>::Integer::from(100u32),
        typ.decode_result(&typ.truncate(typ.encode_measurement(&100).unwrap()).unwrap(), 1).unwrap()
    );
}
