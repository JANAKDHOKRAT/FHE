//! PINE in the one-aggregator protocol, end to end with real BGV
//! ciphertexts, keys and noise (OpenFHE 1.3.1, ring 8192): honest batches,
//! the verifier the collector decrypts against prio's `query`, and
//! malicious clients.
use fhe_flp::pine::circuit::{NUM_WR_CHECKS, Shape};
use fhe_flp::pine::{PART_GRADIENT, PART_PROOFS, PART_WRAPAROUND, PineClient, PineCollector, PineEvaluator, PineParams, PineTask};
use fhe_flp::{Field, PLAIN_MOD};
use prio::field::FieldElement;
use prio::flp::Flp;

const VERIFY_KEY: [u8; 32] = [42; 32];

/// Real norm bound 1.0 with 7 fractional bits, as the reference's first
/// test vector; two main proofs keep the tests short.
fn params(dimension: usize) -> PineParams {
    PineParams {
        dimension,
        l2_norm_bound: 128,
        num_frac_bits: 7,
        chunk_length: 4,
        chunk_length_norm_equality: 4,
        num_proofs: 2,
        num_proofs_norm_equality: 1,
    }
}

fn f(v: u64) -> Field {
    Field::from(u32::try_from(v).unwrap())
}

fn bits(v: u64, n: usize) -> Vec<Field> {
    (0..n).map(|j| f(v >> j & 1)).collect()
}

/// The wraparound part an honest client sends for these dot products.
fn honest_claim(shape: &Shape, results: &[Field]) -> Vec<Field> {
    let mut out = Vec::new();
    for &r in results {
        let v = u64::from(u32::from(r + f(shape.wr_bound() - 1)));
        assert!(v < 2 * shape.wr_bound(), "an honest dot product left the range");
        out.extend(bits(v, shape.wr_bits()));
        out.push(Field::one());
    }
    out
}

/// Runs a batch: the verdicts and, when a report was accepted, the sum.
fn run(task: &PineTask, collector: &mut PineCollector, pk: &openfhe_tbgv_rs::PublicKey, reports: &[Vec<u8>]) -> (Vec<bool>, Option<Vec<f64>>) {
    let mut evaluator = PineEvaluator::new(task, pk, VERIFY_KEY).unwrap();
    for r in reports {
        evaluator.ingest(r).unwrap();
    }
    let verdicts = collector.check(&evaluator.check_request().unwrap()).unwrap();
    let accepted: Vec<bool> = (0..reports.len()).map(|i| verdicts[i / 8] >> (i % 8) & 1 == 1).collect();
    let sum = accepted
        .iter()
        .any(|&a| a)
        .then(|| collector.unshard(&evaluator.aggregate_request(&verdicts).unwrap()).unwrap());
    (accepted, sum)
}

/// The exact sum of the encoded gradients.
fn expected(shape: &Shape, gradients: &[&[f64]]) -> Vec<f64> {
    let mut sum = vec![0i64; shape.dimension()];
    for g in gradients {
        for (s, q) in sum.iter_mut().zip(shape.encode_gradient(g).unwrap()) {
            *s += q;
        }
    }
    sum.into_iter().map(|s| s as f64 / 2f64.powi(shape.num_frac_bits() as i32)).collect()
}

fn gradient(dimension: usize, seed: u64) -> Vec<f64> {
    // Coordinates in [-0.5, 0.5) / sqrt(d): norm below 0.5.
    let mut state = seed;
    (0..dimension)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((state >> 11) as f64 / (1u64 << 53) as f64 - 0.5) / (dimension as f64).sqrt()
        })
        .collect()
}

#[test]
fn honest_gradients_are_summed_exactly() {
    let task = PineTask::new(params(20), [1; 32]).unwrap();
    let (mut collector, pk) = PineCollector::new(&task).unwrap();
    let client = PineClient::new(&task, &pk);
    let mut at_bound = vec![0.0; 20];
    at_bound[3] = -1.0; // norm exactly at the bound
    let gradients = [gradient(20, 1), gradient(20, 2), at_bound, vec![0.0; 20]];
    let reports: Vec<Vec<u8>> = gradients.iter().map(|g| client.shard(g).unwrap()).collect();
    assert_eq!(reports[0].len(), task.report_len());
    let (accepted, sum) = run(&task, &mut collector, &pk, &reports);
    assert_eq!(accepted, vec![true; 4]);
    assert_eq!(collector.accepted(), Some(4));
    let refs: Vec<&[f64]> = gradients.iter().map(|g| g.as_slice()).collect();
    assert_eq!(sum.unwrap(), expected(task.shape(), &refs));
    // Beyond the bound the client refuses to encode.
    let mut beyond = vec![0.0; 20];
    beyond[0] = 1.0;
    beyond[1] = 0.125;
    assert!(client.shard(&beyond).is_err());
}

#[test]
fn the_collector_decrypts_exactly_prios_verifier() {
    let task = PineTask::new(params(20), [2; 32]).unwrap();
    let (mut collector, pk) = PineCollector::new(&task).unwrap();
    let client = PineClient::new(&task, &pk);
    let (report, input, proofs) = client.shard_with_witness(&gradient(20, 3)).unwrap();
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY).unwrap();
    evaluator.ingest(&report).unwrap();
    let (verdicts, verifiers) = collector.check_with_verifiers(&evaluator.check_request().unwrap()).unwrap();
    assert_eq!(verdicts, vec![1]);

    let ch = task.challenges(&VERIFY_KEY, &report).unwrap();
    let (norm_eq, main) = task.circuits();
    let p = task.params();
    let (proofs_ne, proofs_main) = proofs.split_at(p.num_proofs_norm_equality * norm_eq.proof_len());
    let mut want = Vec::new();
    for (proof, &t) in proofs_ne.chunks(norm_eq.proof_len()).zip(&ch.t_norm_equality) {
        want.extend(norm_eq.query(&input, proof, &[t], &[], 1).unwrap());
    }
    for ((proof, &t), jr) in proofs_main.chunks(main.proof_len()).zip(&ch.t_main).zip(ch.joint_rands.chunks(3)) {
        want.extend(main.query(&input, proof, &[t], jr, 1).unwrap());
    }
    assert_eq!(verifiers[0], want);
    assert_eq!(want.len(), task.verifier_len());
    // The dot products the client proved with are those of the vectors the
    // evaluator derives.
    let d = task.shape().dimension();
    assert_eq!(
        input[task.shape().meas_len()..],
        task.shape().wr_results(&input[..d], &task.wr_vectors(&ch.wr_seed))
    );
}

/// One invalid report among honest ones: rejected, and the sum is that of
/// the honest ones.
fn rejected_among_honest(task: &PineTask, bad: impl FnOnce(&PineClient) -> Vec<u8>) {
    let (mut collector, pk) = PineCollector::new(task).unwrap();
    let client = PineClient::new(task, &pk);
    let d = task.shape().dimension();
    let (g1, g2) = (gradient(d, 11), gradient(d, 12));
    let reports = vec![client.shard(&g1).unwrap(), bad(&client), client.shard(&g2).unwrap()];
    let (accepted, sum) = run(task, &mut collector, &pk, &reports);
    assert_eq!(accepted, vec![true, false, true]);
    assert_eq!(sum.unwrap(), expected(task.shape(), &[&g1, &g2]));
}

/// Coordinates (4, 3) scaled to norm 1.25: the client claims the largest
/// allowed squared norm.
#[test]
fn a_norm_beyond_the_bound_is_rejected() {
    let task = PineTask::new(params(20), [3; 32]).unwrap();
    let shape = task.shape().clone();
    rejected_among_honest(&task, |client| {
        let mut g = vec![Field::zero(); 20];
        g[0] = f(128);
        g[1] = f(96);
        g.extend(bits(128 * 128, shape.norm_bits()));
        g.extend(bits(0, shape.norm_bits()));
        client.shard_encoded(&g, |results| honest_claim(&shape, results)).unwrap()
    });
}

/// The attack PINE exists for: `x^2 + y^2 = p + s` over the integers with
/// `s <= B^2`, so that every norm check holds in the field. The dot
/// products leave the range; the client either claims them in range or
/// reports the tests as failed.
#[test]
fn a_squared_norm_that_wraps_the_field_is_rejected() {
    let task = PineTask::new(params(20), [4; 32]).unwrap();
    let shape = task.shape().clone();
    let (x, y, s) = (30_000..46_000u64)
        .find_map(|x| {
            let t = PLAIN_MOD - x * x;
            let y = (t as f64).sqrt().ceil() as u64;
            (y * y >= t && y * y - t <= 128 * 128).then(|| (x, y, y * y - t))
        })
        .unwrap();
    assert_eq!(x * x + y * y, PLAIN_MOD + s);
    for claim_success in [true, false] {
        rejected_among_honest(&task, |client| {
            let mut g = vec![Field::zero(); 20];
            g[0] = f(x);
            g[1] = f(y);
            g.extend(bits(s, shape.norm_bits()));
            g.extend(bits(128 * 128 - s, shape.norm_bits()));
            client
                .shard_encoded(&g, |results| {
                    let mut out = Vec::new();
                    let mut outside = 0;
                    for &r in results {
                        let v = u64::from(u32::from(r + f(shape.wr_bound() - 1)));
                        let in_range = v < 2 * shape.wr_bound();
                        outside += usize::from(!in_range);
                        out.extend(bits(if in_range || claim_success { v } else { 0 }, shape.wr_bits()));
                        out.push(f(u64::from(in_range || claim_success)));
                    }
                    assert!(outside > NUM_WR_CHECKS / 4, "only {outside} tests left the range");
                    out
                })
                .unwrap()
        });
    }
}

/// Squared norm 2 claimed as the "bit" 2 at weight 1: the norm equality and
/// the range check hold, the bit check does not.
#[test]
fn a_claimed_bit_that_is_not_a_bit_is_rejected() {
    let task = PineTask::new(params(20), [5; 32]).unwrap();
    let shape = task.shape().clone();
    rejected_among_honest(&task, |client| {
        let mut g = vec![Field::zero(); 20];
        g[0] = Field::one();
        g[1] = Field::one();
        let mut v = bits(0, shape.norm_bits());
        v[0] = f(2);
        g.extend(v);
        g.extend(bits(128 * 128 - 2, shape.norm_bits()));
        client.shard_encoded(&g, |results| honest_claim(&shape, results)).unwrap()
    });
}

/// The challenges bind the parts: with a part of another valid report, or
/// a fresh encryption of the same gradient part, or another nonce, a valid
/// report is rejected. Each variant keeps everything else unchanged and
/// runs in its own batch.
#[test]
fn parts_of_other_reports_re_encryptions_and_other_nonces_are_rejected() {
    let task = PineTask::new(params(20), [6; 32]).unwrap();
    let (mut collector, pk) = PineCollector::new(&task).unwrap();
    let client = PineClient::new(&task, &pk);
    let g = gradient(20, 21);
    let (a, b) = (client.shard(&g).unwrap(), client.shard(&g).unwrap());
    let (accepted, sum) = run(&task, &mut collector, &pk, &[a.clone(), b.clone()]);
    assert_eq!(accepted, vec![true, true]);
    assert_eq!(sum.unwrap(), expected(task.shape(), &[&g, &g]));

    let mut variants = Vec::new();
    for part in [PART_GRADIENT, PART_WRAPAROUND, PART_PROOFS] {
        let mut spliced = a.clone();
        spliced[task.part_range(part)].copy_from_slice(&b[task.part_range(part)]);
        variants.push(spliced);
    }
    let mut again = a.clone();
    again[task.part_range(PART_GRADIENT)].copy_from_slice(&client.encrypt(&task.shape().encode_gradient_and_norm(&g).unwrap()).unwrap());
    variants.push(again);
    let mut renonced = a.clone();
    renonced[0] ^= 1;
    variants.push(renonced);
    for (i, report) in variants.into_iter().enumerate() {
        assert_ne!(report, a);
        let (accepted, sum) = run(&task, &mut collector, &pk, &[report]);
        assert_eq!(accepted, vec![false], "variant {i}");
        assert!(sum.is_none());
    }
}

/// Coefficients outside a report's layout are multiplied by 0 in every
/// verifier row and masked in the aggregate.
#[test]
fn coefficients_outside_the_layout_change_nothing() {
    let task = PineTask::new(params(20), [7; 32]).unwrap();
    let (mut collector, pk) = PineCollector::new(&task).unwrap();
    let client = PineClient::new(&task, &pk);
    let shape = task.shape().clone();
    let g = gradient(20, 31);
    let mut part = shape.encode_gradient_and_norm(&g).unwrap();
    part.extend((part.len()..8192).map(|i| f(i as u64 * 524_287 % PLAIN_MOD)));
    let padded = client.shard_encoded(&part, |results| honest_claim(&shape, results)).unwrap();
    let (accepted, sum) = run(&task, &mut collector, &pk, &[padded, client.shard(&g).unwrap()]);
    assert_eq!(accepted, vec![true, true]);
    assert_eq!(sum.unwrap(), expected(&shape, &[&g, &g]));
}

#[test]
fn malformed_and_replayed_reports_and_wrong_counts_are_refused() {
    let task = PineTask::new(params(20), [8; 32]).unwrap();
    let (mut collector, pk) = PineCollector::new(&task).unwrap();
    let client = PineClient::new(&task, &pk);
    let report = client.shard(&gradient(20, 41)).unwrap();
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY).unwrap();
    assert!(evaluator.ingest(&report[..report.len() - 1]).is_err());
    evaluator.ingest(&report).unwrap();
    assert!(evaluator.ingest(&report).is_err());
    assert_eq!(evaluator.len(), 1);

    let request = evaluator.check_request().unwrap();
    assert_eq!(request.len(), task.check_request_len(1));
    assert!(collector.check(&request[..request.len() - 1]).is_err());
    let verdicts = collector.check(&request).unwrap();
    assert_eq!(verdicts, vec![1]);
    assert!(evaluator.aggregate_request(&[]).is_err());
    assert!(evaluator.aggregate_request(&[0]).is_err());
    let aggregate = evaluator.aggregate_request(&verdicts).unwrap();
    assert_eq!(aggregate.len(), task.aggregate_request_len());
    let mut wrong_count = aggregate.clone();
    wrong_count[0] = 2;
    assert!(collector.unshard(&wrong_count).is_err());
    assert!(collector.unshard(&aggregate[..aggregate.len() - 1]).is_err());
    assert!(collector.unshard(&aggregate).is_ok());

    // Parameters the reference refuses, and proof counts outside the limits.
    assert!(
        PineTask::new(
            PineParams {
                l2_norm_bound: 40_000,
                ..params(20)
            },
            [8; 32]
        )
        .is_err()
    );
    assert!(PineTask::new(PineParams { num_proofs: 0, ..params(20) }, [8; 32]).is_err());
    assert!(PineTask::new(PineParams { chunk_length: 0, ..params(20) }, [8; 32]).is_err());
}

/// A gradient longer than one ciphertext: 9000 coordinates in two.
#[test]
fn gradients_longer_than_one_ciphertext() {
    let task = PineTask::new(
        PineParams {
            chunk_length_norm_equality: 64,
            ..params(9000)
        },
        [9; 32],
    )
    .unwrap();
    assert_eq!(task.ciphertexts_per_report(), 4);
    let shape = task.shape().clone();
    rejected_among_honest(&task, |client| {
        // Norm 1.25 again, in the two ciphertexts of the gradient.
        let mut g = vec![Field::zero(); 9000];
        g[5] = f(128);
        g[8999] = f(96);
        g.extend(bits(128 * 128, shape.norm_bits()));
        g.extend(bits(0, shape.norm_bits()));
        client.shard_encoded(&g, |results| honest_claim(&shape, results)).unwrap()
    });
}
