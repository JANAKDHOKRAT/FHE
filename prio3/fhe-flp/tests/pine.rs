//! PINE in the one-aggregator protocol, end to end with real BGV
//! ciphertexts, keys, noise and signatures (OpenFHE 1.3.1, ring 8192):
//! honest batches, the verifier the collector decrypts against prio's
//! `query`, malicious clients, the authenticated cohort, the single-use
//! rules, and what an evaluator that deviates can and cannot do.
use ed25519_dalek::SigningKey;
use fhe_flp::pine::circuit::{NUM_WR_CHECKS, Shape};
use fhe_flp::pine::descriptor::TaskDescriptor;
use fhe_flp::pine::{PART_GRADIENT, PART_PROOFS, PART_WRAPAROUND, PineClient, PineCollector, PineEvaluator, PineParams, PineTask};
use fhe_flp::{Field, PLAIN_MOD};
use openfhe_tbgv_rs::PublicKey;
use prio::field::FieldElement;
use prio::flp::Flp;
use std::path::{Path, PathBuf};

const VERIFY_KEY: [u8; 32] = [42; 32];
/// Bytes of a check request before the entries, of an entry, and of what a
/// client appends to a report body.
const CHECK_HEADER: usize = 36;
const ENTRY: usize = 180;
const SEAL: usize = 96;

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

/// `clients` signing keys in the order of their identities.
fn signing_keys(tag: u8, clients: usize) -> Vec<SigningKey> {
    let mut keys: Vec<SigningKey> = (0..clients as u8)
        .map(|i| SigningKey::from_bytes(&[[tag; 31].as_slice(), &[i]].concat().try_into().unwrap()))
        .collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    keys
}

fn descriptor(params: PineParams, tag: u8, keys: &[SigningKey]) -> TaskDescriptor {
    TaskDescriptor {
        application: [tag; 32],
        model_hash: [0; 32],
        round: 1,
        params,
        min_accepted: 1,
        identities: keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
    }
}

/// A task of `clients` authorized identities and their signing keys.
fn task(dimension: usize, tag: u8, clients: usize) -> (PineTask, Vec<SigningKey>) {
    let keys = signing_keys(tag, clients);
    (PineTask::new(descriptor(params(dimension), tag, &keys)).unwrap(), keys)
}

/// A fresh ledger directory, removed when dropped.
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("fhe-flp-pine-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The message of a refusal.
fn refusal<T>(result: fhe_flp::Result<T>) -> String {
    match result {
        Ok(_) => panic!("accepted"),
        Err(e) => e.to_string(),
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

/// Runs a batch: the verdicts and, when a sum can be released, the sum.
/// Reports must come in the order of their clients' identities.
fn run(task: &PineTask, collector: &mut PineCollector, pk: &PublicKey, ledger: &Path, reports: &[Vec<u8>]) -> (Vec<bool>, Option<Vec<f64>>) {
    let mut evaluator = PineEvaluator::new(task, pk, VERIFY_KEY, ledger).unwrap();
    for r in reports {
        evaluator.ingest(r).unwrap();
    }
    let verdicts = collector.check(&evaluator.check_request().unwrap()).unwrap();
    let accepted: Vec<bool> = (0..reports.len()).map(|i| verdicts[i / 8] >> (i % 8) & 1 == 1).collect();
    let releasable = accepted.iter().filter(|&&a| a).count() >= task.descriptor().min_accepted as usize;
    let sum = releasable.then(|| collector.unshard(&evaluator.aggregate_request(&verdicts).unwrap()).unwrap());
    (accepted, sum)
}

/// A collector of the same keys with empty ledgers.
fn same_keys<'a>(task: &'a PineTask, pk: &PublicKey, key: &[u8], ledger: &Path) -> PineCollector<'a> {
    PineCollector::with_keys(task, pk, task.context().deserialize_secret_share(key).unwrap(), ledger).unwrap()
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
    let (task, keys) = task(20, 1, 4);
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(&task, dir.path()).unwrap();
    let mut at_bound = vec![0.0; 20];
    at_bound[3] = -1.0; // norm exactly at the bound
    let gradients = [gradient(20, 1), gradient(20, 2), at_bound, vec![0.0; 20]];
    let reports: Vec<Vec<u8>> = gradients
        .iter()
        .zip(&keys)
        .map(|(g, k)| PineClient::new(&task, &pk, k).unwrap().shard(g).unwrap())
        .collect();
    assert_eq!(reports[0].len(), task.report_len());
    let (accepted, sum) = run(&task, &mut collector, &pk, dir.path(), &reports);
    assert_eq!(accepted, vec![true; 4]);
    assert_eq!(collector.accepted(), Some(4));
    let refs: Vec<&[f64]> = gradients.iter().map(|g| g.as_slice()).collect();
    assert_eq!(sum.unwrap(), expected(task.shape(), &refs));
    // Beyond the bound the client refuses to encode.
    let mut beyond = vec![0.0; 20];
    beyond[0] = 1.0;
    beyond[1] = 0.125;
    assert!(PineClient::new(&task, &pk, &keys[0]).unwrap().shard(&beyond).is_err());
    // A key the task does not authorize cannot make a client.
    assert!(PineClient::new(&task, &pk, &SigningKey::from_bytes(&[200; 32])).is_err());
}

#[test]
fn the_collector_decrypts_exactly_prios_verifier() {
    let (task, keys) = task(20, 2, 1);
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(&task, dir.path()).unwrap();
    let (report, input, proofs) = PineClient::new(&task, &pk, &keys[0]).unwrap().shard_with_witness(&gradient(20, 3)).unwrap();
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    evaluator.ingest(&report).unwrap();
    let (verdicts, verifiers) = collector.check_with_verifiers(&evaluator.check_request().unwrap()).unwrap();
    assert_eq!(verdicts, vec![1]);
    assert_eq!(collector.decryptions(), task.verifier_len() as u64);

    let ch = task.challenges(&task.key_context(&pk).unwrap(), &VERIFY_KEY, &report).unwrap();
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
fn rejected_among_honest(task: &PineTask, keys: &[SigningKey], bad: impl FnOnce(&PineClient) -> Vec<u8>) {
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(task, dir.path()).unwrap();
    let client = |i: usize| PineClient::new(task, &pk, &keys[i]).unwrap();
    let d = task.shape().dimension();
    let (g1, g2) = (gradient(d, 11), gradient(d, 12));
    let reports = vec![client(0).shard(&g1).unwrap(), bad(&client(1)), client(2).shard(&g2).unwrap()];
    let (accepted, sum) = run(task, &mut collector, &pk, dir.path(), &reports);
    assert_eq!(accepted, vec![true, false, true]);
    assert_eq!(sum.unwrap(), expected(task.shape(), &[&g1, &g2]));
}

/// Coordinates (4, 3) scaled to norm 1.25: the client claims the largest
/// allowed squared norm.
#[test]
fn a_norm_beyond_the_bound_is_rejected() {
    let (task, keys) = task(20, 3, 3);
    let shape = task.shape().clone();
    rejected_among_honest(&task, &keys, |client| {
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
    let (task, keys) = task(20, 4, 3);
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
        rejected_among_honest(&task, &keys, |client| {
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
    let (task, keys) = task(20, 5, 3);
    let shape = task.shape().clone();
    rejected_among_honest(&task, &keys, |client| {
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

/// The challenge derivation binds bytes. A malicious client takes its own
/// valid report and replaces a part by that of another valid report, or by
/// a fresh encryption of the same gradient part, or changes the nonce, and
/// signs the result: the signature is valid, the proofs are not. Each
/// variant meets a collector of the same keys with empty ledgers, so that
/// the rejection is the proofs' (decryptions happen) and not the ledgers'.
/// Without a new signature the evaluator refuses the variant outright.
#[test]
fn parts_of_other_reports_re_encryptions_and_other_nonces_are_rejected() {
    let (task, keys) = task(20, 6, 2);
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(&task, dir.path()).unwrap();
    let key = collector.serialize_secret_key().unwrap();
    let client = PineClient::new(&task, &pk, &keys[0]).unwrap();
    let g = gradient(20, 21);
    let (a, b) = (client.shard(&g).unwrap(), PineClient::new(&task, &pk, &keys[1]).unwrap().shard(&g).unwrap());
    let (accepted, sum) = run(&task, &mut collector, &pk, dir.path(), &[a.clone(), b.clone()]);
    assert_eq!(accepted, vec![true, true]);
    assert_eq!(sum.unwrap(), expected(task.shape(), &[&g, &g]));

    let body = &a[..a.len() - SEAL];
    let mut variants = Vec::new();
    for part in [PART_GRADIENT, PART_WRAPAROUND, PART_PROOFS] {
        let mut spliced = body.to_vec();
        spliced[task.part_range(part)].copy_from_slice(&b[task.part_range(part)]);
        variants.push(spliced);
    }
    let mut again = body.to_vec();
    again[task.part_range(PART_GRADIENT)].copy_from_slice(&client.encrypt(&task.shape().encode_gradient_and_norm(&g).unwrap()).unwrap());
    variants.push(again);
    let mut renonced = body.to_vec();
    renonced[0] ^= 1;
    variants.push(renonced);
    for (i, variant) in variants.into_iter().enumerate() {
        assert_ne!(variant, body);
        let fresh = TempDir::new();
        // With the original signature: refused before anything else.
        let unsigned = [variant.as_slice(), &a[a.len() - SEAL..]].concat();
        assert!(
            refusal(PineEvaluator::new(&task, &pk, VERIFY_KEY, fresh.path()).unwrap().ingest(&unsigned)).contains("signature"),
            "variant {i}"
        );
        // Signed by the client: accepted for checking, rejected by the proofs.
        let mut collector = same_keys(&task, &pk, &key, fresh.path());
        let (accepted, sum) = run(&task, &mut collector, &pk, fresh.path(), &[client.seal(&variant).unwrap()]);
        assert_eq!(accepted, vec![false], "variant {i}");
        assert!(sum.is_none());
        assert_eq!(collector.decryptions(), task.verifier_len() as u64);
    }
}

/// Coefficients outside a report's layout are multiplied by 0 in every
/// verifier row and masked in the aggregate.
#[test]
fn coefficients_outside_the_layout_change_nothing() {
    let (task, keys) = task(20, 7, 2);
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(&task, dir.path()).unwrap();
    let shape = task.shape().clone();
    let g = gradient(20, 31);
    let mut part = shape.encode_gradient_and_norm(&g).unwrap();
    part.extend((part.len()..8192).map(|i| f(i as u64 * 524_287 % PLAIN_MOD)));
    let padded = PineClient::new(&task, &pk, &keys[0])
        .unwrap()
        .shard_encoded(&part, |results| honest_claim(&shape, results))
        .unwrap();
    let plain = PineClient::new(&task, &pk, &keys[1]).unwrap().shard(&g).unwrap();
    let (accepted, sum) = run(&task, &mut collector, &pk, dir.path(), &[padded, plain]);
    assert_eq!(accepted, vec![true, true]);
    assert_eq!(sum.unwrap(), expected(&shape, &[&g, &g]));
}

#[test]
fn malformed_and_replayed_reports_and_wrong_requests_are_refused() {
    let (task, keys) = task(20, 8, 2);
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(&task, dir.path()).unwrap();
    let report = PineClient::new(&task, &pk, &keys[0]).unwrap().shard(&gradient(20, 41)).unwrap();
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    assert!(evaluator.ingest(&report[..report.len() - 1]).is_err());
    assert!(refusal(evaluator.check_request()).contains("empty"));
    evaluator.ingest(&report).unwrap();
    assert!(refusal(evaluator.ingest(&report)).contains("identity was used before"));
    assert_eq!(evaluator.len(), 1);

    let request = evaluator.check_request().unwrap();
    assert!(evaluator.check_request().is_err(), "a second check request");
    assert!(
        evaluator
            .ingest(&PineClient::new(&task, &pk, &keys[1]).unwrap().shard(&gradient(20, 42)).unwrap())
            .is_err(),
        "a report after sealing"
    );
    assert_eq!(request.len(), task.check_request_len(1));
    assert!(collector.check(&request[..request.len() - 1]).is_err());
    let verdicts = collector.check(&request).unwrap();
    assert_eq!(verdicts, vec![1]);
    assert!(evaluator.aggregate_request(&[]).is_err());
    assert!(evaluator.aggregate_request(&[0]).is_err());
    let aggregate = evaluator.aggregate_request(&verdicts).unwrap();
    assert_eq!(aggregate.len(), task.aggregate_request_len());
    assert!(evaluator.aggregate_request(&verdicts).is_err(), "a second aggregate request");
    // Another batch, other verdicts, another count, another length.
    let before = collector.decryptions();
    for byte in [0, 32, 64] {
        let mut wrong = aggregate.clone();
        wrong[byte] ^= 1;
        assert!(collector.unshard(&wrong).is_err(), "byte {byte}");
    }
    assert!(collector.unshard(&aggregate[..aggregate.len() - 1]).is_err());
    assert_eq!(collector.decryptions(), before);
    assert!(collector.unshard(&aggregate).is_ok());

    // Parameters the reference refuses, and proof counts outside the limits.
    for p in [
        PineParams {
            l2_norm_bound: 40_000,
            ..params(20)
        },
        PineParams { num_proofs: 0, ..params(20) },
        PineParams { chunk_length: 0, ..params(20) },
    ] {
        assert!(PineTask::new(descriptor(p, 8, &keys)).is_err());
    }
}

/// A gradient longer than one ciphertext: 9000 coordinates in two.
#[test]
fn gradients_longer_than_one_ciphertext() {
    let keys = signing_keys(9, 3);
    let task = PineTask::new(descriptor(
        PineParams {
            chunk_length_norm_equality: 64,
            ..params(9000)
        },
        9,
        &keys,
    ))
    .unwrap();
    assert_eq!(task.ciphertexts_per_report(), 4);
    let shape = task.shape().clone();
    rejected_among_honest(&task, &keys, |client| {
        // Norm 1.25 again, in the two ciphertexts of the gradient.
        let mut g = vec![Field::zero(); 9000];
        g[5] = f(128);
        g[8999] = f(96);
        g.extend(bits(128 * 128, shape.norm_bits()));
        g.extend(bits(0, shape.norm_bits()));
        client.shard_encoded(&g, |results| honest_claim(&shape, results)).unwrap()
    });
}

/// One check per batch, identity and nonce, one release per check, no new
/// check while a checked batch awaits release; also after both parties
/// restart with their ledgers and the collector's stored key.
#[test]
fn checks_and_releases_cannot_be_repeated_and_the_rules_survive_a_restart() {
    let (task, keys) = task(20, 10, 5);
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(&task, dir.path()).unwrap();
    let client = |i: usize| PineClient::new(&task, &pk, &keys[i]).unwrap();
    let g: Vec<Vec<f64>> = (0..5).map(|i| gradient(20, 50 + i)).collect();
    let r: Vec<Vec<u8>> = (0..5).map(|i| client(i).shard(&g[i]).unwrap()).collect();

    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    evaluator.ingest(&r[0]).unwrap();
    let request = evaluator.check_request().unwrap();
    let verdicts = collector.check(&request).unwrap();
    let decrypted = collector.decryptions();
    // While the batch awaits release nothing else is checked.
    assert!(refusal(collector.check(&request)).contains("awaits release"));
    let aggregate = evaluator.aggregate_request(&verdicts).unwrap();
    assert_eq!(collector.unshard(&aggregate).unwrap(), expected(task.shape(), &[&g[0]]));
    assert!(collector.unshard(&aggregate).is_err(), "a second release");
    // The same request again, and the same report under another batch identifier.
    let decrypted_after_release = collector.decryptions();
    assert!(refusal(collector.check(&request)).contains("batch was used before"));
    let mut relabelled = request.clone();
    relabelled[4] ^= 1;
    assert!(refusal(collector.check(&relabelled)).contains("identity was used before"));
    assert_eq!(collector.decryptions(), decrypted_after_release);
    assert!(decrypted_after_release > decrypted);

    // An identity of an earlier batch is refused by the evaluator too; a
    // second report of the same client as well.
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    assert!(refusal(evaluator.ingest(&r[0])).contains("identity was used before"));
    assert!(refusal(evaluator.ingest(&client(0).shard(&g[0]).unwrap())).contains("identity was used before"));
    evaluator.ingest(&r[1]).unwrap();
    let request = evaluator.check_request().unwrap();
    let verdicts = collector.check(&request).unwrap();
    let aggregate = evaluator.aggregate_request(&verdicts).unwrap();

    // Restart: new objects, the stored key, the same ledger directory.
    let key = collector.serialize_secret_key().unwrap();
    drop((collector, evaluator));
    let mut collector = same_keys(&task, &pk, &key, dir.path());
    assert!(refusal(collector.check(&request)).contains("batch was used before"));
    // The batch checked before the restart was not released: it is lost.
    assert!(collector.unshard(&aggregate).is_err(), "a release of a batch checked before the restart");
    assert_eq!(collector.decryptions(), 0);
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    assert!(refusal(evaluator.ingest(&r[1])).contains("identity was used before"));
    let (accepted, sum) = run(&task, &mut collector, &pk, dir.path(), &[r[2].clone()]);
    assert_eq!(accepted, vec![true]);
    assert_eq!(sum.unwrap(), expected(task.shape(), &[&g[2]]));

    // A checked batch given up by the operator can never be released.
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    evaluator.ingest(&r[3]).unwrap();
    let verdicts = collector.check(&evaluator.check_request().unwrap()).unwrap();
    collector.abandon().unwrap();
    assert!(collector.abandon().is_err());
    assert!(collector.unshard(&evaluator.aggregate_request(&verdicts).unwrap()).is_err());
    let (accepted, _) = run(&task, &mut collector, &pk, dir.path(), &[r[4].clone()]);
    assert_eq!(accepted, vec![true]);

    // A key pair that does not match, and a ledger root that does not exist.
    let (_, other_pk) = PineCollector::new(&task, dir.path()).unwrap();
    assert!(PineCollector::with_keys(&task, &other_pk, task.context().deserialize_secret_share(&key).unwrap(), dir.path()).is_err());
    assert!(PineCollector::new(&task, &dir.path().join("missing")).is_err());
}

/// A request with a malformed ciphertext anywhere, here the last one, is
/// refused before the collector records or decrypts anything: no
/// decryption is counted and the intact request is accepted afterwards (a
/// recorded batch would be refused).
#[test]
fn a_malformed_ciphertext_is_refused_before_anything_is_recorded_or_decrypted() {
    let (task, keys) = task(20, 11, 1);
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(&task, dir.path()).unwrap();
    let g = gradient(20, 61);
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    evaluator.ingest(&PineClient::new(&task, &pk, &keys[0]).unwrap().shard(&g).unwrap()).unwrap();
    let request = evaluator.check_request().unwrap();
    let mut malformed = request.clone();
    let len = malformed.len();
    malformed[len - 8..].fill(0xff); // a residue not below the modulus
    assert!(matches!(collector.check(&malformed), Err(fhe_flp::Error::Codec(_))));
    assert_eq!(collector.decryptions(), 0);
    let verdicts = collector.check(&request).unwrap();
    assert_eq!(verdicts, vec![1]);

    let aggregate = evaluator.aggregate_request(&verdicts).unwrap();
    let mut malformed = aggregate.clone();
    let len = malformed.len();
    malformed[len - 8..].fill(0xff);
    let before = collector.decryptions();
    assert!(matches!(collector.unshard(&malformed), Err(fhe_flp::Error::Codec(_))));
    assert_eq!(collector.decryptions(), before);
    assert_eq!(collector.unshard(&aggregate).unwrap(), expected(task.shape(), &[&g]));
}

/// The cohort of a check request is authenticated before anything is
/// decrypted or recorded: an evaluator that deviates cannot present
/// reports that authorized clients did not sign for this task and key, nor
/// one client twice. Every variant is refused with no decryption, and the
/// honest request is accepted afterwards.
#[test]
fn a_cohort_the_clients_did_not_sign_is_refused_before_anything_is_decrypted() {
    let (task, keys) = task(20, 12, 4);
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(&task, dir.path()).unwrap();
    let client = |i: usize| PineClient::new(&task, &pk, &keys[i]).unwrap();
    let g: Vec<Vec<f64>> = (0..3).map(|i| gradient(20, 70 + i)).collect();
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    for (i, gradient) in g.iter().enumerate() {
        evaluator.ingest(&client(i).shard(gradient).unwrap()).unwrap();
    }
    let request = evaluator.check_request().unwrap();
    let entry = |i: usize| CHECK_HEADER + i * ENTRY..CHECK_HEADER + (i + 1) * ENTRY;
    let patched = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut r = request.clone();
        edit(&mut r);
        r
    };
    let variants: Vec<(&str, Vec<u8>, &str)> = vec![
        ("a signature bit", patched(&|r| r[entry(1).end - 1] ^= 1), "signature"),
        ("a part digest", patched(&|r| r[entry(1).start + 20] ^= 1), "signature"),
        ("a nonce", patched(&|r| r[entry(1).start + 4] ^= 1), "signature"),
        (
            "another client's identity",
            patched(&|r| r[entry(2).start..entry(2).start + 4].copy_from_slice(&3u32.to_le_bytes())),
            "signature",
        ),
        (
            "an identity outside the task",
            patched(&|r| r[entry(2).start..entry(2).start + 4].copy_from_slice(&4u32.to_le_bytes())),
            "not authorized",
        ),
        ("one client twice", patched(&|r| r.copy_within(entry(0), entry(1).start)), "increasing order"),
        (
            "reordered entries",
            patched(&|r| {
                let first = r[entry(0)].to_vec();
                r.copy_within(entry(1), entry(0).start);
                r[entry(1)].copy_from_slice(&first);
            }),
            "increasing order",
        ),
    ];
    for (name, variant, reason) in &variants {
        assert_ne!(variant, &request);
        assert!(refusal(collector.check(variant)).contains(reason), "{name}");
        assert_eq!(collector.decryptions(), 0, "{name}");
    }
    let verdicts = collector.check(&request).unwrap();
    assert_eq!(verdicts, vec![0b111]);
    assert_eq!(
        collector.unshard(&evaluator.aggregate_request(&verdicts).unwrap()).unwrap(),
        expected(task.shape(), &[&g[0], &g[1], &g[2]])
    );

    // The evaluator refuses a report signed by a key outside the task, and
    // a report made for another round or for another collector key.
    let report = client(3).shard(&g[0]).unwrap();
    let outsider = SigningKey::from_bytes(&[201; 32]);
    let mut forged = report[..report.len() - SEAL].to_vec();
    forged.extend(outsider.verifying_key().as_bytes());
    forged.extend(ed25519_dalek::Signer::sign(&outsider, &[0u8; 32]).to_bytes());
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    assert!(refusal(evaluator.ingest(&forged)).contains("not authorized"));

    let other_round = PineTask::new(TaskDescriptor {
        round: 2,
        ..descriptor(params(20), 12, &keys)
    })
    .unwrap();
    let other_dir = TempDir::new();
    let (_other_collector, other_pk) = PineCollector::new(&other_round, other_dir.path()).unwrap();
    assert!(
        refusal(
            PineEvaluator::new(&other_round, &other_pk, VERIFY_KEY, other_dir.path())
                .unwrap()
                .ingest(&report)
        )
        .contains("signature")
    );
    let (_second_collector, second_pk) = PineCollector::new(&task, other_dir.path()).unwrap();
    assert!(refusal(PineEvaluator::new(&task, &second_pk, VERIFY_KEY, other_dir.path()).unwrap().ingest(&report)).contains("signature"));
    evaluator.ingest(&report).unwrap();
}

/// The release policy: with fewer accepted reports than the task's
/// threshold the batch is closed and nothing can be released for it.
#[test]
fn below_the_release_threshold_nothing_is_released() {
    let keys = signing_keys(13, 3);
    let task = PineTask::new(TaskDescriptor {
        min_accepted: 2,
        ..descriptor(params(20), 13, &keys)
    })
    .unwrap();
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(&task, dir.path()).unwrap();
    let shape = task.shape().clone();
    let invalid = PineClient::new(&task, &pk, &keys[1])
        .unwrap()
        .shard_encoded(
            &[
                vec![f(128), f(96)],
                vec![Field::zero(); 18],
                bits(128 * 128, shape.norm_bits()),
                bits(0, shape.norm_bits()),
            ]
            .concat(),
            |results| honest_claim(&shape, results),
        )
        .unwrap();
    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    evaluator
        .ingest(&PineClient::new(&task, &pk, &keys[0]).unwrap().shard(&gradient(20, 81)).unwrap())
        .unwrap();
    evaluator.ingest(&invalid).unwrap();
    let verdicts = collector.check(&evaluator.check_request().unwrap()).unwrap();
    assert_eq!(verdicts, vec![0b01]);
    let before = collector.decryptions();
    assert!(collector.unshard(&evaluator.aggregate_request(&verdicts).unwrap()).is_err());
    assert_eq!(collector.decryptions(), before);
    assert!(collector.abandon().is_err(), "the batch was closed by the check");
}

/// A limit, not a protection. The cohort is authenticated, the computation
/// is not: the collector cannot tell whether the ciphertexts it decrypts
/// were computed from the signed reports. Here an evaluator that deviates
/// sends, with the header of the honest aggregate request, a ciphertext
/// summing a report the collector never checked; the collector decrypts it
/// and releases that sum. This test passing means the attack succeeds.
/// Refusing it before decryption needs a proof of the evaluator's
/// computation, which does not exist here (`PINE-REPAIR-STATUS.md`).
#[test]
fn known_limit_an_evaluator_that_deviates_can_substitute_the_sum() {
    let (task, keys) = task(20, 14, 2);
    let dir = TempDir::new();
    let (mut collector, pk) = PineCollector::new(&task, dir.path()).unwrap();
    let (honest, other) = (gradient(20, 91), gradient(20, 92));

    let mut evaluator = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    evaluator
        .ingest(&PineClient::new(&task, &pk, &keys[0]).unwrap().shard(&honest).unwrap())
        .unwrap();
    let verdicts = collector.check(&evaluator.check_request().unwrap()).unwrap();
    assert_eq!(verdicts, vec![1]);
    let aggregate = evaluator.aggregate_request(&verdicts).unwrap();

    let mut second = PineEvaluator::new(&task, &pk, VERIFY_KEY, dir.path()).unwrap();
    second.ingest(&PineClient::new(&task, &pk, &keys[1]).unwrap().shard(&other).unwrap()).unwrap();
    second.check_request().unwrap();
    let mut substitute = second.aggregate_request(&[1]).unwrap();
    substitute[..72].copy_from_slice(&aggregate[..72]);

    let before = collector.decryptions();
    let released = collector.unshard(&substitute).unwrap();
    assert!(collector.decryptions() > before);
    assert_eq!(released, expected(task.shape(), &[&other]));
    assert_ne!(released, expected(task.shape(), &[&honest]));
}
