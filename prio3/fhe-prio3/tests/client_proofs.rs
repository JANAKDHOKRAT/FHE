//! Client proofs of well-formed encryption in verdict mode
//! (`TaskConfig::client_proofs`, `ProvenReport`).
//!
//! Without them a client chooses the noise of the ciphertext the
//! aggregators evaluate and decrypt for it, and the verdict tells it whether
//! that decryption failed: the decryption-failure oracle the IND-CPA^D
//! key-recovery attacks on exact and threshold FHE use (Checri et al., ePrint
//! 2024/116; Cheon et al., ePrint 2024/127). With them every chunk carries a
//! proof (`wfe.rs`) bound to the task, the report id and the chunk position,
//! every aggregator verifies it after the cheap checks, and the circuit runs
//! on the effective ciphertext `2C` whose randomness the proof bounds.
//!
//! Covered: exact aggregates (one and two chunks), invalid but proven
//! reports, every structural refusal (missing, unexpected, miscounted,
//! swapped, tampered, out-of-range, truncated proofs), proofs moved across
//! reports, chunks and tasks, a malicious aggregator's related report
//! (spec 4.3 item 1), noisy ciphertexts, a prover with an oversized witness,
//! the order of the checks (authentication, quota and replay before any
//! proof work), the size bounds, and the noise of worst-case inputs at the
//! proof's masking range through the check and the release.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::messages::{decode, encode};
use fhe_prio3::packed::Expect;
use fhe_prio3::wfe::{self, SlotCodec};
use fhe_prio3::*;
use openfhe_tbgv_rs::{Ciphertext, Context, SecretShare};
use rand::{Rng, SeedableRng};
use std::sync::{Arc, OnceLock};

fn base(t: MeasurementType) -> TaskConfig {
    TaskConfig::new(task_id(140), t, 2)
}

fn proven(t: MeasurementType) -> TaskConfig {
    base(t).with_client_proofs()
}

fn sum() -> MeasurementType {
    MeasurementType::Sum { max_measurement: 100 }
}

/// Keys for the layouts with 8-slot blocks (Sum(100): 7 slots, Histogram(5)).
fn keys_small() -> &'static keys::LocalKeys {
    static K: OnceLock<keys::LocalKeys> = OnceLock::new();
    K.get_or_init(|| keys::run_local_key_ceremony(&proven(sum())).expect("ceremony"))
}

fn sumvec() -> MeasurementType {
    MeasurementType::SumVec {
        length: 1200,
        max_measurement: 15,
    }
}

/// Keys for SumVec(1200, 15): two chunks of 4096-slot blocks.
fn keys_multi() -> &'static keys::LocalKeys {
    static K: OnceLock<keys::LocalKeys> = OnceLock::new();
    K.get_or_init(|| keys::run_local_key_ceremony(&proven(sumvec())).expect("ceremony"))
}

fn all(net: &Net, v: &[Verdict], expected: &Verdict) {
    assert_eq!(v.len(), net.aggs.len());
    assert!(v.iter().all(|x| x == expected), "expected {expected:?}, got {v:?}");
}

/// Each aggregator on its own refuses `r` with `reason` at step 1.
fn every_aggregator_refuses(net: &mut Net, r: &ProvenReport, reason: RejectReason) {
    let r: ProvenReport = decode(&encode(r).unwrap()).unwrap();
    for a in net.aggs.iter_mut() {
        match a.prepare_init_proven(&r) {
            Err(Error::Reject(got)) => assert_eq!(got, reason, "aggregator {}", a.index()),
            other => panic!("aggregator {}: expected {reason:?}, got {:?}", a.index(), other.map(|_| ())),
        }
    }
}

#[test]
fn proven_reports_aggregate_exactly_and_invalid_ones_are_zeroed() {
    let _g = serial();
    let mut net = Net::from_local_keys(proven(sum()), keys_small());
    for v in [3u64, 100, 57, 0, 99] {
        let r = net.client.shard_proven(&Measurement::Sum(v)).unwrap();
        net.expect_accept_proven(&r);
    }
    // proven but invalid: a non-bit slot
    let bad = net.client.shard_raw_elements_proven(&[vec![2, 0, 0, 0, 0, 0, 0]]).unwrap();
    net.expect_reject_proven(&bad, RejectReason::ValidityCheckFailed);
    let (agg, count) = net.collect().unwrap();
    assert_eq!((agg, count), (AggregateResult::Sum(259), 5));

    let mut net = Net::from_local_keys(proven(MeasurementType::Histogram { length: 5 }), keys_small());
    for b in [0usize, 2, 2, 4] {
        let r = net.client.shard_proven(&Measurement::Histogram(b)).unwrap();
        net.expect_accept_proven(&r);
    }
    let two_hot = net.client.shard_raw_elements_proven(&[vec![1, 0, 1, 0, 0]]).unwrap();
    net.expect_reject_proven(&two_hot, RejectReason::ValidityCheckFailed);
    let (agg, count) = net.collect().unwrap();
    assert_eq!((agg, count), (AggregateResult::Histogram(vec![1, 0, 2, 0, 1]), 4));
}

#[test]
fn two_chunk_reports_are_exact_and_a_chunk_cannot_be_moved_to_another_report() {
    let _g = serial();
    let mut net = Net::from_local_keys(proven(sumvec()), keys_multi());
    assert_eq!(net.client.layout().num_chunks, 2);
    let a: Vec<u64> = (0..1200).map(|i| (i % 16) as u64).collect();
    let b: Vec<u64> = (0..1200).map(|i| ((i * 7) % 16) as u64).collect();
    let ra = net.client.shard_proven(&Measurement::SumVec(a.clone())).unwrap();
    let rb = net.client.shard_proven(&Measurement::SumVec(b.clone())).unwrap();
    // an adversary combines the honest report's first chunk (which it
    // cannot re-prove: it does not know its randomness) with a chunk of its
    // own, to learn something about the honest chunk from the verdict
    let mut moved = rb.clone();
    moved.report.chunks[0] = ra.report.chunks[0].clone();
    moved.proofs[0] = ra.proofs[0].clone();
    moved.report.report_id = Report::compute_id(&moved.report.task_id, 0, &moved.report.chunks);
    every_aggregator_refuses(&mut net, &moved, RejectReason::InvalidProof { chunk: 0 });
    net.expect_accept_proven(&ra);
    net.expect_accept_proven(&rb);
    let (agg, count) = net.collect().unwrap();
    let expected: Vec<u128> = a.iter().zip(&b).map(|(x, y)| (x + y) as u128).collect();
    assert_eq!((agg, count), (AggregateResult::SumVec(expected), 2));
}

#[test]
fn every_malformed_or_misplaced_proof_is_refused_by_every_aggregator() {
    let _g = serial();
    let mut net = Net::from_local_keys(proven(sum()), keys_small());
    let honest = net.client.shard_proven(&Measurement::Sum(42)).unwrap();
    let other = net.client.shard_proven(&Measurement::Sum(42)).unwrap();

    // a plain report (no proofs) to a task that requires them, and the
    // client refusing to build one
    let v = net.run_report(&honest.report);
    all(&net, &v, &Verdict::Rejected(RejectReason::MissingProof));
    assert!(net.client.shard(&Measurement::Sum(1)).is_err());
    // proof count
    let mut r = honest.clone();
    r.proofs.clear();
    every_aggregator_refuses(&mut net, &r, RejectReason::WrongProofCount { expected: 1, got: 0 });
    let mut r = honest.clone();
    r.proofs.push(honest.proofs[0].clone());
    every_aggregator_refuses(&mut net, &r, RejectReason::WrongProofCount { expected: 1, got: 2 });
    // another report's proof (same task, same value: only the binding differs)
    let mut r = honest.clone();
    r.proofs[0] = other.proofs[0].clone();
    every_aggregator_refuses(&mut net, &r, RejectReason::InvalidProof { chunk: 0 });
    // tampered commitment hash
    let mut r = honest.clone();
    r.proofs[0].commitments[5] ^= 1;
    every_aggregator_refuses(&mut net, &r, RejectReason::InvalidProof { chunk: 0 });
    // a tampered response coefficient (still in range)
    let mut r = honest.clone();
    let z = &mut r.proofs[0].responses[2].ze0[17];
    *z = if *z > 0 { *z - 1 } else { *z + 1 };
    every_aggregator_refuses(&mut net, &r, RejectReason::InvalidProof { chunk: 0 });
    // an out-of-range response
    let mut r = honest.clone();
    r.proofs[0].responses[0].zu[3] = wfe::B_U;
    every_aggregator_refuses(&mut net, &r, RejectReason::InvalidProof { chunk: 0 });
    let mut r = honest.clone();
    r.proofs[0].responses[1].zm[0] = u32::MAX;
    every_aggregator_refuses(&mut net, &r, RejectReason::InvalidProof { chunk: 0 });
    // a missing repetition, a truncated vector
    let mut r = honest.clone();
    r.proofs[0].responses.pop();
    every_aggregator_refuses(&mut net, &r, RejectReason::InvalidProof { chunk: 0 });
    let mut r = honest.clone();
    r.proofs[0].responses[0].ze1.pop();
    every_aggregator_refuses(&mut net, &r, RejectReason::InvalidProof { chunk: 0 });
    // the same proof under another task's digest does not verify
    let reference = net.aggs[0].codec().reference();
    let ctx = keys::make_context(&net.cfg).unwrap();
    let pkey = ctx.deserialize_public_key(&net.material.public_key).unwrap();
    let chunk = net.aggs[0].codec().decode(&honest.report.chunks[0], Expect::Any).unwrap();
    let mine = ProvenReport::proof_context(&net.cfg.digest(), &honest.report.report_id, 0, 1);
    wfe::verify(&ctx, &pkey, reference, &chunk, &honest.proofs[0], &mine).unwrap();
    let mut elsewhere = net.cfg.clone();
    elsewhere.min_batch_size += 1;
    for ctxt in [
        ProvenReport::proof_context(&elsewhere.digest(), &honest.report.report_id, 0, 1),
        ProvenReport::proof_context(&net.cfg.digest(), &other.report.report_id, 0, 1),
        ProvenReport::proof_context(&net.cfg.digest(), &honest.report.report_id, 1, 2),
        ProvenReport::proof_context(&net.cfg.digest(), &honest.report.report_id, 0, 2),
    ] {
        assert_ne!(ctxt, mine);
        assert!(wfe::verify(&ctx, &pkey, reference, &chunk, &honest.proofs[0], &ctxt).is_err());
    }
    // nothing above was admitted: the honest report still is, exactly once
    net.expect_accept_proven(&honest);
    net.expect_reject_proven(&honest, RejectReason::Replay);
    let (agg, count) = net.collect().unwrap();
    assert_eq!((agg, count), (AggregateResult::Sum(42), 1));

    // proofs sent to a task that does not use them
    let mut plain = Net::from_local_keys(base(sum()), keys_small());
    let r = ProvenReport {
        report: plain.client.shard(&Measurement::Sum(1)).unwrap(),
        proofs: honest.proofs.clone(),
    };
    let v = plain.run_proven(&r);
    all(&plain, &v, &Verdict::Rejected(RejectReason::UnexpectedProof));
}

#[test]
fn related_noisy_or_unprovable_ciphertexts_are_refused() {
    let _g = serial();
    let mut net = Net::from_local_keys(proven(sum()), keys_small());
    let ctx = keys::make_context(&net.cfg).unwrap();
    let pk = ctx.deserialize_public_key(&net.material.public_key).unwrap();
    // a separate aggregator's codec (same keys) to build the forged chunks
    let aux = Net::from_local_keys(proven(sum()), keys_small());
    let codec = aux.aggs[0].codec();
    let reference = codec.reference();
    let honest = net.client.shard_proven(&Measurement::Sum(10)).unwrap();
    let c = codec.decode(&honest.report.chunks[0], Expect::Any).unwrap();

    // a malicious aggregator's related report (spec 4.3 item 1): the honest
    // ciphertext plus an encryption of delta it chose, re-hashed as a new
    // report; it can prove only what it encrypted itself, not the sum
    let delta = ctx.encrypt(&pk, &ctx.plaintext(&[1]).unwrap()).unwrap();
    let related = ctx.add(&c, &delta).unwrap();
    let mut r = honest.clone();
    r.report.chunks[0] = codec.encode(&related).unwrap();
    r.report.report_id = Report::compute_id(&r.report.task_id, 0, &r.report.chunks);
    every_aggregator_refuses(&mut net, &r, RejectReason::InvalidProof { chunk: 0 });

    // the honest ciphertext with oversized noise, the honest proof kept
    let noisy = ctx.add_noise_for_tests(&c, 200, 7).unwrap();
    let mut r = honest.clone();
    r.report.chunks[0] = codec.encode(&noisy).unwrap();
    r.report.report_id = Report::compute_id(&r.report.task_id, 0, &r.report.chunks);
    every_aggregator_refuses(&mut net, &r, RejectReason::InvalidProof { chunk: 0 });

    // a prover whose witness is not short cannot produce a proof at all:
    // every attempt is rejected (the responses would leave their range)
    let n = ctx.ring_dim() as usize;
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let big = |rng: &mut rand::rngs::StdRng, b: i32| -> Vec<i32> { (0..n).map(|_| rng.gen_range(-b..=b)).collect() };
    let w = wfe::Witness {
        m: vec![0; n],
        u: big(&mut rng, 1 << 26),
        e0: big(&mut rng, 1 << 30),
        e1: big(&mut rng, 1 << 30),
    };
    let ct = ctx.encryption_with(&pk, reference, Some(&w.m), &w.u, &w.e0, &w.e1).unwrap();
    assert!(wfe::prove(&ctx, &pk, reference, &ct, &w, b"any", &mut rng).is_err());

    net.expect_accept_proven(&honest);
    let (agg, _) = net.collect().unwrap();
    assert_eq!(agg, AggregateResult::Sum(10));
}

#[test]
fn authentication_quota_and_replay_are_checked_before_any_proof_work() {
    let _g = serial();
    let alice = ClientIdentity::generate();
    let mallory = ClientIdentity::generate();
    let registry: Arc<dyn ClientRegistry> = StaticRegistry::new([alice.public_key()]);
    let mut cfg = proven(sum());
    cfg.auth = AuthPolicy::Required {
        max_reports_per_client_per_batch: 2,
    };
    let k = keys_small();
    let mut net = Net::with_keys(cfg.clone(), k.material.clone(), &k.aggregator_secrets, Some(registry));
    let a = Client::new(cfg.clone(), &net.material.context, &net.material.public_key)
        .unwrap()
        .with_identity(alice);
    let m = Client::new(cfg.clone(), &net.material.context, &net.material.public_key)
        .unwrap()
        .with_identity(mallory);
    let r1 = a.shard_proven(&Measurement::Sum(5)).unwrap();
    let r2 = a.shard_proven(&Measurement::Sum(6)).unwrap();
    let r3 = a.shard_proven(&Measurement::Sum(7)).unwrap();
    let junk = r2.proofs.clone(); // valid proofs, bound to another report
    // unsigned, with junk proofs: refused for the signature
    let mut r = r1.clone();
    r.report.auth = None;
    r.proofs = junk.clone();
    let v = net.run_proven(&r);
    all(
        &net,
        &v,
        &Verdict::Rejected(RejectReason::Unauthenticated("report carries no signature".into())),
    );
    // unregistered, with junk proofs
    let mut r = m.shard_proven(&Measurement::Sum(1)).unwrap();
    r.proofs = junk.clone();
    let v = net.run_proven(&r);
    all(&net, &v, &Verdict::Rejected(RejectReason::UnknownClient));
    // alice with junk proofs: refused for the proof, and charged
    let mut r = r1.clone();
    r.proofs = junk.clone();
    let v = net.run_proven(&r);
    all(&net, &v, &Verdict::Rejected(RejectReason::InvalidProof { chunk: 0 }));
    net.expect_accept_proven(&r1);
    // quota (2) used by the junk attempt and r1: a valid r2 is over quota
    net.expect_reject_proven(&r2, RejectReason::QuotaExceeded);
    let _ = r3;
    let (agg, count) = net.collect().unwrap();
    assert_eq!((agg, count), (AggregateResult::Sum(5), 1));

    // replay of an admitted report with junk proofs: refused as a replay
    let mut net = Net::from_local_keys(proven(sum()), keys_small());
    let r = net.client.shard_proven(&Measurement::Sum(9)).unwrap();
    net.expect_accept_proven(&r);
    let mut again = r.clone();
    again.proofs[0].commitments[0] ^= 0xff;
    net.expect_reject_proven(&again, RejectReason::Replay);
}

#[test]
fn size_bounds_cover_every_encoding() {
    let _g = serial();
    let net = Net::from_local_keys(proven(sum()), keys_small());
    let n = keys::make_context(&net.cfg).unwrap().ring_dim() as usize;
    let r = net.client.shard_proven(&Measurement::Sum(100)).unwrap();
    let proof_len = encode(&r.proofs[0]).unwrap().len();
    assert!(proof_len <= wfe::proof_size_bound(n), "{proof_len} > {}", wfe::proof_size_bound(n));
    let total = encode(&r).unwrap().len();
    let a = &net.aggs[0];
    assert!(total <= a.max_submission_bytes(), "{total} > {}", a.max_submission_bytes());
    assert!(a.max_message_bytes() >= a.max_submission_bytes());
    println!(
        "N = {n}: proof {proof_len} bytes (bound {}), report with proof {total} bytes, ciphertext {} bytes",
        wfe::proof_size_bound(n),
        r.report.ciphertext_bytes()
    );
    // without proofs the bounds are what they were
    let mut plain = Net::from_local_keys(base(sum()), keys_small());
    assert_eq!(plain.aggs[0].max_submission_bytes(), plain.aggs[0].max_report_bytes());
    // cost, measured (one chunk, this machine): client encryption with and
    // without proofs, and an aggregator's step 1 with and without them
    let mut net = net;
    let t = std::time::Instant::now();
    let p = net.client.shard_proven(&Measurement::Sum(7)).unwrap();
    let prove = t.elapsed();
    let t = std::time::Instant::now();
    let q = plain.client.shard(&Measurement::Sum(7)).unwrap();
    let enc = t.elapsed();
    let t = std::time::Instant::now();
    net.aggs[0].prepare_init_proven(&p).unwrap();
    let verify = t.elapsed();
    let t = std::time::Instant::now();
    plain.aggs[0].prepare_init(&q).unwrap();
    let init = t.elapsed();
    println!("client: {enc:.2?} without proofs, {prove:.2?} with; aggregator step 1: {init:.2?} without, {verify:.2?} with");
}

/// Exact noise phase and margin below one party's flooding (`Q'`), as in
/// `tests/key_noise_protocol.rs`.
struct Meter {
    ctx: Context,
    shares: Vec<SecretShare>,
    lt: f64,
    lq0: f64,
}

impl Meter {
    fn new(cfg: &TaskConfig, k: &keys::LocalKeys) -> Self {
        let ctx = keys::make_context(cfg).unwrap();
        let shares = k
            .aggregator_secrets
            .iter()
            .map(|s| ctx.deserialize_secret_share(&keys::AggregatorSecret::decode(s).unwrap().share).unwrap())
            .collect();
        let lt = (cfg.plain_mod as f64).log2();
        let lq0 = (ctx.moduli().unwrap()[0] as f64).log2();
        Self { ctx, shares, lt, lq0 }
    }
    fn margin(&self, c: &Ciphertext) -> f64 {
        let refs: Vec<&SecretShare> = self.shares.iter().collect();
        let (_, noise, logq) = self.ctx.raw_decrypt_for_tests(c, &refs).unwrap();
        (logq - self.lq0 - 1.0) - (noise - self.lt)
    }
}

/// Runs the verdict rounds for `report`, measuring the check value's margin
/// at aggregator 0 before the decryption.
fn verdict_measuring(net: &mut Net, report: &Report, proven: Option<&ProvenReport>, meter: &Meter) -> (Vec<Verdict>, f64) {
    let mc: Vec<MaskCommit> = net
        .aggs
        .iter_mut()
        .map(|a| match proven {
            Some(p) => a.prepare_init_proven(p).unwrap(),
            None => a.prepare_init(report).unwrap(),
        })
        .collect();
    let masks: Vec<MaskMessage> = net
        .aggs
        .iter_mut()
        .map(|a| {
            let o: Vec<MaskCommit> = mc.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
            a.prepare_mask_reveal(&report.report_id, &o).unwrap()
        })
        .collect();
    let commits: Vec<VerifierCommit> = net
        .aggs
        .iter_mut()
        .map(|a| {
            let o: Vec<MaskMessage> = masks.iter().filter(|m| m.aggregator != a.index()).cloned().collect();
            a.prepare_masks(&report.report_id, &o).unwrap()
        })
        .collect();
    let m = meter.margin(net.aggs[0].check_value_for_tests(&report.report_id).unwrap());
    let reveals: Vec<VerifierMessage> = net
        .aggs
        .iter_mut()
        .map(|a| {
            let o: Vec<VerifierCommit> = commits.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
            a.prepare_reveal(&report.report_id, &o).unwrap()
        })
        .collect();
    let v = net
        .aggs
        .iter_mut()
        .map(|a| {
            let o: Vec<VerifierMessage> = reveals.iter().filter(|r| r.aggregator != a.index()).cloned().collect();
            a.prepare_finish(&report.report_id, &o).unwrap()
        })
        .collect();
    (v, m)
}

/// The noise of what the aggregators decrypt, for inputs at the edge of
/// what a proof lets through. A cheater who does not guess a challenge keeps
/// its randomness within the masking ranges `B_U`, `B_E` (its responses
/// must stay in range); the extraction bound is `2N` times that. Such a
/// chunk has no valid proof, so it is fed, already doubled (`2C`, what the
/// aggregators evaluate), to a task without proofs: the same circuit on the
/// same ciphertext. The released sum is linear in the inputs and the check
/// value quadratic, so the extraction bound costs `log2(2N)` bits on the
/// first and twice that on the second. The margin left must be at least 64
/// bits: the flooding then exceeds the noise by `2^64`, the statistical
/// distance the IND-CPA^D analyses ask for at 128-bit security (stricter
/// than the 40 bits of `tests/gate_noise.rs` and `tests/share_noise.rs`).
#[test]
fn worst_case_proven_inputs_stay_exact_and_far_below_the_flooding() {
    let _g = serial();
    let k = keys_small();
    let cfg = base(sum());
    let meter = Meter::new(&cfg, k);
    let ctx = &meter.ctx;
    let pk = ctx.deserialize_public_key(&k.material.public_key).unwrap();
    let n = ctx.ring_dim() as usize;
    let ext = (2.0 * n as f64).log2();
    let reference = ctx.encrypt(&pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
    let sf = reference.meta().unwrap().scaling_factor_int;
    let sc = SlotCodec::new(ctx).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(140);

    // honest proven reports, for comparison
    let mut honest = Net::from_local_keys(proven(sum()), k);
    let mut honest_check = f64::MAX;
    for v in [3u64, 100, 57] {
        let r = honest.client.shard_proven(&Measurement::Sum(v)).unwrap();
        let (verdicts, m) = verdict_measuring(&mut honest, &r.report, Some(&r), &meter);
        all(&honest, &verdicts, &Verdict::Accepted);
        honest_check = honest_check.min(m);
    }
    let acc = honest.aggs[0].aggregate_share().unwrap();
    let honest_sum = meter.margin(&honest.aggs[0].codec().decode(&acc.accumulators[0], Expect::Any).unwrap());

    // masking-range inputs
    let mut net = Net::from_local_keys(cfg.clone(), k);
    let aux = Net::from_local_keys(cfg.clone(), k);
    let layout = net.client.layout().clone();
    let codec_meta = aux.aggs[0].codec().fresh_meta();
    let chunk = |elems: &[u64], rng: &mut rand::rngs::StdRng| -> Vec<u8> {
        let mut full = vec![0u64; n];
        for (i, &v) in elems.iter().enumerate() {
            full[layout.group_slot(0, i)] = v;
        }
        let coeffs = sc.contribution_plaintext(&full, sf);
        let u: Vec<i32> = (0..n).map(|_| rng.gen_range(-wfe::B_U..=wfe::B_U)).collect();
        let e0: Vec<i32> = (0..n).map(|_| rng.gen_range(-wfe::B_E..=wfe::B_E)).collect();
        let e1: Vec<i32> = (0..n).map(|_| rng.gen_range(-wfe::B_E..=wfe::B_E)).collect();
        let c = ctx.encryption_with(&pk, &reference, Some(&coeffs), &u, &e0, &e1).unwrap();
        let eff = wfe::effective(ctx, &c).unwrap();
        assert_eq!(eff.meta().unwrap(), codec_meta, "2C keeps the metadata of a fresh encryption");
        aux.aggs[0].codec().encode(&eff).unwrap()
    };
    let report = |bytes: Vec<u8>| -> Report {
        let chunks = vec![bytes];
        Report {
            task_id: cfg.task_id,
            report_id: Report::compute_id(&cfg.task_id, 0, &chunks),
            group: 0,
            chunks,
            auth: None,
        }
    };
    let mut worst_check = f64::MAX;
    let mut expected = 0u64;
    for v in [3u64, 100, 57, 0, 99] {
        let elems = cfg.measurement_type.encode(&Measurement::Sum(v)).unwrap();
        let r = report(chunk(&elems, &mut rng));
        let (verdicts, m) = verdict_measuring(&mut net, &r, None, &meter);
        all(&net, &verdicts, &Verdict::Accepted);
        worst_check = worst_check.min(m);
        expected += v;
    }
    // invalid inputs at the masking range are still refused
    let r = report(chunk(&[2, 0, 0, 0, 0, 0, 0], &mut rng));
    let (verdicts, m) = verdict_measuring(&mut net, &r, None, &meter);
    all(&net, &verdicts, &Verdict::Rejected(RejectReason::ValidityCheckFailed));
    worst_check = worst_check.min(m);
    let acc = net.aggs[0].aggregate_share().unwrap();
    let worst_sum = meter.margin(&net.aggs[0].codec().decode(&acc.accumulators[0], Expect::Any).unwrap());
    let (agg, count) = net.collect().unwrap();
    assert_eq!((agg, count), (AggregateResult::Sum(expected as u128), 5));

    println!("N = {n}, extraction factor 2N = 2^{ext:.0}");
    println!("honest proven inputs: check value margin {honest_check:.1} bits, released sum {honest_sum:.1} bits");
    println!(
        "masking-range inputs: check value margin {worst_check:.1} bits ({:.1} at the extraction bound), released sum {worst_sum:.1} bits ({:.1} at the extraction bound)",
        worst_check - 2.0 * ext,
        worst_sum - ext
    );
    assert!(worst_check - 2.0 * ext >= 64.0, "check value: {worst_check:.1} bits");
    assert!(worst_sum - ext >= 64.0, "released sum: {worst_sum:.1} bits");
}
