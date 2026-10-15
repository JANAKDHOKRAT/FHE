//! Secret-shared upload (`upload = Shares`): noise of the key parties'
//! share ciphertexts through the whole silent pipeline at production
//! parameters (ring dimension 65536, depth 28, 64 groups, 7 repetitions).
//!
//! With shares, a report never arrives as a ciphertext. Each key party
//! encrypts its own shares of a whole verification batch (one share per
//! group, packed at the groups' element slots) as a contribution proven
//! well formed (`wfe.rs`, effective ciphertext `2C`), and the batch input
//! is the sum of the contributions, restricted to the groups' element
//! slots. A malicious party controls the noise of its contribution within
//! what its proof admits: about `B_U = 2^24` per coefficient of `u` and
//! `B_E = 2^29` of `e` when it does not guess the challenge, `2N` times
//! that at the extraction bound (17 bits more at `N = 65536`).
//!
//! The test runs one full batch whose input is built from an honest
//! contribution plus one at the masking range, through the real circuit,
//! count round and verified release; the released histogram and counts
//! must be exact. It then measures the exact noise of the released
//! accumulators with both key shares and requires the margin below the
//! partial decryptions' flooding to be at least 40 bits after subtracting
//! the 17 bits of the extraction bound (the criterion of
//! `tests/gate_noise.rs`). The same is measured for client-encrypted
//! reports (`upload = Ciphertext`) as the reference.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::*;
use openfhe_tbgv_rs::{Ciphertext, Context, SecretShare};
use rand::{Rng, SeedableRng};

fn id(i: usize) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[..8].copy_from_slice(&(i as u64).to_le_bytes());
    r[31] = 0x6B;
    r
}

struct Keys {
    ctx: Context,
    shares: Vec<SecretShare>,
}

impl Keys {
    /// (log2 exact noise phase, log2 fused flooded value).
    fn margin(&self, c: &Ciphertext) -> (f64, f64) {
        let refs: Vec<&SecretShare> = self.shares.iter().collect();
        let (_, phase, _) = self.ctx.raw_decrypt_for_tests(c, &refs).unwrap();
        let partials: Vec<_> = self.shares.iter().enumerate().map(|(i, s)| s.partial_decrypt(c, i == 0).unwrap()).collect();
        let prefs: Vec<_> = partials.iter().collect();
        let (flooded, _) = self.ctx.fuse_raw_log2(&prefs).unwrap();
        (phase, flooded)
    }
}

/// The plaintext per group: an honest one-hot histogram, except group
/// `bad`, whose first element is 2.
fn batch_values(cfg: &TaskConfig, groups: usize, bad: usize) -> (Vec<Vec<u64>>, Vec<u64>) {
    let MeasurementType::Histogram { length } = cfg.measurement_type else {
        unreachable!()
    };
    let mut per_group = Vec::with_capacity(groups);
    let mut expected = vec![0u64; length];
    for r in 0..groups {
        let mut x = cfg.measurement_type.encode(&Measurement::Histogram(r % length)).unwrap();
        if r == bad {
            x[0] = 2;
        } else {
            expected[r % length] += 1;
        }
        per_group.push(x);
    }
    (per_group, expected)
}

#[test]
fn share_contributions_stay_exact_and_far_below_the_flooding_at_production_parameters() {
    let _g = serial();
    let cfg = TaskConfig::new_silent(task_id(91), MeasurementType::Histogram { length: 16 }, 2);
    cfg.validate().unwrap();
    let started = std::time::Instant::now();
    let k = keys::run_local_key_ceremony(&cfg).unwrap();
    eprintln!("local ceremony: {:?}", started.elapsed());
    let ctx = keys::make_context(&cfg).unwrap();
    let pk = ctx.deserialize_public_key(&k.material.public_key).unwrap();
    let shares: Vec<SecretShare> = k
        .aggregator_secrets
        .iter()
        .map(|s| ctx.deserialize_secret_share(&keys::AggregatorSecret::decode(s).unwrap().share).unwrap())
        .collect();
    let keyset = Keys { ctx: ctx.clone(), shares };
    let client_material = PublicMaterial {
        context: k.material.context.clone(),
        public_key: k.material.public_key.clone(),
        joint_tag: k.material.joint_tag.clone(),
        eval_mult_key: Vec::new(),
        rotation_keys: Vec::new(),
        rotation_indices: k.material.rotation_indices.clone(),
        attestations: Vec::new(),
    };
    let p = cfg.plain_mod;
    let n = ctx.ring_dim() as usize;
    let layout = cfg.layout(ctx.row_slots()).unwrap();
    let groups = layout.groups;
    assert_eq!((n, groups, layout.num_chunks, cfg.mult_depth()), (65536, 64, 1, 28));
    let bad = 9usize;
    let (values, expected) = batch_values(&cfg, groups, bad);
    let m = values[0].len();
    // the restriction to the groups' element slots (one plaintext
    // multiplication per batch, as `Circuit::mask_all_groups`)
    let mut mask = vec![0u64; layout.row];
    for r in 0..groups {
        for i in 0..m {
            mask[layout.group_slot(r, i)] = 1;
        }
    }
    let mask = ctx.plaintext(&mask).unwrap();
    let reference = ctx.encrypt(&pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
    let sf = reference.meta().unwrap().scaling_factor_int;
    let slots = wfe::SlotCodec::new(&ctx).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(91);

    // a contribution whose effective ciphertext decodes to slot vector `v`,
    // with `u` uniform on [-bu, bu] and `e` on [-be, be]
    let contribution = |v: &[u64], bu: i32, be: i32, rng: &mut rand::rngs::StdRng| -> Ciphertext {
        let coeffs = slots.contribution_plaintext(v, sf);
        let u: Vec<i32> = (0..n).map(|_| rng.gen_range(-bu..=bu)).collect();
        let e0: Vec<i32> = (0..n).map(|_| rng.gen_range(-be..=be)).collect();
        let e1: Vec<i32> = (0..n).map(|_| rng.gen_range(-be..=be)).collect();
        let c = ctx.encryption_with(&pk, &reference, Some(&coeffs), &u, &e0, &e1).unwrap();
        wfe::effective(&ctx, &c).unwrap()
    };

    // the real prover and verifier once, at this ring dimension
    {
        let v: Vec<u64> = (0..layout.row).map(|_| rng.gen_range(0..p)).collect();
        let mut full = vec![0u64; n];
        full[..layout.row].copy_from_slice(&v);
        let coeffs = slots.contribution_plaintext(&full, sf);
        let t0 = std::time::Instant::now();
        let (c, proof) = wfe::encrypt_proven(&ctx, &pk, &reference, &coeffs, b"share-noise timing", &mut rng).unwrap();
        let prove = t0.elapsed();
        let t1 = std::time::Instant::now();
        wfe::verify(&ctx, &pk, &reference, &c, &proof, b"share-noise timing").unwrap();
        let verify = t1.elapsed();
        let proof_bytes = messages::encode(&proof).unwrap().len();
        eprintln!("wfe at N = {n}: prove {prove:?}, verify {verify:?}, proof {proof_bytes} bytes");
    }

    let mut margins = Vec::new();
    for label in ["shares, one party at the masking range", "shares, honest", "client ciphertexts (reference)"] {
        let input = match label {
            "client ciphertexts (reference)" => {
                // what upload = Ciphertext feeds the circuit: one fresh
                // encryption per report, masked to its group, summed
                let mut acc: Option<Ciphertext> = None;
                for (r, x) in values.iter().enumerate() {
                    let mut s = vec![0u64; layout.row];
                    for (i, &v) in x.iter().enumerate() {
                        s[layout.group_slot(r, i)] = v;
                    }
                    let mut g = vec![0u64; layout.row];
                    for i in 0..m {
                        g[layout.group_slot(r, i)] = 1;
                    }
                    let c = ctx
                        .mult_plain(&ctx.encrypt(&pk, &ctx.plaintext(&s).unwrap()).unwrap(), &ctx.plaintext(&g).unwrap())
                        .unwrap();
                    acc = Some(match acc {
                        None => c,
                        Some(a) => ctx.add(&a, &c).unwrap(),
                    });
                }
                acc.unwrap()
            }
            _ => {
                // two parties' shares of every group's encoded measurement
                let mut v0 = vec![0u64; n];
                let mut v1 = vec![0u64; n];
                for (r, x) in values.iter().enumerate() {
                    for (i, &v) in x.iter().enumerate() {
                        let s = layout.group_slot(r, i);
                        let a = rng.gen_range(0..p);
                        v0[s] = a;
                        v1[s] = (v + p - a) % p;
                    }
                }
                let (bu, be) = if label == "shares, honest" {
                    (wfe::BETA_U, wfe::BETA_E)
                } else {
                    (wfe::B_U, wfe::B_E)
                };
                let c0 = contribution(&v0, wfe::BETA_U, wfe::BETA_E, &mut rng);
                let c1 = contribution(&v1, bu, be, &mut rng);
                ctx.mult_plain(&ctx.add(&c0, &c1).unwrap(), &mask).unwrap()
            }
        };
        // fresh aggregators from the one copy of the full material (cloning
        // it per variant would hold a second 4 GiB copy of the keys)
        let aggs: Vec<Aggregator> = k
            .aggregator_secrets
            .iter()
            .enumerate()
            .map(|(i, s)| Aggregator::new(cfg.clone(), &k.material, i, s, None).unwrap())
            .collect();
        let mut net = Net {
            cfg: cfg.clone(),
            material: client_material.clone(),
            aggs,
            client: Client::new(cfg.clone(), &client_material.context, &client_material.public_key).unwrap(),
            collector: Collector::new(cfg.clone(), &client_material).unwrap(),
        };
        let zero = ctx.encrypt(&pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
        for agg in net.aggs.iter_mut() {
            agg.accumulate_silent_for_tests(0, id(0), vec![input.try_clone().unwrap()]).unwrap();
            for r in 1..groups {
                agg.accumulate_silent_for_tests(r, id(r), vec![zero.try_clone().unwrap()]).unwrap();
            }
        }
        let t = std::time::Instant::now();
        let res = net.collect_full().unwrap();
        eprintln!("{label}: count round and release in {:?}", t.elapsed());
        assert_eq!(
            (res.aggregate, res.report_count, res.valid_count),
            (AggregateResult::Histogram(expected.clone()), groups as u64, (groups - 1) as u64),
            "{label}"
        );
        let acc = net.aggs[0].snapshot_accumulators().unwrap();
        let sums = keyset.ctx.deserialize_ciphertext(&acc.sums.unwrap()[0]).unwrap();
        let count = keyset.ctx.deserialize_ciphertext(&acc.valid_count_sum.unwrap()).unwrap();
        for (what, c) in [("sum", &sums), ("valid count", &count)] {
            let (phase, flooded) = keyset.margin(c);
            eprintln!(
                "{label}: {what} noise 2^{phase:.1}, flooding 2^{flooded:.1}: margin {:.1} bits",
                flooded - phase
            );
            margins.push((label, what, flooded - phase));
        }
        drop(net);
    }
    let extraction_bits = (2.0 * n as f64).log2();
    for (label, what, mg) in &margins {
        let worst = if label.contains("masking range") { mg - extraction_bits } else { *mg };
        assert!(worst >= 40.0, "{label} {what}: margin {mg:.1} bits ({worst:.1} at the extraction bound)");
    }
}
