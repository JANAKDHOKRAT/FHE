//! Noise margins of the gated release (`gate.rs`) at silent-mode
//! parameters: how far below the partial decryptions' flooding the noise of
//! the released ciphertexts sits, with honest contributions and with a
//! contribution whose randomness is as large as a well-formedness proof
//! (`wfe.rs`) lets a cheater make it.
//!
//! The released value is `R = X' · Z_v · Z_c` with `X' = y - Σ M_p`, the
//! gates being product trees over `X'` and fresh factors. A malicious party
//! controls the noise of its masks and factors only within what its proof
//! admits: about `B_U = 2^24` per coefficient of `u` and `B_E = 2^29` of
//! `e` when it does not guess the challenge, `2N` times that at the
//! extraction bound (`log2(2N) = 17` bits more at `N = 65536`). The test
//! builds the release's arithmetic on a mask at `B_U, B_E` (honest masks
//! are ternary and centered binomial), measures the exact noise with both
//! shares, and requires it to stay at least 40 bits below the flooding
//! after adding the 17 bits of the extraction bound.
use fhe_prio3::*;
use openfhe_tbgv_rs::*;
use rand::{Rng, SeedableRng};

struct Party2 {
    ctx: Context,
    pk: PublicKey,
    s: [SecretShare; 2],
}

fn setup(cfg: &TaskConfig) -> Party2 {
    let ctx = keys::make_context(cfg).unwrap();
    let (pk0, s0) = keygen_first(&ctx).unwrap();
    let (pk, s1) = keygen_next(&ctx, &pk0).unwrap();
    let tag = pk.tag().unwrap();
    let r1 = EvalMultKey::round1_first(&ctx, &s0).unwrap();
    let r1b = EvalMultKey::round1_next(&ctx, &s1, &r1).unwrap();
    let r1sum = EvalMultKey::round1_add(&ctx, &r1, &r1b, &tag).unwrap();
    let r2a = EvalMultKey::round2(&ctx, &s0, &r1sum, &tag).unwrap();
    let r2b = EvalMultKey::round2(&ctx, &s1, &r1sum, &tag).unwrap();
    ctx.install_eval_mult_key(&EvalMultKey::round2_add(&ctx, &r2a, &r2b, &tag).unwrap(), &tag)
        .unwrap();
    Party2 { ctx, pk, s: [s0, s1] }
}

impl Party2 {
    /// (log2 of the exact noise phase, log2 of the fused flooded value): the
    /// margin is their difference.
    fn margin(&self, c: &Ciphertext) -> (f64, f64) {
        let (_, phase, _) = self.ctx.raw_decrypt_for_tests(c, &[&self.s[0], &self.s[1]]).unwrap();
        let a = self.s[0].partial_decrypt(c, true).unwrap();
        let b = self.s[1].partial_decrypt(c, false).unwrap();
        let (flooded, _) = self.ctx.fuse_raw_log2(&[&a, &b]).unwrap();
        (phase, flooded)
    }
}

fn product(ctx: &Context, mut v: Vec<Ciphertext>) -> Ciphertext {
    while v.len() > 1 {
        let mut next = Vec::new();
        let mut it = v.into_iter();
        while let Some(a) = it.next() {
            next.push(match it.next() {
                Some(b) => ctx.mult(&a, &b).unwrap(),
                None => a,
            });
        }
        v = next;
    }
    v.pop().unwrap()
}

fn gate(ctx: &Context, x: &Ciphertext, k: u64, factors: Vec<Ciphertext>) -> Ciphertext {
    let n = ctx.ring_dim() as usize;
    let mut terms = vec![x.try_clone().unwrap()];
    for j in 1..k {
        terms.push(ctx.sub_plain(x, &ctx.plaintext(&vec![j; n]).unwrap()).unwrap());
    }
    terms.extend(factors);
    product(ctx, terms)
}

#[test]
fn gated_release_noise_stays_far_below_the_flooding() {
    // a split-key task with both gates, at the depth of the default chain
    let mut cfg = TaskConfig::new_split_key([77; 32], MeasurementType::Histogram { length: 8 });
    cfg.silent_batch_groups = 1;
    cfg.repetitions = 4;
    cfg.min_batch_size = 100;
    cfg.min_cell_count = 10;
    cfg.validate().unwrap();
    let p2 = setup(&cfg);
    let ctx = &p2.ctx;
    let n = ctx.ring_dim() as usize;
    let t = ctx.plain_mod();
    let reference = ctx.encrypt(&p2.pk, &ctx.plaintext(&[0]).unwrap()).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(5);
    let uniform = |rng: &mut rand::rngs::StdRng| -> Vec<u64> { (0..n).map(|_| rng.gen_range(0..t)).collect() };
    let enc = |m: &[u64], bu: i32, be: i32, rng: &mut rand::rngs::StdRng| -> Ciphertext {
        let u: Vec<i32> = (0..n).map(|_| rng.gen_range(-bu..=bu)).collect();
        let e0: Vec<i32> = (0..n).map(|_| rng.gen_range(-be..=be)).collect();
        let e1: Vec<i32> = (0..n).map(|_| rng.gen_range(-be..=be)).collect();
        let c = ctx.encryption_with(&p2.pk, &reference, Some(m), &u, &e0, &e1).unwrap();
        ctx.add(&c, &c).unwrap() // the effective contribution 2C
    };
    // the refreshed value: cell counts 0..max at every slot, as y - masks
    let cells: Vec<u64> = (0..n).map(|i| (i % 300) as u64).collect();
    let mut margins = Vec::new();
    for (label, bu, be) in [("honest", 1i32, 20i32), ("at the masking range", wfe::B_U, wfe::B_E)] {
        let m_agg = enc(&uniform(&mut rng), 1, 20, &mut rng);
        let m_col = enc(&uniform(&mut rng), bu, be, &mut rng);
        let masks = ctx.add(&m_agg, &m_col).unwrap();
        // y = cells + masks, as the parties decrypt it (computed here from
        // the masks' plaintexts, which only the test knows)
        let dm = {
            let a = p2.s[0].partial_decrypt(&masks, true).unwrap();
            let b = p2.s[1].partial_decrypt(&masks, false).unwrap();
            ctx.fuse(&[&a, &b], n).unwrap()
        };
        let y: Vec<u64> = cells.iter().zip(&dm).map(|(&c, &m)| (c + m) % t).collect();
        let fresh = ctx.add_plain(&ctx.negate(&masks).unwrap(), &ctx.plaintext(&y).unwrap()).unwrap();
        // the aggregator's factor is honest; the collector contributes none
        let f_v = enc(&uniform(&mut rng), 1, 20, &mut rng);
        let f_c = enc(&uniform(&mut rng), 1, 20, &mut rng);
        let started = std::time::Instant::now();
        // the batch-size gate's input is the refreshed valid count (150 >= min
        // here, at every slot), refreshed with the same masks
        let y_count: Vec<u64> = dm.iter().map(|&m| (150 + m) % t).collect();
        let count = ctx.add_plain(&ctx.negate(&masks).unwrap(), &ctx.plaintext(&y_count).unwrap()).unwrap();
        let zv = gate(ctx, &count, cfg.min_batch_size as u64, vec![f_v]);
        let zc = gate(ctx, &fresh, cfg.min_cell_count, vec![f_c]);
        let r = ctx.mult(&fresh, &ctx.mult(&zv, &zc).unwrap()).unwrap();
        eprintln!("{label}: gates and release in {:?}", started.elapsed());
        for (what, c) in [("Z_v", &zv), ("Z_c", &zc), ("R", &r)] {
            let (phase, flooded) = p2.margin(c);
            eprintln!(
                "{label}: {what} noise 2^{phase:.1}, flooding 2^{flooded:.1}: margin {:.1} bits",
                flooded - phase
            );
            margins.push((label, what, flooded - phase));
        }
        // the release decrypts to cells * gates: zero where a cell is below k
        let a = p2.s[0].partial_decrypt(&r, true).unwrap();
        let b = p2.s[1].partial_decrypt(&r, false).unwrap();
        assert!(ctx.fuse_flooding_check(&[&a, &b], vdec::FLOODING_SLACK_BITS).unwrap().0);
        let got = ctx.fuse(&[&a, &b], n).unwrap();
        for s in (0..n).step_by(97) {
            assert_eq!(got[s] == 0, cells[s] < cfg.min_cell_count, "slot {s}: cell {}", cells[s]);
        }
    }
    let extraction_bits = (2.0 * n as f64).log2();
    for (label, what, m) in &margins {
        let worst = if *label == "honest" { *m } else { m - extraction_bits };
        assert!(worst >= 40.0, "{label} {what}: margin {m:.1} bits ({worst:.1} at the extraction bound)");
    }
}
