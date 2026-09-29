//! Assumption A3 (well-formed key contributions), measured.
//!
//! OpenFHE's `NOISE_FLOODING_MULTIPARTY` partial decryption adds `t e` with
//! `e` uniform in `[-Q'/2, Q'/2]`, `Q' = Q_l / q0`. Partial decryptions are
//! revealed at full precision, so whoever fuses them sees
//! `m + t (noise + sum_i e_i)`. A party whose public-key contribution carries
//! extra noise `E` makes a ciphertext encrypted with randomness `u` carry
//! `u E`; once that stands out of the flooding the fuser reads `u`, and
//! `c0 - b u = m + t e0` decrypts the ciphertext from its own bytes.
//!
//! Measured and asserted here:
//! 1. the flooding is uniform and bounded by `Q'/2` per party;
//! 2. honest noise at every decryption point is hundreds of bits below
//!    `Q'`, and the decryption has about 14 bits of room above the flooding;
//! 3. inflation large enough to read `u` passes `vdec`'s `q0/4` bound, and
//!    is caught by the full-precision flooding check;
//! 4. the limit of any check on decrypted values alone: a party that shrinks
//!    its *own* flooding to `[-Q'/6, Q'/6]` and inflates by exactly `Q'/3`
//!    produces a fused value distributed exactly as an honest one (so no
//!    bound or distribution test can see it), and still guesses each
//!    coefficient of `u` right 5/9 of the time instead of 1/3, more with
//!    repeated decryptions of the same noise. What rules this party out is
//!    the key ceremony: its inflation (about 2^296 here) is far above what
//!    the ceremony's amplified deep check lets a key carry (2^59 for the
//!    public key; `fhe-prio3/tests/key_noise_protocol.rs`).
use openfhe_tbgv_rs::*;
use std::time::Instant;

const SLACK: u32 = 20;

struct Keys {
    ctx: Context,
    pk: PublicKey,
    s: [SecretShare; 2],
    tag: String,
}

fn keys(plain_mod: u64, depth: u32, relin: bool) -> Keys {
    let ctx = Context::new(Params { plain_mod, mult_depth: depth, security_bits: 128 }).unwrap();
    let (pk0, s0) = keygen_first(&ctx).unwrap();
    let (pk, s1) = keygen_next(&ctx, &pk0).unwrap();
    let tag = pk.tag().unwrap();
    if relin {
        let r1 = EvalMultKey::round1_first(&ctx, &s0).unwrap();
        let r1b = EvalMultKey::round1_next(&ctx, &s1, &r1).unwrap();
        let r1sum = EvalMultKey::round1_add(&ctx, &r1, &r1b, &tag).unwrap();
        let r2a = EvalMultKey::round2(&ctx, &s0, &r1sum, &tag).unwrap();
        let r2b = EvalMultKey::round2(&ctx, &s1, &r1sum, &tag).unwrap();
        ctx.install_eval_mult_key(&EvalMultKey::round2_add(&ctx, &r2a, &r2b, &tag).unwrap(), &tag).unwrap();
    }
    Keys { ctx, pk, s: [s0, s1], tag }
}

impl Keys {
    fn partials(&self, c: &Ciphertext) -> [PartialDecryption; 2] {
        [self.s[0].partial_decrypt(c, true).unwrap(), self.s[1].partial_decrypt(c, false).unwrap()]
    }
}

fn xorshift(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed | 1;
    move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }
}

fn ternary(n: usize, seed: u64) -> Vec<i8> {
    let mut r = xorshift(seed);
    (0..n).map(|_| (r() % 3) as i8 - 1).collect()
}

fn small(n: usize, seed: u64) -> Vec<i8> {
    let mut r = xorshift(seed);
    (0..n).map(|_| (r() % 7) as i8 - 3).collect()
}

/// Honest noise, flooding range and room at one decryption point.
fn honest_point(k: &Keys, c: &Ciphertext, label: &str) -> f64 {
    let ctx = &k.ctx;
    let lt = (ctx.plain_mod() as f64).log2();
    let q0 = (c.meta().unwrap().num_towers, ctx.moduli().unwrap()[0]);
    let (_, noise, logq) = ctx.raw_decrypt_for_tests(c, &[&k.s[0], &k.s[1]]).unwrap();
    let parts = k.partials(c);
    let (fused, _) = ctx.fuse_raw_log2(&[&parts[0], &parts[1]]).unwrap();
    let logqp = logq - (q0.1 as f64).log2();
    let t0 = Instant::now();
    let (within, ratio) = ctx.fuse_flooding_check(&[&parts[0], &parts[1]], SLACK).unwrap();
    let dt = t0.elapsed();
    let (mx, q0v) = ctx.fuse_magnitude(&[&parts[0], &parts[1]]).unwrap();
    let noise_t = noise - lt;
    println!(
        "{label}: towers {}, Q_l 2^{logq:.1}, Q' 2^{logqp:.1} | honest noise 2^{noise_t:.1} t, fused 2^{:.1} t | \
         margin {:.1} bits, room above flooding {:.1} bits | check {} (max/(n Q'/2) = {ratio:.4}, {:.1} ms) | q0/4 {}",
        q0.0,
        fused - lt,
        (logqp - 1.0) - noise_t,
        (logq - 1.0) - (lt + 1.0 + logqp - 1.0),
        if within { "passes" } else { "FAILS" },
        dt.as_secs_f64() * 1e3,
        if mx < q0v / 4 { "passes" } else { "fails" }
    );
    assert!(within, "{label}: an honest fusion fails the flooding check");
    (logqp - 1.0) - noise_t
}

/// Guess each coefficient of u from observations y_j = e_j + A u (e_j uniform
/// in [-Q'/2, Q'/2], independent): the u values consistent with every
/// observation, one of them at random. Returns the fraction guessed right.
fn guess_rate(obs: &[Vec<f64>], a: f64, half: f64, u: &[i8]) -> f64 {
    let mut r = xorshift(99);
    let mut right = 0usize;
    for i in 0..u.len() {
        let feasible: Vec<i8> = [-1i8, 0, 1].into_iter().filter(|&c| obs.iter().all(|y| (y[i] - a * c as f64).abs() <= half * (1.0 + 1e-9))).collect();
        if feasible.is_empty() {
            continue;
        }
        if feasible[(r() % feasible.len() as u64) as usize] == u[i] {
            right += 1;
        }
    }
    right as f64 / u.len() as f64
}

#[test]
fn key_noise_gap_verdict_parameters() {
    let k = keys(4_293_918_721, 3, true);
    let ctx = &k.ctx;
    let n = ctx.ring_dim() as usize;
    let lt = (ctx.plain_mod() as f64).log2();
    let q0 = ctx.moduli().unwrap()[0] as f64;
    let fresh = ctx.encrypt(&k.pk, &ctx.plaintext(&[1, 2, 3]).unwrap()).unwrap();

    // 1. the flooding: one partial decryption of the all-zero ciphertext is t e
    let zero = ctx.zero_encryption(&k.pk, &fresh, &vec![0; n], &vec![0; n], &vec![0; n]).unwrap();
    let pz = k.s[1].partial_decrypt(&zero, false).unwrap();
    let (e, _, logq) = ctx.fuse_raw_over_t(&[&pz]).unwrap();
    let half = 2f64.powf(logq - q0.log2()) / 2.0;
    let mean = e.iter().sum::<f64>() / n as f64 / half;
    let m2 = e.iter().map(|x| (x / half).powi(2)).sum::<f64>() / n as f64;
    let m4 = e.iter().map(|x| (x / half).powi(4)).sum::<f64>() / n as f64;
    let max = e.iter().fold(0f64, |a, x| a.max(x.abs())) / half;
    println!("flooding of one partial, in units of Q'/2: max {max:.6}, mean {mean:.4}, E[x^2] {m2:.4} (uniform: 1/3), kurtosis {:.3} (uniform: 1.8)", m4 / (m2 * m2));
    assert!(max <= 1.0 + 1e-9 && max > 0.999, "flooding is bounded by Q'/2 and reaches it");
    assert!((m2 - 1.0 / 3.0).abs() < 0.02 && (m4 / (m2 * m2) - 1.8).abs() < 0.05, "flooding is uniform");
    let (within, ratio) = ctx.fuse_flooding_check(&[&pz], SLACK).unwrap();
    assert!(within, "one flooded partial: ratio {ratio}");

    // 2. honest decryption points
    let mut margin = f64::MAX;
    margin = margin.min(honest_point(&k, &fresh, "fresh ciphertext"));
    let mut big = fresh.try_clone().unwrap();
    for _ in 0..20 {
        big = ctx.add(&big, &big).unwrap(); // noise of a sum of 2^20 reports (worst case: all equal)
    }
    margin = margin.min(honest_point(&k, &big, "sum of 2^20 (max_batch_size)"));
    let mut deep = ctx.mult(&fresh, &fresh).unwrap();
    deep = ctx.mult(&deep, &fresh).unwrap();
    deep = ctx.mult(&deep, &fresh).unwrap();
    margin = margin.min(honest_point(&k, &deep, "depth 3 (the verdict check value)"));
    println!("smallest honest smudging margin: {margin:.1} bits");
    assert!(margin > 100.0);

    // 3. inflation sweep: victim ciphertext with known randomness u
    let u = ternary(n, 7);
    let (e0, e1) = (small(n, 11), small(n, 13));
    let msg: Vec<u64> = (0..16).map(|i| (i * 977) % 4_293_918_721).collect();
    let pt = ctx.plaintext(&msg).unwrap();
    let qp_bits = logq - q0.log2();
    println!("inflation E = 2^k (constant), Q' = 2^{qp_bits:.1}:");
    println!("   k | decrypts | q0/4 | flooding check (max/(n Q'/2)) | u guessed right");
    let mut caught_all_recovering = true;
    let mut ks: Vec<u32> = (0..=((qp_bits as u32) + 12)).step_by(16).collect();
    ks.extend((qp_bits as u32 - 6)..=(qp_bits as u32 + 12));
    for kk in ks {
        let pk2 = ctx.inflate_public_key_for_tests(&k.pk, kk, 5, true).unwrap();
        let victim = ctx.add_plain(&ctx.zero_encryption(&pk2, &fresh, &u, &e0, &e1).unwrap(), &pt).unwrap();
        let parts = k.partials(&victim);
        let decrypts = ctx.fuse(&[&parts[0], &parts[1]], msg.len()).map(|v| v == msg).unwrap_or(false);
        let (mx, q0v) = ctx.fuse_magnitude(&[&parts[0], &parts[1]]).unwrap();
        let (within, ratio) = ctx.fuse_flooding_check(&[&parts[0], &parts[1]], SLACK).unwrap();
        let (vals, _, _) = ctx.fuse_raw_over_t(&[&parts[0], &parts[1]]).unwrap();
        let scale = 2f64.powi(kk as i32);
        let rate = (0..n).filter(|&i| ((vals[i] / scale).round() as i64).clamp(-1, 1) == u[i] as i64).count() as f64 / n as f64;
        println!("  {kk:>3} | {:>8} | {:>4} | {:>6} ({ratio:.4}) | {rate:.4}", decrypts, if mx < q0v / 4 { "pass" } else { "fail" }, if within { "pass" } else { "CAUGHT" });
        if rate > 0.9 && decrypts && within {
            caught_all_recovering = false;
        }
    }
    assert!(caught_all_recovering, "an inflation that reads u passed the flooding check");

    // 4. the tuned party: inflation exactly Q'/3, its own flooding in [-Q'/6, Q'/6]
    let pk3 = ctx.inflate_public_key_ratio_for_tests(&k.pk, 1, 3).unwrap();
    let victim = ctx.add_plain(&ctx.zero_encryption(&pk3, &fresh, &u, &e0, &e1).unwrap(), &pt).unwrap();
    let a = 2f64.powf(qp_bits) / 3.0;
    let mut obs = Vec::new();
    let mut passes = 0;
    let rounds = 6; // one decryption of a value plus five checks of it (vdec, N = 32768)
    for _ in 0..rounds {
        let honest = k.s[0].partial_decrypt(&victim, true).unwrap();
        let shaped = ctx.partial_decrypt_shaped_for_tests(&victim, &k.s[1], false, 1, 3).unwrap();
        assert_eq!(ctx.fuse(&[&honest, &shaped], msg.len()).unwrap(), msg, "the tuned party's decryption is correct");
        let (within, ratio) = ctx.fuse_flooding_check(&[&honest, &shaped], SLACK).unwrap();
        let (mx, q0v) = ctx.fuse_magnitude(&[&honest, &shaped]).unwrap();
        if within && mx < q0v / 4 {
            passes += 1;
        }
        println!("tuned party: flooding check {} (ratio {ratio:.4})", if within { "passes" } else { "CAUGHT" });
        // what the party sees once it removes its own flooding: the same
        // partial with none (it knows the flooding it drew)
        let bare = ctx.partial_decrypt_shaped_for_tests(&victim, &k.s[1], false, 0, 1).unwrap();
        let (y, _, _) = ctx.fuse_raw_over_t(&[&honest, &bare]).unwrap();
        obs.push(y);
    }
    let one = guess_rate(&obs[..1], a, half, &u);
    let all = guess_rate(&obs, a, half, &u);
    println!("tuned party: passes every check {passes}/{rounds}; u guessed right {one:.4} after one decryption (1/3 by chance, 5/9 predicted), {all:.4} after {rounds}");
    assert_eq!(passes, rounds, "the tuned party is invisible to the bounds");
    assert!(one > 0.5 && all > one, "and still learns about u");
    Context::clear_keys_for_tag(&k.tag).unwrap();
    let _ = lt;
}

#[test]
fn key_noise_gap_silent_bottom() {
    let k = keys(786_433, 25, true);
    let ctx = &k.ctx;
    let mut g = ctx.encrypt(&k.pk, &ctx.plaintext(&[1, 2, 3, 4]).unwrap()).unwrap();
    honest_point(&k, &g, "silent fresh");
    for _ in 0..24 {
        g = ctx.square(&g).unwrap();
    }
    let m = honest_point(&k, &g, "silent bottom (24 squarings)");
    let mut big = g.try_clone().unwrap();
    for _ in 0..16 {
        big = ctx.add(&big, &big).unwrap(); // a sum over 2^16 reports (max_batch_size)
    }
    let m2 = honest_point(&k, &big, "silent bottom, sum of 2^16");
    assert!(m.min(m2) > 60.0);
    Context::clear_keys_for_tag(&k.tag).unwrap();
}
