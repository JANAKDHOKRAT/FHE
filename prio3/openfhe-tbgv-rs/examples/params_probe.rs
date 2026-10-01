//! Measures what OpenFHE chooses for candidate silent-mode parameters and
//! how long each primitive of the per-report path takes at them.
//!
//!   cargo run --release --example params_probe [-- --ops]
//!
//! Part A (always): for each (plaintext prime, depth) pair, the ring
//! dimension, tower count and log2 Q the context gets at 128-bit security.
//! Part B (`--ops`): a two-party key setup at the current silent parameters
//! and at the 65537 candidate, then the mean time of a ciphertext
//! multiplication, a plaintext multiplication, a rotation, a squaring and
//! an addition, and of one full Fermat chain `x^(p-1)`.
use openfhe_tbgv_rs::*;
use std::time::Instant;

fn context(p: u64, depth: u32) -> Context {
    Context::new(Params {
        plain_mod: p,
        mult_depth: depth,
        security_bits: 128,
    })
    .expect("context")
}

fn fermat_depth(p: u64) -> u32 {
    let e = p - 1;
    (64 - e.leading_zeros() - 1) + (e.count_ones() - 1)
}

fn part_a() {
    println!("== A. parameter choice at 128-bit security");
    println!("{:>8} {:>6} {:>9} {:>7} {:>8}", "p", "depth", "ring_dim", "towers", "log2Q");
    for (p, depth) in [
        (786_433u64, 25u32),
        (786_433, 22),
        (65_537, 22),
        (65_537, 21),
        (65_537, 20),
        (65_537, 19),
        (65_537, 18),
        (65_537, 16),
        (65_537, 14),
    ] {
        let ctx = context(p, depth);
        println!("{:>8} {:>6} {:>9} {:>7} {:>8.1}", p, depth, ctx.ring_dim(), ctx.num_towers(), ctx.log2_q());
    }
}

fn setup(p: u64, depth: u32, indices: &[i32]) -> (Context, PublicKey) {
    let ctx = context(p, depth);
    let (pk0, sk0) = keygen_first(&ctx).unwrap();
    let prev = ctx.deserialize_public_key(&pk0.serialize().unwrap()).unwrap();
    let (pk, sk1) = keygen_next(&ctx, &prev).unwrap();
    let shares = [sk0, sk1];
    let tag = pk.tag().unwrap();
    let r1_first = EvalMultKey::round1_first(&ctx, &shares[0]).unwrap();
    let r1_first_bytes = r1_first.serialize().unwrap();
    let mut r1_sum = ctx.deserialize_eval_mult_key(&r1_first_bytes).unwrap();
    let first = ctx.deserialize_eval_mult_key(&r1_first_bytes).unwrap();
    let contrib = EvalMultKey::round1_next(&ctx, &shares[1], &first).unwrap();
    let contrib = ctx.deserialize_eval_mult_key(&contrib.serialize().unwrap()).unwrap();
    r1_sum = EvalMultKey::round1_add(&ctx, &r1_sum, &contrib, &tag).unwrap();
    let r1_sum_bytes = r1_sum.serialize().unwrap();
    let mut r2_sum: Option<EvalMultKey> = None;
    for sk in &shares {
        let sum = ctx.deserialize_eval_mult_key(&r1_sum_bytes).unwrap();
        let c = EvalMultKey::round2(&ctx, sk, &sum, &tag).unwrap();
        let c = ctx.deserialize_eval_mult_key(&c.serialize().unwrap()).unwrap();
        r2_sum = Some(match r2_sum {
            None => c,
            Some(acc) => EvalMultKey::round2_add(&ctx, &acc, &c, &tag).unwrap(),
        });
    }
    ctx.install_eval_mult_key(&r2_sum.unwrap(), &tag).unwrap();
    let acc = RotationKeys::first(&ctx, &shares[0], indices).unwrap();
    let prev = ctx.deserialize_rotation_keys(&acc.serialize().unwrap()).unwrap();
    let contrib = RotationKeys::next(&ctx, &shares[1], &prev, indices, &tag).unwrap();
    let contrib = ctx.deserialize_rotation_keys(&contrib.serialize().unwrap()).unwrap();
    let acc = RotationKeys::add(&ctx, &prev, &contrib, &tag).unwrap();
    ctx.install_rotation_keys(&acc, &tag).unwrap();
    (ctx, pk)
}

fn mean_ms<F: FnMut()>(runs: u32, mut f: F) -> f64 {
    let t = Instant::now();
    for _ in 0..runs {
        f();
    }
    t.elapsed().as_secs_f64() * 1000.0 / runs as f64
}

fn part_b(p: u64, depth: u32) {
    println!("== B. primitive timings at p = {p}, depth = {depth}");
    let t = Instant::now();
    let (ctx, pk) = setup(p, depth, &[-1, -2, -3, 1, 2, 4]);
    println!(
        "setup: ring_dim {} towers {} log2Q {:.1}, two-party keys with 6 rotation indices in {:.1} s",
        ctx.ring_dim(),
        ctx.num_towers(),
        ctx.log2_q(),
        t.elapsed().as_secs_f64()
    );
    let n = ctx.row_slots();
    let vals: Vec<u64> = (0..n as u64).map(|i| i % 2).collect();
    let coeffs: Vec<u64> = (0..n as u64).map(|i| (i * 7919 + 13) % p).collect();
    let x = ctx.encrypt(&pk, &ctx.plaintext(&vals).unwrap()).unwrap();
    let pt = ctx.plaintext(&coeffs).unwrap();
    let ones = ctx.plaintext(&vec![1u64; n]).unwrap();
    let runs = 3;
    let t_enc = mean_ms(runs, || {
        let _ = ctx.plaintext(&coeffs).unwrap();
    });
    let t_add = mean_ms(runs, || {
        let _ = ctx.add(&x, &x).unwrap();
    });
    let t_mp = mean_ms(runs, || {
        let _ = ctx.mult_plain(&x, &pt).unwrap();
    });
    let t_rot = mean_ms(runs, || {
        let _ = ctx.rotate(&x, -1).unwrap();
    });
    let t_mult = mean_ms(runs, || {
        let xm1 = ctx.sub_plain(&x, &ones).unwrap();
        let _ = ctx.mult(&x, &xm1).unwrap();
    });
    let t_sq = mean_ms(runs, || {
        let _ = ctx.square(&x).unwrap();
    });
    // a level-2 ciphertext, as the report term is, for rotation cost at that level
    let xm1 = ctx.sub_plain(&x, &ones).unwrap();
    let e = ctx.mult(&x, &xm1).unwrap();
    let term = ctx.mult_plain(&e, &pt).unwrap();
    let t_rot2 = mean_ms(runs, || {
        let _ = ctx.rotate(&term, -1).unwrap();
    });
    // full Fermat chain on the level-2 term (as silent_validity does on S)
    let t0 = Instant::now();
    let ex = p - 1;
    let bits = 64 - ex.leading_zeros();
    let mut acc = term.try_clone().unwrap();
    for b in (0..bits - 1).rev() {
        acc = ctx.square(&acc).unwrap();
        if (ex >> b) & 1 == 1 {
            acc = ctx.mult(&acc, &term).unwrap();
        }
    }
    let t_fermat = t0.elapsed().as_secs_f64() * 1000.0;
    println!("plaintext encode      {t_enc:9.1} ms");
    println!("add                   {t_add:9.1} ms");
    println!("mult_plain (level 0)  {t_mp:9.1} ms");
    println!("rotate (level 0)      {t_rot:9.1} ms");
    println!("rotate (level 2)      {t_rot2:9.1} ms");
    println!("mult ct x ct (lvl 0)  {t_mult:9.1} ms  (includes one sub_plain)");
    println!("square (level 0)      {t_sq:9.1} ms");
    println!("Fermat chain x^(p-1)  {t_fermat:9.1} ms  ({} levels)", fermat_depth(p));
    let per_report_today = t_mult + 8.0 * t_mp + 3.0 * t_rot2 + t_mp + 9.0 * t_enc;
    let per_report_norot = t_mult + 3.0 * t_mp + t_mp + 4.0 * t_enc;
    println!("model: today's per-report path  = mult + 8 mult_plain + 3 rotate(l2) + mask + 9 encodes = {per_report_today:.0} ms");
    println!("model: rotation-free path       = mult + 3 mult_plain + mask + 4 encodes           = {per_report_norot:.0} ms");
}

fn part_c() {
    println!("== C. silent depths at p = 786433 with tuned key switching / scaling");
    println!("{:>6} {:>6} {:>8} {:>9} {:>7} {:>8}", "depth", "dnum", "scaling", "ring_dim", "towers", "log2Q");
    for depth in [26u32, 27, 28] {
        for (dnum, scaling) in [(0u32, 0u32), (4, 0), (5, 0), (6, 0), (8, 0), (0, 40), (4, 40), (6, 40)] {
            match Context::new_tuned(
                Params {
                    plain_mod: 786_433,
                    mult_depth: depth,
                    security_bits: 128,
                },
                dnum,
                scaling,
            ) {
                Ok(ctx) => println!(
                    "{:>6} {:>6} {:>8} {:>9} {:>7} {:>8.1}",
                    depth,
                    dnum,
                    scaling,
                    ctx.ring_dim(),
                    ctx.num_towers(),
                    ctx.log2_q()
                ),
                Err(e) => println!("{:>6} {:>6} {:>8} error: {e}", depth, dnum, scaling),
            }
        }
    }
}

fn main() {
    let ops = std::env::args().any(|a| a == "--ops");
    if std::env::args().any(|a| a == "--tuned") {
        part_c();
        return;
    }
    part_a();
    if ops {
        part_b(786_433, 25);
        part_b(65_537, 22);
    }
}
