//! Assumption A3 at the protocol's own decryption points. Keys come from the
//! distributed ceremony with one party inflating one of its contributions
//! by the largest amount the ceremony's checks let through (found by
//! `ceremony_sweep`); the noise of every ciphertext the protocol decrypts is
//! then measured at full precision, without flooding, against the flooding
//! range `Q'` of that decryption. A margin of `m` bits means the noise is
//! `2^-m` of what one honest party's flooding covers: the statistical
//! distance it leaves per coefficient is at most `2^-m`.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::ceremony::{self, Deviation, MemoryNetwork};
use fhe_prio3::packed::Expect;
use fhe_prio3::*;

fn ceremony_with(cfg: &TaskConfig, dev: Deviation, session: u8) -> Option<(PublicMaterial, Vec<Vec<u8>>)> {
    let ids: Vec<AggregatorIdentity> = (0..3).map(|_| AggregatorIdentity::generate()).collect();
    let pinned: Vec<[u8; 32]> = ids.iter().map(|i| i.public_key()).collect();
    let net = MemoryNetwork::default();
    let out: Vec<_> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..3)
            .map(|i| {
                let mut t = net.party(i);
                let (cfg, id, pinned) = (cfg.clone(), &ids[i], &pinned);
                let d = if i == 1 { dev } else { Deviation::None };
                s.spawn(move || ceremony::run_deviating(&cfg, i, id, pinned, [session; 32], &mut t, d))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    if out.iter().any(|r| r.is_err()) {
        return None;
    }
    let outs: Vec<_> = out.into_iter().map(|r| r.unwrap()).collect();
    Some((outs[0].material.clone(), outs.iter().map(|o| o.secret.clone()).collect()))
}

#[test]
fn inflated_keys_that_pass_the_ceremony_leave_the_decryptions_inside_the_flooding() {
    let _g = serial();
    let cfg = TaskConfig::new(task_id(95), MeasurementType::Sum { max_measurement: 100 }, 3);
    // (source, largest inflation ceremony_sweep saw pass): at the boundary
    // the ceremony's randomized check passes or stops it by chance, so step
    // down until it passes, as a party would
    let cases: Vec<(&str, fn(u32) -> Deviation, u32)> = vec![
        ("honest keys", |_| Deviation::None, 0),
        ("public key", Deviation::InflatedPublicKeyNoise, 59),
        ("eval-mult round 1", Deviation::InflatedRelin1Noise, 116),
        ("eval-mult round 2", Deviation::InflatedRelin2Noise, 123),
        ("rotation keys", Deviation::InflatedRotationNoise, 130),
        // every contribution at once, stepping all four down together
        ("all four keys (public key 2^k-71, rounds 2^k-14 and 2^k-7, rotations 2^k)", |k| Deviation::InflatedKeys([k - 71, k - 14, k - 7, k]), 130),
    ];
    let mut worst = f64::MAX;
    let mut session = 60u8;
    for (name, mk, top) in cases {
        let mut found = None;
        for k in (top.saturating_sub(12)..=top).rev() {
            session += 1;
            if let Some(r) = ceremony_with(&cfg, mk(k), session) {
                found = Some((k, r));
                break;
            }
        }
        let (k, (material, shares)) = found.unwrap_or_else(|| panic!("{name}: no inflation within 12 bits of the sweep's threshold passed"));
        let name = if top == 0 { name.to_string() } else { format!("{name} 2^{k}") };
        let mut net = Net::with_keys(cfg.clone(), material.clone(), &shares, None);
        let ctx = keys::make_context(&cfg).unwrap();
        let sks: Vec<_> = shares
            .iter()
            .map(|s| ctx.deserialize_secret_share(&keys::AggregatorSecret::decode(s).unwrap().share).unwrap())
            .collect();
        let sk_refs: Vec<_> = sks.iter().collect();
        let lt = (cfg.plain_mod as f64).log2();
        let lq0 = (ctx.moduli().unwrap()[0] as f64).log2();
        let margin = |c: &openfhe_tbgv_rs::Ciphertext| {
            let (_, noise, logq) = ctx.raw_decrypt_for_tests(c, &sk_refs).unwrap();
            (logq - lq0 - 1.0) - (noise - lt)
        };
        // a report's chunk, and its verdict check value (depth 3, the one
        // per-report decryption)
        let report = net.client.shard(&Measurement::Sum(42)).unwrap();
        let chunk = net.aggs[0].codec().decode(&report.chunks[0], Expect::Any).unwrap();
        let m_fresh = margin(&chunk);
        let mc: Vec<MaskCommit> = net.aggs.iter_mut().map(|a| a.prepare_init(&report).unwrap()).collect();
        let masks: Vec<MaskMessage> = net
            .aggs
            .iter_mut()
            .map(|a| {
                let o: Vec<MaskCommit> = mc.iter().filter(|c| c.aggregator != a.index()).cloned().collect();
                a.prepare_mask_reveal(&report.report_id, &o).unwrap()
            })
            .collect();
        let o: Vec<MaskMessage> = masks.iter().filter(|m| m.aggregator != 0).cloned().collect();
        net.aggs[0].prepare_masks(&report.report_id, &o).unwrap();
        let m_check = margin(net.aggs[0].check_value_for_tests(&report.report_id).unwrap());
        // the released sum over a batch
        let mut net = Net::with_keys(cfg.clone(), material, &shares, None);
        for v in [3u64, 100, 57, 0, 99] {
            net.expect_accept(&net.client.shard(&Measurement::Sum(v)).unwrap());
        }
        let share = net.aggs[0].aggregate_share().unwrap();
        let acc = net.aggs[0].codec().decode(&share.accumulators[0], Expect::Any).unwrap();
        let m_sum = margin(&acc);
        println!("{name}: margin below one party's flooding: fresh {m_fresh:.1} bits, verdict check value {m_check:.1} bits, released sum {m_sum:.1} bits");
        worst = worst.min(m_fresh).min(m_check).min(m_sum);
    }
    println!("smallest margin over every case and decryption point: {worst:.1} bits");
    assert!(worst > 60.0, "an inflation the ceremony accepts leaves a decryption within 2^-60 of the flooding");
}
