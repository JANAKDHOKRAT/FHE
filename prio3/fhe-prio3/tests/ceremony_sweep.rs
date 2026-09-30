//! Measurement, run on demand (`cargo test --release --test ceremony_sweep
//! -- --ignored --nocapture`, a few minutes): for each key contribution, the
//! largest noise inflation `2^k` one party can put in it and still get
//! through the key ceremony's checks, by binary search. The results feed
//! `tests/key_noise_protocol.rs` and SECURITY.md §6.2. At the boundary the
//! ceremony's randomized check passes or stops a value by chance, so a
//! repeated run can differ by a bit.
mod common;
use common::{serial, task_id};
use fhe_prio3::ceremony::{self, Deviation, MemoryNetwork};
use fhe_prio3::*;
#[test]
#[ignore = "measurement, several minutes"]
fn largest_inflation_each_key_can_carry_through_the_ceremony() {
    let _g = serial();
    let cfg = TaskConfig::new(task_id(94), MeasurementType::Count, 3);
    let ids: Vec<AggregatorIdentity> = (0..3).map(|_| AggregatorIdentity::generate()).collect();
    let pinned: Vec<[u8; 32]> = ids.iter().map(|i| i.public_key()).collect();
    let mut session = 40u8;
    for (name, mk) in [
        ("public key", Deviation::InflatedPublicKeyNoise as fn(u32) -> Deviation),
        ("eval-mult round 1", Deviation::InflatedRelin1Noise),
        ("eval-mult round 2", Deviation::InflatedRelin2Noise),
        ("rotation keys", Deviation::InflatedRotationNoise),
    ] {
        let (mut lo, mut hi) = (0u32, 300u32); // lo passes, hi caught
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            session += 1;
            let net = MemoryNetwork::default();
            let out: Vec<_> = std::thread::scope(|s| {
                let hs: Vec<_> = (0..3)
                    .map(|i| {
                        let mut t = net.party(i);
                        let (cfg, id, pinned) = (cfg.clone(), &ids[i], &pinned);
                        let dev = if i == 1 { mk(mid) } else { Deviation::None };
                        s.spawn(move || ceremony::run_deviating(&cfg, i, id, pinned, [session; 32], &mut t, dev))
                    })
                    .collect();
                hs.into_iter().map(|h| h.join().unwrap()).collect()
            });
            let ok = out.iter().all(|r| r.is_ok());
            let why = out.iter().filter_map(|r| r.as_ref().err().map(|e| e.to_string())).next().unwrap_or_default();
            println!(
                "{name} k = {mid}: {}",
                if ok {
                    "completes".to_string()
                } else {
                    format!("stopped: {}", &why[..why.len().min(150)])
                }
            );
            if ok { lo = mid } else { hi = mid }
        }
        println!("{name}: largest inflation the ceremony lets through: 2^{lo}; smallest stopped: 2^{hi}");
    }
}
