//! The distributed key ceremony (`ceremony.rs`): three aggregators, each on
//! its own thread with its own identity and nothing shared but the
//! transport, generate the joint keys; the result runs the protocol. Then
//! every deviation a malicious party can make is caught by the honest ones.
mod common;

use common::{Net, serial, task_id};
use fhe_prio3::ceremony::{self, Deviation, MemoryNetwork};
use fhe_prio3::messages::encode;
use fhe_prio3::*;

fn run_all(cfg: &TaskConfig, ids: &[AggregatorIdentity], pinned: &[[u8; 32]], session: [u8; 32], devs: &[Deviation]) -> Vec<Result<ceremony::CeremonyOutput>> {
    let net = MemoryNetwork::default();
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..ids.len())
            .map(|i| {
                let mut t = net.party(i);
                let (cfg, id, dev) = (cfg.clone(), &ids[i], devs[i]);
                s.spawn(move || ceremony::run_deviating(&cfg, i, id, pinned, session, &mut t, dev))
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("party thread")).collect()
    })
}

fn identities(n: usize) -> (Vec<AggregatorIdentity>, Vec<[u8; 32]>) {
    let ids: Vec<AggregatorIdentity> = (0..n).map(|_| AggregatorIdentity::generate()).collect();
    let pinned = ids.iter().map(|i| i.public_key()).collect();
    (ids, pinned)
}

#[test]
fn three_aggregators_generate_working_keys_without_a_dealer() {
    let _g = serial();
    let t = MeasurementType::SumVec { length: 4, bits: 3 };
    let cfg = TaskConfig::new(task_id(90), t.clone(), 3);
    let (ids, pinned) = identities(3);
    let out = run_all(&cfg, &ids, &pinned, [1u8; 32], &[Deviation::None; 3]);
    let out: Vec<ceremony::CeremonyOutput> = out.into_iter().map(|r| r.expect("honest ceremony")).collect();
    // every party holds the same attested material and transcript, and its own share
    for o in &out[1..] {
        assert_eq!(encode(&o.material).unwrap(), encode(&out[0].material).unwrap());
        assert_eq!(o.transcript, out[0].transcript);
    }
    assert_ne!(out[0].share, out[1].share);
    attest::verify_material(&cfg, &out[0].material, &pinned).unwrap();
    assert_eq!(out[0].material.rotation_indices, cfg.layout(keys::make_context(&cfg).unwrap().row_slots()).unwrap().rotation_indices());

    // the keys run the protocol: accept, reject, aggregate
    let shares: Vec<Vec<u8>> = out.iter().map(|o| o.share.clone()).collect();
    let material = out.into_iter().next().unwrap().material;
    let mut net = Net::with_keys(cfg, material, &shares, None);
    let rows = vec![vec![1u64, 7, 0, 3], vec![5, 2, 6, 7], vec![0, 0, 1, 4]];
    for r in &rows {
        net.expect_accept(&net.client.shard(&Measurement::SumVec(r.clone())).unwrap());
    }
    net.expect_reject(&net.client.shard_raw_elements(&[vec![1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0]]).unwrap(), RejectReason::ValidityCheckFailed);
    let res = net.collect_full().unwrap();
    assert_eq!(res.aggregate, AggregateResult::SumVec(vec![6, 9, 7, 14]));
}

#[test]
fn every_deviation_is_caught_by_the_honest_parties() {
    let _g = serial();
    let cfg = TaskConfig::new(task_id(91), MeasurementType::Count, 3);
    let (ids, pinned) = identities(3);
    let cases: &[(Deviation, &str)] = &[
        (Deviation::WrongIdentity, "not signed by its pinned identity"),
        (Deviation::WrongSeed, "revealed a seed other than the one it committed to"),
        (Deviation::BlobMismatch, "pk does not match its commitment"),
        (Deviation::GarbagePublicKey, "joint key check"),
        (Deviation::GarbageRotation(0), "joint key check"),
        (Deviation::OtherSecretRelin2, "joint key check"),
        (Deviation::WrongPartial, "joint key check"),
        (Deviation::MisshapedPartial, "partial decryption: UnexpectedShape"),
        (Deviation::WrongTranscript, "saw another transcript"),
    ];
    for (k, &(dev, why)) in cases.iter().enumerate() {
        let out = run_all(&cfg, &ids, &pinned, [10 + k as u8; 32], &[Deviation::None, dev, Deviation::None]);
        let honest: Vec<String> = [0, 2]
            .iter()
            .map(|&i| match &out[i] {
                Ok(_) => panic!("{dev:?}: honest party {i} completed"),
                Err(e) => e.to_string(),
            })
            .collect();
        assert!(honest.iter().any(|e| e.contains(why)), "{dev:?}: {honest:?}");
        // an honest party either found it itself or stopped on the other's abort
        for e in &honest {
            assert!(e.contains(why) || e.contains("aborted"), "{dev:?}: {e}");
        }
    }
}

#[test]
fn parties_on_other_parameters_or_identities_stop_at_the_first_round() {
    let _g = serial();
    let cfg = TaskConfig::new(task_id(92), MeasurementType::Count, 2);
    let (ids, pinned) = identities(2);
    // party 1 runs another task configuration
    let mut other = cfg.clone();
    other.min_batch_size = 7;
    let net = MemoryNetwork::default();
    let out = std::thread::scope(|s| {
        let a = {
            let (mut t, cfg, pinned) = (net.party(0), cfg.clone(), pinned.clone());
            let id = &ids[0];
            s.spawn(move || ceremony::run(&cfg, 0, id, &pinned, [3u8; 32], &mut t))
        };
        let b = {
            let (mut t, pinned) = (net.party(1), pinned.clone());
            let id = &ids[1];
            s.spawn(move || ceremony::run(&other, 1, id, &pinned, [3u8; 32], &mut t))
        };
        [a.join().unwrap(), b.join().unwrap()]
    });
    for r in &out {
        let e = r.as_ref().err().expect("must stop").to_string();
        assert!(e.contains("another task or session") || e.contains("aborted"), "{e}");
    }
    // an identity that is not the pinned one refuses to start
    let mut t = MemoryNetwork::default().party(0);
    let e = ceremony::run(&cfg, 0, &ids[1], &pinned, [4u8; 32], &mut t).err().unwrap().to_string();
    assert!(e.contains("not the pinned key"), "{e}");
    assert!(ceremony::run(&cfg, 0, &ids[0], &pinned[..1], [4u8; 32], &mut t).is_err());
}

/// Assumption A3, at the ceremony. A party whose public-key share carries
/// oversized noise still produces keys that decrypt correctly, so the joint
/// key check's slot comparison passes; the flooding check on the same
/// decryption, and on the deep check value (the test ciphertext taken to
/// the task's full depth), stops every honest party before any client
/// encrypts. Smaller inflations pass: the checks bound what could stand out
/// of the flooding at the protocol's decryptions, they do not prove keys
/// well formed.
#[test]
fn oversized_key_noise_is_stopped_at_the_ceremony_up_to_the_flooding_range() {
    let _g = serial();
    let cfg = TaskConfig::new(task_id(93), MeasurementType::Count, 3);
    let (ids, pinned) = identities(3);
    // the flooding range of a fresh verdict-mode decryption is 2^298
    // (openfhe-tbgv-rs/tests/key_noise_gap.rs); 2^300 lets a fuser read the
    // encryption randomness of what it decrypts
    let out = run_all(&cfg, &ids, &pinned, [30u8; 32], &[Deviation::None, Deviation::InflatedPublicKeyNoise(300), Deviation::None]);
    for i in [0, 2] {
        let e = out[i].as_ref().err().unwrap_or_else(|| panic!("honest party {i} completed")).to_string();
        assert!(e.contains("exceeds what 3 flooded partial decryptions can reach") || e.contains("aborted"), "party {i}: {e}");
    }
    assert!(out.iter().any(|r| r.as_ref().err().map(|e| e.to_string().contains("joint key check: fused value exceeds")).unwrap_or(false)));
    // 2^120: 178 bits below the flooding of a fresh decryption, but it would
    // stand out at the depth-3 verdict check value; the deep key check stops it
    let out = run_all(&cfg, &ids, &pinned, [31u8; 32], &[Deviation::None, Deviation::InflatedPublicKeyNoise(120), Deviation::None]);
    assert!(out.iter().any(|r| r.as_ref().err().map(|e| e.to_string().contains("deep key check")).unwrap_or(false)), "{:?}", out.iter().map(|r| r.as_ref().err().map(|e| e.to_string())).collect::<Vec<_>>());
    // 2^40: the ceremony completes (tests/key_noise_protocol.rs measures what
    // the largest accepted inflations leave at the protocol's decryptions)
    let out = run_all(&cfg, &ids, &pinned, [32u8; 32], &[Deviation::None, Deviation::InflatedPublicKeyNoise(40), Deviation::None]);
    assert!(out.iter().all(|r| r.is_ok()), "{:?}", out.iter().map(|r| r.as_ref().err().map(|e| e.to_string())).collect::<Vec<_>>());
}
