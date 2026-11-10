//! End-to-end qualification runner on real handwritten digit data.
//! Holds client data and the reference in ONE process to measure correctness;
//! it is not a privacy-isolated service deployment. Deployment uses the local
//! training, evaluator, and collector-session APIs in separate processes.
//! Usage: train_pine digits.csv NEW_OUTPUT_DIRECTORY [rounds=5] [clients=4]
use ed25519_dalek::SigningKey;
use fhe_flp::pine::collector_session::CollectorSession;
use fhe_flp::pine::training::{Example, Model, TrainingConfig, TrainingState, prepare_update};
use fhe_flp::pine::{PineClient, PineEvaluator, PineParams, PineTask};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(3..=5).contains(&args.len()) {
        return Err("usage: train_pine digits.csv NEW_OUTPUT_DIRECTORY [rounds=5] [clients=4]".into());
    }
    let rounds: usize = args.get(3).map(|v| v.parse()).transpose()?.unwrap_or(5);
    let clients: usize = args.get(4).map(|v| v.parse()).transpose()?.unwrap_or(4);
    if rounds == 0 || !(2..=64).contains(&clients) {
        return Err("positive rounds and 2..64 clients required".into());
    }
    let raw = std::fs::read(&args[1])?;
    let hash: [u8; 32] = Sha256::digest(&raw).into();
    let mut train: Vec<Vec<Example>> = (0..clients).map(|_| Vec::new()).collect();
    let mut test = Vec::new();
    let mut train_count = 0;
    for (i, line) in std::str::from_utf8(&raw)?.lines().enumerate() {
        let values: Vec<f64> = line.split(',').map(str::parse).collect::<Result<_, _>>()?;
        if values.len() != 65
            || values.iter().any(|x| !x.is_finite())
            || values[..64].iter().any(|x| !(0.0..=16.0).contains(x))
            || !(0.0..=9.0).contains(&values[64])
            || values[64].fract() != 0.0
        {
            return Err(format!("invalid digits CSV row {}", i + 1).into());
        }
        let row = Example {
            features: values[..64].iter().map(|x| x / 16.0).collect(),
            label: values[64] as usize,
        };
        if i % 5 == 0 {
            test.push(row);
        } else {
            train[train_count % clients].push(row);
            train_count += 1;
        }
    }
    if test.is_empty() || train.iter().any(Vec::is_empty) {
        return Err("not enough data".into());
    }
    let output = PathBuf::from(&args[2]);
    std::fs::create_dir(&output)?; // No overwrite, including of evidence or ledgers.
    let mut evidence = std::fs::OpenOptions::new().write(true).create_new(true).open(output.join("rounds.jsonl"))?;
    let config = TrainingConfig {
        local_epochs: 5,
        local_learning_rate: 0.5,
        server_learning_rate: 1.0,
    };
    let mut state = TrainingState {
        model: Model::zeros(64, 10)?,
        next_round: 0,
    };
    state.save_new(&output.join("model-0.bin"))?;
    let initial_accuracy = state.model.accuracy(&test)?;
    let mut keys: Vec<_> = (0..clients)
        .map(|_| {
            let mut b = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut b);
            SigningKey::from_bytes(&b)
        })
        .collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    // Bind this application's dataset/protocol configuration for qualification.
    // Production application IDs should identify the agreed training job.
    for _ in 0..rounds {
        let started = Instant::now();
        let params = PineParams {
            dimension: 650,
            l2_norm_bound: 32768,
            num_frac_bits: 15,
            chunk_length: 4,
            chunk_length_norm_equality: 4,
            num_proofs: 7,
            num_proofs_norm_equality: 4,
        };
        let descriptor = state.descriptor(
            &config,
            &hash,
            params,
            clients as u32,
            keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
        )?;
        let task = PineTask::new(descriptor)?;
        let ledger = output.join(format!("round-{}", state.next_round));
        std::fs::create_dir(&ledger)?;
        let (mut collector, pk) = CollectorSession::new(&task, &ledger, clients)?;
        let mut verify_key = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut verify_key);
        let mut evaluator = PineEvaluator::new(&task, &pk, verify_key, &ledger)?;
        let mut integer_reference = vec![0i64; 650];
        let mut report_bytes = 0usize;
        let mut largest_squared_norm = 0u128;
        for (key, local_data) in keys.iter().zip(&train) {
            let delta = state.model.local_delta(local_data, &config)?;
            let update = prepare_update(task.shape(), &delta)?;
            largest_squared_norm = largest_squared_norm.max(update.squared_norm);
            for (sum, q) in integer_reference.iter_mut().zip(&update.integers) {
                *sum = sum.checked_add(*q).ok_or("reference overflow")?;
            }
            let report = PineClient::new(&task, &pk, key)?.shard(&update.measurement)?;
            report_bytes += report.len();
            evaluator.ingest(&report)?;
        }
        let request = evaluator.check_request()?;
        let verdict = collector.check(&request)?;
        let aggregate = evaluator.aggregate_request(&verdict)?;
        let release = collector.release(&aggregate)?;
        if release.accepted != clients as u64 {
            return Err("honest training report rejected".into());
        }
        let reference_sum: Vec<_> = integer_reference.iter().map(|q| *q as f64 / 32768.0).collect();
        if release.sum != reference_sum {
            return Err("encrypted sum differs from integer plaintext reference".into());
        }
        let next = state.apply(&config, &hash, task.descriptor(), &release)?;
        // Independent plaintext model update, not a second call to apply().
        let expected_weights: Vec<_> = state
            .model
            .weights
            .iter()
            .zip(&integer_reference)
            .map(|(w, q)| w + config.server_learning_rate * ((*q as f64 / 32768.0) / clients as f64))
            .collect();
        if next.model.weights != expected_weights || next.next_round != state.next_round + 1 {
            return Err("model differs from quantized plaintext reference".into());
        }
        next.save_new(&output.join(format!("model-{}.bin", next.next_round)))?;
        if TrainingState::load(&output.join(format!("model-{}.bin", next.next_round)))? != next {
            return Err("checkpoint round trip failed".into());
        }
        let accuracy = next.model.accuracy(&test)?;
        let line = format!(
            "{{\"round\":{},\"parameters\":650,\"clients\":{},\"train_samples\":{},\"test_samples\":{},\"accepted\":{},\"integer_sum_exact\":true,\"model_exact\":true,\"checkpoint_exact\":true,\"largest_squared_norm\":{},\"squared_bound\":1073741824,\"initial_test_accuracy\":{},\"test_accuracy\":{},\"report_bytes\":{},\"check_bytes\":{},\"aggregate_bytes\":{},\"secret_key_operations\":{},\"seconds\":{}}}",
            state.next_round,
            clients,
            train_count,
            test.len(),
            release.accepted,
            largest_squared_norm,
            initial_accuracy,
            accuracy,
            report_bytes,
            request.len(),
            aggregate.len(),
            collector.secret_key_operations(),
            started.elapsed().as_secs_f64()
        );
        writeln!(evidence, "{line}")?;
        evidence.sync_all()?;
        println!("{line}");
        state = next;
    }
    Ok(())
}
