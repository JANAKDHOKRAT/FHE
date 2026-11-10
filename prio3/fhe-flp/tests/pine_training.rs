use ed25519_dalek::SigningKey;
use fhe_flp::pine::collector_session::{CollectorSession, ReleasedSum};
use fhe_flp::pine::training::{Example, Model, TrainingConfig, TrainingState, prepare_update};
use fhe_flp::pine::{PineClient, PineEvaluator, PineParams, PineTask};
use std::path::PathBuf;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("pine-training-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn config() -> TrainingConfig {
    TrainingConfig {
        local_epochs: 2,
        local_learning_rate: 0.2,
        server_learning_rate: 1.0,
    }
}
fn params(d: usize) -> PineParams {
    PineParams {
        dimension: d,
        l2_norm_bound: 128,
        num_frac_bits: 7,
        chunk_length: 4,
        chunk_length_norm_equality: 4,
        num_proofs: 2,
        num_proofs_norm_equality: 1,
    }
}
fn keys() -> Vec<SigningKey> {
    let mut keys: Vec<_> = (1..=3).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    keys
}
fn state() -> TrainingState {
    TrainingState {
        model: Model::zeros(2, 2).unwrap(),
        next_round: 0,
    }
}
fn task(state: &TrainingState) -> PineTask {
    PineTask::new(
        state
            .descriptor(
                &config(),
                &[11; 32],
                params(state.model.weights.len()),
                2,
                keys().iter().map(|k| k.verifying_key().to_bytes()).collect(),
            )
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn quantization_checks_integer_norm_after_rounding() {
    use fhe_flp::pine::circuit::Shape;
    let shape = Shape::new(2, 128, 7).unwrap();
    // Unit real norm, but ties-to-nearest gives [91,91], whose norm exceeds 128.
    let delta = vec![1.0 / 2f64.sqrt(); 2];
    assert!(shape.encode_gradient_and_norm(&delta).is_err());
    let update = prepare_update(&shape, &delta).unwrap();
    assert!(update.squared_norm <= 128 * 128);
    assert_eq!(shape.encode_gradient(&update.measurement).unwrap(), update.integers);
    for dimension in [1, 2, 10, 650, 10_000] {
        let shape = Shape::new(dimension, 128, 7).unwrap();
        for magnitude in [0.0, 0.0001, 0.5, 1000.0] {
            let g: Vec<_> = (0..dimension).map(|j| if j % 2 == 0 { magnitude } else { -magnitude }).collect();
            let q = prepare_update(&shape, &g).unwrap();
            assert!(q.squared_norm <= 128 * 128);
        }
    }
    assert!(prepare_update(&shape, &[f64::NAN, 0.0]).is_err());
    assert!(prepare_update(&shape, &[f64::INFINITY, 0.0]).is_err());
}

#[test]
fn local_step_matches_cross_entropy_gradient() {
    let m = Model::zeros(1, 2).unwrap();
    let data = vec![Example { features: vec![2.0], label: 1 }];
    let c = TrainingConfig {
        local_epochs: 1,
        local_learning_rate: 0.1,
        server_learning_rate: 1.0,
    };
    assert_eq!(m.local_delta(&data, &c).unwrap(), vec![-0.1, -0.05, 0.1, 0.05]);
    let mut bad = c.clone();
    bad.local_learning_rate = f64::NAN;
    assert!(m.local_delta(&data, &bad).is_err());
}

#[test]
fn malformed_request_is_terminal_and_survives_restart() {
    let dir = Directory::new();
    let t = task(&state());
    let (mut c, _) = CollectorSession::new(&t, &dir.0, 3).unwrap();
    let error = c.check(&[1, 2, 3]).unwrap_err();
    assert_eq!(error.to_string(), "collector request refused");
    assert_eq!(c.secret_key_operations(), 0);
    assert_eq!(c.check(&[0; 100]).unwrap_err(), error);
    assert_eq!(c.release(&[0; 100]).unwrap_err(), error);
    drop(c);
    assert!(CollectorSession::new(&t, &dir.0, 3).is_err());
}

#[test]
fn complete_encrypted_training_rounds_match_integer_reference() {
    let dir = Directory::new();
    let c = config();
    let keys = keys();
    let data = vec![
        Example {
            features: vec![1.0, 0.0],
            label: 0,
        },
        Example {
            features: vec![0.0, 1.0],
            label: 1,
        },
    ];
    let mut state = state();
    for round in 0..3 {
        let t = task(&state);
        let (mut collector, pk) = CollectorSession::new(&t, &dir.0, 3).unwrap();
        let mut evaluator = PineEvaluator::new(&t, &pk, rand::random(), &dir.0).unwrap();
        let mut expected = vec![0i64; t.params().dimension];
        for key in &keys {
            let update = prepare_update(t.shape(), &state.model.local_delta(&data, &c).unwrap()).unwrap();
            for (sum, q) in expected.iter_mut().zip(&update.integers) {
                *sum += q;
            }
            let report = PineClient::new(&t, &pk, key).unwrap().shard(&update.measurement).unwrap();
            evaluator.ingest(&report).unwrap();
        }
        let check = evaluator.check_request().unwrap();
        let verdicts = collector.check(&check).unwrap();
        assert_eq!(verdicts, vec![7]);
        let checks = collector.secret_key_operations();
        assert_eq!(checks as usize, 3 * (t.ciphertexts_per_report() + t.verifier_len()));
        assert!(collector.check(&check).is_err());
        assert_eq!(collector.secret_key_operations(), checks);
        let aggregate = evaluator.aggregate_request(&verdicts).unwrap();
        let release = collector.release(&aggregate).unwrap();
        assert_eq!(release.accepted, 3);
        assert_eq!(release.sum, expected.iter().map(|q| *q as f64 / 128.0).collect::<Vec<_>>());
        assert!(collector.release(&aggregate).is_err());
        let next = state.apply(&c, &[11; 32], t.descriptor(), &release).unwrap();
        let reference: Vec<_> = state.model.weights.iter().zip(&expected).map(|(w, q)| w + (*q as f64 / 128.0) / 3.0).collect();
        assert_eq!(next.model.weights, reference);
        assert!(next.apply(&c, &[11; 32], t.descriptor(), &release).is_err());
        let mut changed = c.clone();
        changed.server_learning_rate = 2.0;
        assert!(state.apply(&changed, &[11; 32], t.descriptor(), &release).is_err());
        let bad = ReleasedSum {
            task: release.task.clone(),
            accepted: 0,
            sum: release.sum.clone(),
        };
        assert!(state.apply(&c, &[11; 32], t.descriptor(), &bad).is_err());
        let file = dir.0.join(format!("model-{round}"));
        next.save_new(&file).unwrap();
        assert!(next.save_new(&file).is_err());
        state = TrainingState::load(&file).unwrap();
        assert_eq!(state, next);
        let mut bytes = std::fs::read(&file).unwrap();
        bytes[40] ^= 1;
        std::fs::write(&file, bytes).unwrap();
        assert!(TrainingState::load(&file).is_err());
    }
    assert_eq!(state.next_round, 3);
    assert_eq!(state.model.accuracy(&data).unwrap(), 1.0);
}

#[test]
fn wrong_model_report_is_refused_before_secret_work() {
    let dir = Directory::new();
    let mut s = state();
    let t = task(&s);
    let (mut collector, pk) = CollectorSession::new(&t, &dir.0, 3).unwrap();
    s.model.weights[0] = 1.0;
    let other = task(&s);
    let mut evaluator = PineEvaluator::new(&other, &pk, rand::random(), &dir.0).unwrap();
    for key in &keys() {
        evaluator.ingest(&PineClient::new(&other, &pk, key).unwrap().shard(&[0.0; 6]).unwrap()).unwrap();
    }
    assert!(collector.check(&evaluator.check_request().unwrap()).is_err());
    assert_eq!(collector.secret_key_operations(), 0);
}

#[test]
fn rejected_client_is_excluded_from_sum_and_average() {
    use fhe_flp::Field;
    use prio::field::FieldElement;
    let dir = Directory::new();
    let state = state();
    let t = task(&state);
    let keys = keys();
    let (mut collector, pk) = CollectorSession::new(&t, &dir.0, 3).unwrap();
    let mut evaluator = PineEvaluator::new(&t, &pk, rand::random(), &dir.0).unwrap();
    for key in &keys[..2] {
        evaluator
            .ingest(&PineClient::new(&t, &pk, key).unwrap().shard(&[0.25, 0.0, 0.0, 0.0, 0.0, 0.0]).unwrap())
            .unwrap();
    }
    // Valid gradient=zero but a forged norm witness and matching FLP proof.
    // A proof generated for a false statement must still be rejected.
    let mut g = t.shape().encode_gradient_and_norm(&[0.0; 6]).unwrap();
    g[6] = Field::one();
    let malicious = PineClient::new(&t, &pk, &keys[2])
        .unwrap()
        .shard_encoded(&g, |results| {
            let mut out = Vec::new();
            for r in results {
                let v = u32::from(*r + Field::from((t.shape().wr_bound() - 1) as u32));
                for bit in 0..t.shape().wr_bits() {
                    out.push(Field::from((v >> bit) & 1));
                }
                out.push(Field::one());
            }
            out
        })
        .unwrap();
    evaluator.ingest(&malicious).unwrap();
    let verdict = collector.check(&evaluator.check_request().unwrap()).unwrap();
    assert_eq!(verdict, vec![3]);
    let release = collector.release(&evaluator.aggregate_request(&verdict).unwrap()).unwrap();
    assert_eq!(release.accepted, 2);
    assert_eq!(release.sum, vec![0.5, 0.0, 0.0, 0.0, 0.0, 0.0]);
    let next = state.apply(&config(), &[11; 32], t.descriptor(), &release).unwrap();
    assert_eq!(next.model.weights[0], 0.25);
}

#[test]
fn malformed_release_burns_release_without_secret_work() {
    let dir = Directory::new();
    let t = task(&state());
    let keys = keys();
    let (mut collector, pk) = CollectorSession::new(&t, &dir.0, 3).unwrap();
    let mut evaluator = PineEvaluator::new(&t, &pk, rand::random(), &dir.0).unwrap();
    for key in &keys {
        evaluator.ingest(&PineClient::new(&t, &pk, key).unwrap().shard(&[0.0; 6]).unwrap()).unwrap();
    }
    let verdict = collector.check(&evaluator.check_request().unwrap()).unwrap();
    let count = collector.secret_key_operations();
    assert!(collector.release(&[0; 1]).is_err());
    assert_eq!(collector.secret_key_operations(), count);
    assert!(collector.release(&evaluator.aggregate_request(&verdict).unwrap()).is_err());
    assert_eq!(collector.secret_key_operations(), count);
}

#[test]
fn under_threshold_is_terminal_without_aggregate_release() {
    let dir = Directory::new();
    let t = task(&state());
    let keys = keys();
    let (mut collector, pk) = CollectorSession::new(&t, &dir.0, 3).unwrap();
    let mut evaluator = PineEvaluator::new(&t, &pk, rand::random(), &dir.0).unwrap();
    evaluator
        .ingest(&PineClient::new(&t, &pk, &keys[0]).unwrap().shard(&[0.0; 6]).unwrap())
        .unwrap();
    let check = evaluator.check_request().unwrap();
    assert!(collector.check(&check).is_err());
    let count = collector.secret_key_operations();
    assert!(count > 0);
    assert!(collector.check(&check).is_err());
    assert!(collector.release(&vec![0; t.aggregate_request_len()]).is_err());
    assert_eq!(collector.secret_key_operations(), count);
}
