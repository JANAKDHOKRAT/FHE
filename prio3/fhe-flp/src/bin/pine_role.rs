//! Separate processes for clients, the one BGV evaluator, and the full-key collector.
//! The collector has no API to export its secret key. Local pipes are the only
//! implemented transport. Malicious-evaluator security is NOT established.
use ed25519_dalek::SigningKey;
use fhe_flp::pine::collector_session::{CollectorSession, ReleasedSum};
use fhe_flp::pine::descriptor::TaskDescriptor;
use fhe_flp::pine::process_wire::*;
use fhe_flp::pine::training::{Example, Model, TrainingConfig, TrainingState, prepare_update};
use fhe_flp::pine::{PineClient, PineEvaluator, PineParams, PineTask};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;

const FILE_LIMIT: u64 = 64 * 1024 * 1024;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    application: [u8; 32],
    params: PineParams,
    training: TrainingConfig,
    min_accepted: u32,
}

fn read_file(path: &str, limit: u64) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    std::fs::File::open(path)?.take(limit + 1).read_to_end(&mut b)?;
    if b.len() as u64 > limit {
        return Err("file exceeds limit".into());
    }
    Ok(b)
}
fn write_new(path: &str, b: &[u8], private: bool) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut f = options.open(path)?;
    f.write_all(b)?;
    f.sync_all()?;
    std::fs::File::open(Path::new(path).parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}
fn job(path: &str) -> Result<Job> {
    let j: Job = serde_json::from_slice(&read_file(path, 65536)?)?;
    j.training.validate()?;
    Ok(j)
}
fn descriptor(path: &str) -> Result<TaskDescriptor> {
    Ok(TaskDescriptor::decode(&read_file(path, 1024 * 1024)?)?)
}
fn dataset(path: &str, model: &Model) -> Result<Vec<Example>> {
    let bytes = read_file(path, FILE_LIMIT)?;
    let mut data = Vec::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let v: Vec<f64> = line.split(',').map(str::parse).collect::<std::result::Result<_, _>>()?;
        if v.len() != model.features + 1 || v.iter().any(|x| !x.is_finite()) {
            return Err("invalid data row".into());
        }
        let label = v[model.features];
        if label < 0.0 || label >= model.classes as f64 || label.fract() != 0.0 {
            return Err("invalid class".into());
        }
        data.push(Example {
            features: v[..model.features].to_vec(),
            label: label as usize,
        });
    }
    if data.is_empty() {
        return Err("empty local dataset".into());
    }
    Ok(data)
}
fn validate_round(state: &TrainingState, j: &Job, d: &TaskDescriptor) -> Result<()> {
    if state.descriptor(&j.training, &j.application, j.params.clone(), j.min_accepted, d.identities.clone())? != *d {
        return Err("model/job/task mismatch".into());
    }
    Ok(())
}
fn local_update(task_path: &str, model_path: &str, job_path: &str, data_path: &str) -> Result<(PineTask, fhe_flp::pine::training::PreparedUpdate)> {
    let d = descriptor(task_path)?;
    let state = TrainingState::load(Path::new(model_path))?;
    let j = job(job_path)?;
    validate_round(&state, &j, &d)?;
    let data = dataset(data_path, &state.model)?;
    let task = PineTask::new(d)?;
    let q = prepare_update(task.shape(), &state.model.local_delta(&data, &j.training)?)?;
    Ok((task, q))
}
fn run(args: &[String]) -> Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    match args.first().map(String::as_str) {
        Some("keygen") if args.len() == 2 => {
            let mut secret = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut secret);
            let key = SigningKey::from_bytes(&secret);
            write_new(&args[1], &secret, true)?;
            write_frame(&mut output, IDENTITY, &key.verifying_key().to_bytes())?;
        }
        Some("init-model") if args.len() == 4 => {
            let model = Model::zeros(args[1].parse()?, args[2].parse()?)?;
            TrainingState { model, next_round: 0 }.save_new(Path::new(&args[3]))?;
        }
        Some("task") if args.len() == 5 => {
            let state = TrainingState::load(Path::new(&args[1]))?;
            let j = job(&args[2])?;
            let ids = read_file(&args[3], 1024 * 1024)?;
            if ids.len() % 32 != 0 {
                return Err("invalid identities".into());
            }
            let identities = ids.chunks_exact(32).map(|v| v.try_into().expect("chunk")).collect();
            let d = state.descriptor(&j.training, &j.application, j.params, j.min_accepted, identities)?;
            let task = PineTask::new(d)?;
            write_new(&args[4], &task.descriptor().encode()?, false)?;
        }
        Some("client") if args.len() == 7 => {
            // Only client-owned data/key, public model/task and public BGV key.
            let (task, q) = local_update(&args[1], &args[2], &args[3], &args[4])?;
            let bytes = read_file(&args[5], 32)?;
            let key = SigningKey::from_bytes(&bytes.try_into().map_err(|_| "invalid client key")?);
            let pk = task.context().deserialize_public_key(&read_file(&args[6], MAX_PUBLIC_KEY as u64)?)?;
            let report = PineClient::new(&task, &pk, &key)?.shard(&q.measurement)?;
            write_frame(&mut output, REPORT, &report)?;
        }
        Some("reference") if args.len() == 5 => {
            // Qualification oracle only: never sent to evaluator or collector.
            let (_, q) = local_update(&args[1], &args[2], &args[3], &args[4])?;
            writeln!(output, "{}", serde_json::to_string(&q.integers)?)?;
        }
        Some("collector") if args.len() == 5 => {
            // Refuse BEFORE reading files/generating keys unless explicitly
            // acknowledging the unresolved cryptographic admission relation.
            if args[4] != "--allow-unverified-evaluator" {
                return Err("production proof gate closed".into());
            }
            let task = PineTask::new(descriptor(&args[1])?)?;
            let n: usize = args[3].parse()?;
            let (mut collector, pk) = CollectorSession::new(&task, Path::new(&args[2]), n)?;
            write_frame(&mut output, PUBLIC_KEY, &pk.serialize()?)?;
            let check = read_frame(&mut input, CHECK, task.check_request_len(n))?;
            let verdict = collector.check(&check)?;
            write_frame(&mut output, VERDICT, &verdict)?;
            let aggregate = read_frame(&mut input, AGGREGATE, task.aggregate_request_len())?;
            let release = collector.release(&aggregate)?;
            let mut body = Sha256::digest(task.descriptor().encode()?).to_vec();
            body.extend(release.accepted.to_le_bytes());
            for x in release.sum {
                body.extend(x.to_bits().to_le_bytes());
            }
            write_frame(&mut output, RELEASE, &body)?;
        }
        Some("evaluator") if args.len() == 5 => {
            let task = PineTask::new(descriptor(&args[1])?)?;
            let n: usize = args[4].parse()?;
            if n == 0 || n > task.descriptor().identities.len() || n as u64 > task.max_batch() {
                return Err("invalid cohort size".into());
            }
            let pk = task.context().deserialize_public_key(&read_file(&args[3], MAX_PUBLIC_KEY as u64)?)?;
            let mut verify_key = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut verify_key);
            let mut evaluator = PineEvaluator::new(&task, &pk, verify_key, Path::new(&args[2]))?;
            for _ in 0..n {
                evaluator.ingest(&read_frame(&mut input, REPORT, task.report_len())?)?;
            }
            write_frame(&mut output, CHECK, &evaluator.check_request()?)?;
            let verdict = read_frame(&mut input, VERDICT, n.div_ceil(8))?;
            write_frame(&mut output, AGGREGATE, &evaluator.aggregate_request(&verdict)?)?;
        }
        Some("update") if args.len() == 7 => {
            let d = descriptor(&args[1])?;
            let state = TrainingState::load(Path::new(&args[2]))?;
            let j = job(&args[3])?;
            validate_round(&state, &j, &d)?;
            let bytes = read_file(&args[4], FILE_LIMIT)?;
            let mut reader = &bytes[..];
            let b = read_frame(&mut reader, RELEASE, 40 + 8 * d.params.dimension)?;
            if !reader.is_empty() || b.len() != 40 + 8 * d.params.dimension || b[..32] != Sha256::digest(d.encode()?)[..] {
                return Err("invalid release".into());
            }
            let release = ReleasedSum {
                task: d.clone(),
                accepted: u64::from_le_bytes(b[32..40].try_into()?),
                sum: b[40..]
                    .chunks_exact(8)
                    .map(|b| f64::from_bits(u64::from_le_bytes(b.try_into().expect("chunk"))))
                    .collect(),
            };
            let next = state.apply(&j.training, &j.application, &d, &release)?;
            next.save_new(Path::new(&args[5]))?;
            let test = dataset(&args[6], &next.model)?;
            writeln!(
                output,
                "{}",
                serde_json::json!({"round":next.next_round,"accuracy":next.model.accuracy(&test)?,"accepted":release.accepted})
            )?;
        }
        _ => return Err("invalid role arguments".into()),
    }
    Ok(())
}
fn main() {
    if run(&std::env::args().skip(1).collect::<Vec<_>>()).is_err() {
        // No library errors or secret-dependent details cross the role boundary.
        eprintln!("role request refused");
        std::process::exit(1);
    }
}
