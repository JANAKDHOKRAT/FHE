//! Process-boundary refusal tests. These test framing and fail-closed startup,
//! not malicious-evaluator cryptographic security.
use ed25519_dalek::SigningKey;
use fhe_flp::pine::PineParams;
use fhe_flp::pine::descriptor::TaskDescriptor;
use fhe_flp::pine::process_wire::{PUBLIC_KEY, REPORT, read_frame, write_frame};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("pine-process-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn task(&self) -> PathBuf {
        let d = TaskDescriptor {
            application: [0; 32],
            model_hash: [0; 32],
            round: 0,
            min_accepted: 1,
            identities: vec![SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes()],
            params: PineParams {
                dimension: 6,
                l2_norm_bound: 128,
                num_frac_bits: 7,
                chunk_length: 4,
                chunk_length_norm_equality: 4,
                num_proofs: 2,
                num_proofs_norm_equality: 1,
            },
        };
        let p = self.0.join("task.bin");
        std::fs::write(&p, d.encode().unwrap()).unwrap();
        p
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pine_role"))
}

#[test]
fn unverified_production_collector_never_starts() {
    let d = Directory::new();
    let task = d.task();
    let result = binary().arg("collector").arg(&task).arg(&d.0).arg("1").output().unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr, b"role request refused\n");
    assert_eq!(std::fs::read_dir(&d.0).unwrap().count(), 1); // no ledger or key generation path
}

#[test]
fn raw_report_frame_is_not_a_collector_check_and_task_cannot_restart() {
    let d = Directory::new();
    let task = d.task();
    let mut child = binary()
        .arg("collector")
        .arg(&task)
        .arg(&d.0)
        .args(["1", "--allow-unverified-evaluator"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    assert!(!read_frame(&mut stdout, PUBLIC_KEY, 4 * 1024 * 1024).unwrap().is_empty());
    write_frame(child.stdin.as_mut().unwrap(), REPORT, &[0; 32]).unwrap();
    drop(child.stdin.take());
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    assert!(!child.wait().unwrap().success());
    assert!(rest.is_empty());
    let mut error = Vec::new();
    child.stderr.take().unwrap().read_to_end(&mut error).unwrap();
    assert_eq!(error, b"role request refused\n");
    let retry = binary()
        .arg("collector")
        .arg(&task)
        .arg(&d.0)
        .args(["1", "--allow-unverified-evaluator"])
        .output()
        .unwrap();
    assert!(!retry.status.success());
    assert!(retry.stdout.is_empty());
    assert_eq!(retry.stderr, error);
}

#[test]
fn oversized_check_header_is_refused_without_reading_body() {
    let d = Directory::new();
    let task = d.task();
    let mut child = binary()
        .arg("collector")
        .arg(task)
        .arg(&d.0)
        .args(["1", "--allow-unverified-evaluator"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    read_frame(&mut stdout, PUBLIC_KEY, 4 * 1024 * 1024).unwrap();
    let input = child.stdin.as_mut().unwrap();
    input.write_all(b"PNEIPC01\x03").unwrap();
    input.write_all(&u64::MAX.to_le_bytes()).unwrap();
    input.flush().unwrap();
    // Keep stdin open: refusal must not wait for the claimed body.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("waited for oversized frame body");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
}
