//! Real process exit and recovery with actual OpenFHE keys/ciphertexts.
//! Does not simulate power loss or validate network-filesystem durability.
use fhe_flp::f65537::Field65537;
use fhe_flp::single::oblivious::{ObliviousCollector, ObliviousEvaluator};
use fhe_flp::single::{SingleClient, SingleTask};
use openfhe_tbgv_rs::keygen_first;
use prio::flp::types::Count;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

fn save(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn restart_worker() {
    let Some(root) = std::env::var_os("FHE_OBLIVIOUS_RESTART_ROOT") else { return };
    let root = std::path::PathBuf::from(root);
    let task = SingleTask::new(Count::<Field65537>::new(), [111; 32], 9).unwrap();
    let stage = std::env::var("FHE_OBLIVIOUS_RESTART_STAGE").unwrap();
    let (pk, sk) = if stage.starts_with("before") {
        let (pk, sk) = keygen_first(task.context()).unwrap();
        save(&root.join("pk"), &pk.serialize().unwrap());
        save(&root.join("sk"), &sk.serialize().unwrap());
        (pk, sk)
    } else {
        (
            task.context().deserialize_public_key(&fs::read(root.join("pk")).unwrap()).unwrap(),
            task.context().deserialize_secret_share(&fs::read(root.join("sk")).unwrap()).unwrap(),
        )
    };
    let own_pk = task.context().deserialize_public_key(&pk.serialize().unwrap()).unwrap();
    let mut collector = ObliviousCollector::with_keys(&task, own_pk, sk, &root).unwrap();
    if stage == "before-revoke" {
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        ev.ingest(&SingleClient::new(&task, &pk).shard(&true).unwrap()).unwrap();
        let mut request = ev.check_request().unwrap();
        let ring = task.context().ring_dim() as usize;
        let q = task.context().moduli().unwrap()[0];
        let mut residues = vec![0u64; 2 * ring];
        residues[..ring].fill(q / 2);
        let codec = fhe_flp::codec::ResidueCodec::new(&[q]).unwrap();
        let bytes = codec.pack(&residues, 2, ring).unwrap();
        request[104..104 + bytes.len()].copy_from_slice(&bytes);
        assert!(collector.check(&request).unwrap_err().to_string().contains("phase guard"));
        std::process::exit(0);
    }
    if stage == "after-revoke" {
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        ev.ingest(&SingleClient::new(&task, &pk).shard(&true).unwrap()).unwrap();
        assert!(collector.check(&ev.check_request().unwrap()).is_err());
        return;
    }
    if stage == "before" {
        let report = SingleClient::new(&task, &pk).shard(&true).unwrap();
        save(&root.join("report"), &report);
        let mut ev = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
        ev.ingest(&report).unwrap();
        let request = ev.check_request().unwrap();
        save(&root.join("check"), &request);
        let reply = collector.check(&request).unwrap();
        save(&root.join("final"), &ev.final_request(&reply).unwrap());
        // Exit without destructors and without completing the pending release.
        std::process::exit(0);
    }
    assert!(collector.check(&fs::read(root.join("check")).unwrap()).is_err());
    assert!(collector.unshard(&fs::read(root.join("final")).unwrap()).is_err());
    let mut retry = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
    retry.ingest(&fs::read(root.join("report")).unwrap()).unwrap();
    assert!(collector.check(&retry.check_request().unwrap()).is_err());
    let mut fresh = ObliviousEvaluator::new(&task, &pk, [42; 32]).unwrap();
    fresh.ingest(&SingleClient::new(&task, &pk).shard(&true).unwrap()).unwrap();
    let reply = collector.check(&fresh.check_request().unwrap()).unwrap();
    assert_eq!(collector.unshard(&fresh.final_request(&reply).unwrap()).unwrap(), 1);
}

fn run_processes(stages: &[&str]) {
    let root = std::env::temp_dir().join(format!(
        "oblivious-process-restart-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for stage in stages {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "restart_worker", "--nocapture"])
            .env("FHE_OBLIVIOUS_RESTART_ROOT", &root)
            .env("FHE_OBLIVIOUS_RESTART_STAGE", stage)
            .output()
            .unwrap();
        assert!(output.status.success(), "stage {stage}: {}", String::from_utf8_lossy(&output.stderr));
    }
    // Delete only this test's random directory, including its test secret key.
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn replay_is_refused_in_a_new_process_after_exit_with_pending_batch() {
    run_processes(&["before", "after"]);
}
#[test]
fn phase_revocation_survives_an_actual_process_exit() {
    run_processes(&["before-revoke", "after-revoke"]);
}
