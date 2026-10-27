use count_auth::{count, *};
use ed25519_dalek::SigningKey;
use fhe_paper_core::*;
use fhe_prio3::{MeasurementType, config::SilentCheck};
use std::sync::Arc;
#[test]
fn actual_bgv_count_authentication_release_and_restart() {
    let dir = std::env::temp_dir().join(format!("count-auth-fhe-{}-{:x?}", std::process::id(), Policy::random_batch()));
    create_store_dir(&dir).unwrap();
    let task = PaperTask::new_native(
        [77; 32],
        MeasurementType::Count,
        SilentCheck::Exact,
        NativeParameters {
            plain_mod: 786433,
            key_switch_digits: 4,
            count_projection: true,
            groups: Some(4),
            ..Default::default()
        },
    )
    .unwrap()
    .with_batch_limit(32)
    .unwrap();
    let (em, cm, collector_key) = setup(&task).unwrap();
    let em = Arc::new(em);
    let server_key = SigningKey::generate(&mut rand_core::OsRng);
    let clients: [SigningKey; 3] = std::array::from_fn(|_| SigningKey::generate(&mut rand_core::OsRng));
    let (profile, cap) = count::profile(&task, &cm).unwrap();
    let epoch = Policy::random_batch();
    let batch = Policy::random_batch();
    let policy = Policy::new(
        task.config().task_id,
        profile,
        epoch,
        batch,
        2,
        32,
        cap,
        server_key.verifying_key().to_bytes(),
        clients.iter().map(|c| c.verifying_key().to_bytes()),
    )
    .unwrap();
    let one = count::client_frame(&task, &cm, &policy, &clients[0], true, 0).unwrap();
    let zero = count::client_frame(&task, &cm, &policy, &clients[1], false, 1).unwrap();
    let mut ingress = count::Ingress::open(&dir.join("admission"), task.clone(), em.clone(), &cm, policy.clone()).unwrap();
    ingress.submit(&one).unwrap();
    assert!(matches!(ingress.submit(&one), Err(Error::Replay)));
    assert!(matches!(ingress.seal(&server_key), Err(Error::TooSmall)));
    drop(ingress);
    let mut ingress = count::Ingress::open(&dir.join("admission"), task.clone(), em, &cm, policy.clone()).unwrap();
    assert!(matches!(ingress.submit(&one), Err(Error::Replay)));
    let mut forged = zero.clone();
    forged[140] ^= 0x80;
    assert!(ingress.submit(&forged).is_err());
    assert_eq!(ingress.count().unwrap(), 1);
    ingress.submit(&zero).unwrap();
    let release = ingress.seal(&server_key).unwrap();
    assert_eq!(release, ingress.seal(&server_key).unwrap());
    assert!(ingress.submit(&one).is_err());
    let mut collector = count::Collector::open(&dir.join("collector"), task.clone(), &cm, &collector_key, policy.clone()).unwrap();
    // Substitute the declared count while staying inside allowed [2,32].
    let mut forged = release.clone();
    forged[36..40].copy_from_slice(&32u32.to_le_bytes());
    assert!(collector.decrypt(&forged).is_err());
    assert!(collector.decrypt(&one).is_err());
    assert_eq!(collector.decrypt(&release).unwrap(), 1);
    drop(collector);
    let mut collector = count::Collector::open(&dir.join("collector"), task.clone(), &cm, &collector_key, policy.clone()).unwrap();
    assert_eq!(collector.decrypt(&release).unwrap(), 1);
    let wrong_epoch = Policy::new(
        task.config().task_id,
        profile,
        Policy::random_batch(),
        batch,
        2,
        32,
        cap,
        server_key.verifying_key().to_bytes(),
        clients.iter().map(|c| c.verifying_key().to_bytes()),
    )
    .unwrap();
    assert!(Release::decode(&wrong_epoch, &release).is_err());
    eprintln!(
        "REAL_FHE_RESULT correct_count=1 clients=2 framed_report_bytes={} release_bytes={} policy_cap={} ring={} depth={} digits=4",
        one.len(),
        release.len(),
        cap,
        task.row_slots() * 2,
        task.mult_depth()
    );
    std::fs::remove_dir_all(dir).unwrap();
}
