use count_auth::*;
use ed25519_dalek::SigningKey;
use std::{path::PathBuf, process::Command};
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn policy() -> Policy {
    Policy::new(
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        2,
        4,
        1024,
        key(90).verifying_key().to_bytes(),
        (10..16).map(|n| key(n).verifying_key().to_bytes()),
    )
    .unwrap()
}
fn directory() -> PathBuf {
    let p = std::env::temp_dir().join(format!("count-auth-{}-{:x?}", std::process::id(), Policy::random_batch()));
    create_store_dir(&p).unwrap();
    p
}
fn signed(n: u8, value: u8) -> Submission {
    Submission::sign(&policy(), &key(n), vec![value; 8]).unwrap()
}
#[test]
fn replay_persists_and_conflicting_policy_is_refused() {
    let dir = directory();
    let db = dir.join("admission.sqlite");
    let s = signed(10, 1);
    {
        let mut a = Admission::open(&db, policy()).unwrap();
        a.submit(&s, |_| Ok(())).unwrap();
        assert!(matches!(a.submit(&s, |_| Ok(())), Err(Error::Replay)));
    }
    let mut a = Admission::open(&db, policy()).unwrap();
    assert_eq!(a.count().unwrap(), 1);
    assert!(matches!(a.submit(&s, |_| Ok(())), Err(Error::Replay)));
    let different = Policy::new(
        [1; 32],
        [2; 32],
        [3; 32],
        [5; 32],
        2,
        4,
        1024,
        key(90).verifying_key().to_bytes(),
        (10..16).map(|n| key(n).verifying_key().to_bytes()),
    )
    .unwrap();
    assert!(Admission::open(&db, different).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn signature_scope_lengths_and_registry_fail_before_admission() {
    let p = policy();
    let good = signed(10, 1).encode();
    for i in [0, 4, 36, 68, 72, 136] {
        let mut bad = good.clone();
        bad[i] ^= 0x80;
        assert!(Submission::decode(&p, &bad).is_err());
    }
    let mut oversized = good.clone();
    oversized[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Submission::read_from(&p, &mut oversized.as_slice()).is_err());
    assert!(Submission::decode(&p, &signed(99, 1).encode()).is_err());
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(Submission::decode(&p, &trailing).is_err());
    assert!(Submission::decode(&p, &good[..good.len() - 1]).is_err());
    let dir = directory();
    let mut a = Admission::open(&dir.join("a"), p).unwrap();
    assert!(a.submit(&signed(10, 1), |_| Err(Error::Frame)).is_err());
    assert_eq!(a.count().unwrap(), 0);
    assert!(matches!(a.submit(&signed(10, 2), |_| Ok(())), Err(Error::Replay)));
    a.submit(&signed(11, 2), |_| Ok(())).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn minimum_maximum_seal_and_cached_release_are_durable() {
    let dir = directory();
    let path = dir.join("db");
    let p = policy();
    let mut a = Admission::open(&path, p.clone()).unwrap();
    a.submit(&signed(10, 1), |_| Ok(())).unwrap();
    assert!(matches!(a.seal(&key(90), |_| Ok(vec![5])), Err(Error::TooSmall)));
    for n in 11..14 {
        a.submit(&signed(n, n), |_| Ok(())).unwrap();
    }
    assert!(matches!(a.submit(&signed(14, 14), |_| Ok(())), Err(Error::Closed)));
    assert!(matches!(a.seal(&key(91), |_| Ok(vec![5])), Err(Error::Signature)));
    let release = a
        .seal(&key(90), |rows| {
            assert_eq!(rows.len(), 4);
            Ok(vec![5])
        })
        .unwrap()
        .encode();
    drop(a);
    let mut reopened = Admission::open(&path, p.clone()).unwrap();
    assert_eq!(
        release,
        reopened.seal(&key(90), |_| panic!("must reuse durable signed output")).unwrap().encode()
    );
    assert!(reopened.submit(&signed(15, 15), |_| Ok(())).is_err());
    let mut receipts = Receipts::open(&dir.join("receipts")).unwrap();
    for offset in [4, 36, 40, 76, 140] {
        let mut bad = release.clone();
        bad[offset] ^= 1;
        assert!(receipts.consume(&p, &bad, |_| panic!("unauthenticated release reached decrypt")).is_err());
    }
    assert_eq!(
        receipts
            .consume(&p, &release, |r| {
                assert_eq!(r.reports, 4);
                Ok(2)
            })
            .unwrap(),
        2
    );
    drop(receipts);
    let mut receipts = Receipts::open(&dir.join("receipts")).unwrap();
    assert_eq!(receipts.consume(&p, &release, |_| panic!("retry must not decrypt twice")).unwrap(), 2);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn concurrent_process_replay_and_abrupt_exit_recover() {
    let dir = directory();
    let db = dir.join("db");
    Admission::open(&db, policy()).unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut children = vec![];
    for _ in 0..8 {
        children.push(
            Command::new(&exe)
                .args(["process_worker", "--ignored", "--exact", "--nocapture"])
                .env("COUNT_AUTH_DB", &db)
                .spawn()
                .unwrap(),
        );
    }
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(Admission::open(&db, policy()).unwrap().count().unwrap(), 1);
    let status = Command::new(&exe)
        .args(["crash_worker", "--ignored", "--exact"])
        .env("COUNT_AUTH_DB", &db)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(99));
    let mut a = Admission::open(&db, policy()).unwrap();
    assert_eq!(a.count().unwrap(), 1);
    a.submit(&signed(11, 11), |_| Ok(())).unwrap();
    assert_eq!(a.count().unwrap(), 2);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
#[ignore = "child process only"]
fn process_worker() {
    let path = PathBuf::from(std::env::var_os("COUNT_AUTH_DB").unwrap());
    let mut a = Admission::open(&path, policy()).unwrap();
    match a.submit(&signed(10, 1), |_| Ok(())) {
        Ok(()) => eprintln!("accepted"),
        Err(Error::Replay) => eprintln!("replay refused"),
        other => panic!("unexpected {other:?}"),
    }
}
#[test]
#[ignore = "intentional process exit without Rust destructors"]
fn crash_worker() {
    let db = rusqlite::Connection::open(PathBuf::from(std::env::var_os("COUNT_AUTH_DB").unwrap())).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    db.execute(
        "INSERT INTO reports(client,digest,payload) VALUES(?1,?2,?3)",
        rusqlite::params![[44u8; 32].as_slice(), [55u8; 32].as_slice(), [66u8; 8].as_slice()],
    )
    .unwrap();
    std::process::exit(99)
}
#[cfg(unix)]
#[test]
fn refuses_public_directory_and_database_symlink() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = directory();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Admission::open(&dir.join("a"), policy()).is_err());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(dir.join("target"), b"not database").unwrap();
    symlink(dir.join("target"), dir.join("linked")).unwrap();
    assert!(Admission::open(&dir.join("linked"), policy()).is_err());
    assert_eq!(std::fs::read(dir.join("target")).unwrap(), b"not database");
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn aborted_seal_and_decryption_are_atomic_and_conflicts_are_refused() {
    let dir = directory();
    let p = policy();
    let mut a = Admission::open(&dir.join("a"), p.clone()).unwrap();
    for n in 10..12 {
        a.submit(&signed(n, n), |_| Ok(())).unwrap();
    }
    assert!(a.seal(&key(90), |_| Err(Error::Frame)).is_err());
    assert_eq!(a.count().unwrap(), 2);
    a.submit(&signed(12, 12), |_| Ok(())).unwrap();
    let first = a.seal(&key(90), |_| Ok(vec![1])).unwrap().encode();
    let mut b = Admission::open(&dir.join("b"), p.clone()).unwrap();
    for n in 10..12 {
        b.submit(&signed(n, n + 1), |_| Ok(())).unwrap();
    }
    let second = b.seal(&key(90), |_| Ok(vec![2])).unwrap().encode();
    let mut receipts = Receipts::open(&dir.join("r")).unwrap();
    assert!(receipts.consume(&p, &first, |_| Err(Error::Frame)).is_err());
    assert_eq!(receipts.consume(&p, &first, |_| Ok(1)).unwrap(), 1);
    assert!(matches!(
        receipts.consume(&p, &second, |_| panic!("conflicting release reached secret key")),
        Err(Error::ConflictingRelease)
    ));
    let mut forged = first.clone();
    forged[36..40].copy_from_slice(&2u32.to_le_bytes());
    assert!(receipts.consume(&p, &forged, |_| panic!("modified count reached secret key")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn client_key_cannot_also_authorize_releases() {
    let server = key(90).verifying_key().to_bytes();
    assert!(
        Policy::new(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            2,
            4,
            1024,
            server,
            [server, key(10).verifying_key().to_bytes()]
        )
        .is_err()
    );
}
