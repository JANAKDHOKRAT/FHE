//! The native qualification must not satisfy or weaken threshold qualification.
use openfhe_tbgv_rs::*;
#[test]
fn qualification_modes_are_separate() {
    let _serial = serial();
    let params = Params {
        plain_mod: 786433,
        mult_depth: 3,
        security_bits: 128,
    };
    let native = Context::new_single(params, 3).unwrap();
    let report = verify_single_rebuild_once(&native, 3).unwrap();
    assert_eq!(report.deepest_level, 3);
    assert!(report.objects_checked >= 11);
    assert!(rebuild_verified(&native).unwrap().is_some());
    // Its successful native rebuild cache is not a threshold success.
    assert!(verify_rebuild_once(&native, 3).is_err());
    let threshold = Context::new_tuned(Params { mult_depth: 24, ..params }, 3, 0).unwrap();
    assert!(!threshold.is_single_mode().unwrap());
    assert!(verify_single_rebuild_once(&threshold, 3).is_err());
}

#[test]
fn startup_cache_does_not_cross_key_switching_profiles() {
    let _serial = serial();
    let params = Params {
        plain_mod: 786433,
        mult_depth: 24,
        security_bits: 128,
    };
    let a = Context::new_single(params, 3).unwrap();
    let b = Context::new_single(params, 5).unwrap();
    assert_eq!(a.moduli().unwrap(), b.moduli().unwrap());
    assert_ne!(
        a.key_basis_moduli(KeyBasis::KeySwitch).unwrap(),
        b.key_basis_moduli(KeyBasis::KeySwitch).unwrap()
    );
    verify_single_rebuild_once(&a, 1).unwrap();
    assert!(rebuild_verified(&a).unwrap().is_some());
    assert!(rebuild_verified(&b).unwrap().is_none());
}

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
