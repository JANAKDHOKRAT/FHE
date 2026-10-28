//! Shared by the integration tests.

/// OpenFHE keeps evaluation keys in unsynchronised process-global tables:
/// one deployment at a time. A panic in one test must not poison the rest.
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn task_id(seed: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = seed;
    id[31] = 0xA5;
    id
}
