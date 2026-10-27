//! Durable authenticated admission and release, NOT an encryption-validity or
//! circuit-privacy proof. Requires an honest evaluator and trusted local storage.
//! No process may bypass this API in a service that claims its replay policy.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    path::Path,
    sync::{Mutex, OnceLock},
    time::Duration,
};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("policy: {0}")]
    Policy(&'static str),
    #[error("invalid authenticated frame")]
    Frame,
    #[error("signature refused")]
    Signature,
    #[error("unregistered client")]
    Unregistered,
    #[error("replay or duplicate client in this batch")]
    Replay,
    #[error("batch closed or full")]
    Closed,
    #[error("batch below minimum size")]
    TooSmall,
    #[error("different release already consumed for batch")]
    ConflictingRelease,
    #[error("database: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("FHE: {0}")]
    Fhe(#[from] fhe_prio3::error::Error),
    #[error("OpenFHE: {0}")]
    OpenFhe(#[from] openfhe_tbgv_rs::Error),
    #[error("cryptographic operation lock poisoned")]
    Poisoned,
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn crypto_lock() -> Result<std::sync::MutexGuard<'static, ()>> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().map_err(|_| Error::Poisoned)
}
const REPORT_DOMAIN: &[u8] = b"count-auth/v1/report";
const RELEASE_DOMAIN: &[u8] = b"count-auth/v1/release";
const HEADER: usize = 136;
/// Explicit trusted policy. Batch identifiers must be freshly generated and
/// policy/registry must come through authenticated provisioning, not a client.
#[derive(Clone)]
pub struct Policy {
    task: [u8; 32],
    profile: [u8; 32],
    epoch: [u8; 32],
    batch: [u8; 32],
    scope: [u8; 32],
    minimum: u32,
    maximum: u32,
    payload_cap: usize,
    release_key: [u8; 32],
    clients: BTreeSet<[u8; 32]>,
}
impl Policy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task: [u8; 32],
        profile: [u8; 32],
        epoch: [u8; 32],
        batch: [u8; 32],
        minimum: u32,
        maximum: u32,
        payload_cap: usize,
        release_key: [u8; 32],
        clients: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<Self> {
        let clients: BTreeSet<_> = clients.into_iter().collect();
        if minimum < 2
            || maximum < minimum
            || maximum > 32
            || payload_cap == 0
            || payload_cap > 32 * 1024 * 1024
            || clients.len() < minimum as usize
            || clients.len() > 32
        {
            return Err(Error::Policy("invalid bounds/registry"));
        }
        if clients.contains(&release_key) {
            return Err(Error::Policy("client and evaluator release-signing keys must be distinct"));
        }
        for pk in clients.iter().chain(std::iter::once(&release_key)) {
            let k = VerifyingKey::from_bytes(pk).map_err(|_| Error::Signature)?;
            if k.is_weak() {
                return Err(Error::Signature);
            }
        }
        let mut h = Sha256::new();
        h.update(b"count-auth/v1/policy");
        for b in [task, profile, epoch, batch, release_key] {
            h.update(b);
        }
        h.update(minimum.to_le_bytes());
        h.update(maximum.to_le_bytes());
        h.update((payload_cap as u64).to_le_bytes());
        h.update((clients.len() as u32).to_le_bytes());
        for pk in &clients {
            h.update(pk);
        }
        let scope = h.finalize().into();
        Ok(Self {
            task,
            profile,
            epoch,
            batch,
            scope,
            minimum,
            maximum,
            payload_cap,
            release_key,
            clients,
        })
    }
    pub fn random_batch() -> [u8; 32] {
        let mut b = [0; 32];
        OsRng.fill_bytes(&mut b);
        b
    }
    pub fn scope(&self) -> [u8; 32] {
        self.scope
    }
    pub fn identifiers(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (self.profile, self.epoch, self.batch)
    }
    pub fn payload_cap(&self) -> usize {
        self.payload_cap
    }
}
fn report_message(scope: &[u8; 32], client: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut b = REPORT_DOMAIN.to_vec();
    b.extend(scope);
    b.extend(client);
    b.extend((payload.len() as u64).to_le_bytes());
    b.extend(hash(payload));
    b
}
/// Fixed header + bounded opaque bytes, avoiding an untrusted Vec-length
/// deserializer. The payload has a separate, Count-specific canonical parser.
#[derive(Clone)]
pub struct Submission {
    scope: [u8; 32],
    client: [u8; 32],
    signature: [u8; 64],
    payload: Vec<u8>,
}
impl Submission {
    pub fn sign(policy: &Policy, key: &SigningKey, payload: Vec<u8>) -> Result<Self> {
        if payload.len() > policy.payload_cap {
            return Err(Error::Frame);
        }
        let client = key.verifying_key().to_bytes();
        let signature = key.sign(&report_message(&policy.scope, &client, &payload)).to_bytes();
        Ok(Self {
            scope: policy.scope,
            client,
            signature,
            payload,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER + self.payload.len());
        b.extend(b"FCS1");
        b.extend(self.scope);
        b.extend(self.client);
        b.extend((self.payload.len() as u32).to_le_bytes());
        b.extend(self.signature);
        b.extend(&self.payload);
        b
    }
    fn header(policy: &Policy, header: &[u8]) -> Result<(usize, [u8; 32])> {
        if header.len() != HEADER || &header[..4] != b"FCS1" || header[4..36] != policy.scope {
            return Err(Error::Frame);
        }
        let client: [u8; 32] = header[36..68].try_into().map_err(|_| Error::Frame)?;
        if !policy.clients.contains(&client) {
            return Err(Error::Unregistered);
        }
        let len = u32::from_le_bytes(header[68..72].try_into().map_err(|_| Error::Frame)?) as usize;
        if len > policy.payload_cap {
            return Err(Error::Frame);
        }
        Ok((len, client))
    }
    pub fn decode(policy: &Policy, bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER {
            return Err(Error::Frame);
        }
        let (len, client) = Self::header(policy, &bytes[..HEADER])?;
        if bytes.len() != HEADER + len {
            return Err(Error::Frame);
        }
        let signature = bytes[72..136].try_into().map_err(|_| Error::Frame)?;
        let key = VerifyingKey::from_bytes(&client).map_err(|_| Error::Signature)?;
        key.verify_strict(&report_message(&policy.scope, &client, &bytes[HEADER..]), &Signature::from_bytes(&signature))
            .map_err(|_| Error::Signature)?;
        Ok(Self {
            scope: policy.scope,
            client,
            signature,
            payload: bytes[HEADER..].to_vec(),
        })
    }
    /// Reader must have transport read deadlines. Never allocates a claimed
    /// payload until scope, registry and maximum size have been checked.
    pub fn read_from(policy: &Policy, reader: &mut impl Read) -> Result<Self> {
        let mut header = [0; HEADER];
        reader.read_exact(&mut header)?;
        let (len, _) = Self::header(policy, &header)?;
        let mut bytes = Vec::with_capacity(HEADER + len);
        bytes.extend(header);
        bytes.resize(HEADER + len, 0);
        reader.read_exact(&mut bytes[HEADER..])?;
        Self::decode(policy, &bytes)
    }
    fn verify(&self, policy: &Policy) -> Result<()> {
        if self.scope != policy.scope || !policy.clients.contains(&self.client) || self.payload.len() > policy.payload_cap {
            return Err(Error::Frame);
        }
        VerifyingKey::from_bytes(&self.client)
            .map_err(|_| Error::Signature)?
            .verify_strict(
                &report_message(&self.scope, &self.client, &self.payload),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::Signature)
    }
}
/// Creates an owner-only store directory; never relaxes an existing directory.
#[cfg(unix)]
pub fn create_store_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    if !path.exists() {
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let meta = std::fs::symlink_metadata(path)?;
    // SAFETY: getuid has no preconditions and reads the caller's OS identity.
    let uid = unsafe { libc::getuid() };
    if !meta.is_dir() || meta.uid() != uid || meta.permissions().mode() & 0o077 != 0 {
        return Err(Error::Policy("store directory must be owned by this user, mode0700, not a symlink"));
    }
    Ok(())
}
#[cfg(not(unix))]
pub fn create_store_dir(_path: &Path) -> Result<()> {
    Err(Error::Policy("private store qualification requires Unix"))
}
fn connect(path: &Path) -> Result<Connection> {
    // Dedicated trusted directory required: refuse replacement/rollback by an
    // untrusted OS user. SQLite provides process locking and crash recovery.
    let parent = path.parent().ok_or(Error::Policy("database needs private parent directory"))?;
    create_store_dir(parent)?;
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let db = Connection::open_with_flags(path, flags)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    db.busy_timeout(Duration::from_secs(30))?;
    db.pragma_update(None, "journal_mode", "WAL")?;
    db.pragma_update(None, "synchronous", "FULL")?;
    Ok(db)
}
pub struct Admission {
    db: Connection,
    policy: Policy,
}
impl Admission {
    pub fn open(path: &Path, policy: Policy) -> Result<Self> {
        let mut db = connect(path)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS batch(id INTEGER PRIMARY KEY CHECK(id=1),scope BLOB NOT NULL CHECK(length(scope)=32),sealed INTEGER NOT NULL DEFAULT 0 CHECK(sealed IN(0,1)),release BLOB); CREATE TABLE IF NOT EXISTS attempts(client BLOB PRIMARY KEY CHECK(length(client)=32)); CREATE TABLE IF NOT EXISTS reports(client BLOB PRIMARY KEY CHECK(length(client)=32),digest BLOB NOT NULL UNIQUE CHECK(length(digest)=32),payload BLOB NOT NULL);")?;
        tx.execute("INSERT OR IGNORE INTO batch(id,scope) VALUES(1,?1)", [policy.scope.as_slice()])?;
        let scope: Vec<u8> = tx.query_row("SELECT scope FROM batch WHERE id=1", [], |r| r.get(0))?;
        if scope != policy.scope {
            return Err(Error::Policy("database belongs to another policy/epoch/batch"));
        }
        tx.commit()?;
        Ok(Self { db, policy })
    }
    /// One authenticated attempt per eligible client, including a malformed
    /// signed payload. Bad signatures never consume another client's quota.
    /// Failed validation commits only the attempt, never a report.
    pub fn submit(&mut self, s: &Submission, validate: impl FnOnce(&[u8]) -> Result<()>) -> Result<()> {
        s.verify(&self.policy)?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sealed: i64 = tx.query_row("SELECT sealed FROM batch WHERE id=1", [], |r| r.get(0))?;
        if sealed != 0 {
            return Err(Error::Closed);
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM attempts WHERE client=?1 UNION ALL SELECT 1 FROM reports WHERE client=?1 OR digest=?2)",
            params![s.client.as_slice(), hash(&s.payload).as_slice()],
            |r| r.get(0),
        )?;
        if exists {
            return Err(Error::Replay);
        }
        let count: u32 = tx.query_row("SELECT count(*) FROM reports", [], |r| r.get(0))?;
        if count >= self.policy.maximum {
            return Err(Error::Closed);
        }
        tx.execute("INSERT INTO attempts(client) VALUES(?1)", [s.client.as_slice()])?;
        if let Err(error) = validate(&s.payload) {
            tx.commit()?;
            return Err(error);
        }
        tx.execute(
            "INSERT INTO reports(client,digest,payload) VALUES(?1,?2,?3)",
            params![s.client.as_slice(), hash(&s.payload).as_slice(), &s.payload],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn count(&self) -> Result<u32> {
        Ok(self.db.query_row("SELECT count(*) FROM reports", [], |r| r.get(0))?)
    }
    /// Transaction freezes admission while the honest evaluator computes. A crash
    /// before commit rolls back; after commit the exact same release is returned.
    pub fn seal(&mut self, key: &SigningKey, evaluate: impl FnOnce(&[Vec<u8>]) -> Result<Vec<u8>>) -> Result<Release> {
        if key.verifying_key().to_bytes() != self.policy.release_key {
            return Err(Error::Signature);
        }
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<Vec<u8>> = tx.query_row("SELECT release FROM batch WHERE id=1", [], |r| r.get(0))?;
        if let Some(stored) = stored {
            return Release::decode(&self.policy, &stored);
        }
        let mut stmt = tx.prepare("SELECT client,digest,payload FROM reports ORDER BY client")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        if rows.len() < self.policy.minimum as usize {
            return Err(Error::TooSmall);
        }
        if rows.len() > self.policy.maximum as usize {
            return Err(Error::Closed);
        }
        let mut h = Sha256::new();
        h.update(b"count-auth/v1/transcript");
        h.update(self.policy.scope);
        h.update((rows.len() as u32).to_le_bytes());
        for (c, d, _) in &rows {
            h.update(c);
            h.update(d);
        }
        let transcript = h.finalize().into();
        let payloads: Vec<_> = rows.into_iter().map(|(_, _, p)| p).collect();
        let output = evaluate(&payloads)?;
        if output.len() > self.policy.payload_cap {
            return Err(Error::Frame);
        }
        let release = Release::sign(&self.policy, key, payloads.len() as u32, transcript, output);
        tx.execute("UPDATE batch SET sealed=1,release=?1 WHERE id=1", [release.encode()])?;
        tx.commit()?;
        Ok(release)
    }
}
#[derive(Clone)]
pub struct Release {
    scope: [u8; 32],
    pub reports: u32,
    transcript: [u8; 32],
    pub output: Vec<u8>,
    signature: [u8; 64],
}
impl Release {
    fn message(&self) -> Vec<u8> {
        let mut m = RELEASE_DOMAIN.to_vec();
        m.extend(self.scope);
        m.extend(self.reports.to_le_bytes());
        m.extend(self.transcript);
        m.extend((self.output.len() as u64).to_le_bytes());
        m.extend(hash(&self.output));
        m
    }
    fn sign(p: &Policy, key: &SigningKey, reports: u32, transcript: [u8; 32], output: Vec<u8>) -> Self {
        let mut r = Self {
            scope: p.scope,
            reports,
            transcript,
            output,
            signature: [0; 64],
        };
        r.signature = key.sign(&r.message()).to_bytes();
        r
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = b"FCR1".to_vec();
        b.extend(self.scope);
        b.extend(self.reports.to_le_bytes());
        b.extend(self.transcript);
        b.extend((self.output.len() as u32).to_le_bytes());
        b.extend(self.signature);
        b.extend(&self.output);
        b
    }
    pub fn decode(p: &Policy, bytes: &[u8]) -> Result<Self> {
        const H: usize = 140;
        if bytes.len() < H || &bytes[..4] != b"FCR1" || bytes[4..36] != p.scope {
            return Err(Error::Frame);
        }
        let reports = u32::from_le_bytes(bytes[36..40].try_into().map_err(|_| Error::Frame)?);
        let len = u32::from_le_bytes(bytes[72..76].try_into().map_err(|_| Error::Frame)?) as usize;
        if reports < p.minimum || reports > p.maximum || len > p.payload_cap || bytes.len() != H + len {
            return Err(Error::Frame);
        }
        let r = Self {
            scope: p.scope,
            reports,
            transcript: bytes[40..72].try_into().map_err(|_| Error::Frame)?,
            signature: bytes[76..140].try_into().map_err(|_| Error::Frame)?,
            output: bytes[H..].to_vec(),
        };
        VerifyingKey::from_bytes(&p.release_key)
            .map_err(|_| Error::Signature)?
            .verify_strict(&r.message(), &Signature::from_bytes(&r.signature))
            .map_err(|_| Error::Signature)?;
        Ok(r)
    }
}
/// Durable, idempotent collector release. Exact retries return the cached
/// count; conflicting releases for the same scope are refused before decryption.
pub struct Receipts {
    db: Connection,
}
impl Receipts {
    pub fn open(path: &Path) -> Result<Self> {
        let db = connect(path)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS receipts(scope BLOB PRIMARY KEY CHECK(length(scope)=32),digest BLOB NOT NULL CHECK(length(digest)=32),value BLOB NOT NULL CHECK(length(value)=8));")?;
        Ok(Self { db })
    }
    pub fn consume(&mut self, p: &Policy, bytes: &[u8], decrypt: impl FnOnce(&Release) -> Result<u64>) -> Result<u64> {
        let release = Release::decode(p, bytes)?;
        let digest = hash(bytes);
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row("SELECT digest,value FROM receipts WHERE scope=?1", [p.scope.as_slice()], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        if let Some((d, v)) = prior {
            if d != digest {
                return Err(Error::ConflictingRelease);
            }
            return Ok(u64::from_le_bytes(v.as_slice().try_into().map_err(|_| Error::Frame)?));
        }
        let value = decrypt(&release)?;
        if value > release.reports as u64 {
            return Err(Error::Frame);
        }
        tx.execute(
            "INSERT INTO receipts(scope,digest,value) VALUES(?1,?2,?3)",
            params![p.scope.as_slice(), digest.as_slice(), value.to_le_bytes().as_slice()],
        )?;
        tx.commit()?;
        Ok(value)
    }
}

pub mod count;
