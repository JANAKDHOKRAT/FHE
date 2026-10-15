//! Secret-shared upload ([`Upload::Shares`]): Prio3's report format, with
//! the validity check still run under encryption.
//!
//! Client. The encoded measurement `x` (field elements mod `p`) is split
//! into one additive share per key party, `x = s_0 + s_1 + ... (mod p)`.
//! Party `i > 0` receives a 32-byte seed from which its share is expanded
//! with SHAKE128 ([`expand_seed`]); party 0 receives its share explicitly,
//! `s_0 = x - sum_{i>0} s_i`. Each share is sealed to its party's X25519
//! key ([`TaskConfig::upload_keys`]): ephemeral Diffie-Hellman, HKDF-SHA256
//! and AES-256-GCM, with associated data binding the task, the report nonce,
//! the party and the number of parties. The report id hashes the task, the
//! nonce and every sealed byte, so the value the shares add up to is fixed
//! once the report is sent, before the check's coefficients (derived from
//! the id and the aggregators' secret verify key) exist. Nothing else
//! changes about the check: the same random linear combination of
//! `x_i (x_i - 1)` and the linear constraints, the same Fermat test.
//!
//! Key parties. The leader admits reports (cheap, deterministic structural
//! checks) and assigns report `k` of a verification batch to group `k`.
//! When the batch is full (or the batch closes) it sends the reports to the
//! other key parties ([`ShareFlushRequest`]). Every key party opens its own
//! sealed input of each report, writes its shares at the reports' group
//! slots and encrypts them under the joint key as one contribution per
//! chunk with a proof that it is well formed (`wfe.rs`; the effective
//! ciphertext `2C` decodes to the shares). The aggregators verify the
//! others' proofs, add the effective contributions, restrict the sum to the
//! element slots of the occupied groups (one plaintext multiplication: the
//! level the per-report group mask uses with ciphertext upload) and run the
//! unchanged validity circuit on it.
//!
//! A sealed input that does not open, or opens to a non-canonical share,
//! is taken as an all-zero share by the party that holds it. That is a
//! deterministic function of the report bytes and the party's key, so the
//! report still adds up to a fixed value the client chose (an arbitrary
//! value the check then accepts or zeroes); nobody else learns which input
//! failed, and no party needs to agree with another about it.
//!
//! Contributions are deterministic: the encryption and proof randomness is
//! expanded (ChaCha20) from a key derived from the party's upload secret,
//! the task and the flush digest. A party asked again for a flush it
//! already contributed to (after a restart, or a retried request) returns
//! the identical bytes, so nothing but the digest needs to be persisted.
//! Different flushes never share randomness (the flush digest binds the
//! sequence number and every report id).

use crate::config::{TaskConfig, Upload};
use crate::error::{Error, RejectReason, Result};
use crate::field::Field;
use crate::layout::Layout;
use crate::messages::{ReportId, SealedInput, ShareContribution, ShareFlushRequest, ShareReport};
use crate::packed::{Codec, Expect};
use crate::types::Measurement;
use crate::wfe;
use crate::xof::Xof;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use openfhe_tbgv_rs::{Ciphertext, Context, PublicKey};
use rand::SeedableRng;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

/// Domain of sealed input shares: a sealed input never opens as an
/// aggregate share or a release reveal (`seal.rs`), nor the reverse.
pub const INPUT_SEAL_DOMAIN: &[u8] = b"fhe-prio3/3 sealed input share";
/// Length of a seed share.
pub const SEED_LEN: usize = 32;
/// AES-GCM tag length.
const TAG_LEN: usize = 16;
/// Bytes per element of the explicit share (little-endian `u32`, below `p`).
pub const ELEMENT_BYTES: usize = 4;

/// A key party's long-term upload key pair: clients seal its input shares
/// to the public half, which the task names in [`TaskConfig::upload_keys`].
pub struct UploadKey {
    secret: StaticSecret,
}

impl UploadKey {
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(rand_core::OsRng),
        }
    }
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(*bytes),
        }
    }
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
    pub fn public_key(&self) -> [u8; 32] {
        X25519Public::from(&self.secret).to_bytes()
    }

    /// Key of the deterministic randomness of this party's contribution to
    /// one flush (see the module documentation).
    fn contribution_seed(&self, cfg: &TaskConfig, flush_digest: &[u8; 32], party: usize) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"fhe-prio3/3 share contribution randomness"), &self.secret.to_bytes());
        let mut info = Vec::with_capacity(32 + 32 + 8);
        info.extend_from_slice(&cfg.digest());
        info.extend_from_slice(flush_digest);
        info.extend_from_slice(&(party as u64).to_le_bytes());
        let mut seed = [0u8; 32];
        hk.expand(&info, &mut seed).expect("32 bytes is a valid HKDF output length");
        seed
    }
}

/// Exact length of party `party`'s sealed ciphertext for an encoded
/// measurement of `m` elements.
pub fn sealed_len(party: usize, m: usize) -> usize {
    if party == 0 { m * ELEMENT_BYTES + TAG_LEN } else { SEED_LEN + TAG_LEN }
}

fn aad(task_id: &[u8; 32], nonce: &[u8; 16], party: usize, parties: usize) -> Vec<u8> {
    let mut a = Vec::with_capacity(INPUT_SEAL_DOMAIN.len() + 64);
    a.extend_from_slice(INPUT_SEAL_DOMAIN);
    a.extend_from_slice(task_id);
    a.extend_from_slice(nonce);
    a.extend_from_slice(&(party as u32).to_le_bytes());
    a.extend_from_slice(&(parties as u32).to_le_bytes());
    a
}

fn seal_input(task_id: &[u8; 32], nonce: &[u8; 16], party: usize, parties: usize, plain: &[u8], recipient: &[u8; 32]) -> Result<SealedInput> {
    let recipient_pk = X25519Public::from(*recipient);
    let eph = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_pk = X25519Public::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&recipient_pk);
    if !shared.was_contributory() {
        return Err(Error::Config(format!("upload key of party {party} is a low-order point")));
    }
    let mut key = crate::seal::derive_key(INPUT_SEAL_DOMAIN, shared.as_bytes(), &eph_pk, recipient)?;
    let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    key.zeroize();
    let mut gcm_nonce = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut gcm_nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&gcm_nonce),
            Payload {
                msg: plain,
                aad: &aad(task_id, nonce, party, parties),
            },
        )
        .map_err(|_| Error::Protocol("sealing an input share".into()))?;
    Ok(SealedInput {
        ephemeral: eph_pk,
        nonce: gcm_nonce,
        ciphertext,
    })
}

/// Opens party `party`'s sealed input, or `None` if it does not open.
fn open_input(key: &UploadKey, task_id: &[u8; 32], nonce: &[u8; 16], party: usize, parties: usize, sealed: &SealedInput) -> Option<Vec<u8>> {
    let shared = key.secret.diffie_hellman(&X25519Public::from(sealed.ephemeral));
    if !shared.was_contributory() {
        return None;
    }
    let mut k = crate::seal::derive_key(INPUT_SEAL_DOMAIN, shared.as_bytes(), &sealed.ephemeral, &key.public_key()).ok()?;
    let cipher = Aes256Gcm::new_from_slice(&k).expect("32-byte key");
    k.zeroize();
    cipher
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: &aad(task_id, nonce, party, parties),
            },
        )
        .ok()
}

/// Party `party`'s share expanded from its seed: `m` elements uniform in
/// `[0, p)`, by rejection from the low `ceil(log2 p)` bits of 32-bit words.
pub fn expand_seed(field: &Field, task_id: &[u8; 32], nonce: &[u8; 16], party: usize, seed: &[u8], m: usize) -> Vec<u64> {
    let mut xof = Xof::new(b"input share", &[task_id, nonce, &(party as u64).to_le_bytes(), seed]);
    (0..m).map(|_| xof.next_field_elem_dense(field)).collect()
}

fn encode_explicit(share: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(share.len() * ELEMENT_BYTES);
    for &v in share {
        out.extend_from_slice(&(v as u32).to_le_bytes());
    }
    out
}

/// The explicit share, if every element is canonical (below `p`).
fn decode_explicit(field: &Field, bytes: &[u8], m: usize) -> Option<Vec<u64>> {
    if bytes.len() != m * ELEMENT_BYTES {
        return None;
    }
    let p = field.modulus();
    bytes
        .chunks_exact(ELEMENT_BYTES)
        .map(|c| {
            let v = u32::from_le_bytes(c.try_into().expect("4 bytes")) as u64;
            (v < p).then_some(v)
        })
        .collect()
}

/// What happened to a party's sealed input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputShare {
    /// The input opened to a canonical share.
    Opened(Vec<u64>),
    /// It did not open (wrong key, tampered, low-order ephemeral key) or
    /// its explicit share was not canonical: the party uses zero.
    Unopenable,
}

impl InputShare {
    /// The share the party contributes (all zero when unopenable).
    pub fn values(&self, m: usize) -> Vec<u64> {
        match self {
            InputShare::Opened(v) => v.clone(),
            InputShare::Unopenable => vec![0; m],
        }
    }
}

/// Party `party`'s share of `report` (structure already checked).
pub fn party_share(cfg: &TaskConfig, field: &Field, key: &UploadKey, report: &ShareReport, party: usize) -> InputShare {
    let m = cfg.measurement_type.input_len();
    let parties = cfg.num_key_parties();
    let Some(mut plain) = open_input(key, &report.task_id, &report.nonce, party, parties, &report.inputs[party]) else {
        return InputShare::Unopenable;
    };
    let share = if party == 0 {
        decode_explicit(field, &plain, m)
    } else if plain.len() == SEED_LEN {
        Some(expand_seed(field, &report.task_id, &report.nonce, party, &plain, m))
    } else {
        None
    };
    plain.zeroize();
    match share {
        Some(v) => InputShare::Opened(v),
        None => InputShare::Unopenable,
    }
}

/// Structural checks of a share report that every key party makes the same
/// way and that need no secret: upload kind, task, input count, exact
/// sealed lengths and the report id. Signatures, quotas and replays are
/// checked by the caller.
pub fn check_structure(cfg: &TaskConfig, report: &ShareReport) -> std::result::Result<(), RejectReason> {
    if cfg.upload != Upload::Shares {
        return Err(RejectReason::WrongUpload);
    }
    if report.task_id != cfg.task_id {
        return Err(RejectReason::WrongTask);
    }
    let parties = cfg.num_key_parties();
    if report.inputs.len() != parties {
        return Err(RejectReason::WrongInputShareCount {
            expected: parties,
            got: report.inputs.len(),
        });
    }
    let m = cfg.measurement_type.input_len();
    for (party, input) in report.inputs.iter().enumerate() {
        let expected = sealed_len(party, m);
        if input.ciphertext.len() != expected {
            return Err(RejectReason::MalformedInputShare {
                party,
                expected,
                got: input.ciphertext.len(),
            });
        }
    }
    if ShareReport::compute_id(&report.task_id, &report.nonce, &report.inputs) != report.report_id {
        return Err(RejectReason::ReportIdMismatch);
    }
    Ok(())
}

/// The client side of [`Upload::Shares`]: encodes, shares and seals. Needs
/// the task alone (its upload keys), no homomorphic material.
pub struct ShareClient {
    cfg: TaskConfig,
    field: Field,
    identity: Option<crate::auth::ClientIdentity>,
}

impl ShareClient {
    pub fn new(cfg: TaskConfig) -> Result<Self> {
        let field = cfg.validate()?;
        if cfg.upload != Upload::Shares {
            return Err(Error::Config("ShareClient needs a task whose upload is Upload::Shares".into()));
        }
        Ok(Self { cfg, field, identity: None })
    }

    /// Attaches the signing identity used when the task requires authentication.
    pub fn with_identity(mut self, identity: crate::auth::ClientIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn config(&self) -> &TaskConfig {
        &self.cfg
    }

    /// Encodes `m` and shares it.
    pub fn shard(&self, m: &Measurement) -> Result<ShareReport> {
        let x = self.cfg.measurement_type.encode(m)?;
        self.shard_encoded(&x)
    }

    /// Shares an already encoded measurement. Any field elements are
    /// accepted: this is also how a malicious client is modelled (the
    /// check, not the client, decides validity).
    pub fn shard_encoded(&self, x: &[u64]) -> Result<ShareReport> {
        let m = self.cfg.measurement_type.input_len();
        if x.len() != m || x.iter().any(|&v| v >= self.field.modulus()) {
            return Err(Error::Config(format!("an encoded measurement has {m} elements below p")));
        }
        let parties = self.cfg.num_key_parties();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let mut explicit = x.to_vec();
        let mut plains: Vec<Vec<u8>> = Vec::with_capacity(parties);
        plains.push(Vec::new());
        for party in 1..parties {
            let mut seed = vec![0u8; SEED_LEN];
            rand_core::OsRng.fill_bytes(&mut seed);
            let s = expand_seed(&self.field, &self.cfg.task_id, &nonce, party, &seed, m);
            for (e, v) in explicit.iter_mut().zip(&s) {
                *e = self.field.sub(*e, *v);
            }
            plains.push(seed);
        }
        plains[0] = encode_explicit(&explicit);
        explicit.zeroize();
        let inputs = self.seal_all(&nonce, &plains)?;
        for p in plains.iter_mut() {
            p.zeroize();
        }
        self.finish(nonce, inputs)
    }

    /// TEST HOOK: a report whose party-`i` plaintext is `plains[i]`
    /// verbatim (any length or content), sealed correctly. Models clients
    /// that send malformed or non-canonical shares.
    pub fn shard_raw_inputs_for_tests(&self, plains: &[Vec<u8>]) -> Result<ShareReport> {
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let inputs = self.seal_all(&nonce, plains)?;
        self.finish(nonce, inputs)
    }

    /// TEST HOOK: re-signs and re-identifies a report whose inputs a test
    /// changed (a malicious client sending a consistent but altered report).
    pub fn finish_altered_for_tests(&self, nonce: [u8; 16], inputs: Vec<SealedInput>) -> Result<ShareReport> {
        self.finish(nonce, inputs)
    }

    fn seal_all(&self, nonce: &[u8; 16], plains: &[Vec<u8>]) -> Result<Vec<SealedInput>> {
        let parties = plains.len();
        plains
            .iter()
            .enumerate()
            .map(|(party, plain)| {
                let key = self
                    .cfg
                    .upload_keys
                    .get(party)
                    .ok_or_else(|| Error::Config(format!("no upload key for party {party}")))?;
                seal_input(&self.cfg.task_id, nonce, party, parties, plain, key)
            })
            .collect()
    }

    fn finish(&self, nonce: [u8; 16], inputs: Vec<SealedInput>) -> Result<ShareReport> {
        let report_id = ShareReport::compute_id(&self.cfg.task_id, &nonce, &inputs);
        let auth = match (&self.cfg.auth, &self.identity) {
            (crate::config::AuthPolicy::Open, _) => None,
            (crate::config::AuthPolicy::Required { .. }, Some(id)) => Some(id.sign(&self.cfg.task_id, &report_id)),
            (crate::config::AuthPolicy::Required { .. }, None) => {
                return Err(Error::Config("task requires authentication but the client has no identity".into()));
            }
        };
        Ok(ShareReport {
            task_id: self.cfg.task_id,
            report_id,
            nonce,
            inputs,
            auth,
        })
    }
}

/// What a key party needs to contribute to, or combine, a flush.
pub struct ShareEnv<'a> {
    pub cfg: &'a TaskConfig,
    pub field: &'a Field,
    pub layout: &'a Layout,
    pub ctx: &'a Context,
    pub pk: &'a PublicKey,
    pub codec: &'a Codec,
    pub key: &'a UploadKey,
    /// Key-party index: aggregators `0..num_aggregators`, then the collector.
    pub party: usize,
}

/// Binds a contribution's proof to its use, so it cannot be replayed as
/// another party's, another chunk's or another flush's.
fn proof_context(cfg: &TaskConfig, flush_digest: &[u8; 32], party: usize, chunk: usize) -> Vec<u8> {
    let mut c = b"shares".to_vec();
    c.extend_from_slice(&cfg.digest());
    c.extend_from_slice(flush_digest);
    c.extend_from_slice(&(party as u64).to_le_bytes());
    c.extend_from_slice(&(chunk as u64).to_le_bytes());
    c
}

/// A fresh encryption of zero: the shape every contribution must have.
fn reference(ctx: &Context, pk: &PublicKey) -> Result<Ciphertext> {
    Ok(ctx.encrypt(pk, &ctx.plaintext(&[0])?)?)
}

/// Checks the shape of a flush request every party agrees on: task,
/// report count within the layout's groups, report `k` in group `k`.
pub fn check_request(cfg: &TaskConfig, layout: &Layout, req: &ShareFlushRequest) -> Result<()> {
    if req.task_id != cfg.task_id {
        return Err(Error::Protocol("share flush for another task".into()));
    }
    if req.reports.is_empty() || req.reports.len() > layout.groups {
        return Err(Error::Protocol(format!(
            "share flush of {} reports; between 1 and {} (the layout's groups)",
            req.reports.len(),
            layout.groups
        )));
    }
    let mut ids = std::collections::HashSet::with_capacity(req.reports.len());
    for r in &req.reports {
        if !ids.insert(r.report_id) {
            return Err(Error::Protocol("a share flush lists one report twice".into()));
        }
    }
    Ok(())
}

/// The (group, report id) list of a flush: report `k` occupies group `k`.
pub fn flush_reports(req: &ShareFlushRequest) -> Vec<(usize, ReportId)> {
    req.reports.iter().enumerate().map(|(g, r)| (g, r.report_id)).collect()
}

/// This party's contribution to `req` (deterministic; see the module
/// documentation). The reports' structure must have been checked.
pub fn contribution(env: &ShareEnv, req: &ShareFlushRequest) -> Result<ShareContribution> {
    let digest = req.digest();
    let n = env.ctx.ring_dim() as usize;
    let m = env.cfg.measurement_type.input_len();
    let shares: Vec<Vec<u64>> = req
        .reports
        .iter()
        .map(|r| party_share(env.cfg, env.field, env.key, r, env.party).values(m))
        .collect();
    let mut seed = env.key.contribution_seed(env.cfg, &digest, env.party);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    let reference = reference(env.ctx, env.pk)?;
    let sf = reference.meta()?.scaling_factor_int;
    let slots = wfe::SlotCodec::new(env.ctx)?;
    let mut chunks = Vec::with_capacity(env.layout.num_chunks);
    let mut proofs = Vec::with_capacity(env.layout.num_chunks);
    for c in 0..env.layout.num_chunks {
        let mut v = vec![0u64; n];
        for (g, share) in shares.iter().enumerate() {
            for (local, global) in env.layout.chunk_range(c).enumerate() {
                v[env.layout.group_slot(g, local)] = share[global];
            }
        }
        let mut coeffs = slots.contribution_plaintext(&v, sf);
        v.zeroize();
        let (ct, proof) = wfe::encrypt_proven(env.ctx, env.pk, &reference, &coeffs, &proof_context(env.cfg, &digest, env.party, c), &mut rng)?;
        coeffs.zeroize();
        chunks.push(env.codec.encode(&ct)?);
        proofs.push(proof);
    }
    Ok(ShareContribution {
        task_id: env.cfg.task_id,
        party: env.party,
        seq: req.seq,
        flush_digest: digest,
        chunks,
        proofs,
    })
}

/// Aggregators: checks every key party's contribution to `req` (the shape,
/// the binding to this flush, this party's own against the digest it
/// recorded, and every other party's proofs) and returns the sum of the
/// effective contributions per chunk, still unrestricted: the caller
/// masks it to the occupied groups' element slots.
pub fn combine(env: &ShareEnv, req: &ShareFlushRequest, contributions: &[ShareContribution], own_digest: &[u8; 32]) -> Result<Vec<Ciphertext>> {
    let parties = env.cfg.num_key_parties();
    let digest = req.digest();
    let mut sorted: Vec<&ShareContribution> = contributions.iter().collect();
    sorted.sort_by_key(|c| c.party);
    if sorted.len() != parties || sorted.iter().enumerate().any(|(i, c)| c.party != i) {
        return Err(Error::Protocol(format!("expected one share contribution from each of {parties} key parties")));
    }
    let reference = reference(env.ctx, env.pk)?;
    let fresh = env.codec.fresh_meta();
    let mut acc: Option<Vec<Ciphertext>> = None;
    for c in sorted {
        let p = c.party;
        if c.task_id != env.cfg.task_id || c.seq != req.seq || c.flush_digest != digest {
            return Err(Error::Protocol(format!("key party {p}'s share contribution is for another task or flush")));
        }
        if c.chunks.len() != env.layout.num_chunks || c.proofs.len() != env.layout.num_chunks {
            return Err(Error::Protocol(format!("key party {p}'s share contribution has the wrong shape")));
        }
        if p == env.party && c.digest() != *own_digest {
            return Err(Error::Protocol("the share contributions do not carry this party's own".into()));
        }
        let mut eff = Vec::with_capacity(c.chunks.len());
        for (i, (bytes, proof)) in c.chunks.iter().zip(&c.proofs).enumerate() {
            let ct = env
                .codec
                .decode(bytes, Expect::Exactly(fresh))
                .map_err(|e| Error::Protocol(format!("key party {p}'s share contribution {i}: {e}")))?;
            if p != env.party {
                wfe::verify(env.ctx, env.pk, &reference, &ct, proof, &proof_context(env.cfg, &digest, p, i))
                    .map_err(|e| Error::Protocol(format!("key party {p}'s share contribution {i}: {e}")))?;
            }
            eff.push(wfe::effective(env.ctx, &ct)?);
        }
        acc = Some(match acc {
            None => eff,
            Some(a) => a.iter().zip(&eff).map(|(x, y)| env.ctx.add(x, y)).collect::<std::result::Result<_, _>>()?,
        });
    }
    acc.ok_or_else(|| Error::Protocol("no share contributions".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TaskConfig;
    use crate::types::MeasurementType;

    fn task(parties_split: bool) -> (TaskConfig, Vec<UploadKey>) {
        let mut cfg = if parties_split {
            TaskConfig::new_split_key([7; 32], MeasurementType::Histogram { length: 5 })
        } else {
            TaskConfig::new_silent([7; 32], MeasurementType::Histogram { length: 5 }, 3)
        };
        let keys: Vec<UploadKey> = (0..cfg.num_key_parties()).map(|_| UploadKey::generate()).collect();
        cfg.upload = Upload::Shares;
        cfg.upload_keys = keys.iter().map(|k| k.public_key()).collect();
        (cfg, keys)
    }

    fn reconstruct(cfg: &TaskConfig, keys: &[UploadKey], r: &ShareReport) -> Vec<u64> {
        let field = cfg.field();
        let m = cfg.measurement_type.input_len();
        let mut x = vec![0u64; m];
        for (p, k) in keys.iter().enumerate() {
            let s = party_share(cfg, &field, k, r, p);
            assert!(matches!(s, InputShare::Opened(_)), "party {p}");
            for (a, b) in x.iter_mut().zip(s.values(m)) {
                *a = field.add(*a, b);
            }
        }
        x
    }

    #[test]
    fn shares_add_up_to_the_encoding_and_reports_are_small() {
        for split in [false, true] {
            let (cfg, keys) = task(split);
            let client = ShareClient::new(cfg.clone()).unwrap();
            for j in 0..5 {
                let r = client.shard(&Measurement::Histogram(j)).unwrap();
                check_structure(&cfg, &r).unwrap();
                assert_eq!(reconstruct(&cfg, &keys, &r), cfg.measurement_type.encode(&Measurement::Histogram(j)).unwrap());
                // 5 elements: 5 * 4 + 16 for party 0, 32 + 16 per seed, 44 per envelope
                let parties = cfg.num_key_parties();
                assert_eq!(r.sealed_bytes(), 44 * parties + 36 + 48 * (parties - 1));
            }
        }
    }

    #[test]
    fn each_share_alone_is_independent_of_the_measurement() {
        // party 1's share is a SHAKE128 expansion of a fresh seed, party 0's
        // is x minus it: two reports of the same value have unrelated shares
        let (cfg, keys) = task(true);
        let client = ShareClient::new(cfg.clone()).unwrap();
        let field = cfg.field();
        let a = client.shard(&Measurement::Histogram(2)).unwrap();
        let b = client.shard(&Measurement::Histogram(2)).unwrap();
        for (p, key) in keys.iter().enumerate().take(2) {
            assert_ne!(party_share(&cfg, &field, key, &a, p), party_share(&cfg, &field, key, &b, p));
        }
        assert_ne!(a.report_id, b.report_id);
    }

    #[test]
    fn a_party_cannot_open_another_partys_input_and_tampering_is_unopenable() {
        let (cfg, keys) = task(false);
        let field = cfg.field();
        let client = ShareClient::new(cfg.clone()).unwrap();
        let r = client.shard(&Measurement::Histogram(1)).unwrap();
        // another party's key, or another party index, does not open it
        assert_eq!(party_share(&cfg, &field, &keys[1], &r, 0), InputShare::Unopenable);
        let mut swapped = r.clone();
        swapped.inputs.swap(1, 2);
        assert_eq!(party_share(&cfg, &field, &keys[1], &swapped, 1), InputShare::Unopenable);
        // a changed nonce changes the associated data
        let mut t = r.clone();
        t.nonce[0] ^= 1;
        assert_eq!(party_share(&cfg, &field, &keys[0], &t, 0), InputShare::Unopenable);
        // a flipped ciphertext bit fails the tag
        let mut t = r.clone();
        t.inputs[2].ciphertext[3] ^= 1;
        assert_eq!(party_share(&cfg, &field, &keys[2], &t, 2), InputShare::Unopenable);
        // a low-order ephemeral key never opens
        let mut t = r.clone();
        t.inputs[1].ephemeral = [0u8; 32];
        assert_eq!(party_share(&cfg, &field, &keys[1], &t, 1), InputShare::Unopenable);
        // any change is also caught by the report id
        assert_eq!(check_structure(&cfg, &t), Err(RejectReason::ReportIdMismatch));
    }

    #[test]
    fn non_canonical_and_misshaped_inputs() {
        let (cfg, keys) = task(true);
        let field = cfg.field();
        let client = ShareClient::new(cfg.clone()).unwrap();
        let p = cfg.plain_mod as u32;
        // an explicit element equal to p is not canonical
        let mut explicit = Vec::new();
        for v in [p, 0, 0, 0, 0] {
            explicit.extend_from_slice(&v.to_le_bytes());
        }
        let r = client.shard_raw_inputs_for_tests(&[explicit, vec![9u8; SEED_LEN]]).unwrap();
        check_structure(&cfg, &r).unwrap();
        assert_eq!(party_share(&cfg, &field, &keys[0], &r, 0), InputShare::Unopenable);
        assert!(matches!(party_share(&cfg, &field, &keys[1], &r, 1), InputShare::Opened(_)));
        // wrong lengths are structural rejections, for every party
        let r = client.shard_raw_inputs_for_tests(&[vec![0u8; 19], vec![9u8; SEED_LEN]]).unwrap();
        assert_eq!(
            check_structure(&cfg, &r),
            Err(RejectReason::MalformedInputShare {
                party: 0,
                expected: 36,
                got: 35
            })
        );
        let r = client.shard_raw_inputs_for_tests(&[vec![0u8; 20], vec![9u8; SEED_LEN + 1]]).unwrap();
        assert_eq!(
            check_structure(&cfg, &r),
            Err(RejectReason::MalformedInputShare {
                party: 1,
                expected: 48,
                got: 49
            })
        );
        let r = client.shard_raw_inputs_for_tests(&[vec![0u8; 20]]).unwrap();
        assert_eq!(check_structure(&cfg, &r), Err(RejectReason::WrongInputShareCount { expected: 2, got: 1 }));
        // a task uploading ciphertexts refuses share reports
        let mut other = cfg.clone();
        other.upload = Upload::Ciphertext;
        other.upload_keys.clear();
        assert_eq!(check_structure(&other, &r), Err(RejectReason::WrongUpload));
    }

    #[test]
    fn seed_expansion_is_uniform_below_p_and_bound_to_its_inputs() {
        let field = Field::new(786_433).unwrap();
        let a = expand_seed(&field, &[1; 32], &[2; 16], 1, &[3; 32], 4096);
        assert!(a.iter().all(|&v| v < 786_433));
        assert_eq!(a, expand_seed(&field, &[1; 32], &[2; 16], 1, &[3; 32], 4096));
        assert_ne!(a, expand_seed(&field, &[1; 32], &[2; 16], 2, &[3; 32], 4096));
        assert_ne!(a, expand_seed(&field, &[1; 32], &[9; 16], 1, &[3; 32], 4096));
        assert_ne!(a, expand_seed(&field, &[9; 32], &[2; 16], 1, &[3; 32], 4096));
        // the top quarter of [0, 2^20) is rejected, the rest kept: the mean
        // of 4096 uniform draws is within 5% of p/2
        let mean = a.iter().sum::<u64>() as f64 / a.len() as f64;
        assert!((mean / (786_433.0 / 2.0) - 1.0).abs() < 0.05, "{mean}");
    }

    #[test]
    fn upload_keys_are_validated() {
        let (mut cfg, _) = task(false);
        cfg.validate().unwrap();
        let k = cfg.upload_keys[0];
        cfg.upload_keys[1] = k;
        assert!(cfg.validate().is_err(), "a repeated key");
        cfg.upload_keys[1] = [0u8; 32];
        assert!(cfg.validate().is_err(), "a small-order point");
        cfg.upload_keys.pop();
        assert!(cfg.validate().is_err(), "one key per party");
        let (mut cfg, _) = task(false);
        cfg.silent_batch_groups = 1;
        assert!(cfg.validate().is_err(), "batched layout only");
        let (mut cfg, _) = task(false);
        cfg.mode = crate::config::VerificationMode::Verdict;
        assert!(cfg.validate().is_err(), "silent mode only");
        let mut plain = TaskConfig::new_silent([7; 32], MeasurementType::Count, 2);
        plain.upload_keys = vec![UploadKey::generate().public_key(); 2];
        assert!(plain.validate().is_err(), "keys without share upload");
    }
}
