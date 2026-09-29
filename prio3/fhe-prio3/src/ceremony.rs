//! Distributed key ceremony: the aggregators generate the joint keys across
//! machines, each keeping its secret share, with no dealer.
//!
//! `keys::run_local_ceremony` runs every party in one process and therefore
//! sees every share; it serves tests and simulations. This module is the
//! deployment path. Each aggregator runs [`run`] on its own machine with its
//! long-term Ed25519 identity and the pinned identity keys of the others,
//! over any [`Transport`] (the node crate provides HTTPS).
//!
//! Threats and how each is met:
//!
//! * **Malicious `a`.** OpenFHE's multiparty key generation takes the
//!   public `a` (of the public key, and of every key-switching key) from
//!   the first party. A party that chooses `a` with a trapdoor could read
//!   the others' `b = e - a s` as their secrets. Here `a` is a common
//!   reference string expanded from `H(seed_0, .., seed_{n-1})`, where
//!   every party committed to its seed before any was revealed (rounds 1
//!   and 2): no party can steer it.
//! * **Rogue keys.** A party that picks its public-key share after seeing
//!   the others' can make the joint key one it alone can open
//!   (`b_n = b* - sum others`). Every contribution is committed (a signed
//!   SHA-256) before any is revealed (rounds 3 and 4, 5 and 6), so shares
//!   are chosen independently.
//! * **Malformed contributions.** Only `b` residues travel (the receiver
//!   rebuilds each key from its own copy of `a`), are checked for exact
//!   length and against every tower modulus before OpenFHE builds anything,
//!   and never reach OpenFHE's deserializer. A contribution that is well
//!   formed but wrong (noise of the wrong size, a different secret per
//!   key) is caught by the joint key check.
//! * **Joint key check.** Every party encrypts a random vector under the
//!   joint public key (committed in round 5, revealed in 6); the sum is
//!   squared (eval-mult key), rotated by every index (rotation keys) and
//!   combined with random weights fixed by all the test ciphertexts, and
//!   decrypted with every party's partial decryption, committed in round 7
//!   before any is revealed in 8 (so no party can choose its partial to
//!   make a wrong result look right). The ceremony succeeds only if the
//!   decryption equals the value computed from the revealed vectors in
//!   every slot.
//! * **Equivocation and substitution.** Every message is signed by its
//!   sender's pinned identity over the task digest, the session and the
//!   round. In round 9 each party signs the digest of the whole transcript
//!   and of the joint material, and attests the material
//!   ([`crate::attest`]); a party that showed different messages to
//!   different peers, or computed different keys, is caught there.
//!
//! What it does not do: it does not tolerate an aborting party (n-of-n: any
//! party can stop the ceremony, as it can stop decryption later), and it
//! proves nothing about a party's noise distribution beyond what the joint
//! key check measures. A party that keeps its share secret and follows the
//! protocol keeps the joint secret hidden from all others together.

use crate::attest::{self, AggregatorIdentity, MaterialAttestation};
use crate::config::TaskConfig;
use crate::error::{Error, Result};
use crate::keys::make_context;
use crate::messages::{PublicMaterial, encode};
use crate::packed::{Codec, Expect};
use crate::xof::Xof;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use openfhe_tbgv_rs::{Ciphertext, CiphertextMeta, Context, EvalMultKey, KeyBasis, PartialDecryption, PublicKey, RotationKeys};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CEREMONY_DOMAIN: &[u8] = b"fhe-prio3/1 ceremony";

/// Rounds, in order. Each party publishes one signed message per round and
/// reads every other party's before it moves on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Round {
    SeedCommit = 1,
    SeedReveal = 2,
    KeyCommit = 3,
    KeyReveal = 4,
    Relin2Commit = 5,
    Relin2Reveal = 6,
    PartialCommit = 7,
    PartialReveal = 8,
    Confirm = 9,
}

impl Round {
    pub const ALL: [Round; 9] = [
        Round::SeedCommit,
        Round::SeedReveal,
        Round::KeyCommit,
        Round::KeyReveal,
        Round::Relin2Commit,
        Round::Relin2Reveal,
        Round::PartialCommit,
        Round::PartialReveal,
        Round::Confirm,
    ];
    pub fn number(self) -> u8 {
        self as u8
    }
    pub fn from_number(n: u8) -> Option<Round> {
        Round::ALL.iter().copied().find(|r| r.number() == n)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    /// `commit = H(seed)`; `params` fingerprints the context and the key
    /// shapes, so parties on different parameters stop here.
    SeedCommit { commit: [u8; 32], params: [u8; 32] },
    SeedReveal { seed: [u8; 32] },
    /// Hashes of the blobs released with round 4: the public-key share,
    /// the round-1 eval-mult contribution and one per rotation index.
    KeyCommit { pk: [u8; 32], relin1: [u8; 32], rot: Vec<[u8; 32]> },
    KeyReveal,
    /// Hashes of the round-2 eval-mult contribution and of the test
    /// ciphertext, and the commitment to the test vector's seed.
    Relin2Commit { relin2: [u8; 32], check_ct: [u8; 32], check_seed: [u8; 32] },
    Relin2Reveal,
    PartialCommit { partial: [u8; 32] },
    PartialReveal { check_seed: [u8; 32] },
    /// Digest of the transcript and the joint material, and the attestation.
    Confirm { transcript: [u8; 32], attestation: MaterialAttestation },
}

/// A signed ceremony message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub task_digest: [u8; 32],
    pub session: [u8; 32],
    pub round: Round,
    pub sender: u32,
    pub payload: Payload,
    /// Ed25519 over [`Message::signed_bytes`].
    pub signature: Vec<u8>,
}

impl Message {
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        let body = encode(&(&self.task_digest, &self.session, self.round, self.sender, &self.payload))?;
        let mut m = CEREMONY_DOMAIN.to_vec();
        m.extend_from_slice(&Sha256::digest(&body));
        Ok(m)
    }
    /// Hash of the whole signed message, for the transcript.
    fn digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(encode(self)?).into())
    }
}

/// Where blobs are released: the reveal round of the phase that committed them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blob {
    PublicKey,
    Relin1,
    Rotation(usize),
    Relin2,
    CheckCiphertext,
    Partial,
}

impl Blob {
    pub fn name(&self) -> String {
        match self {
            Blob::PublicKey => "pk".into(),
            Blob::Relin1 => "relin1".into(),
            Blob::Rotation(k) => format!("rot-{k}"),
            Blob::Relin2 => "relin2".into(),
            Blob::CheckCiphertext => "check".into(),
            Blob::Partial => "partial".into(),
        }
    }
    pub fn round(&self) -> Round {
        match self {
            Blob::PublicKey | Blob::Relin1 | Blob::Rotation(_) => Round::KeyReveal,
            Blob::Relin2 | Blob::CheckCiphertext => Round::Relin2Reveal,
            Blob::Partial => Round::PartialReveal,
        }
    }
}

/// Message exchange between the parties. Blobs are staged before the
/// commitment to them is published and become readable by the others only
/// with this party's message for their reveal round, which it publishes
/// after it holds every other party's commitment.
pub trait Transport {
    fn stage_blob(&mut self, round: Round, name: &str, bytes: Vec<u8>) -> Result<()>;
    /// Publishes this party's message, releasing the blobs staged for its round.
    fn publish(&mut self, msg: &Message) -> Result<()>;
    /// Party `from`'s message for `round`, waiting until it is published.
    fn fetch(&mut self, round: Round, from: usize) -> Result<Message>;
    /// A blob of party `from` released with its message for `round`.
    fn fetch_blob(&mut self, round: Round, from: usize, name: &str) -> Result<Vec<u8>>;
    /// Tells the other parties this one stopped (they fail instead of waiting).
    fn abort(&mut self, reason: &str);
}

pub struct CeremonyOutput {
    /// Joint material with every aggregator's attestation.
    pub material: PublicMaterial,
    /// This party's serialized secret share (keep it sealed).
    pub share: Vec<u8>,
    /// The digest every party signed in round 9.
    pub transcript: [u8; 32],
}

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update((CEREMONY_DOMAIN.len() as u32).to_le_bytes());
    s.update(CEREMONY_DOMAIN);
    for p in parts {
        s.update((p.len() as u64).to_le_bytes());
        s.update(p);
    }
    s.finalize().into()
}

fn blob_hash(session: &[u8; 32], sender: usize, blob: &Blob, bytes: &[u8]) -> [u8; 32] {
    h(&[b"blob", session, &(sender as u64).to_le_bytes(), blob.name().as_bytes(), bytes])
}

fn seed_commit(label: &[u8], session: &[u8; 32], sender: usize, seed: &[u8; 32]) -> [u8; 32] {
    h(&[label, session, &(sender as u64).to_le_bytes(), seed])
}

fn to_bytes(v: &[u64]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

/// Exactly `len` residues; their ranges are checked where keys are built.
fn from_bytes(b: &[u8], len: usize, what: &str) -> Result<Vec<u64>> {
    if b.len() != len * 8 {
        return Err(Error::Protocol(format!("{what}: {} bytes, expected {}", b.len(), len * 8)));
    }
    Ok(b.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes"))).collect())
}

/// Uniform residues for `polys` polynomials over `moduli`, `n` coefficients
/// each, from SHAKE128 by rejection sampling (exactly uniform per tower).
pub fn expand_crs(seed: &[u8; 32], label: &str, moduli: &[u64], n: usize, polys: usize) -> Vec<u64> {
    let mut x = Xof::new(b"ceremony crs", &[seed, label.as_bytes()]);
    let mut out = Vec::with_capacity(polys * moduli.len() * n);
    let mut buf = [0u8; 8];
    for _ in 0..polys {
        for &q in moduli {
            let shift = q.leading_zeros();
            for _ in 0..n {
                loop {
                    x.fill(&mut buf);
                    let v = u64::from_le_bytes(buf) >> shift;
                    if v < q {
                        out.push(v);
                        break;
                    }
                }
            }
        }
    }
    out
}

/// Test vector of the joint key check: `row` uniform elements of `[0, p)`.
fn check_vector(session: &[u8; 32], seed: &[u8; 32], f: &crate::field::Field, row: usize) -> Vec<u64> {
    let mut x = Xof::new(b"ceremony check vector", &[session, seed]);
    (0..row).map(|_| x.next_field_elem(f)).collect()
}

/// Deviations from the protocol, for the tests that show each is caught.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum Deviation {
    None,
    /// Uniform residues for the public-key share (committed consistently).
    GarbagePublicKey,
    /// Uniform residues for the contribution to rotation key `k`.
    GarbageRotation(usize),
    /// Round-2 eval-mult contribution made with a fresh secret.
    OtherSecretRelin2,
    /// Serves a public-key share other than the committed one.
    BlobMismatch,
    /// A partial decryption of the check value under another secret (well formed).
    WrongPartial,
    /// A partial decryption of another ciphertext (other level and towers).
    MisshapedPartial,
    /// Reveals a seed other than the committed one.
    WrongSeed,
    /// Signs round 9 over another transcript.
    WrongTranscript,
    /// Signs its messages with another key.
    WrongIdentity,
}

struct Party<'a> {
    index: usize,
    n: usize,
    identity: &'a AggregatorIdentity,
    pinned: Vec<VerifyingKey>,
    session: [u8; 32],
    task_digest: [u8; 32],
    transcript: Vec<[u8; 32]>,
    dev: Deviation,
}

impl<'a> Party<'a> {
    fn sign(&self, round: Round, payload: Payload) -> Result<Message> {
        let mut m = Message { task_digest: self.task_digest, session: self.session, round, sender: self.index as u32, payload, signature: Vec::new() };
        let bytes = m.signed_bytes()?;
        m.signature = if self.dev == Deviation::WrongIdentity {
            ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng).sign(&bytes).to_bytes().to_vec()
        } else {
            self.identity.sign(&bytes).to_bytes().to_vec()
        };
        Ok(m)
    }

    /// Publishes this round's message, then reads and verifies everyone's
    /// (its own included, in index order) and appends them to the transcript.
    fn exchange(&mut self, t: &mut dyn Transport, round: Round, payload: Payload) -> Result<Vec<Payload>> {
        let mine = self.sign(round, payload)?;
        t.publish(&mine)?;
        let mut out = Vec::with_capacity(self.n);
        for j in 0..self.n {
            let m = if j == self.index { mine.clone() } else { t.fetch(round, j)? };
            self.verify(&m, round, j)?;
            self.transcript.push(m.digest()?);
            out.push(m.payload);
        }
        Ok(out)
    }

    fn verify(&self, m: &Message, round: Round, from: usize) -> Result<()> {
        if m.round != round || m.sender as usize != from {
            return Err(Error::Protocol(format!("ceremony: party {from} sent a message for round {:?} from {}", m.round, m.sender)));
        }
        if m.task_digest != self.task_digest || m.session != self.session {
            return Err(Error::Protocol(format!("ceremony: party {from}'s round {round:?} message is for another task or session")));
        }
        let sig: [u8; 64] = m.signature.as_slice().try_into().map_err(|_| Error::Protocol(format!("ceremony: party {from}: signature must be 64 bytes")))?;
        self.pinned[from]
            .verify_strict(&m.signed_bytes()?, &Signature::from_bytes(&sig))
            .map_err(|_| Error::Protocol(format!("ceremony: party {from}'s round {round:?} message is not signed by its pinned identity")))?;
        let kind_ok = matches!(
            (round, &m.payload),
            (Round::SeedCommit, Payload::SeedCommit { .. })
                | (Round::SeedReveal, Payload::SeedReveal { .. })
                | (Round::KeyCommit, Payload::KeyCommit { .. })
                | (Round::KeyReveal, Payload::KeyReveal)
                | (Round::Relin2Commit, Payload::Relin2Commit { .. })
                | (Round::Relin2Reveal, Payload::Relin2Reveal)
                | (Round::PartialCommit, Payload::PartialCommit { .. })
                | (Round::PartialReveal, Payload::PartialReveal { .. })
                | (Round::Confirm, Payload::Confirm { .. })
        );
        if !kind_ok {
            return Err(Error::Protocol(format!("ceremony: party {from} sent the wrong kind of message for round {round:?}")));
        }
        Ok(())
    }

    /// A released blob of party `from`, checked against its commitment.
    fn blob(&self, t: &mut dyn Transport, from: usize, blob: &Blob, committed: &[u8; 32]) -> Result<Vec<u8>> {
        let bytes = t.fetch_blob(blob.round(), from, &blob.name())?;
        if blob_hash(&self.session, from, blob, &bytes) != *committed {
            return Err(Error::Protocol(format!("ceremony: party {from}'s {} does not match its commitment", blob.name())));
        }
        Ok(bytes)
    }

    fn stage(&self, t: &mut dyn Transport, blob: &Blob, bytes: Vec<u8>) -> Result<[u8; 32]> {
        let hash = blob_hash(&self.session, self.index, blob, &bytes);
        t.stage_blob(blob.round(), &blob.name(), bytes)?;
        Ok(hash)
    }
}

/// Fingerprint of everything the parties must agree on before any key
/// material is made.
fn params_fingerprint(cfg: &TaskConfig, ctx: &Context, indices: &[i32]) -> Result<[u8; 32]> {
    let mut parts: Vec<Vec<u8>> = vec![cfg.digest().to_vec(), ctx.plain_mod().to_le_bytes().to_vec(), ctx.ring_dim().to_le_bytes().to_vec(), (ctx.key_num_parts()? as u64).to_le_bytes().to_vec()];
    parts.push(to_bytes(&ctx.moduli()?));
    parts.push(to_bytes(&ctx.key_basis_moduli(KeyBasis::PublicKey)?));
    parts.push(to_bytes(&ctx.key_basis_moduli(KeyBasis::KeySwitch)?));
    parts.push(indices.iter().flat_map(|i| i.to_le_bytes()).collect());
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    Ok(h(&refs))
}

/// Hash of the joint material, excluding attestations.
fn material_digest(m: &PublicMaterial) -> [u8; 32] {
    let rot: Vec<[u8; 32]> = m.rotation_keys.iter().map(|k| Sha256::digest(k).into()).collect();
    let rot_bytes: Vec<u8> = rot.iter().flatten().copied().collect();
    let idx: Vec<u8> = m.rotation_indices.iter().flat_map(|i| i.to_le_bytes()).collect();
    h(&[b"material", &m.context, &m.public_key, m.joint_tag.as_bytes(), &Sha256::digest(&m.eval_mult_key), &rot_bytes, &idx])
}

/// Runs the ceremony as aggregator `index`. `pinned[j]` is aggregator `j`'s
/// identity key (this party's own included); `session` is a fresh value all
/// parties agreed on for this run.
pub fn run(cfg: &TaskConfig, index: usize, identity: &AggregatorIdentity, pinned: &[[u8; 32]], session: [u8; 32], t: &mut dyn Transport) -> Result<CeremonyOutput> {
    run_deviating(cfg, index, identity, pinned, session, t, Deviation::None)
}

#[doc(hidden)]
pub fn run_deviating(
    cfg: &TaskConfig,
    index: usize,
    identity: &AggregatorIdentity,
    pinned: &[[u8; 32]],
    session: [u8; 32],
    t: &mut dyn Transport,
    dev: Deviation,
) -> Result<CeremonyOutput> {
    let r = run_inner(cfg, index, identity, pinned, session, t, dev);
    if let Err(e) = &r {
        t.abort(&e.to_string());
    }
    r
}

fn run_inner(
    cfg: &TaskConfig,
    index: usize,
    identity: &AggregatorIdentity,
    pinned: &[[u8; 32]],
    session: [u8; 32],
    t: &mut dyn Transport,
    dev: Deviation,
) -> Result<CeremonyOutput> {
    let n = cfg.num_aggregators;
    if pinned.len() != n || index >= n {
        return Err(Error::Config(format!("ceremony: {} pinned keys and index {index} for {n} aggregators", pinned.len())));
    }
    if pinned[index] != identity.public_key() {
        return Err(Error::Config(format!("ceremony: this identity is not the pinned key of aggregator {index}")));
    }
    let pinned_keys = pinned
        .iter()
        .map(|k| VerifyingKey::from_bytes(k).map_err(|_| Error::Config("ceremony: invalid pinned identity key".into())))
        .collect::<Result<Vec<_>>>()?;
    let mut me = Party { index, n, identity, pinned: pinned_keys, session, task_digest: cfg.digest(), transcript: Vec::new(), dev };

    let ctx = make_context(cfg)?;
    // test ciphertexts and partial decryptions arrive in the packed format,
    // whose rebuild is verified once per process (see `packed.rs`)
    openfhe_tbgv_rs::verify_rebuild_once(&ctx, cfg.mult_depth())?;
    let ring = ctx.ring_dim() as usize;
    let row = ctx.row_slots();
    let p = ctx.plain_mod();
    let field = crate::field::Field::new(p).ok_or_else(|| Error::Config("plain_mod is not a usable field".into()))?;
    let indices = cfg.layout(row)?.rotation_indices();
    let pk_moduli = ctx.key_basis_moduli(KeyBasis::PublicKey)?;
    let ks_moduli = ctx.key_basis_moduli(KeyBasis::KeySwitch)?;
    let parts = ctx.key_num_parts()?;
    let pk_len = pk_moduli.len() * ring;
    let ks_len = parts * ks_moduli.len() * ring;

    // Rounds 1-2: the common random string.
    let mut seed = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
    let params = params_fingerprint(cfg, &ctx, &indices)?;
    let commits = me.exchange(t, Round::SeedCommit, Payload::SeedCommit { commit: seed_commit(b"crs seed", &session, index, &seed), params })?;
    for (j, c) in commits.iter().enumerate() {
        if let Payload::SeedCommit { params: q, .. } = c {
            if *q != params {
                return Err(Error::Protocol(format!("ceremony: party {j} runs other parameters (context, key shapes, rotation indices or task)")));
            }
        }
    }
    let revealed = if dev == Deviation::WrongSeed { [0u8; 32] } else { seed };
    let reveals = me.exchange(t, Round::SeedReveal, Payload::SeedReveal { seed: revealed })?;
    let mut crs_parts: Vec<Vec<u8>> = vec![b"crs".to_vec(), me.task_digest.to_vec(), session.to_vec()];
    for (j, (c, r)) in commits.iter().zip(&reveals).enumerate() {
        let (Payload::SeedCommit { commit, .. }, Payload::SeedReveal { seed: s }) = (c, r) else { unreachable!("kinds checked") };
        if seed_commit(b"crs seed", &session, j, s) != *commit {
            return Err(Error::Protocol(format!("ceremony: party {j} revealed a seed other than the one it committed to")));
        }
        crs_parts.push(s.to_vec());
    }
    let crs = h(&crs_parts.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
    let joint_tag = hex::encode(&h(&[b"joint tag", &crs])[..16]);

    // Round 3: this party's share and contributions, committed.
    let pk_t = PublicKey::template(&ctx, &expand_crs(&crs, "pk", &pk_moduli, ring, 1))?;
    let relin_t = EvalMultKey::template(&ctx, &expand_crs(&crs, "relin", &ks_moduli, ring, parts))?;
    let (my_pk, share) = PublicKey::share(&ctx, &pk_t)?;
    let mut rng = rand::thread_rng();
    let garbage = |moduli: &[u64], polys: usize, rng: &mut rand::rngs::ThreadRng| -> Vec<u64> {
        use rand::Rng;
        (0..polys).flat_map(|_| moduli.iter().flat_map(|&q| (0..ring).map(move |_| q)).collect::<Vec<_>>()).map(|q| rng.gen_range(0..q)).collect()
    };
    let pk_b = if dev == Deviation::GarbagePublicKey { garbage(&pk_moduli, 1, &mut rng) } else { my_pk.export(0)? };
    let h_pk = me.stage(t, &Blob::PublicKey, to_bytes(&pk_b))?;
    if dev == Deviation::BlobMismatch {
        // serve other residues than the committed ones
        t.stage_blob(Round::KeyReveal, &Blob::PublicKey.name(), to_bytes(&garbage(&pk_moduli, 1, &mut rng)))?;
    }
    let h_r1 = me.stage(t, &Blob::Relin1, to_bytes(&EvalMultKey::round1_next(&ctx, &share, &relin_t)?.export(1)?))?;
    let mut h_rot = Vec::with_capacity(indices.len());
    for (k, &idx) in indices.iter().enumerate() {
        let b = if dev == Deviation::GarbageRotation(k) {
            garbage(&ks_moduli, parts, &mut rng)
        } else {
            let tmpl = RotationKeys::single(&ctx, idx, &EvalMultKey::template(&ctx, &expand_crs(&crs, &format!("rot {idx}"), &ks_moduli, ring, parts))?)?;
            RotationKeys::next(&ctx, &share, &tmpl, &[idx], &joint_tag)?.get(idx)?.export(1)?
        };
        h_rot.push(me.stage(t, &Blob::Rotation(k), to_bytes(&b))?);
    }
    let key_commits = me.exchange(t, Round::KeyCommit, Payload::KeyCommit { pk: h_pk, relin1: h_r1, rot: h_rot })?;
    for (j, c) in key_commits.iter().enumerate() {
        if let Payload::KeyCommit { rot, .. } = c {
            if rot.len() != indices.len() {
                return Err(Error::Protocol(format!("ceremony: party {j} committed {} rotation keys, expected {}", rot.len(), indices.len())));
            }
        }
    }

    // Round 4: reveal; everyone builds the joint keys from the residues.
    me.exchange(t, Round::KeyReveal, Payload::KeyReveal)?;
    let commit_of = |j: usize| match &key_commits[j] {
        Payload::KeyCommit { pk, relin1, rot } => (*pk, *relin1, rot.clone()),
        _ => unreachable!("kinds checked"),
    };
    let mut joint_pk: Option<PublicKey> = None;
    let mut relin1: Option<EvalMultKey> = None;
    for j in 0..n {
        let (c_pk, c_r1, _) = commit_of(j);
        let b = from_bytes(&me.blob(t, j, &Blob::PublicKey, &c_pk)?, pk_len, "public-key share")?;
        let part = PublicKey::with_b(&ctx, &pk_t, &b)?;
        joint_pk = Some(match joint_pk {
            None => part,
            Some(acc) => PublicKey::add(&ctx, &acc, &part, &joint_tag)?,
        });
        let b = from_bytes(&me.blob(t, j, &Blob::Relin1, &c_r1)?, ks_len, "eval-mult round-1 contribution")?;
        let part = EvalMultKey::with_b(&ctx, &relin_t, &b)?;
        relin1 = Some(match relin1 {
            None => part,
            Some(acc) => EvalMultKey::round1_add(&ctx, &acc, &part, &joint_tag)?,
        });
    }
    // n = 1 leaves the single share untagged; adding it to nothing tags it
    let joint_pk = joint_pk.expect("n >= 1");
    let relin1 = relin1.expect("n >= 1");
    let mut rotation_keys = Vec::with_capacity(indices.len());
    for (k, &idx) in indices.iter().enumerate() {
        let tmpl = EvalMultKey::template(&ctx, &expand_crs(&crs, &format!("rot {idx}"), &ks_moduli, ring, parts))?;
        let mut acc: Option<RotationKeys> = None;
        for j in 0..n {
            let committed = commit_of(j).2[k];
            let b = from_bytes(&me.blob(t, j, &Blob::Rotation(k), &committed)?, ks_len, "rotation contribution")?;
            let part = RotationKeys::single(&ctx, idx, &EvalMultKey::with_b(&ctx, &tmpl, &b)?)?;
            acc = Some(match acc {
                None => part,
                Some(a) => RotationKeys::add(&ctx, &a, &part, &joint_tag)?,
            });
        }
        rotation_keys.push(acc.expect("n >= 1").serialize()?);
    }
    let joint_pk_bytes = joint_pk.serialize()?;

    // Round 5: round-2 eval-mult contribution and the test ciphertext, committed.
    let r2 = if dev == Deviation::OtherSecretRelin2 {
        let (_, other) = PublicKey::share(&ctx, &pk_t)?;
        EvalMultKey::round2(&ctx, &other, &relin1, &joint_tag)?
    } else {
        EvalMultKey::round2(&ctx, &share, &relin1, &joint_tag)?
    };
    let mut r2_bytes = to_bytes(&r2.export(0)?);
    r2_bytes.extend(to_bytes(&r2.export(1)?));
    drop(r2);
    let h_r2 = me.stage(t, &Blob::Relin2, r2_bytes)?;
    let codec = Codec::new(&ctx, &joint_pk, &joint_pk_bytes)?;
    let mut check_seed = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut check_seed);
    let my_ct = ctx.encrypt(&joint_pk, &ctx.plaintext(&check_vector(&session, &check_seed, &field, row))?)?;
    let h_ct = me.stage(t, &Blob::CheckCiphertext, codec.encode(&my_ct)?)?;
    let c_seed = seed_commit(b"check seed", &session, index, &check_seed);
    let r2_commits = me.exchange(t, Round::Relin2Commit, Payload::Relin2Commit { relin2: h_r2, check_ct: h_ct, check_seed: c_seed })?;

    // Round 6: reveal; the joint eval-mult key and the test ciphertext.
    me.exchange(t, Round::Relin2Reveal, Payload::Relin2Reveal)?;
    let mut mk: Option<EvalMultKey> = None;
    let mut test: Option<Ciphertext> = None;
    let mut ct_hashes = Vec::with_capacity(n);
    for (j, c) in r2_commits.iter().enumerate() {
        let Payload::Relin2Commit { relin2, check_ct, .. } = c else { unreachable!("kinds checked") };
        let bytes = me.blob(t, j, &Blob::Relin2, relin2)?;
        let v = from_bytes(&bytes, 2 * ks_len, "eval-mult round-2 contribution")?;
        let part = EvalMultKey::build(&ctx, &v[..ks_len], &v[ks_len..])?;
        mk = Some(match mk {
            None => part,
            Some(acc) => EvalMultKey::round2_add(&ctx, &acc, &part, &joint_tag)?,
        });
        let ct = codec
            .decode(&me.blob(t, j, &Blob::CheckCiphertext, check_ct)?, Expect::Exactly(codec.fresh_meta()))
            .map_err(|e| Error::Protocol(format!("ceremony: party {j}'s test ciphertext: {e}")))?;
        test = Some(match test {
            None => ct,
            Some(acc) => ctx.add(&acc, &ct)?,
        });
        ct_hashes.extend_from_slice(check_ct);
    }
    let mk = mk.expect("n >= 1");
    let material = PublicMaterial {
        context: ctx.serialize()?,
        public_key: joint_pk_bytes,
        joint_tag: joint_tag.clone(),
        eval_mult_key: mk.serialize()?,
        rotation_keys,
        rotation_indices: indices.clone(),
        attestations: Vec::new(),
    };
    drop(mk);
    let _lease = crate::keys::install(&ctx, &material)?;

    // The check value: T = x^2 + w_0 x + sum_k w_k rot_k(x), weights fixed
    // by every test ciphertext (committed before any was revealed).
    let x = test.expect("n >= 1");
    let mut wx = Xof::new(b"ceremony check weights", &[&session, &ct_hashes]);
    let weights: Vec<u64> = (0..=indices.len()).map(|_| wx.next_field_elem(&field)).collect();
    let mut t_ct = ctx.add(&ctx.square(&x)?, &ctx.mult_plain(&x, &ctx.plaintext(&vec![weights[0]; row])?)?)?;
    for (k, &idx) in indices.iter().enumerate() {
        t_ct = ctx.add(&t_ct, &ctx.mult_plain(&ctx.rotate(&x, idx)?, &ctx.plaintext(&vec![weights[k + 1]; row])?)?)?;
    }
    let partial_meta = CiphertextMeta { num_elements: 1, ..t_ct.meta()? };
    let mine = match dev {
        Deviation::WrongPartial => PublicKey::share(&ctx, &pk_t)?.1.partial_decrypt(&t_ct, index == 0)?,
        Deviation::MisshapedPartial => share.partial_decrypt(&x, index == 0)?,
        _ => share.partial_decrypt(&t_ct, index == 0)?,
    };
    let h_pd = me.stage(t, &Blob::Partial, codec.encode(mine.ciphertext())?)?;

    // Rounds 7-8: partial decryptions committed, then revealed with the test seeds.
    let pd_commits = me.exchange(t, Round::PartialCommit, Payload::PartialCommit { partial: h_pd })?;
    let seeds = me.exchange(t, Round::PartialReveal, Payload::PartialReveal { check_seed })?;
    let mut partials = Vec::with_capacity(n);
    let mut sum = vec![0u64; row];
    for j in 0..n {
        let (Payload::PartialCommit { partial }, Payload::PartialReveal { check_seed: s }, Payload::Relin2Commit { check_seed: c, .. }) = (&pd_commits[j], &seeds[j], &r2_commits[j]) else {
            unreachable!("kinds checked")
        };
        if seed_commit(b"check seed", &session, j, s) != *c {
            return Err(Error::Protocol(format!("ceremony: party {j} revealed a test vector seed other than the one it committed to")));
        }
        for (acc, v) in sum.iter_mut().zip(check_vector(&session, s, &field, row)) {
            *acc = (*acc + v) % p;
        }
        let ct = codec
            .decode(&me.blob(t, j, &Blob::Partial, partial)?, Expect::Exactly(partial_meta))
            .map_err(|e| Error::Protocol(format!("ceremony: party {j}'s partial decryption: {e}")))?;
        partials.push(PartialDecryption::from_ciphertext(ct, j == 0));
    }
    let refs: Vec<&PartialDecryption> = partials.iter().collect();
    let got = ctx.fuse(&refs, row)?;
    let mulmod = |a: u64, b: u64| ((a as u128 * b as u128) % p as u128) as u64;
    let bad = (0..row)
        .filter(|&s| {
            let mut e = (mulmod(sum[s], sum[s]) + mulmod(weights[0], sum[s])) % p;
            for (k, &idx) in indices.iter().enumerate() {
                e = (e + mulmod(weights[k + 1], sum[(s as i64 + idx as i64).rem_euclid(row as i64) as usize])) % p;
            }
            got[s] != e
        })
        .count();
    if bad > 0 {
        return Err(Error::Protocol(format!("ceremony: joint key check failed in {bad} of {row} slots (a contribution or a partial decryption is wrong)")));
    }

    // Round 9: everyone signs the same transcript and attests the material.
    let mut digest_parts: Vec<u8> = me.transcript.iter().flatten().copied().collect();
    digest_parts.extend_from_slice(&material_digest(&material));
    let transcript = h(&[b"transcript", &digest_parts]);
    let signed = if dev == Deviation::WrongTranscript { h(&[b"other"]) } else { transcript };
    let attestation = attest::attest(cfg, &material, index, identity);
    let confirms = me.exchange(t, Round::Confirm, Payload::Confirm { transcript: signed, attestation })?;
    let mut material = material;
    for (j, c) in confirms.into_iter().enumerate() {
        let Payload::Confirm { transcript: d, attestation } = c else { unreachable!("kinds checked") };
        if d != transcript {
            return Err(Error::Protocol(format!("ceremony: party {j} saw another transcript or computed other keys")));
        }
        material.attestations.push(attestation);
    }
    attest::verify_material(cfg, &material, pinned)?;
    Ok(CeremonyOutput { material, share: share.serialize()?, transcript })
}

/// In-process transport over shared memory, for tests and simulations:
/// one [`MemoryTransport`] per party over a common [`MemoryNetwork`].
#[derive(Clone, Default)]
pub struct MemoryNetwork {
    inner: std::sync::Arc<(std::sync::Mutex<NetState>, std::sync::Condvar)>,
}

#[derive(Default)]
struct NetState {
    messages: std::collections::HashMap<(Round, usize), Message>,
    staged: std::collections::HashMap<(Round, usize, String), Vec<u8>>,
    released: std::collections::HashSet<(Round, usize)>,
    aborted: Option<(usize, String)>,
}

pub struct MemoryTransport {
    net: MemoryNetwork,
    index: usize,
    timeout: std::time::Duration,
}

impl MemoryNetwork {
    pub fn party(&self, index: usize) -> MemoryTransport {
        MemoryTransport { net: self.clone(), index, timeout: std::time::Duration::from_secs(600) }
    }
}

impl MemoryTransport {
    fn wait<T>(&self, what: &str, mut f: impl FnMut(&NetState) -> Option<T>) -> Result<T> {
        let (lock, cv) = &*self.net.inner;
        let deadline = std::time::Instant::now() + self.timeout;
        let mut st = lock.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(v) = f(&st) {
                return Ok(v);
            }
            if let Some((j, why)) = &st.aborted {
                return Err(Error::Protocol(format!("ceremony: party {j} aborted: {why}")));
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(Error::Protocol(format!("ceremony: timed out waiting for {what}")));
            }
            st = cv.wait_timeout(st, deadline - now).unwrap_or_else(|e| e.into_inner()).0;
        }
    }
}

impl Transport for MemoryTransport {
    fn stage_blob(&mut self, round: Round, name: &str, bytes: Vec<u8>) -> Result<()> {
        let (lock, _) = &*self.net.inner;
        lock.lock().unwrap_or_else(|e| e.into_inner()).staged.insert((round, self.index, name.to_string()), bytes);
        Ok(())
    }
    fn publish(&mut self, msg: &Message) -> Result<()> {
        let (lock, cv) = &*self.net.inner;
        let mut st = lock.lock().unwrap_or_else(|e| e.into_inner());
        st.messages.insert((msg.round, self.index), msg.clone());
        st.released.insert((msg.round, self.index));
        cv.notify_all();
        Ok(())
    }
    fn fetch(&mut self, round: Round, from: usize) -> Result<Message> {
        self.wait(&format!("party {from}'s round {round:?} message"), |st| st.messages.get(&(round, from)).cloned())
    }
    fn fetch_blob(&mut self, round: Round, from: usize, name: &str) -> Result<Vec<u8>> {
        let key = (round, from, name.to_string());
        // readable only once its owner has published the round's message
        let blob = self.wait(&format!("party {from}'s {name}"), |st| st.released.contains(&(round, from)).then(|| st.staged.get(&key).cloned()))?;
        blob.ok_or_else(|| Error::Protocol(format!("ceremony: party {from} released no {name}")))
    }
    fn abort(&mut self, reason: &str) {
        let (lock, cv) = &*self.net.inner;
        let mut st = lock.lock().unwrap_or_else(|e| e.into_inner());
        st.aborted.get_or_insert((self.index, reason.to_string()));
        cv.notify_all();
    }
}
