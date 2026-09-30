//! The n-of-n key ceremony, expressed as per-party steps over byte messages
//! so that it can run across processes. `run_local_ceremony` executes every
//! step in one process for tests and simulations.

use crate::config::TaskConfig;
use crate::error::{Error, Result};
use crate::messages::PublicMaterial;
use openfhe_tbgv_rs::{Context, EvalMultKey, Params, PublicKey, RotationKeys, SecretShare, keygen_first, keygen_next};
use zeroize::Zeroize;

/// The task's verify key: 32 secret bytes that every aggregator holds and no
/// client does. The validity challenge of each report is expanded from it
/// and the report id (`verify::Challenge::derive`), so a client cannot
/// compute the challenge its ciphertexts will face and cannot search offline
/// for ciphertexts that pass it (the role of Prio3's `verify_key`). The
/// distributed ceremony generates it jointly; it is stored with the key
/// share in [`AggregatorSecret`].
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyKey([u8; 32]);

impl VerifyKey {
    pub const LEN: usize = 32;

    /// A fresh uniformly random key from the operating system.
    pub fn random() -> Self {
        let mut k = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut k);
        Self(k)
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for VerifyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifyKey(<redacted>)")
    }
}

impl Drop for VerifyKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Everything secret an aggregator holds for a task: its share of the
/// joint BGV secret key and the task's verify key. This is what a ceremony
/// hands to each aggregator and what [`crate::Aggregator::new`] takes.
///
/// Encoding: `MAGIC (16 bytes) || version (1) || verify key (32) || share`.
/// The header lets a node refuse, with a clear error, a stored key share
/// from before the verify key existed (a bare OpenFHE serialization).
pub struct AggregatorSecret {
    pub verify_key: VerifyKey,
    /// Serialized `SecretShare`.
    pub share: Vec<u8>,
}

impl AggregatorSecret {
    pub const MAGIC: &'static [u8; 16] = b"fhe-prio3/secret";
    pub const VERSION: u8 = 1;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::MAGIC.len() + 1 + VerifyKey::LEN + self.share.len());
        out.extend_from_slice(Self::MAGIC);
        out.push(Self::VERSION);
        out.extend_from_slice(self.verify_key.as_bytes());
        out.extend_from_slice(&self.share);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let head = Self::MAGIC.len() + 1 + VerifyKey::LEN;
        if bytes.len() < head || &bytes[..Self::MAGIC.len()] != Self::MAGIC {
            return Err(Error::Config(
                "aggregator secret has no fhe-prio3/secret header: it is a bare key share from before the verify key existed, \
                 or not an aggregator secret at all. Re-run the key ceremony for this task"
                    .into(),
            ));
        }
        let version = bytes[Self::MAGIC.len()];
        if version != Self::VERSION {
            return Err(Error::Config(format!(
                "aggregator secret version {version}, this build reads version {}",
                Self::VERSION
            )));
        }
        let key: [u8; 32] = bytes[Self::MAGIC.len() + 1..head].try_into().expect("32 bytes");
        if bytes.len() == head {
            return Err(Error::Config("aggregator secret carries no key share".into()));
        }
        Ok(Self {
            verify_key: VerifyKey::from_bytes(key),
            share: bytes[head..].to_vec(),
        })
    }
}

impl Drop for AggregatorSecret {
    fn drop(&mut self) {
        self.share.zeroize();
    }
}

/// Creates the crypto context for a task. Every party runs this with the
/// same configuration and checks the resulting parameters match.
pub fn make_context(cfg: &TaskConfig) -> Result<Context> {
    cfg.validate()?;
    // OpenFHE caches contexts in an unsynchronised process-global factory;
    // parties created on several threads (the ceremony tests) take turns.
    static CONTEXT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = CONTEXT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ctx = Context::new(Params {
        plain_mod: cfg.plain_mod,
        mult_depth: cfg.mult_depth(),
        security_bits: cfg.security_bits,
    })?;
    // Fails loudly if p is not compatible with the chosen ring dimension.
    ctx.plaintext(&[1])?;
    Ok(ctx)
}

/// Public-key step for party `i`: party 0 passes `None`, every later party
/// passes the accumulated public key of the previous party. Returns the new
/// accumulated public key and this party's secret share.
pub fn keygen_step(ctx: &Context, prev: Option<&[u8]>) -> Result<(PublicKey, SecretShare)> {
    Ok(match prev {
        None => keygen_first(ctx)?,
        Some(bytes) => {
            let prev = ctx.deserialize_public_key(bytes)?;
            keygen_next(ctx, &prev)?
        }
    })
}

/// Eval-mult key, round 1. Party 0 passes `None`; others pass party 0's
/// round-1 message.
pub fn multkey_round1(ctx: &Context, share: &SecretShare, first: Option<&[u8]>) -> Result<Vec<u8>> {
    let k = match first {
        None => EvalMultKey::round1_first(ctx, share)?,
        Some(b) => EvalMultKey::round1_next(ctx, share, &ctx.deserialize_eval_mult_key(b)?)?,
    };
    Ok(k.serialize()?)
}

pub fn multkey_round1_sum(ctx: &Context, contributions: &[Vec<u8>], joint_tag: &str) -> Result<Vec<u8>> {
    let mut acc = ctx.deserialize_eval_mult_key(&contributions[0])?;
    for c in &contributions[1..] {
        acc = EvalMultKey::round1_add(ctx, &acc, &ctx.deserialize_eval_mult_key(c)?, joint_tag)?;
    }
    Ok(acc.serialize()?)
}

pub fn multkey_round2(ctx: &Context, share: &SecretShare, round1_sum: &[u8], joint_tag: &str) -> Result<Vec<u8>> {
    Ok(EvalMultKey::round2(ctx, share, &ctx.deserialize_eval_mult_key(round1_sum)?, joint_tag)?.serialize()?)
}

pub fn multkey_round2_sum(ctx: &Context, contributions: &[Vec<u8>], joint_tag: &str) -> Result<Vec<u8>> {
    let mut acc = ctx.deserialize_eval_mult_key(&contributions[0])?;
    for c in &contributions[1..] {
        acc = EvalMultKey::round2_add(ctx, &acc, &ctx.deserialize_eval_mult_key(c)?, joint_tag)?;
    }
    Ok(acc.serialize()?)
}

/// Rotation-key step: party 0 passes `None`; later parties pass the
/// accumulated keys and receive the new accumulation.
pub fn rotkeys_step(ctx: &Context, share: &SecretShare, prev: Option<&[u8]>, indices: &[i32], joint_tag: &str) -> Result<Vec<u8>> {
    let acc = match prev {
        None => RotationKeys::first(ctx, share, indices)?,
        Some(b) => {
            let prev = ctx.deserialize_rotation_keys(b)?;
            let mine = RotationKeys::next(ctx, share, &prev, indices, joint_tag)?;
            RotationKeys::add(ctx, &prev, &mine, joint_tag)?
        }
    };
    Ok(acc.serialize()?)
}

/// Installed evaluation keys live in OpenFHE's process-global tables, keyed
/// by the joint tag, and are not tied to any `Context`. Without bookkeeping
/// they outlive every aggregator that used them (gigabytes per task in
/// silent mode; a process that serves several tasks in sequence, or a test
/// binary, runs out of memory). `LEASES` counts the live holders per tag.
static LEASES: std::sync::Mutex<std::collections::BTreeMap<String, usize>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Holds the evaluation keys of one joint tag installed. Dropping the last
/// lease for a tag removes its keys from the process-global tables.
pub struct KeyLease {
    tag: String,
}

impl Drop for KeyLease {
    fn drop(&mut self) {
        let mut leases = LEASES.lock().unwrap_or_else(|e| e.into_inner());
        let n = leases.get_mut(&self.tag).expect("lease exists");
        *n -= 1;
        if *n == 0 {
            leases.remove(&self.tag);
            // A failure here can only be a malformed tag, which install() already accepted.
            let _ = Context::clear_keys_for_tag(&self.tag);
        }
    }
}

/// Installs joint evaluation keys into the process, one rotation key at a
/// time (each is ~126 MiB at ring dimension 65536), and returns a lease.
/// A tag names one joint key, so when a lease for it is already held the
/// keys are installed already and are not deserialized again. Key
/// installation mutates process-global tables and is serialised here.
pub fn install(ctx: &Context, material: &PublicMaterial) -> Result<KeyLease> {
    if material.rotation_keys.len() != material.rotation_indices.len() {
        return Err(crate::Error::Config("rotation key list does not match index list".into()));
    }
    let mut leases = LEASES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(n) = leases.get_mut(&material.joint_tag) {
        *n += 1;
        return Ok(KeyLease {
            tag: material.joint_tag.clone(),
        });
    }
    let mk = ctx.deserialize_eval_mult_key(&material.eval_mult_key)?;
    ctx.install_eval_mult_key(&mk, &material.joint_tag)?;
    drop(mk);
    ctx.clear_rotation_keys(&material.joint_tag)?;
    for bytes in &material.rotation_keys {
        let rk = ctx.deserialize_rotation_keys(bytes)?;
        ctx.merge_rotation_keys(&rk, &material.joint_tag)?;
    }
    leases.insert(material.joint_tag.clone(), 1);
    Ok(KeyLease {
        tag: material.joint_tag.clone(),
    })
}

/// Runs the whole ceremony in-process. Every inter-party value crosses a
/// serialization boundary. Returns the public material and one encoded
/// [`AggregatorSecret`] per aggregator (its key share and the task's verify
/// key, drawn here from the operating system: this is a dealer, for tests
/// and trials).
pub fn run_local_ceremony(cfg: &TaskConfig) -> Result<(PublicMaterial, Vec<Vec<u8>>)> {
    let ctx = make_context(cfg)?;
    let n = cfg.num_aggregators;
    let layout = cfg.layout(ctx.row_slots())?;
    let indices = layout.rotation_indices();

    let mut shares = Vec::with_capacity(n);
    let mut pk_bytes: Option<Vec<u8>> = None;
    for _ in 0..n {
        let (pk, sk) = keygen_step(&ctx, pk_bytes.as_deref())?;
        pk_bytes = Some(pk.serialize()?);
        shares.push(sk);
    }
    let pk_bytes = pk_bytes.unwrap();
    let joint_tag = ctx.deserialize_public_key(&pk_bytes)?.tag()?;

    let first = multkey_round1(&ctx, &shares[0], None)?;
    let mut r1 = vec![first.clone()];
    for s in &shares[1..] {
        r1.push(multkey_round1(&ctx, s, Some(&first))?);
    }
    let r1_sum = multkey_round1_sum(&ctx, &r1, &joint_tag)?;
    let r2: Vec<Vec<u8>> = shares.iter().map(|s| multkey_round2(&ctx, s, &r1_sum, &joint_tag)).collect::<Result<_>>()?;
    let eval_mult_key = multkey_round2_sum(&ctx, &r2, &joint_tag)?;

    // One sequential ceremony per rotation index keeps the peak memory at a
    // few keys instead of the whole set.
    let mut rotation_keys = Vec::with_capacity(indices.len());
    for &idx in &indices {
        let mut rot: Option<Vec<u8>> = None;
        for s in &shares {
            rot = Some(rotkeys_step(&ctx, s, rot.as_deref(), &[idx], &joint_tag)?);
        }
        rotation_keys.push(rot.unwrap());
    }

    let material = PublicMaterial {
        context: ctx.serialize()?,
        public_key: pk_bytes,
        joint_tag,
        eval_mult_key,
        rotation_keys,
        rotation_indices: indices,
        attestations: Vec::new(),
    };
    let verify_key = VerifyKey::random();
    let secrets = shares
        .iter()
        .map(|s| {
            Ok(AggregatorSecret {
                verify_key: verify_key.clone(),
                share: s.serialize()?,
            }
            .encode())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((material, secrets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregator_secret_round_trips_and_refuses_bare_shares() {
        let s = AggregatorSecret {
            verify_key: VerifyKey::from_bytes([9u8; 32]),
            share: vec![1, 2, 3],
        };
        let d = AggregatorSecret::decode(&s.encode()).unwrap();
        assert_eq!(d.verify_key, s.verify_key);
        assert_eq!(d.share, s.share);
        // a key share stored before the verify key existed: refused, with the remedy
        let e = AggregatorSecret::decode(b"\x00\x01 an OpenFHE serialization of a secret key")
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("Re-run the key ceremony"), "{e}");
        // another version, a missing share, truncation
        let mut v2 = s.encode();
        v2[16] = 2;
        assert!(AggregatorSecret::decode(&v2).err().unwrap().to_string().contains("version 2"));
        assert!(AggregatorSecret::decode(&s.encode()[..49]).err().unwrap().to_string().contains("no key share"));
        assert!(AggregatorSecret::decode(&s.encode()[..40]).is_err());
        // the key never shows in logs
        assert_eq!(format!("{:?}", s.verify_key), "VerifyKey(<redacted>)");
    }
}
