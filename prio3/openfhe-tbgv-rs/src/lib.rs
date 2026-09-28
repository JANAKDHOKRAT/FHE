//! Safe Rust API over OpenFHE's threshold (n-of-n multiparty) BGV scheme.
//!
//! The wrapper exposes exactly the primitives an aggregation protocol needs:
//! a sequential n-of-n key generation, the two-round joint relinearisation
//! key ceremony, the one-round joint rotation key ceremony, SIMD plaintexts,
//! leveled evaluation, and partial decryption with noise flooding plus
//! fusion. No function in this crate can decrypt with fewer than all key
//! shares except [`SecretShare::decrypt_alone_for_tests`], which exists to
//! demonstrate in tests that a single share does not decrypt.
//!
//! All plaintext values are field elements in `[0, p)` where `p` is the
//! plaintext modulus. Conversion to OpenFHE's centered representation is done
//! internally.

mod ffi;

use std::ffi::{CStr, CString};
use std::fmt;
use std::sync::Arc;

/// Error raised by the underlying library, carrying OpenFHE's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "openfhe: {}", self.0)
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn last_error() -> Error {
    // SAFETY: tbgv_last_error returns a valid NUL-terminated thread-local string.
    let s = unsafe { CStr::from_ptr(ffi::tbgv_last_error()) };
    Error(s.to_string_lossy().into_owned())
}

fn take_buffer(ok: i32, buf: *mut u8, len: usize) -> Result<Vec<u8>> {
    if ok == 0 || buf.is_null() {
        return Err(last_error());
    }
    // SAFETY: buf points to len bytes allocated by the shim with malloc.
    let v = unsafe { std::slice::from_raw_parts(buf, len).to_vec() };
    unsafe { ffi::tbgv_buffer_free(buf) };
    Ok(v)
}

fn take_string(p: *mut std::os::raw::c_char) -> Result<String> {
    if p.is_null() {
        return Err(Error("null string from shim".into()));
    }
    // SAFETY: p is a malloc'd NUL-terminated string owned by us.
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    unsafe { ffi::tbgv_string_free(p) };
    Ok(s)
}

fn c_tag(tag: &str) -> Result<CString> {
    CString::new(tag).map_err(|_| Error("key tag contains NUL".into()))
}

struct ContextInner(ffi::TbgvContext);
impl Drop for ContextInner {
    fn drop(&mut self) {
        unsafe { ffi::tbgv_context_free(self.0) }
    }
}
// SAFETY: a context is a heap object that may be moved between threads.
// It is deliberately not `Sync`: OpenFHE keeps evaluation keys and the
// context cache in process-global tables without locking, so one process
// must drive one context from one thread (OpenFHE parallelises internally
// with OpenMP).
unsafe impl Send for ContextInner {}

/// BGV crypto context: parameters plus installed public evaluation keys.
#[derive(Clone)]
pub struct Context {
    inner: Arc<ContextInner>,
}

/// Parameters for [`Context::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Plaintext modulus. Must be prime and congruent to 1 modulo twice the
    /// ring dimension for full SIMD packing.
    pub plain_mod: u64,
    /// Maximum multiplicative depth of the circuits to be evaluated.
    pub mult_depth: u32,
    /// 128, 192 or 256 (HE standard classical security).
    pub security_bits: u32,
}

impl Context {
    /// Creates a context in `NOISE_FLOODING_MULTIPARTY` mode with
    /// `FLEXIBLEAUTOEXT` scaling. The ring dimension is chosen by OpenFHE from
    /// the security level and the modulus chain.
    pub fn new(params: Params) -> Result<Self> {
        let p = unsafe { ffi::tbgv_context_new(params.plain_mod, params.mult_depth, params.security_bits) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(Self { inner: Arc::new(ContextInner(p)) })
    }

    fn raw(&self) -> ffi::TbgvContext {
        self.inner.0
    }

    pub fn plain_mod(&self) -> u64 {
        unsafe { ffi::tbgv_context_plain_mod(self.raw()) }
    }
    pub fn ring_dim(&self) -> u32 {
        unsafe { ffi::tbgv_context_ring_dim(self.raw()) }
    }
    /// Number of slots per rotation row. Rotations are cyclic within a row.
    pub fn row_slots(&self) -> usize {
        (self.ring_dim() / 2) as usize
    }
    pub fn mult_depth(&self) -> u32 {
        unsafe { ffi::tbgv_context_mult_depth(self.raw()) }
    }
    pub fn log2_q(&self) -> f64 {
        unsafe { ffi::tbgv_context_log2_q(self.raw()) }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = std::ptr::null_mut();
        let mut len = 0usize;
        let ok = unsafe { ffi::tbgv_context_serialize(self.raw(), &mut buf, &mut len) };
        take_buffer(ok, buf, len)
    }
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let p = unsafe { ffi::tbgv_context_deserialize(bytes.as_ptr(), bytes.len()) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(Self { inner: Arc::new(ContextInner(p)) })
    }

    fn center(&self, v: u64) -> Result<i64> {
        let p = self.plain_mod();
        if v >= p {
            return Err(Error(format!("value {v} not reduced modulo {p}")));
        }
        let half = (p - 1) / 2;
        Ok(if v <= half { v as i64 } else { v as i64 - p as i64 })
    }
    fn uncenter(&self, v: i64) -> u64 {
        let p = self.plain_mod() as i64;
        let r = v.rem_euclid(p);
        r as u64
    }

    /// Packs field elements (in `[0, p)`) into a SIMD plaintext. Slots beyond
    /// `values.len()` are zero.
    pub fn plaintext(&self, values: &[u64]) -> Result<Plaintext> {
        if values.len() > self.ring_dim() as usize {
            return Err(Error("too many slots for the ring dimension".into()));
        }
        let centered: Result<Vec<i64>> = values.iter().map(|&v| self.center(v)).collect();
        let centered = centered?;
        let p = unsafe { ffi::tbgv_plaintext_new(self.raw(), centered.as_ptr(), centered.len()) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(Plaintext { ptr: p, ctx: self.clone() })
    }

    pub fn encrypt(&self, pk: &PublicKey, pt: &Plaintext) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_encrypt(self.raw(), pk.ptr, pt.ptr) })
    }

    fn wrap_ct(&self, p: ffi::TbgvCiphertext) -> Result<Ciphertext> {
        if p.is_null() {
            return Err(last_error());
        }
        Ok(Ciphertext { ptr: p, ctx: self.clone() })
    }

    pub fn add(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_eval_add(self.raw(), a.ptr, b.ptr) })
    }
    pub fn sub(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_eval_sub(self.raw(), a.ptr, b.ptr) })
    }
    /// Ciphertext-ciphertext product with relinearisation. Requires the joint
    /// eval-mult key to be installed.
    pub fn mult(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_eval_mult(self.raw(), a.ptr, b.ptr) })
    }
    pub fn add_plain(&self, a: &Ciphertext, b: &Plaintext) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_eval_add_plain(self.raw(), a.ptr, b.ptr) })
    }
    pub fn sub_plain(&self, a: &Ciphertext, b: &Plaintext) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_eval_sub_plain(self.raw(), a.ptr, b.ptr) })
    }
    pub fn mult_plain(&self, a: &Ciphertext, b: &Plaintext) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_eval_mult_plain(self.raw(), a.ptr, b.ptr) })
    }
    /// Cyclic rotation within each row: positive `index` moves slot `i+index`
    /// into slot `i` (a left shift). Requires a joint rotation key for `index`.
    pub fn rotate(&self, a: &Ciphertext, index: i32) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_eval_rotate(self.raw(), a.ptr, index) })
    }

    pub fn negate(&self, a: &Ciphertext) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_eval_negate(self.raw(), a.ptr) })
    }

    /// TEST HOOK: a copy of `ct` with `p * N(X)` added to its first component,
    /// `N` having uniformly random coefficients below `2^log2_magnitude`. The
    /// plaintext is unchanged, the noise is not. Models a client that submits
    /// a value that is not a proper encryption.
    pub fn add_noise_for_tests(&self, ct: &Ciphertext, log2_magnitude: u32, seed: u64) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_ciphertext_add_noise_for_tests(self.raw(), ct.ptr, log2_magnitude, seed) })
    }

    pub fn deserialize_ciphertext(&self, bytes: &[u8]) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_ciphertext_deserialize(self.raw(), bytes.as_ptr(), bytes.len()) })
    }
    pub fn deserialize_public_key(&self, bytes: &[u8]) -> Result<PublicKey> {
        let p = unsafe { ffi::tbgv_pubkey_deserialize(self.raw(), bytes.as_ptr(), bytes.len()) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(PublicKey { ptr: p, ctx: self.clone() })
    }
    pub fn deserialize_secret_share(&self, bytes: &[u8]) -> Result<SecretShare> {
        let p = unsafe { ffi::tbgv_seckey_deserialize(self.raw(), bytes.as_ptr(), bytes.len()) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(SecretShare { ptr: p, ctx: self.clone() })
    }
    pub fn deserialize_eval_mult_key(&self, bytes: &[u8]) -> Result<EvalMultKey> {
        let p = unsafe { ffi::tbgv_evalkey_deserialize(self.raw(), bytes.as_ptr(), bytes.len()) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(EvalMultKey { ptr: p, ctx: self.clone() })
    }
    pub fn deserialize_rotation_keys(&self, bytes: &[u8]) -> Result<RotationKeys> {
        let p = unsafe { ffi::tbgv_rotkeys_deserialize(self.raw(), bytes.as_ptr(), bytes.len()) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(RotationKeys { ptr: p, ctx: self.clone() })
    }

    /// Installs the joint relinearisation key under `joint_tag`, the key tag
    /// of the joint public key.
    pub fn install_eval_mult_key(&self, key: &EvalMultKey, joint_tag: &str) -> Result<()> {
        let t = c_tag(joint_tag)?;
        if unsafe { ffi::tbgv_context_install_multkey(self.raw(), key.ptr, t.as_ptr()) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }
    /// Installs the joint rotation keys under `joint_tag`.
    pub fn install_rotation_keys(&self, keys: &RotationKeys, joint_tag: &str) -> Result<()> {
        let t = c_tag(joint_tag)?;
        if unsafe { ffi::tbgv_context_install_rotkeys(self.raw(), keys.ptr, t.as_ptr()) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    /// Adds `keys` to the rotation keys installed under `joint_tag`,
    /// keeping the ones already there. Lets large key sets be installed one
    /// index at a time.
    pub fn merge_rotation_keys(&self, keys: &RotationKeys, joint_tag: &str) -> Result<()> {
        let t = c_tag(joint_tag)?;
        if unsafe { ffi::tbgv_context_merge_rotkeys(self.raw(), keys.ptr, t.as_ptr()) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }
    /// Removes every rotation key installed under `joint_tag`.
    pub fn clear_rotation_keys(&self, joint_tag: &str) -> Result<()> {
        let t = c_tag(joint_tag)?;
        if unsafe { ffi::tbgv_context_clear_rotkeys(self.raw(), t.as_ptr()) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    /// Fuses partial decryptions. Exactly one must have been produced with
    /// `lead = true`. Returns the first `num_slots` slots as field elements.
    pub fn fuse(&self, partials: &[&PartialDecryption], num_slots: usize) -> Result<Vec<u64>> {
        if partials.is_empty() {
            return Err(Error("no partial decryptions".into()));
        }
        let leads = partials.iter().filter(|p| p.lead).count();
        if leads != 1 {
            return Err(Error(format!("expected exactly one lead partial decryption, got {leads}")));
        }
        let ptrs: Vec<ffi::TbgvCiphertext> = partials.iter().map(|p| p.ct.ptr).collect();
        let mut out = vec![0i64; num_slots];
        let n = unsafe { ffi::tbgv_fuse(self.raw(), ptrs.as_ptr(), ptrs.len(), out.as_mut_ptr(), num_slots) };
        if n == 0 && num_slots > 0 {
            return Err(last_error());
        }
        Ok(out[..n].iter().map(|&v| self.uncenter(v)).collect())
    }
}

/// First party of the n-of-n key generation. Returns (public key so far, share).
pub fn keygen_first(ctx: &Context) -> Result<(PublicKey, SecretShare)> {
    let mut pk = std::ptr::null_mut();
    let mut sk = std::ptr::null_mut();
    if unsafe { ffi::tbgv_keygen_first(ctx.raw(), &mut pk, &mut sk) } == 0 {
        return Err(last_error());
    }
    Ok((PublicKey { ptr: pk, ctx: ctx.clone() }, SecretShare { ptr: sk, ctx: ctx.clone() }))
}

/// Subsequent party: takes the joint public key accumulated so far and
/// returns the new joint public key plus this party's share. The last
/// party's output is the final joint public key.
pub fn keygen_next(ctx: &Context, prev_joint_pk: &PublicKey) -> Result<(PublicKey, SecretShare)> {
    let mut pk = std::ptr::null_mut();
    let mut sk = std::ptr::null_mut();
    if unsafe { ffi::tbgv_keygen_next(ctx.raw(), prev_joint_pk.ptr, &mut pk, &mut sk) } == 0 {
        return Err(last_error());
    }
    Ok((PublicKey { ptr: pk, ctx: ctx.clone() }, SecretShare { ptr: sk, ctx: ctx.clone() }))
}

macro_rules! handle_type {
    ($name:ident, $free:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $name {
            ptr: *mut std::ffi::c_void,
            #[allow(dead_code)]
            ctx: Context,
        }
        impl Drop for $name {
            fn drop(&mut self) {
                unsafe { ffi::$free(self.ptr) }
            }
        }
        // SAFETY: heap objects owned exclusively by this handle.
        unsafe impl Send for $name {}
    };
}

handle_type!(PublicKey, tbgv_pubkey_free, "Joint (or partial joint) public key.");
handle_type!(SecretShare, tbgv_seckey_free, "One party's additive share of the secret key.");
handle_type!(EvalMultKey, tbgv_evalkey_free, "Relinearisation key or ceremony message.");
handle_type!(RotationKeys, tbgv_rotkeys_free, "Rotation key map or ceremony message.");
handle_type!(Plaintext, tbgv_plaintext_free, "Packed SIMD plaintext.");
handle_type!(Ciphertext, tbgv_ciphertext_free, "BGV ciphertext.");

impl PublicKey {
    /// OpenFHE key tag. All ciphertexts encrypted under this key carry it and
    /// evaluation keys are looked up by it.
    pub fn tag(&self) -> Result<String> {
        take_string(unsafe { ffi::tbgv_pubkey_tag(self.ptr) })
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = std::ptr::null_mut();
        let mut len = 0usize;
        let ok = unsafe { ffi::tbgv_pubkey_serialize(self.ptr, &mut buf, &mut len) };
        take_buffer(ok, buf, len)
    }
}

impl SecretShare {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = std::ptr::null_mut();
        let mut len = 0usize;
        let ok = unsafe { ffi::tbgv_seckey_serialize(self.ptr, &mut buf, &mut len) };
        take_buffer(ok, buf, len)
    }

    /// Produces this party's partial decryption of `ct` with flooding noise.
    /// Exactly one party per fusion must set `lead`.
    pub fn partial_decrypt(&self, ct: &Ciphertext, lead: bool) -> Result<PartialDecryption> {
        let p = unsafe { ffi::tbgv_partial_decrypt(self.ctx.raw(), ct.ptr, self.ptr, lead as i32) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(PartialDecryption { ct: Ciphertext { ptr: p, ctx: self.ctx.clone() }, lead })
    }

    /// Single-share decryption. With more than one party this returns
    /// garbage by construction; it exists so tests can demonstrate that.
    pub fn decrypt_alone_for_tests(&self, ct: &Ciphertext, num_slots: usize) -> Result<Vec<u64>> {
        let mut out = vec![0i64; num_slots];
        let n = unsafe { ffi::tbgv_decrypt_single(self.ctx.raw(), self.ptr, ct.ptr, out.as_mut_ptr(), num_slots) };
        if n == 0 && num_slots > 0 {
            return Err(last_error());
        }
        Ok(out[..n].iter().map(|&v| self.ctx.uncenter(v)).collect())
    }
}

impl EvalMultKey {
    /// Round 1, first party: `KeySwitchGen(s_0, s_0)`.
    pub fn round1_first(ctx: &Context, sk: &SecretShare) -> Result<Self> {
        Self::wrap(ctx, unsafe { ffi::tbgv_multkey_round1_first(ctx.raw(), sk.ptr) })
    }
    /// Round 1, other parties: contribution built from the first party's key.
    pub fn round1_next(ctx: &Context, sk: &SecretShare, first: &EvalMultKey) -> Result<Self> {
        Self::wrap(ctx, unsafe { ffi::tbgv_multkey_round1_next(ctx.raw(), sk.ptr, first.ptr) })
    }
    /// Sums two round-1 contributions.
    pub fn round1_add(ctx: &Context, a: &EvalMultKey, b: &EvalMultKey, joint_tag: &str) -> Result<Self> {
        let t = c_tag(joint_tag)?;
        Self::wrap(ctx, unsafe { ffi::tbgv_multkey_round1_add(ctx.raw(), a.ptr, b.ptr, t.as_ptr()) })
    }
    /// Round 2, every party: multiplies the round-1 sum by its own share.
    pub fn round2(ctx: &Context, sk: &SecretShare, round1_sum: &EvalMultKey, joint_tag: &str) -> Result<Self> {
        let t = c_tag(joint_tag)?;
        Self::wrap(ctx, unsafe { ffi::tbgv_multkey_round2(ctx.raw(), sk.ptr, round1_sum.ptr, t.as_ptr()) })
    }
    /// Sums two round-2 contributions; the total is the joint eval-mult key.
    pub fn round2_add(ctx: &Context, a: &EvalMultKey, b: &EvalMultKey, joint_tag: &str) -> Result<Self> {
        let t = c_tag(joint_tag)?;
        Self::wrap(ctx, unsafe { ffi::tbgv_multkey_round2_add(ctx.raw(), a.ptr, b.ptr, t.as_ptr()) })
    }
    fn wrap(ctx: &Context, p: ffi::TbgvEvalKey) -> Result<Self> {
        if p.is_null() {
            return Err(last_error());
        }
        Ok(Self { ptr: p, ctx: ctx.clone() })
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = std::ptr::null_mut();
        let mut len = 0usize;
        let ok = unsafe { ffi::tbgv_evalkey_serialize(self.ptr, &mut buf, &mut len) };
        take_buffer(ok, buf, len)
    }
}

impl RotationKeys {
    /// First party's rotation keys for `indices`.
    pub fn first(ctx: &Context, sk: &SecretShare, indices: &[i32]) -> Result<Self> {
        Self::wrap(ctx, unsafe { ffi::tbgv_rotkeys_first(ctx.raw(), sk.ptr, indices.as_ptr(), indices.len()) })
    }
    /// Subsequent party's contribution, built from the accumulated keys.
    pub fn next(ctx: &Context, sk: &SecretShare, prev: &RotationKeys, indices: &[i32], joint_tag: &str) -> Result<Self> {
        let t = c_tag(joint_tag)?;
        Self::wrap(ctx, unsafe {
            ffi::tbgv_rotkeys_next(ctx.raw(), sk.ptr, prev.ptr, indices.as_ptr(), indices.len(), t.as_ptr())
        })
    }
    pub fn add(ctx: &Context, a: &RotationKeys, b: &RotationKeys, joint_tag: &str) -> Result<Self> {
        let t = c_tag(joint_tag)?;
        Self::wrap(ctx, unsafe { ffi::tbgv_rotkeys_add(ctx.raw(), a.ptr, b.ptr, t.as_ptr()) })
    }
    fn wrap(ctx: &Context, p: ffi::TbgvRotKeys) -> Result<Self> {
        if p.is_null() {
            return Err(last_error());
        }
        Ok(Self { ptr: p, ctx: ctx.clone() })
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = std::ptr::null_mut();
        let mut len = 0usize;
        let ok = unsafe { ffi::tbgv_rotkeys_serialize(self.ptr, &mut buf, &mut len) };
        take_buffer(ok, buf, len)
    }
}

/// Structural facts about a ciphertext, used to validate untrusted input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextInfo {
    pub level: u32,
    pub num_elements: u32,
    pub noise_scale_deg: u32,
    pub num_limbs: u32,
    pub packed_encoding: bool,
    pub key_tag: String,
}

impl Ciphertext {
    pub fn try_clone(&self) -> Result<Ciphertext> {
        self.ctx.wrap_ct(unsafe { ffi::tbgv_ciphertext_clone(self.ptr) })
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = std::ptr::null_mut();
        let mut len = 0usize;
        let ok = unsafe { ffi::tbgv_ciphertext_serialize(self.ptr, &mut buf, &mut len) };
        take_buffer(ok, buf, len)
    }
    pub fn info(&self) -> Result<CiphertextInfo> {
        let (mut level, mut ne, mut nsd, mut limbs, mut packed) = (0u32, 0u32, 0u32, 0u32, 0u32);
        if unsafe { ffi::tbgv_ciphertext_info(self.ptr, &mut level, &mut ne, &mut nsd, &mut limbs, &mut packed) } == 0 {
            return Err(last_error());
        }
        let key_tag = take_string(unsafe { ffi::tbgv_ciphertext_key_tag(self.ptr) })?;
        Ok(CiphertextInfo { level, num_elements: ne, noise_scale_deg: nsd, num_limbs: limbs, packed_encoding: packed == 1, key_tag })
    }
}

/// A partial decryption produced by one key share.
pub struct PartialDecryption {
    ct: Ciphertext,
    lead: bool,
}
unsafe impl Send for PartialDecryption {}

impl PartialDecryption {
    pub fn is_lead(&self) -> bool {
        self.lead
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        self.ct.serialize()
    }
    /// Reconstructs a partial decryption received from another party. The
    /// `lead` flag is part of the message, not the bytes.
    pub fn deserialize(ctx: &Context, bytes: &[u8], lead: bool) -> Result<Self> {
        Ok(Self { ct: ctx.deserialize_ciphertext(bytes)?, lead })
    }
}
