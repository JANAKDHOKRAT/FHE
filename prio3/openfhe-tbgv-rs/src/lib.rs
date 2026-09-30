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
mod selftest;

pub use selftest::{RebuildReport, rebuild_verified, verify_rebuild_once};

use std::ffi::{CStr, CString};
use std::fmt;
use std::sync::{Arc, OnceLock};

/// The OpenFHE version this crate was built against; `build.rs` accepts
/// only tested versions.
pub const OPENFHE_VERSION: &str = env!("TBGV_OPENFHE_VERSION");

/// Resolved paths of the OpenFHE shared libraries loaded in this process.
pub fn loaded_openfhe_libraries() -> Result<Vec<String>> {
    let s = take_string(unsafe { ffi::tbgv_loaded_openfhe_libraries() })?;
    Ok(s.lines().filter(|l| !l.is_empty()).map(str::to_string).collect())
}

/// Checks that the OpenFHE libraries loaded at run time are the version
/// this crate was built and tested against. The binaries link OpenFHE by
/// major version (`libOPENFHEpke.so.1`), so without this check a different
/// 1.x library would be used silently. Runs once per process; every
/// [`Context`] constructor calls it.
pub fn check_loaded_openfhe() -> Result<()> {
    static OUTCOME: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    OUTCOME
        .get_or_init(|| {
            let libs = loaded_openfhe_libraries().map_err(|e| e.0)?;
            let suffix = format!(".so.{OPENFHE_VERSION}");
            for needed in ["libOPENFHEcore", "libOPENFHEpke"] {
                if !libs.iter().any(|l| l.rsplit('/').next().is_some_and(|f| f.starts_with(needed))) {
                    return Err(format!("{needed} is not loaded in this process (loaded: {libs:?})"));
                }
            }
            for l in &libs {
                let file = l.rsplit('/').next().unwrap_or(l);
                if !file.ends_with(&suffix) {
                    return Err(format!(
                        "loaded OpenFHE library {l} is not version {OPENFHE_VERSION}, the version this build was tested against"
                    ));
                }
            }
            Ok(())
        })
        .clone()
        .map_err(Error)
}

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
// SAFETY: a context is a heap object that may be moved between threads
// (`Send`). Sharing references (`Sync`) is sound for *evaluation*: OpenFHE's
// evaluation, encryption and decryption entry points only read the context
// and the installed keys, which is how OpenFHE's own examples run OpenMP
// loops over ciphertexts. What must not run concurrently with anything else
// is key installation (`install_*`, `merge_rotation_keys`,
// `clear_rotation_keys`) and context creation, which mutate process-global
// tables without locking. Callers serialise those (this crate's tests and
// the aggregator node do).
unsafe impl Send for ContextInner {}
unsafe impl Sync for ContextInner {}

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
        check_loaded_openfhe()?;
        let p = unsafe { ffi::tbgv_context_new(params.plain_mod, params.mult_depth, params.security_bits) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(Self {
            inner: Arc::new(ContextInner(p)),
        })
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
    /// Number of RNS towers minus two. This is an upper bound on the depth
    /// the context was created for, not that depth: in
    /// `NOISE_FLOODING_MULTIPARTY` mode with `FLEXIBLEAUTOEXT`, OpenFHE 1.3.1
    /// gives a depth-`d` context `d + 4` towers (measured for `d = 3` and
    /// `d = 25`), so this returns `d + 2`.
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
        check_loaded_openfhe()?;
        let p = unsafe { ffi::tbgv_context_deserialize(bytes.as_ptr(), bytes.len()) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(Self {
            inner: Arc::new(ContextInner(p)),
        })
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

    /// Number of RNS towers of the full modulus chain (a fresh ciphertext has all of them).
    pub fn num_towers(&self) -> u32 {
        unsafe { ffi::tbgv_context_num_towers(self.raw()) }
    }

    /// Moduli of towers `0..num_towers()` of the full chain. A ciphertext
    /// with `k` towers uses the first `k` of them.
    pub fn moduli(&self) -> Result<Vec<u64>> {
        let mut out = vec![0u64; self.num_towers() as usize];
        if unsafe { ffi::tbgv_context_moduli(self.raw(), out.as_mut_ptr(), out.len()) } == 0 {
            return Err(last_error());
        }
        Ok(out)
    }

    /// Rebuilds a ciphertext from its residues and metadata inside this
    /// context, without touching OpenFHE's deserializer. `reference` must be
    /// a fresh encryption made by the caller under the joint key; it supplies
    /// the key tag, the encoding and the tower parameters. The shim rejects
    /// any metadata or residue outside the documented bounds before building.
    ///
    /// Refused until [`verify_rebuild_once`] has passed for this context's
    /// parameters in this process, and for objects deeper than the level it
    /// verified: the rebuild is exact only if the loaded OpenFHE gives the
    /// metadata the meaning the tested version gives it.
    pub fn build_ciphertext(&self, reference: &Ciphertext, meta: &CiphertextMeta, residues: &[u64]) -> Result<Ciphertext> {
        match rebuild_verified(self)? {
            None => {
                return Err(Error(
                    "ciphertext rebuild has not been verified on this OpenFHE library for these parameters; call verify_rebuild_once at startup".into(),
                ));
            }
            Some(d) if meta.level > d => {
                return Err(Error(format!("rebuild at level {} is deeper than the verified depth {d}", meta.level)));
            }
            Some(_) => {}
        }
        self.build_ciphertext_unverified(reference, meta, residues)
    }

    pub(crate) fn build_ciphertext_unverified(&self, reference: &Ciphertext, meta: &CiphertextMeta, residues: &[u64]) -> Result<Ciphertext> {
        self.wrap_ct(unsafe {
            ffi::tbgv_ciphertext_build(
                self.raw(),
                reference.ptr,
                meta.num_elements,
                meta.num_towers,
                meta.level,
                meta.noise_scale_deg,
                meta.scaling_factor_int,
                residues.as_ptr(),
                residues.len(),
            )
        })
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

    /// `a * a` with relinearisation. Same result as `mult(a, a)`, fewer
    /// polynomial products.
    pub fn square(&self, a: &Ciphertext) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_eval_square(self.raw(), a.ptr) })
    }

    pub fn negate(&self, a: &Ciphertext) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_eval_negate(self.raw(), a.ptr) })
    }

    /// TEST HOOK: a copy of `ct` with `p * N(X)` added to its first component,
    /// `N` having uniformly random coefficients below `2^log2_magnitude`. The
    /// plaintext is unchanged, the noise is not. Models a client that submits
    /// a value that is not a proper encryption.
    /// Standard deviation of OpenFHE's flooding noise for partial
    /// decryptions (`NOISE_FLOODING_MULTIPARTY`), in units of `t`.
    pub fn flooding_sigma(&self) -> Result<f64> {
        let s = unsafe { ffi::tbgv_flooding_sigma(self.raw()) };
        if s < 0.0 {
            return Err(last_error());
        }
        Ok(s)
    }

    /// The fused value at full precision: `sum_i partial_i = m + t (noise +
    /// flooding)` over the partials' modulus `Q_l`, before OpenFHE's fusion
    /// reduces it to `q0`. Anyone holding the partials can compute it.
    /// Returns `(log2 max |coefficient|, log2 Q_l)`.
    pub fn fuse_raw_log2(&self, partials: &[&PartialDecryption]) -> Result<(f64, f64)> {
        self.fuse_raw_inner(partials, None)
    }

    /// [`Self::fuse_raw_log2`] plus every centered coefficient divided by `t`.
    pub fn fuse_raw_over_t(&self, partials: &[&PartialDecryption]) -> Result<(Vec<f64>, f64, f64)> {
        let mut out = vec![0f64; self.ring_dim() as usize];
        let (m, q) = self.fuse_raw_inner(partials, Some(&mut out))?;
        Ok((out, m, q))
    }

    fn fuse_raw_inner(&self, partials: &[&PartialDecryption], out: Option<&mut Vec<f64>>) -> Result<(f64, f64)> {
        let ptrs: Vec<ffi::TbgvCiphertext> = partials.iter().map(|p| p.ct.ptr).collect();
        let (mut m, mut q) = (0f64, 0f64);
        let (op, ol) = match out {
            Some(v) => (v.as_mut_ptr(), v.len()),
            None => (std::ptr::null_mut(), 0),
        };
        if unsafe { ffi::tbgv_fuse_raw(self.raw(), ptrs.as_ptr(), ptrs.len(), op, ol, &mut m, &mut q) } == 0 {
            return Err(last_error());
        }
        Ok((m, q))
    }

    /// Whether the fused value lies where `n` partial decryptions flooded as
    /// OpenFHE floods them can put it: every coefficient of
    /// `sum_i partial_i` within `t (n Q'/2 + Q' 2^-slack + 1)`, `Q' = Q_l / q0`
    /// (OpenFHE draws each party's flooding uniformly from `[-Q'/2, Q'/2]`;
    /// `Q' 2^-slack` is the allowance for honest noise and the message).
    /// Returns `(within, max |coefficient| / (t n Q'/2))`.
    pub fn fuse_flooding_check(&self, partials: &[&PartialDecryption], slack_bits: u32) -> Result<(bool, f64)> {
        let ptrs: Vec<ffi::TbgvCiphertext> = partials.iter().map(|p| p.ct.ptr).collect();
        let (mut within, mut ratio) = (0i32, 0f64);
        if unsafe { ffi::tbgv_fuse_flooding_check(self.raw(), ptrs.as_ptr(), ptrs.len(), slack_bits, &mut within, &mut ratio) } == 0 {
            return Err(last_error());
        }
        Ok((within == 1, ratio))
    }

    /// Tests only: a partial decryption flooded uniformly in `[-W, W]`,
    /// `W = Q' num / (2 den)`, instead of OpenFHE's `[-Q'/2, Q'/2]` (what a
    /// party that shapes its own flooding sends).
    pub fn partial_decrypt_shaped_for_tests(&self, ct: &Ciphertext, share: &SecretShare, lead: bool, num: u64, den: u64) -> Result<PartialDecryption> {
        let p = unsafe { ffi::tbgv_partial_decrypt_shaped_for_tests(self.raw(), ct.ptr, share.ptr, lead as i32, num, den, 0) };
        let ct = self.wrap_ct(p)?;
        Ok(PartialDecryption::from_ciphertext(ct, lead))
    }

    /// Tests only: the public key with `b + t E`, `E = Q' num / den` (the
    /// constant polynomial), `Q' = Q / q0` of the ciphertext modulus.
    pub fn inflate_public_key_ratio_for_tests(&self, pk: &PublicKey, num: u64, den: u64) -> Result<PublicKey> {
        let p = unsafe { ffi::tbgv_pubkey_inflate_ratio_for_tests(self.raw(), pk.ptr, num, den) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(PublicKey { ptr: p, ctx: self.clone() })
    }

    /// Tests only: `c0 + c1 * sum_i s_i` at full precision, without any
    /// flooding, i.e. `m + t * noise`. Returns every coefficient over `t`,
    /// `log2 max |coefficient|` and `log2 Q_l`.
    pub fn raw_decrypt_for_tests(&self, ct: &Ciphertext, shares: &[&SecretShare]) -> Result<(Vec<f64>, f64, f64)> {
        let ptrs: Vec<ffi::TbgvSecretKey> = shares.iter().map(|s| s.ptr).collect();
        let mut out = vec![0f64; self.ring_dim() as usize];
        let (mut m, mut q) = (0f64, 0f64);
        if unsafe { ffi::tbgv_raw_decrypt_for_tests(self.raw(), ct.ptr, ptrs.as_ptr(), ptrs.len(), out.as_mut_ptr(), out.len(), &mut m, &mut q) } == 0 {
            return Err(last_error());
        }
        Ok((out, m, q))
    }

    /// Tests only: the public key with `b + t E`, i.e. what a party whose key
    /// contribution carries the extra noise `E` produces. `E = 2^log2_k` (the
    /// constant polynomial) if `constant`, else uniform in `(-2^log2_k, 2^log2_k)`.
    pub fn inflate_public_key_for_tests(&self, pk: &PublicKey, log2_k: u32, seed: u64, constant: bool) -> Result<PublicKey> {
        let p = unsafe { ffi::tbgv_pubkey_inflate_for_tests(self.raw(), pk.ptr, log2_k, seed, constant as i32) };
        if p.is_null() {
            return Err(last_error());
        }
        Ok(PublicKey { ptr: p, ctx: self.clone() })
    }

    pub fn add_noise_for_tests(&self, ct: &Ciphertext, log2_magnitude: u32, seed: u64) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_ciphertext_add_noise_for_tests(self.raw(), ct.ptr, log2_magnitude, seed) })
    }

    /// OpenFHE's own loader. Trusted input only: it trusts the lengths and
    /// moduli it reads, and mutated bytes crash the process (arithmetic
    /// fault, abort, segmentation fault). Bytes from another party go
    /// through [`Context::build_ciphertext`] instead.
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
    /// Removes the evaluation-multiplication and rotation keys installed
    /// under `joint_tag` from the process-global tables. Installed keys
    /// belong to the process, not to a `Context`: they stay alive after
    /// every context is dropped until this is called. Must not run
    /// concurrently with evaluation under the same tag.
    pub fn clear_keys_for_tag(joint_tag: &str) -> Result<()> {
        let t = c_tag(joint_tag)?;
        if unsafe { ffi::tbgv_clear_keys_for_tag(t.as_ptr()) } == 0 {
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

    /// The value fusion reads before reducing it mod `t`: the largest
    /// centered coefficient of the fused partials after mod-reducing to the
    /// first tower, and that tower's modulus `q0`. An honest fusion lies far
    /// below `q0 / 2`; a larger value means the result wrapped modulo `q0`
    /// (see `fhe_prio3::vdec`).
    pub fn fuse_magnitude(&self, partials: &[&PartialDecryption]) -> Result<(u64, u64)> {
        let ptrs: Vec<ffi::TbgvCiphertext> = partials.iter().map(|p| p.ct.ptr).collect();
        let (mut mx, mut q0) = (0u64, 0u64);
        if unsafe { ffi::tbgv_fuse_magnitude(self.raw(), ptrs.as_ptr(), ptrs.len(), &mut mx, &mut q0) } == 0 {
            return Err(last_error());
        }
        Ok((mx, q0))
    }

    /// `X^k * ct` for `k < 2N`: slot `s` is multiplied by `w_s^k`, where
    /// `w` is [`Context::monomial_slots`]. Exact, no noise growth, no level.
    pub fn mult_monomial(&self, ct: &Ciphertext, k: u32) -> Result<Ciphertext> {
        self.wrap_ct(unsafe { ffi::tbgv_ciphertext_mult_monomial(self.raw(), ct.ptr, k) })
    }

    /// `(b u + t e0, a u + t e1)` under `pk`, on `reference`'s towers and with
    /// its metadata: an encryption of zero whose randomness the caller
    /// chose and can reveal. Coefficient vectors have the ring dimension.
    pub fn zero_encryption(&self, pk: &PublicKey, reference: &Ciphertext, u: &[i8], e0: &[i8], e1: &[i8]) -> Result<Ciphertext> {
        let n = self.ring_dim() as usize;
        if u.len() != n || e0.len() != n || e1.len() != n {
            return Err(Error("coefficient vectors must have the ring dimension".into()));
        }
        self.wrap_ct(unsafe { ffi::tbgv_zero_encryption(self.raw(), pk.ptr, reference.ptr, u.as_ptr(), e0.as_ptr(), e1.as_ptr(), n) })
    }

    /// Slot values of the plaintext polynomial `X`, all `N` slots, in `[0, t)`.
    pub fn monomial_slots(&self) -> Result<Vec<u64>> {
        let mut out = vec![0u64; self.ring_dim() as usize];
        if unsafe { ffi::tbgv_monomial_slots(self.raw(), out.as_mut_ptr(), out.len()) } == 0 {
            return Err(last_error());
        }
        Ok(out)
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
        // SAFETY: heap objects owned exclusively by this handle; OpenFHE
        // objects are immutable once created except through `&mut` here.
        unsafe impl Send for $name {}
        unsafe impl Sync for $name {}
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
        Ok(PartialDecryption {
            ct: Ciphertext { ptr: p, ctx: self.ctx.clone() },
            lead,
        })
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

/// The two polynomial bases of key material: the public key lives on the
/// public-key basis, every key-switching key (eval-mult and rotation keys)
/// on the extended basis `QP`, with [`Context::key_num_parts`] polynomials
/// per vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBasis {
    PublicKey = 0,
    KeySwitch = 1,
}

/// Distributed key ceremony: key material generated against a common
/// random `a` and exchanged as raw residues (layout: polynomial, tower,
/// coefficient; EVALUATION format). Residues are validated against the tower
/// moduli before OpenFHE builds anything, so received bytes never reach
/// OpenFHE's deserializer.
impl Context {
    /// Moduli of the towers of `basis`.
    pub fn key_basis_moduli(&self, basis: KeyBasis) -> Result<Vec<u64>> {
        let n = unsafe { ffi::tbgv_key_basis_towers(self.raw(), basis as u32) } as usize;
        if n == 0 {
            return Err(last_error());
        }
        let mut out = vec![0u64; n];
        if unsafe { ffi::tbgv_key_basis_moduli(self.raw(), basis as u32, out.as_mut_ptr(), n) } == 0 {
            return Err(last_error());
        }
        Ok(out)
    }

    /// Polynomials per vector of a key-switching key (hybrid key switching's `dnum`).
    pub fn key_num_parts(&self) -> Result<usize> {
        match unsafe { ffi::tbgv_key_num_parts(self.raw()) } {
            0 => Err(last_error()),
            n => Ok(n as usize),
        }
    }

    /// Residues of one polynomial on `basis`.
    pub fn key_poly_len(&self, basis: KeyBasis) -> Result<usize> {
        Ok(self.key_basis_moduli(basis)?.len() * self.ring_dim() as usize)
    }
}

impl PublicKey {
    /// `(b = 0, a)`: what [`PublicKey::share`] generates against.
    pub fn template(ctx: &Context, a: &[u64]) -> Result<Self> {
        Self::wrap(ctx, unsafe { ffi::tbgv_pubkey_template(ctx.raw(), a.as_ptr(), a.len()) })
    }
    /// A fresh secret share `s` and the public share `(e - a s, a)` for the template's `a`.
    pub fn share(ctx: &Context, template: &PublicKey) -> Result<(PublicKey, SecretShare)> {
        let mut pk = std::ptr::null_mut();
        let mut sk = std::ptr::null_mut();
        if unsafe { ffi::tbgv_keygen_share(ctx.raw(), template.ptr, &mut pk, &mut sk) } == 0 {
            return Err(last_error());
        }
        Ok((PublicKey { ptr: pk, ctx: ctx.clone() }, SecretShare { ptr: sk, ctx: ctx.clone() }))
    }
    /// Residues of `b` (element 0) or `a` (element 1).
    pub fn export(&self, element: u32) -> Result<Vec<u64>> {
        let mut out = vec![0u64; self.ctx.key_poly_len(KeyBasis::PublicKey)?];
        if unsafe { ffi::tbgv_pubkey_export(self.ctx.raw(), self.ptr, element, out.as_mut_ptr(), out.len()) } == 0 {
            return Err(last_error());
        }
        Ok(out)
    }
    /// The template's `a` with the given `b`.
    pub fn with_b(ctx: &Context, template: &PublicKey, b: &[u64]) -> Result<Self> {
        Self::wrap(ctx, unsafe { ffi::tbgv_pubkey_with_b(ctx.raw(), template.ptr, b.as_ptr(), b.len()) })
    }
    /// `(b1 + b2, a)` under `joint_tag`; fails unless both have the same `a`.
    pub fn add(ctx: &Context, p1: &PublicKey, p2: &PublicKey, joint_tag: &str) -> Result<Self> {
        let t = c_tag(joint_tag)?;
        Self::wrap(ctx, unsafe { ffi::tbgv_pubkey_add(ctx.raw(), p1.ptr, p2.ptr, t.as_ptr()) })
    }
    fn wrap(ctx: &Context, p: ffi::TbgvPublicKey) -> Result<Self> {
        if p.is_null() {
            return Err(last_error());
        }
        Ok(Self { ptr: p, ctx: ctx.clone() })
    }
}

impl EvalMultKey {
    /// A key-switching key `(b = 0, a)` to generate round-1 eval-mult
    /// contributions ([`EvalMultKey::round1_next`]) or rotation contributions
    /// ([`RotationKeys::single`], [`RotationKeys::next`]) against.
    pub fn template(ctx: &Context, a: &[u64]) -> Result<Self> {
        Self::wrap(ctx, unsafe { ffi::tbgv_evalkey_template(ctx.raw(), a.as_ptr(), a.len()) })
    }
    /// Residues of the `a` vector (`which = 0`) or the `b` vector (`which = 1`).
    pub fn export(&self, which: u32) -> Result<Vec<u64>> {
        let mut out = vec![0u64; self.ctx.key_num_parts()? * self.ctx.key_poly_len(KeyBasis::KeySwitch)?];
        if unsafe { ffi::tbgv_evalkey_export(self.ctx.raw(), self.ptr, which, out.as_mut_ptr(), out.len()) } == 0 {
            return Err(last_error());
        }
        Ok(out)
    }
    /// A key from both vectors' residues.
    pub fn build(ctx: &Context, a: &[u64], b: &[u64]) -> Result<Self> {
        Self::wrap(ctx, unsafe { ffi::tbgv_evalkey_build(ctx.raw(), a.as_ptr(), a.len(), b.as_ptr(), b.len()) })
    }
    /// The template's `a` vector with the given `b` vector.
    pub fn with_b(ctx: &Context, template: &EvalMultKey, b: &[u64]) -> Result<Self> {
        Self::wrap(ctx, unsafe { ffi::tbgv_evalkey_with_b(ctx.raw(), template.ptr, b.as_ptr(), b.len()) })
    }
    pub fn same_a(&self, other: &EvalMultKey) -> Result<bool> {
        match unsafe { ffi::tbgv_evalkey_same_a(self.ptr, other.ptr) } {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(last_error()),
        }
    }
}

impl RotationKeys {
    /// The one-entry map holding `key` for rotation `index`.
    pub fn single(ctx: &Context, index: i32, key: &EvalMultKey) -> Result<Self> {
        Self::wrap(ctx, unsafe { ffi::tbgv_rotkeys_single(ctx.raw(), index, key.ptr) })
    }
    /// The key of a one-entry map for rotation `index`.
    pub fn get(&self, index: i32) -> Result<EvalMultKey> {
        EvalMultKey::wrap(&self.ctx, unsafe { ffi::tbgv_rotkeys_get(self.ctx.raw(), self.ptr, index) })
    }
}

/// The metadata that travels with a ciphertext's residues: together they
/// determine the ciphertext exactly (for objects in EVALUATION format built
/// from the receiver's own reference).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CiphertextMeta {
    pub num_elements: u32,
    pub num_towers: u32,
    pub level: u32,
    pub noise_scale_deg: u32,
    pub scaling_factor_int: u64,
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
    pub fn meta(&self) -> Result<CiphertextMeta> {
        let (mut ne, mut nt, mut lvl, mut deg, mut sf) = (0u32, 0u32, 0u32, 0u32, 0u64);
        if unsafe { ffi::tbgv_ciphertext_meta(self.ptr, &mut ne, &mut nt, &mut lvl, &mut deg, &mut sf) } == 0 {
            return Err(last_error());
        }
        Ok(CiphertextMeta {
            num_elements: ne,
            num_towers: nt,
            level: lvl,
            noise_scale_deg: deg,
            scaling_factor_int: sf,
        })
    }
    /// Residues element-major, then tower, then coefficient index.
    pub fn export_residues(&self) -> Result<Vec<u64>> {
        let m = self.meta()?;
        let mut out = vec![0u64; m.num_elements as usize * m.num_towers as usize * self.ctx.ring_dim() as usize];
        if unsafe { ffi::tbgv_ciphertext_export(self.ptr, out.as_mut_ptr(), out.len()) } == 0 {
            return Err(last_error());
        }
        Ok(out)
    }
    pub fn info(&self) -> Result<CiphertextInfo> {
        let (mut level, mut ne, mut nsd, mut limbs, mut packed) = (0u32, 0u32, 0u32, 0u32, 0u32);
        if unsafe { ffi::tbgv_ciphertext_info(self.ptr, &mut level, &mut ne, &mut nsd, &mut limbs, &mut packed) } == 0 {
            return Err(last_error());
        }
        let key_tag = take_string(unsafe { ffi::tbgv_ciphertext_key_tag(self.ptr) })?;
        Ok(CiphertextInfo {
            level,
            num_elements: ne,
            noise_scale_deg: nsd,
            num_limbs: limbs,
            packed_encoding: packed == 1,
            key_tag,
        })
    }
}

/// A partial decryption produced by one key share.
pub struct PartialDecryption {
    ct: Ciphertext,
    lead: bool,
}
unsafe impl Send for PartialDecryption {}
unsafe impl Sync for PartialDecryption {}

impl PartialDecryption {
    pub fn is_lead(&self) -> bool {
        self.lead
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        self.ct.serialize()
    }
    /// Reconstructs a partial decryption received from another party. The
    /// `lead` flag is part of the message, not the bytes. Trusted input only
    /// (OpenFHE's own format); untrusted input goes through
    /// [`Context::build_ciphertext`] and [`PartialDecryption::from_ciphertext`].
    pub fn deserialize(ctx: &Context, bytes: &[u8], lead: bool) -> Result<Self> {
        Ok(Self {
            ct: ctx.deserialize_ciphertext(bytes)?,
            lead,
        })
    }
    /// The partial decryption as a (one-element) ciphertext, for transport.
    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ct
    }
    /// Wraps a rebuilt one-element ciphertext as a partial decryption.
    pub fn from_ciphertext(ct: Ciphertext, lead: bool) -> Self {
        Self { ct, lead }
    }
}
