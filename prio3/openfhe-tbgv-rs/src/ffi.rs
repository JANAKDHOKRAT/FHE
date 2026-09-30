//! Raw C bindings to `wrapper/tbgv.h`. Do not use directly; see the safe API in `lib.rs`.
#![allow(non_camel_case_types, dead_code)]

use std::os::raw::{c_char, c_double, c_int};

pub type TbgvContext = *mut std::ffi::c_void;
pub type TbgvPublicKey = *mut std::ffi::c_void;
pub type TbgvSecretKey = *mut std::ffi::c_void;
pub type TbgvEvalKey = *mut std::ffi::c_void;
pub type TbgvRotKeys = *mut std::ffi::c_void;
pub type TbgvPlaintext = *mut std::ffi::c_void;
pub type TbgvCiphertext = *mut std::ffi::c_void;

unsafe extern "C" {
    pub fn tbgv_last_error() -> *const c_char;
    pub fn tbgv_buffer_free(buf: *mut u8);
    pub fn tbgv_string_free(s: *mut c_char);

    pub fn tbgv_context_new(plain_mod: u64, mult_depth: u32, security_bits: u32) -> TbgvContext;
    pub fn tbgv_context_free(ctx: TbgvContext);
    pub fn tbgv_context_plain_mod(ctx: TbgvContext) -> u64;
    pub fn tbgv_context_ring_dim(ctx: TbgvContext) -> u32;
    pub fn tbgv_context_mult_depth(ctx: TbgvContext) -> u32;
    pub fn tbgv_context_log2_q(ctx: TbgvContext) -> c_double;
    pub fn tbgv_context_serialize(ctx: TbgvContext, out: *mut *mut u8, out_len: *mut usize) -> c_int;
    pub fn tbgv_context_deserialize(buf: *const u8, len: usize) -> TbgvContext;

    pub fn tbgv_keygen_first(ctx: TbgvContext, out_pk: *mut TbgvPublicKey, out_sk: *mut TbgvSecretKey) -> c_int;
    pub fn tbgv_keygen_next(ctx: TbgvContext, prev: TbgvPublicKey, out_pk: *mut TbgvPublicKey, out_sk: *mut TbgvSecretKey) -> c_int;
    pub fn tbgv_pubkey_tag(pk: TbgvPublicKey) -> *mut c_char;
    pub fn tbgv_pubkey_free(pk: TbgvPublicKey);
    pub fn tbgv_seckey_free(sk: TbgvSecretKey);
    pub fn tbgv_pubkey_serialize(pk: TbgvPublicKey, out: *mut *mut u8, out_len: *mut usize) -> c_int;
    pub fn tbgv_pubkey_deserialize(ctx: TbgvContext, buf: *const u8, len: usize) -> TbgvPublicKey;
    pub fn tbgv_seckey_serialize(sk: TbgvSecretKey, out: *mut *mut u8, out_len: *mut usize) -> c_int;
    pub fn tbgv_seckey_deserialize(ctx: TbgvContext, buf: *const u8, len: usize) -> TbgvSecretKey;

    pub fn tbgv_multkey_round1_first(ctx: TbgvContext, sk: TbgvSecretKey) -> TbgvEvalKey;
    pub fn tbgv_multkey_round1_next(ctx: TbgvContext, sk: TbgvSecretKey, first: TbgvEvalKey) -> TbgvEvalKey;
    pub fn tbgv_multkey_round1_add(ctx: TbgvContext, a: TbgvEvalKey, b: TbgvEvalKey, tag: *const c_char) -> TbgvEvalKey;
    pub fn tbgv_multkey_round2(ctx: TbgvContext, sk: TbgvSecretKey, sum: TbgvEvalKey, tag: *const c_char) -> TbgvEvalKey;
    pub fn tbgv_multkey_round2_add(ctx: TbgvContext, a: TbgvEvalKey, b: TbgvEvalKey, tag: *const c_char) -> TbgvEvalKey;
    pub fn tbgv_context_install_multkey(ctx: TbgvContext, key: TbgvEvalKey, tag: *const c_char) -> c_int;
    pub fn tbgv_evalkey_free(key: TbgvEvalKey);
    pub fn tbgv_evalkey_serialize(key: TbgvEvalKey, out: *mut *mut u8, out_len: *mut usize) -> c_int;
    pub fn tbgv_evalkey_deserialize(ctx: TbgvContext, buf: *const u8, len: usize) -> TbgvEvalKey;

    pub fn tbgv_rotkeys_first(ctx: TbgvContext, sk: TbgvSecretKey, idx: *const i32, n: usize) -> TbgvRotKeys;
    pub fn tbgv_rotkeys_next(ctx: TbgvContext, sk: TbgvSecretKey, prev: TbgvRotKeys, idx: *const i32, n: usize, tag: *const c_char) -> TbgvRotKeys;
    pub fn tbgv_rotkeys_add(ctx: TbgvContext, a: TbgvRotKeys, b: TbgvRotKeys, tag: *const c_char) -> TbgvRotKeys;
    pub fn tbgv_context_install_rotkeys(ctx: TbgvContext, keys: TbgvRotKeys, tag: *const c_char) -> c_int;
    pub fn tbgv_context_merge_rotkeys(ctx: TbgvContext, keys: TbgvRotKeys, tag: *const c_char) -> c_int;
    pub fn tbgv_context_clear_rotkeys(ctx: TbgvContext, tag: *const c_char) -> c_int;
    pub fn tbgv_context_num_towers(ctx: TbgvContext) -> u32;
    pub fn tbgv_context_moduli(ctx: TbgvContext, out: *mut u64, out_len: usize) -> c_int;
    pub fn tbgv_ciphertext_meta(
        ct: TbgvCiphertext,
        num_elements: *mut u32,
        num_towers: *mut u32,
        level: *mut u32,
        noise_scale_deg: *mut u32,
        scaling_factor_int: *mut u64,
    ) -> c_int;
    pub fn tbgv_ciphertext_export(ct: TbgvCiphertext, out: *mut u64, out_len: usize) -> c_int;
    pub fn tbgv_ciphertext_build(
        ctx: TbgvContext,
        reference: TbgvCiphertext,
        num_elements: u32,
        num_towers: u32,
        level: u32,
        noise_scale_deg: u32,
        scaling_factor_int: u64,
        values: *const u64,
        len: usize,
    ) -> TbgvCiphertext;
    pub fn tbgv_clear_keys_for_tag(tag: *const c_char) -> c_int;
    pub fn tbgv_rotkeys_free(keys: TbgvRotKeys);
    pub fn tbgv_rotkeys_serialize(keys: TbgvRotKeys, out: *mut *mut u8, out_len: *mut usize) -> c_int;
    pub fn tbgv_rotkeys_deserialize(ctx: TbgvContext, buf: *const u8, len: usize) -> TbgvRotKeys;

    pub fn tbgv_key_basis_towers(ctx: TbgvContext, basis: u32) -> u32;
    pub fn tbgv_key_basis_moduli(ctx: TbgvContext, basis: u32, out: *mut u64, out_len: usize) -> c_int;
    pub fn tbgv_key_num_parts(ctx: TbgvContext) -> u32;
    pub fn tbgv_pubkey_template(ctx: TbgvContext, a: *const u64, len: usize) -> TbgvPublicKey;
    pub fn tbgv_keygen_share(ctx: TbgvContext, tmpl: TbgvPublicKey, out_pk: *mut TbgvPublicKey, out_sk: *mut TbgvSecretKey) -> c_int;
    pub fn tbgv_pubkey_export(ctx: TbgvContext, pk: TbgvPublicKey, element: u32, out: *mut u64, out_len: usize) -> c_int;
    pub fn tbgv_pubkey_with_b(ctx: TbgvContext, tmpl: TbgvPublicKey, b: *const u64, len: usize) -> TbgvPublicKey;
    pub fn tbgv_pubkey_add(ctx: TbgvContext, p1: TbgvPublicKey, p2: TbgvPublicKey, tag: *const c_char) -> TbgvPublicKey;
    pub fn tbgv_evalkey_template(ctx: TbgvContext, a: *const u64, len: usize) -> TbgvEvalKey;
    pub fn tbgv_evalkey_export(ctx: TbgvContext, key: TbgvEvalKey, which: u32, out: *mut u64, out_len: usize) -> c_int;
    pub fn tbgv_evalkey_build(ctx: TbgvContext, a: *const u64, a_len: usize, b: *const u64, b_len: usize) -> TbgvEvalKey;
    pub fn tbgv_evalkey_with_b(ctx: TbgvContext, tmpl: TbgvEvalKey, b: *const u64, b_len: usize) -> TbgvEvalKey;
    pub fn tbgv_evalkey_same_a(k1: TbgvEvalKey, k2: TbgvEvalKey) -> c_int;
    pub fn tbgv_rotkeys_single(ctx: TbgvContext, index: i32, key: TbgvEvalKey) -> TbgvRotKeys;
    pub fn tbgv_rotkeys_get(ctx: TbgvContext, keys: TbgvRotKeys, index: i32) -> TbgvEvalKey;

    pub fn tbgv_ciphertext_mult_monomial(ctx: TbgvContext, ct: TbgvCiphertext, k: u32) -> TbgvCiphertext;
    pub fn tbgv_zero_encryption(
        ctx: TbgvContext,
        pk: TbgvPublicKey,
        reference: TbgvCiphertext,
        u: *const i8,
        e0: *const i8,
        e1: *const i8,
        n: usize,
    ) -> TbgvCiphertext;
    pub fn tbgv_monomial_slots(ctx: TbgvContext, out: *mut u64, out_len: usize) -> c_int;
    pub fn tbgv_fuse_magnitude(ctx: TbgvContext, partials: *const TbgvCiphertext, n: usize, max_abs: *mut u64, q0: *mut u64) -> c_int;

    pub fn tbgv_plaintext_new(ctx: TbgvContext, values: *const i64, n: usize) -> TbgvPlaintext;
    pub fn tbgv_plaintext_free(pt: TbgvPlaintext);
    pub fn tbgv_encrypt(ctx: TbgvContext, pk: TbgvPublicKey, pt: TbgvPlaintext) -> TbgvCiphertext;
    pub fn tbgv_ciphertext_clone(ct: TbgvCiphertext) -> TbgvCiphertext;
    pub fn tbgv_ciphertext_free(ct: TbgvCiphertext);
    pub fn tbgv_ciphertext_info(
        ct: TbgvCiphertext,
        level: *mut u32,
        num_elements: *mut u32,
        noise_scale_deg: *mut u32,
        num_limbs: *mut u32,
        packed: *mut u32,
    ) -> c_int;
    pub fn tbgv_ciphertext_key_tag(ct: TbgvCiphertext) -> *mut c_char;
    pub fn tbgv_ciphertext_same_context(ctx: TbgvContext, ct: TbgvCiphertext) -> c_int;
    pub fn tbgv_ciphertext_serialize(ct: TbgvCiphertext, out: *mut *mut u8, out_len: *mut usize) -> c_int;
    pub fn tbgv_ciphertext_deserialize(ctx: TbgvContext, buf: *const u8, len: usize) -> TbgvCiphertext;

    pub fn tbgv_eval_add(ctx: TbgvContext, a: TbgvCiphertext, b: TbgvCiphertext) -> TbgvCiphertext;
    pub fn tbgv_eval_sub(ctx: TbgvContext, a: TbgvCiphertext, b: TbgvCiphertext) -> TbgvCiphertext;
    pub fn tbgv_eval_mult(ctx: TbgvContext, a: TbgvCiphertext, b: TbgvCiphertext) -> TbgvCiphertext;
    pub fn tbgv_eval_add_plain(ctx: TbgvContext, a: TbgvCiphertext, b: TbgvPlaintext) -> TbgvCiphertext;
    pub fn tbgv_eval_sub_plain(ctx: TbgvContext, a: TbgvCiphertext, b: TbgvPlaintext) -> TbgvCiphertext;
    pub fn tbgv_eval_mult_plain(ctx: TbgvContext, a: TbgvCiphertext, b: TbgvPlaintext) -> TbgvCiphertext;
    pub fn tbgv_eval_rotate(ctx: TbgvContext, a: TbgvCiphertext, index: i32) -> TbgvCiphertext;
    pub fn tbgv_eval_negate(ctx: TbgvContext, a: TbgvCiphertext) -> TbgvCiphertext;
    pub fn tbgv_eval_square(ctx: TbgvContext, a: TbgvCiphertext) -> TbgvCiphertext;
    pub fn tbgv_ciphertext_add_noise_for_tests(ctx: TbgvContext, ct: TbgvCiphertext, log2_magnitude: u32, seed: u64) -> TbgvCiphertext;

    pub fn tbgv_flooding_sigma(ctx: TbgvContext) -> f64;
    pub fn tbgv_fuse_raw(
        ctx: TbgvContext,
        partials: *const TbgvCiphertext,
        n: usize,
        out_over_t: *mut f64,
        out_len: usize,
        log2_max: *mut f64,
        log2_q: *mut f64,
    ) -> c_int;
    pub fn tbgv_raw_decrypt_for_tests(
        ctx: TbgvContext,
        ct: TbgvCiphertext,
        sks: *const TbgvSecretKey,
        n: usize,
        out_over_t: *mut f64,
        out_len: usize,
        log2_max: *mut f64,
        log2_q: *mut f64,
    ) -> c_int;
    pub fn tbgv_pubkey_inflate_for_tests(ctx: TbgvContext, pk: TbgvPublicKey, log2_k: u32, seed: u64, constant: c_int) -> TbgvPublicKey;

    pub fn tbgv_fuse_flooding_check(ctx: TbgvContext, partials: *const TbgvCiphertext, n: usize, slack_bits: u32, within: *mut c_int, ratio: *mut f64)
    -> c_int;
    pub fn tbgv_partial_decrypt_shaped_for_tests(
        ctx: TbgvContext,
        ct: TbgvCiphertext,
        sk: TbgvSecretKey,
        is_lead: c_int,
        num: u64,
        den: u64,
        seed: u64,
    ) -> TbgvCiphertext;
    pub fn tbgv_pubkey_inflate_ratio_for_tests(ctx: TbgvContext, pk: TbgvPublicKey, num: u64, den: u64) -> TbgvPublicKey;

    pub fn tbgv_partial_decrypt(ctx: TbgvContext, ct: TbgvCiphertext, sk: TbgvSecretKey, is_lead: c_int) -> TbgvCiphertext;
    pub fn tbgv_fuse(ctx: TbgvContext, partials: *const TbgvCiphertext, n: usize, out: *mut i64, out_len: usize) -> usize;
    pub fn tbgv_decrypt_single(ctx: TbgvContext, sk: TbgvSecretKey, ct: TbgvCiphertext, out: *mut i64, out_len: usize) -> usize;
    pub fn tbgv_loaded_openfhe_libraries() -> *mut c_char;
}
