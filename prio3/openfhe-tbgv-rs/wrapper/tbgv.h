/**
 * tbgv.h — C-linkage shim over the OpenFHE BGV-RNS *threshold* (multiparty) API.
 *
 * Every function that can fail returns NULL (pointer results) or 0 (int
 * results) and stores a human-readable message retrievable with
 * tbgv_last_error(). The message is thread-local.
 *
 * Ownership: every handle returned by a tbgv_* function is owned by the
 * caller and must be released with the matching *_free().
 *
 * Contexts are cached process-wide by OpenFHE (keyed on parameters), so two
 * contexts created with identical parameters in one process share the same
 * underlying object. Evaluation keys are installed per key tag.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* TbgvContext;
typedef void* TbgvPublicKey;
typedef void* TbgvSecretKey;
typedef void* TbgvEvalKey;     /* relinearisation / eval-mult key */
typedef void* TbgvRotKeys;     /* map<automorphism index, EvalKey> */
typedef void* TbgvPlaintext;
typedef void* TbgvCiphertext;  /* also used for partial decryptions */

const char* tbgv_last_error(void);
void tbgv_buffer_free(uint8_t* buf);
void tbgv_string_free(char* s);

/* ---- context ---------------------------------------------------------- */
TbgvContext tbgv_context_new(uint64_t plain_mod, uint32_t mult_depth, uint32_t security_bits);
void tbgv_context_free(TbgvContext ctx);
uint64_t tbgv_context_plain_mod(TbgvContext ctx);
uint32_t tbgv_context_ring_dim(TbgvContext ctx);
uint32_t tbgv_context_mult_depth(TbgvContext ctx);
double tbgv_context_log2_q(TbgvContext ctx);
int tbgv_context_serialize(TbgvContext ctx, uint8_t** out, size_t* out_len);
TbgvContext tbgv_context_deserialize(const uint8_t* buf, size_t len);

/* ---- n-of-n key generation (sequential) ------------------------------- */
int tbgv_keygen_first(TbgvContext ctx, TbgvPublicKey* out_pk, TbgvSecretKey* out_sk);
int tbgv_keygen_next(TbgvContext ctx, TbgvPublicKey prev_joint_pk, TbgvPublicKey* out_joint_pk, TbgvSecretKey* out_sk);
char* tbgv_pubkey_tag(TbgvPublicKey pk);
void tbgv_pubkey_free(TbgvPublicKey pk);
void tbgv_seckey_free(TbgvSecretKey sk);
int tbgv_pubkey_serialize(TbgvPublicKey pk, uint8_t** out, size_t* out_len);
TbgvPublicKey tbgv_pubkey_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len);
int tbgv_seckey_serialize(TbgvSecretKey sk, uint8_t** out, size_t* out_len);
TbgvSecretKey tbgv_seckey_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len);

/* ---- joint eval-mult key ceremony ------------------------------------- */
/* round 1 */
TbgvEvalKey tbgv_multkey_round1_first(TbgvContext ctx, TbgvSecretKey sk);
TbgvEvalKey tbgv_multkey_round1_next(TbgvContext ctx, TbgvSecretKey sk, TbgvEvalKey first_round_key);
TbgvEvalKey tbgv_multkey_round1_add(TbgvContext ctx, TbgvEvalKey a, TbgvEvalKey b, const char* joint_tag);
/* round 2 */
TbgvEvalKey tbgv_multkey_round2(TbgvContext ctx, TbgvSecretKey sk, TbgvEvalKey round1_sum, const char* joint_tag);
TbgvEvalKey tbgv_multkey_round2_add(TbgvContext ctx, TbgvEvalKey a, TbgvEvalKey b, const char* joint_tag);
int tbgv_context_install_multkey(TbgvContext ctx, TbgvEvalKey key, const char* joint_tag);
void tbgv_evalkey_free(TbgvEvalKey key);
int tbgv_evalkey_serialize(TbgvEvalKey key, uint8_t** out, size_t* out_len);
TbgvEvalKey tbgv_evalkey_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len);

/* ---- joint rotation key ceremony (one sequential round) ---------------- */
TbgvRotKeys tbgv_rotkeys_first(TbgvContext ctx, TbgvSecretKey sk, const int32_t* indices, size_t n);
TbgvRotKeys tbgv_rotkeys_next(TbgvContext ctx, TbgvSecretKey sk, TbgvRotKeys prev, const int32_t* indices, size_t n, const char* joint_tag);
TbgvRotKeys tbgv_rotkeys_add(TbgvContext ctx, TbgvRotKeys a, TbgvRotKeys b, const char* joint_tag);
/* Installs `keys` under `joint_tag`, merging with keys already installed
 * for that tag (used to install per-index keys one at a time). */
int tbgv_context_merge_rotkeys(TbgvContext ctx, TbgvRotKeys keys, const char* joint_tag);
/* Removes every rotation key installed under `joint_tag`. */
int tbgv_context_clear_rotkeys(TbgvContext ctx, const char* joint_tag);
/* Removes the evaluation-multiplication and rotation keys installed under
 * `joint_tag` from the process-global tables (they belong to no context). */
int tbgv_clear_keys_for_tag(const char* joint_tag);
int tbgv_context_install_rotkeys(TbgvContext ctx, TbgvRotKeys keys, const char* joint_tag);
void tbgv_rotkeys_free(TbgvRotKeys keys);
int tbgv_rotkeys_serialize(TbgvRotKeys keys, uint8_t** out, size_t* out_len);
TbgvRotKeys tbgv_rotkeys_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len);

/* ---- plaintext / ciphertext ------------------------------------------- */
/* values must be centered: -(p-1)/2 <= v <= (p-1)/2 */
TbgvPlaintext tbgv_plaintext_new(TbgvContext ctx, const int64_t* values, size_t n);
void tbgv_plaintext_free(TbgvPlaintext pt);
TbgvCiphertext tbgv_encrypt(TbgvContext ctx, TbgvPublicKey pk, TbgvPlaintext pt);
TbgvCiphertext tbgv_ciphertext_clone(TbgvCiphertext ct);
void tbgv_ciphertext_free(TbgvCiphertext ct);
/* Structural facts about a ciphertext, for validating untrusted input. */
int tbgv_ciphertext_info(TbgvCiphertext ct, uint32_t* level, uint32_t* num_elements,
                         uint32_t* noise_scale_deg, uint32_t* num_limbs, uint32_t* encoding_packed);
char* tbgv_ciphertext_key_tag(TbgvCiphertext ct);
int tbgv_ciphertext_same_context(TbgvContext ctx, TbgvCiphertext ct);
int tbgv_ciphertext_serialize(TbgvCiphertext ct, uint8_t** out, size_t* out_len);
TbgvCiphertext tbgv_ciphertext_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len);

TbgvCiphertext tbgv_eval_add(TbgvContext ctx, TbgvCiphertext a, TbgvCiphertext b);
TbgvCiphertext tbgv_eval_sub(TbgvContext ctx, TbgvCiphertext a, TbgvCiphertext b);
TbgvCiphertext tbgv_eval_mult(TbgvContext ctx, TbgvCiphertext a, TbgvCiphertext b);
TbgvCiphertext tbgv_eval_add_plain(TbgvContext ctx, TbgvCiphertext a, TbgvPlaintext b);
TbgvCiphertext tbgv_eval_sub_plain(TbgvContext ctx, TbgvCiphertext a, TbgvPlaintext b);
TbgvCiphertext tbgv_eval_mult_plain(TbgvContext ctx, TbgvCiphertext a, TbgvPlaintext b);
TbgvCiphertext tbgv_eval_rotate(TbgvContext ctx, TbgvCiphertext a, int32_t index);
TbgvCiphertext tbgv_eval_negate(TbgvContext ctx, TbgvCiphertext a);
/* a*a with relinearisation; cheaper than tbgv_eval_mult(a, a). */
TbgvCiphertext tbgv_eval_square(TbgvContext ctx, TbgvCiphertext a);

/* TEST HOOK. Returns a copy of `ct` whose first component has p*N(X) added,
 * where N has uniformly random coefficients below 2^log2_magnitude. The
 * plaintext modulo p is unchanged but the noise is enlarged: this models a
 * client that submits something that is not a proper encryption. */
TbgvCiphertext tbgv_ciphertext_add_noise_for_tests(TbgvContext ctx, TbgvCiphertext ct, uint32_t log2_magnitude, uint64_t seed);

/* ---- threshold decryption --------------------------------------------- */
TbgvCiphertext tbgv_partial_decrypt(TbgvContext ctx, TbgvCiphertext ct, TbgvSecretKey sk, int is_lead);
/* Fuse partial decryptions (exactly one produced with is_lead=1). Writes up to
 * out_len centered values; returns number written, or 0 on error. */
size_t tbgv_fuse(TbgvContext ctx, const TbgvCiphertext* partials, size_t n, int64_t* out, size_t out_len);

/* Single-key decryption; used only by tests to demonstrate that one share
 * alone does not decrypt. */
size_t tbgv_decrypt_single(TbgvContext ctx, TbgvSecretKey sk, TbgvCiphertext ct, int64_t* out, size_t out_len);

#ifdef __cplusplus
}
#endif
