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
TbgvContext tbgv_context_new_tuned(uint64_t plain_mod, uint32_t mult_depth, uint32_t security_bits, uint32_t num_large_digits, uint32_t scaling_mod_size);
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
/* Fails unless both maps cover the same indices (OpenFHE would drop the others). */
TbgvRotKeys tbgv_rotkeys_add(TbgvContext ctx, TbgvRotKeys a, TbgvRotKeys b, const char* joint_tag);
/* Installs `keys` under `joint_tag`, merging with keys already installed
 * for that tag (used to install per-index keys one at a time). */
int tbgv_context_merge_rotkeys(TbgvContext ctx, TbgvRotKeys keys, const char* joint_tag);
/* ---- raw residue transport ---------------------------------------------
 * A ciphertext crosses the network as its RNS residues plus five metadata
 * values; the receiver rebuilds it inside its own context. Outside bytes are
 * never handed to OpenFHE's deserializer. */

/* Number of RNS towers of the context's full modulus chain. */
uint32_t tbgv_context_num_towers(TbgvContext ctx);
/* Writes the moduli of towers 0..L-1 of the full chain; out_len must be L. */
int tbgv_context_moduli(TbgvContext ctx, uint64_t* out, size_t out_len);
/* Metadata needed to rebuild `ct`. Fails if the elements disagree on their
 * tower count or are not in EVALUATION format. */
int tbgv_ciphertext_meta(TbgvCiphertext ct, uint32_t* num_elements, uint32_t* num_towers,
                         uint32_t* level, uint32_t* noise_scale_deg, uint64_t* scaling_factor_int);
/* Writes the residues element-major, then tower, then coefficient index.
 * out_len must equal num_elements * num_towers * ring_dim. */
int tbgv_ciphertext_export(TbgvCiphertext ct, uint64_t* out, size_t out_len);
/* Rebuilds a ciphertext from residues and metadata. `reference` is a fresh
 * encryption made by the caller under the joint key: it supplies the key
 * tag, the encoding and the tower parameters (the first `num_towers` towers
 * of its chain). Every argument is validated before any OpenFHE object is
 * touched: 1 <= num_elements <= 2, 1 <= num_towers <= L, level + num_towers
 * == L, 1 <= noise_scale_deg <= 2, 1 <= scaling_factor_int < t,
 * len == num_elements * num_towers * ring_dim, and every residue below the
 * modulus of its tower. Returns NULL (with an error message) otherwise. */
TbgvCiphertext tbgv_ciphertext_build(TbgvContext ctx, TbgvCiphertext reference, uint32_t num_elements,
                                     uint32_t num_towers, uint32_t level, uint32_t noise_scale_deg,
                                     uint64_t scaling_factor_int, const uint64_t* values, size_t len);

/* Removes every rotation key installed under `joint_tag`. */
int tbgv_context_clear_rotkeys(TbgvContext ctx, const char* joint_tag);
/* Removes the evaluation-multiplication and rotation keys installed under
 * `joint_tag` from the process-global tables (they belong to no context). */
int tbgv_clear_keys_for_tag(const char* joint_tag);
int tbgv_context_install_rotkeys(TbgvContext ctx, TbgvRotKeys keys, const char* joint_tag);
void tbgv_rotkeys_free(TbgvRotKeys keys);
int tbgv_rotkeys_serialize(TbgvRotKeys keys, uint8_t** out, size_t* out_len);
TbgvRotKeys tbgv_rotkeys_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len);

/* ---- distributed key ceremony -------------------------------------------
 * Parties contribute key material against a common random `a` (a CRS drawn
 * from a jointly generated seed) instead of the first party's. Key
 * polynomials cross the network as raw residues in EVALUATION format and
 * are rebuilt here; residues are validated against the tower moduli before
 * any OpenFHE object is built. Basis 0 is the public-key basis, basis 1 the
 * key-switching basis QP; a key-switching key has `tbgv_key_num_parts`
 * polynomials per vector. Residue layout: polynomial, tower, coefficient. */
uint32_t tbgv_key_basis_towers(TbgvContext ctx, uint32_t basis);
int tbgv_key_basis_moduli(TbgvContext ctx, uint32_t basis, uint64_t* out, size_t out_len);
uint32_t tbgv_key_num_parts(TbgvContext ctx);
/* A public key (b = 0, a) to generate shares against. */
TbgvPublicKey tbgv_pubkey_template(TbgvContext ctx, const uint64_t* a, size_t len);
/* Fresh secret share s and public share (e - a*s, a) for the template's a. */
int tbgv_keygen_share(TbgvContext ctx, TbgvPublicKey tmpl, TbgvPublicKey* out_pk, TbgvSecretKey* out_sk);
/* Element 0 (b) or 1 (a) of a public key on the public-key basis. */
int tbgv_pubkey_export(TbgvContext ctx, TbgvPublicKey pk, uint32_t element, uint64_t* out, size_t out_len);
/* The template's a with the given b. */
TbgvPublicKey tbgv_pubkey_with_b(TbgvContext ctx, TbgvPublicKey tmpl, const uint64_t* b, size_t len);
/* b1 + b2 under the tag; fails unless both keys have the same a. */
TbgvPublicKey tbgv_pubkey_add(TbgvContext ctx, TbgvPublicKey p1, TbgvPublicKey p2, const char* tag);
/* A key-switching key (b = 0, a) that tbgv_multkey_round1_next and
 * tbgv_rotkeys_next (via tbgv_rotkeys_single) generate against. */
TbgvEvalKey tbgv_evalkey_template(TbgvContext ctx, const uint64_t* a, size_t len);
/* which: 0 = a-vector, 1 = b-vector. */
int tbgv_evalkey_export(TbgvContext ctx, TbgvEvalKey key, uint32_t which, uint64_t* out, size_t out_len);
TbgvEvalKey tbgv_evalkey_build(TbgvContext ctx, const uint64_t* a, size_t a_len, const uint64_t* b, size_t b_len);
TbgvEvalKey tbgv_evalkey_with_b(TbgvContext ctx, TbgvEvalKey tmpl, const uint64_t* b, size_t b_len);
/* 1 if both a-vectors are equal, 0 if not, -1 on error. */
int tbgv_evalkey_same_a(TbgvEvalKey k1, TbgvEvalKey k2);
/* A one-entry rotation key map for rotation `index`, and its inverse. */
TbgvRotKeys tbgv_rotkeys_single(TbgvContext ctx, int32_t index, TbgvEvalKey key);
TbgvEvalKey tbgv_rotkeys_get(TbgvContext ctx, TbgvRotKeys keys, int32_t index);

/* ---- verifiable decryption ---------------------------------------------
 * Blinded known-answer checks of partial decryptions (fhe-prio3 vdec.rs). */
/* X^k * ct for k in [0, 2N): each slot multiplied by the k-th power of its
 * root of unity; no noise growth, metadata unchanged. */
TbgvCiphertext tbgv_ciphertext_mult_monomial(TbgvContext ctx, TbgvCiphertext ct, uint32_t k);
/* (b u + t e0, a u + t e1) over the towers of `reference`, with its metadata:
 * an encryption of zero under `pk` with the given small coefficients
 * (length n = ring dimension). */
TbgvCiphertext tbgv_zero_encryption(TbgvContext ctx, TbgvPublicKey pk, TbgvCiphertext reference, const int8_t* u,
                                    const int8_t* e0, const int8_t* e1, size_t n);
/* Slot values (in [0, t)) of the plaintext polynomial X; out_len = N. */
int tbgv_monomial_slots(TbgvContext ctx, uint64_t* out, size_t out_len);
/* The fused value that decryption reads, before it is reduced mod t:
 * largest |coefficient| (centered) after mod-reducing to the first tower,
 * and that tower's modulus. */
int tbgv_fuse_magnitude(TbgvContext ctx, const TbgvCiphertext* partials, size_t n, uint64_t* max_abs, uint64_t* q0);

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
/* Full-precision decryption values (see tbgv.cpp). `out_over_t` may be NULL. */
double tbgv_flooding_sigma(TbgvContext ctx);
int tbgv_fuse_raw(TbgvContext ctx, const TbgvCiphertext* partials, size_t n, double* out_over_t, size_t out_len, double* log2_max,
                  double* log2_q);
int tbgv_raw_decrypt_for_tests(TbgvContext ctx, TbgvCiphertext ct, const TbgvSecretKey* sks, size_t n, double* out_over_t,
                               size_t out_len, double* log2_max, double* log2_q);
TbgvPublicKey tbgv_pubkey_inflate_for_tests(TbgvContext ctx, TbgvPublicKey pk, uint32_t log2_k, uint64_t seed, int constant);
/* Every fused coefficient within t (n Q'/2 + Q' 2^-slack + 1), Q' = Q_l / q0:
 * what n partials flooded as OpenFHE floods them can reach. */
int tbgv_fuse_flooding_check(TbgvContext ctx, const TbgvCiphertext* partials, size_t n, uint32_t slack_bits, int* within,
                             double* ratio);
TbgvCiphertext tbgv_partial_decrypt_shaped_for_tests(TbgvContext ctx, TbgvCiphertext ct, TbgvSecretKey sk, int is_lead,
                                                     uint64_t num, uint64_t den, uint64_t seed);
TbgvPublicKey tbgv_pubkey_inflate_ratio_for_tests(TbgvContext ctx, TbgvPublicKey pk, uint64_t num, uint64_t den);

TbgvCiphertext tbgv_partial_decrypt(TbgvContext ctx, TbgvCiphertext ct, TbgvSecretKey sk, int is_lead);
/* Fuse partial decryptions (exactly one produced with is_lead=1). Writes up to
 * out_len centered values; returns number written, or 0 on error. */
size_t tbgv_fuse(TbgvContext ctx, const TbgvCiphertext* partials, size_t n, int64_t* out, size_t out_len);

/* Single-key decryption; used only by tests to demonstrate that one share
 * alone does not decrypt. */
size_t tbgv_decrypt_single(TbgvContext ctx, TbgvSecretKey sk, TbgvCiphertext ct, int64_t* out, size_t out_len);

/* Resolved paths of the OpenFHE shared libraries loaded in this process,
 * one per line (empty string if none are loaded). */
char* tbgv_loaded_openfhe_libraries(void);

#ifdef __cplusplus
}
#endif
