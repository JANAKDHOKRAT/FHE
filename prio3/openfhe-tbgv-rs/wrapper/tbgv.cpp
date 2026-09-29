// tbgv.cpp — implementation of tbgv.h over OpenFHE (BGV-RNS, MULTIPARTY).
#include "tbgv.h"

#include <cstring>
#include <climits>
#include <cstdlib>
#include <link.h>
#include <random>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/ciphertext-ser.h"
#include "openfhe/pke/scheme/bgvrns/bgvrns-ser.h"

using namespace lbcrypto;

namespace {

thread_local std::string g_last_error;

void set_error(const std::string& s) { g_last_error = s; }

using CC = CryptoContext<DCRTPoly>;
using PK = PublicKey<DCRTPoly>;
using SK = PrivateKey<DCRTPoly>;
using EK = EvalKey<DCRTPoly>;
using CT = Ciphertext<DCRTPoly>;
using RotMap = std::shared_ptr<std::map<uint32_t, EK>>;

CC& cc_of(TbgvContext h) { return *static_cast<CC*>(h); }
PK& pk_of(TbgvPublicKey h) { return *static_cast<PK*>(h); }
SK& sk_of(TbgvSecretKey h) { return *static_cast<SK*>(h); }
EK& ek_of(TbgvEvalKey h) { return *static_cast<EK*>(h); }
RotMap& rk_of(TbgvRotKeys h) { return *static_cast<RotMap*>(h); }
Plaintext& pt_of(TbgvPlaintext h) { return *static_cast<Plaintext*>(h); }
CT& ct_of(TbgvCiphertext h) { return *static_cast<CT*>(h); }

template <typename T>
int serialize_to(const T& obj, uint8_t** out, size_t* out_len) {
    std::stringstream ss;
    Serial::Serialize(obj, ss, SerType::BINARY);
    const std::string s = ss.str();
    uint8_t* buf = static_cast<uint8_t*>(std::malloc(s.size() ? s.size() : 1));
    if (!buf) { set_error("malloc failed"); return 0; }
    std::memcpy(buf, s.data(), s.size());
    *out = buf;
    *out_len = s.size();
    return 1;
}

template <typename T>
void deserialize_from(T& obj, const uint8_t* buf, size_t len) {
    std::string s(reinterpret_cast<const char*>(buf), len);
    std::stringstream ss(s);
    Serial::Deserialize(obj, ss, SerType::BINARY);
}

char* dup_string(const std::string& s) {
    char* out = static_cast<char*>(std::malloc(s.size() + 1));
    if (!out) return nullptr;
    std::memcpy(out, s.c_str(), s.size() + 1);
    return out;
}

#define TBGV_TRY try {
#define TBGV_CATCH(ret)                                   \
    } catch (const std::exception& e) {                   \
        set_error(e.what());                              \
        return ret;                                       \
    } catch (...) {                                       \
        set_error("unknown C++ exception");               \
        return ret;                                       \
    }

}  // namespace

extern "C" {

const char* tbgv_last_error(void) { return g_last_error.c_str(); }
void tbgv_buffer_free(uint8_t* buf) { std::free(buf); }
void tbgv_string_free(char* s) { std::free(s); }

/* ---- context ---------------------------------------------------------- */

TbgvContext tbgv_context_new(uint64_t plain_mod, uint32_t mult_depth, uint32_t security_bits) {
    TBGV_TRY
    CCParams<CryptoContextBGVRNS> params;
    params.SetPlaintextModulus(plain_mod);
    params.SetMultiplicativeDepth(mult_depth);
    params.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);
    params.SetScalingTechnique(FLEXIBLEAUTOEXT);
    params.SetSecretKeyDist(UNIFORM_TERNARY);
    switch (security_bits) {
        case 128: params.SetSecurityLevel(HEStd_128_classic); break;
        case 192: params.SetSecurityLevel(HEStd_192_classic); break;
        case 256: params.SetSecurityLevel(HEStd_256_classic); break;
        default: set_error("security_bits must be 128, 192 or 256"); return nullptr;
    }
    CC cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);
    return new CC(cc);
    TBGV_CATCH(nullptr)
}

void tbgv_context_free(TbgvContext ctx) { delete static_cast<CC*>(ctx); }

uint64_t tbgv_context_plain_mod(TbgvContext ctx) {
    return cc_of(ctx)->GetCryptoParameters()->GetPlaintextModulus();
}
uint32_t tbgv_context_ring_dim(TbgvContext ctx) { return cc_of(ctx)->GetRingDimension(); }
uint32_t tbgv_context_mult_depth(TbgvContext ctx) {
    // Towers minus two: an upper bound on the configured depth (OpenFHE 1.3.1
    // gives a depth-d NOISE_FLOODING_MULTIPARTY / FLEXIBLEAUTOEXT context d + 4
    // towers). See Context::mult_depth.
    return static_cast<uint32_t>(cc_of(ctx)->GetCryptoParameters()->GetElementParams()->GetParams().size()) - 2;
}
double tbgv_context_log2_q(TbgvContext ctx) {
    return std::log2(cc_of(ctx)->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble());
}
int tbgv_context_serialize(TbgvContext ctx, uint8_t** out, size_t* out_len) {
    TBGV_TRY return serialize_to(cc_of(ctx), out, out_len); TBGV_CATCH(0)
}
TbgvContext tbgv_context_deserialize(const uint8_t* buf, size_t len) {
    TBGV_TRY
    CC cc;
    deserialize_from(cc, buf, len);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);
    return new CC(cc);
    TBGV_CATCH(nullptr)
}

/* ---- key generation ---------------------------------------------------- */

int tbgv_keygen_first(TbgvContext ctx, TbgvPublicKey* out_pk, TbgvSecretKey* out_sk) {
    TBGV_TRY
    auto kp = cc_of(ctx)->KeyGen();
    if (!kp.good()) { set_error("KeyGen failed"); return 0; }
    *out_pk = new PK(kp.publicKey);
    *out_sk = new SK(kp.secretKey);
    return 1;
    TBGV_CATCH(0)
}

int tbgv_keygen_next(TbgvContext ctx, TbgvPublicKey prev_joint_pk, TbgvPublicKey* out_joint_pk, TbgvSecretKey* out_sk) {
    TBGV_TRY
    auto kp = cc_of(ctx)->MultipartyKeyGen(pk_of(prev_joint_pk));
    if (!kp.good()) { set_error("MultipartyKeyGen failed"); return 0; }
    *out_joint_pk = new PK(kp.publicKey);
    *out_sk = new SK(kp.secretKey);
    return 1;
    TBGV_CATCH(0)
}

char* tbgv_pubkey_tag(TbgvPublicKey pk) { return dup_string(pk_of(pk)->GetKeyTag()); }
void tbgv_pubkey_free(TbgvPublicKey pk) { delete static_cast<PK*>(pk); }
void tbgv_seckey_free(TbgvSecretKey sk) { delete static_cast<SK*>(sk); }

int tbgv_pubkey_serialize(TbgvPublicKey pk, uint8_t** out, size_t* out_len) {
    TBGV_TRY return serialize_to(pk_of(pk), out, out_len); TBGV_CATCH(0)
}
TbgvPublicKey tbgv_pubkey_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len) {
    TBGV_TRY
    PK pk;
    deserialize_from(pk, buf, len);
    if (!pk) { set_error("public key deserialization produced null"); return nullptr; }
    if (pk->GetCryptoContext().get() != cc_of(ctx).get()) { set_error("public key belongs to a different context"); return nullptr; }
    return new PK(pk);
    TBGV_CATCH(nullptr)
}
int tbgv_seckey_serialize(TbgvSecretKey sk, uint8_t** out, size_t* out_len) {
    TBGV_TRY return serialize_to(sk_of(sk), out, out_len); TBGV_CATCH(0)
}
TbgvSecretKey tbgv_seckey_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len) {
    TBGV_TRY
    SK sk;
    deserialize_from(sk, buf, len);
    if (!sk) { set_error("secret key deserialization produced null"); return nullptr; }
    if (sk->GetCryptoContext().get() != cc_of(ctx).get()) { set_error("secret key belongs to a different context"); return nullptr; }
    return new SK(sk);
    TBGV_CATCH(nullptr)
}

/* ---- eval-mult key ceremony -------------------------------------------- */

TbgvEvalKey tbgv_multkey_round1_first(TbgvContext ctx, TbgvSecretKey sk) {
    TBGV_TRY return new EK(cc_of(ctx)->KeySwitchGen(sk_of(sk), sk_of(sk))); TBGV_CATCH(nullptr)
}
TbgvEvalKey tbgv_multkey_round1_next(TbgvContext ctx, TbgvSecretKey sk, TbgvEvalKey first) {
    TBGV_TRY return new EK(cc_of(ctx)->MultiKeySwitchGen(sk_of(sk), sk_of(sk), ek_of(first))); TBGV_CATCH(nullptr)
}
TbgvEvalKey tbgv_multkey_round1_add(TbgvContext ctx, TbgvEvalKey a, TbgvEvalKey b, const char* tag) {
    TBGV_TRY return new EK(cc_of(ctx)->MultiAddEvalKeys(ek_of(a), ek_of(b), tag)); TBGV_CATCH(nullptr)
}
TbgvEvalKey tbgv_multkey_round2(TbgvContext ctx, TbgvSecretKey sk, TbgvEvalKey sum, const char* tag) {
    TBGV_TRY return new EK(cc_of(ctx)->MultiMultEvalKey(sk_of(sk), ek_of(sum), tag)); TBGV_CATCH(nullptr)
}
TbgvEvalKey tbgv_multkey_round2_add(TbgvContext ctx, TbgvEvalKey a, TbgvEvalKey b, const char* tag) {
    TBGV_TRY return new EK(cc_of(ctx)->MultiAddEvalMultKeys(ek_of(a), ek_of(b), tag)); TBGV_CATCH(nullptr)
}
int tbgv_context_install_multkey(TbgvContext ctx, TbgvEvalKey key, const char* tag) {
    TBGV_TRY
    // Idempotent: OpenFHE refuses to overwrite an existing vector for a tag,
    // so an earlier installation in this process is replaced.
    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(std::string(tag));
    cc_of(ctx)->InsertEvalMultKey({ek_of(key)}, tag);
    return 1;
    TBGV_CATCH(0)
}
void tbgv_evalkey_free(TbgvEvalKey key) { delete static_cast<EK*>(key); }
int tbgv_evalkey_serialize(TbgvEvalKey key, uint8_t** out, size_t* out_len) {
    TBGV_TRY return serialize_to(ek_of(key), out, out_len); TBGV_CATCH(0)
}
TbgvEvalKey tbgv_evalkey_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len) {
    TBGV_TRY
    EK k;
    deserialize_from(k, buf, len);
    if (!k) { set_error("eval key deserialization produced null"); return nullptr; }
    if (k->GetCryptoContext().get() != cc_of(ctx).get()) { set_error("eval key belongs to a different context"); return nullptr; }
    return new EK(k);
    TBGV_CATCH(nullptr)
}

/* ---- rotation key ceremony --------------------------------------------- */

TbgvRotKeys tbgv_rotkeys_first(TbgvContext ctx, TbgvSecretKey sk, const int32_t* indices, size_t n) {
    TBGV_TRY
    std::vector<int32_t> idx(indices, indices + n);
    CC& cc = cc_of(ctx);
    const std::string tag = sk_of(sk)->GetKeyTag();
    cc->EvalAtIndexKeyGen(sk_of(sk), idx);
    // Copy the map out of the static store and remove it from there: the
    // per-party key is a ceremony message, not an installed key.
    auto map = std::make_shared<std::map<uint32_t, EK>>(CryptoContextImpl<DCRTPoly>::GetEvalAutomorphismKeyMap(tag));
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(tag);
    return new RotMap(map);
    TBGV_CATCH(nullptr)
}
TbgvRotKeys tbgv_rotkeys_next(TbgvContext ctx, TbgvSecretKey sk, TbgvRotKeys prev, const int32_t* indices, size_t n, const char* tag) {
    TBGV_TRY
    std::vector<int32_t> idx(indices, indices + n);
    return new RotMap(cc_of(ctx)->MultiEvalAtIndexKeyGen(sk_of(sk), rk_of(prev), idx, tag));
    TBGV_CATCH(nullptr)
}
TbgvRotKeys tbgv_rotkeys_add(TbgvContext ctx, TbgvRotKeys a, TbgvRotKeys b, const char* tag) {
    TBGV_TRY return new RotMap(cc_of(ctx)->MultiAddEvalAutomorphismKeys(rk_of(a), rk_of(b), tag)); TBGV_CATCH(nullptr)
}
int tbgv_context_install_rotkeys(TbgvContext ctx, TbgvRotKeys keys, const char* tag) {
    TBGV_TRY
    (void)ctx;
    // Idempotent: replace any keys previously installed under this tag.
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(std::string(tag));
    CryptoContextImpl<DCRTPoly>::InsertEvalAutomorphismKey(rk_of(keys), tag);
    return 1;
    TBGV_CATCH(0)
}
int tbgv_context_merge_rotkeys(TbgvContext ctx, TbgvRotKeys keys, const char* tag) {
    TBGV_TRY
    (void)ctx;
    CryptoContextImpl<DCRTPoly>::InsertEvalAutomorphismKey(rk_of(keys), tag);
    return 1;
    TBGV_CATCH(0)
}
int tbgv_clear_keys_for_tag(const char* tag) {
    TBGV_TRY
    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(std::string(tag));
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(std::string(tag));
    return 1;
    TBGV_CATCH(0)
}
int tbgv_context_clear_rotkeys(TbgvContext ctx, const char* tag) {
    TBGV_TRY
    (void)ctx;
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(std::string(tag));
    return 1;
    TBGV_CATCH(0)
}
void tbgv_rotkeys_free(TbgvRotKeys keys) { delete static_cast<RotMap*>(keys); }
int tbgv_rotkeys_serialize(TbgvRotKeys keys, uint8_t** out, size_t* out_len) {
    TBGV_TRY return serialize_to(*rk_of(keys), out, out_len); TBGV_CATCH(0)
}
TbgvRotKeys tbgv_rotkeys_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len) {
    TBGV_TRY
    auto map = std::make_shared<std::map<uint32_t, EK>>();
    deserialize_from(*map, buf, len);
    for (const auto& kv : *map) {
        if (!kv.second || kv.second->GetCryptoContext().get() != cc_of(ctx).get()) {
            set_error("rotation key belongs to a different context");
            return nullptr;
        }
    }
    return new RotMap(map);
    TBGV_CATCH(nullptr)
}

/* ---- plaintext / ciphertext -------------------------------------------- */

TbgvPlaintext tbgv_plaintext_new(TbgvContext ctx, const int64_t* values, size_t n) {
    TBGV_TRY
    std::vector<int64_t> v(values, values + n);
    return new Plaintext(cc_of(ctx)->MakePackedPlaintext(v));
    TBGV_CATCH(nullptr)
}
void tbgv_plaintext_free(TbgvPlaintext pt) { delete static_cast<Plaintext*>(pt); }

TbgvCiphertext tbgv_encrypt(TbgvContext ctx, TbgvPublicKey pk, TbgvPlaintext pt) {
    TBGV_TRY return new CT(cc_of(ctx)->Encrypt(pk_of(pk), pt_of(pt))); TBGV_CATCH(nullptr)
}
TbgvCiphertext tbgv_ciphertext_clone(TbgvCiphertext ct) {
    TBGV_TRY return new CT(ct_of(ct)->Clone()); TBGV_CATCH(nullptr)
}
void tbgv_ciphertext_free(TbgvCiphertext ct) { delete static_cast<CT*>(ct); }

int tbgv_ciphertext_info(TbgvCiphertext h, uint32_t* level, uint32_t* num_elements,
                         uint32_t* noise_scale_deg, uint32_t* num_limbs, uint32_t* encoding_packed) {
    TBGV_TRY
    CT& ct = ct_of(h);
    *level = ct->GetLevel();
    *num_elements = static_cast<uint32_t>(ct->GetElements().size());
    *noise_scale_deg = ct->GetNoiseScaleDeg();
    *num_limbs = ct->GetElements().empty() ? 0 : static_cast<uint32_t>(ct->GetElements()[0].GetNumOfElements());
    *encoding_packed = (ct->GetEncodingType() == PACKED_ENCODING) ? 1 : 0;
    return 1;
    TBGV_CATCH(0)
}
char* tbgv_ciphertext_key_tag(TbgvCiphertext ct) { return dup_string(ct_of(ct)->GetKeyTag()); }
int tbgv_ciphertext_same_context(TbgvContext ctx, TbgvCiphertext ct) {
    return ct_of(ct)->GetCryptoContext().get() == cc_of(ctx).get() ? 1 : 0;
}
int tbgv_ciphertext_serialize(TbgvCiphertext ct, uint8_t** out, size_t* out_len) {
    TBGV_TRY return serialize_to(ct_of(ct), out, out_len); TBGV_CATCH(0)
}
TbgvCiphertext tbgv_ciphertext_deserialize(TbgvContext ctx, const uint8_t* buf, size_t len) {
    TBGV_TRY
    CT ct;
    deserialize_from(ct, buf, len);
    if (!ct) { set_error("ciphertext deserialization produced null"); return nullptr; }
    if (ct->GetCryptoContext().get() != cc_of(ctx).get()) { set_error("ciphertext belongs to a different context"); return nullptr; }
    return new CT(ct);
    TBGV_CATCH(nullptr)
}

TbgvCiphertext tbgv_eval_add(TbgvContext ctx, TbgvCiphertext a, TbgvCiphertext b) {
    TBGV_TRY return new CT(cc_of(ctx)->EvalAdd(ct_of(a), ct_of(b))); TBGV_CATCH(nullptr)
}
TbgvCiphertext tbgv_eval_sub(TbgvContext ctx, TbgvCiphertext a, TbgvCiphertext b) {
    TBGV_TRY return new CT(cc_of(ctx)->EvalSub(ct_of(a), ct_of(b))); TBGV_CATCH(nullptr)
}
TbgvCiphertext tbgv_eval_mult(TbgvContext ctx, TbgvCiphertext a, TbgvCiphertext b) {
    TBGV_TRY return new CT(cc_of(ctx)->EvalMult(ct_of(a), ct_of(b))); TBGV_CATCH(nullptr)
}
TbgvCiphertext tbgv_eval_add_plain(TbgvContext ctx, TbgvCiphertext a, TbgvPlaintext b) {
    TBGV_TRY return new CT(cc_of(ctx)->EvalAdd(ct_of(a), pt_of(b))); TBGV_CATCH(nullptr)
}
TbgvCiphertext tbgv_eval_sub_plain(TbgvContext ctx, TbgvCiphertext a, TbgvPlaintext b) {
    TBGV_TRY return new CT(cc_of(ctx)->EvalSub(ct_of(a), pt_of(b))); TBGV_CATCH(nullptr)
}
TbgvCiphertext tbgv_eval_mult_plain(TbgvContext ctx, TbgvCiphertext a, TbgvPlaintext b) {
    TBGV_TRY return new CT(cc_of(ctx)->EvalMult(ct_of(a), pt_of(b))); TBGV_CATCH(nullptr)
}
TbgvCiphertext tbgv_eval_rotate(TbgvContext ctx, TbgvCiphertext a, int32_t index) {
    TBGV_TRY return new CT(cc_of(ctx)->EvalRotate(ct_of(a), index)); TBGV_CATCH(nullptr)
}

TbgvCiphertext tbgv_eval_square(TbgvContext ctx, TbgvCiphertext a) {
    TBGV_TRY return new CT(cc_of(ctx)->EvalSquare(ct_of(a))); TBGV_CATCH(nullptr)
}

TbgvCiphertext tbgv_eval_negate(TbgvContext ctx, TbgvCiphertext a) {
    TBGV_TRY return new CT(cc_of(ctx)->EvalNegate(ct_of(a))); TBGV_CATCH(nullptr)
}

TbgvCiphertext tbgv_ciphertext_add_noise_for_tests(TbgvContext ctx, TbgvCiphertext h, uint32_t log2_magnitude, uint64_t seed) {
    TBGV_TRY
    CT ct = ct_of(h)->Clone();
    const uint64_t p = cc_of(ctx)->GetCryptoParameters()->GetPlaintextModulus();
    DCRTPoly& c0 = ct->GetElements()[0];
    const Format fmt = c0.GetFormat();
    // Work on a big-integer (non-RNS) copy to build coefficients of arbitrary size.
    DCRTPoly coef = c0;
    coef.SetFormat(Format::COEFFICIENT);
    DCRTPoly::PolyLargeType big = coef.CRTInterpolate();
    const BigInteger Q = big.GetModulus();
    const BigInteger P(std::to_string(p));
    const BigInteger two64("18446744073709551616");
    std::mt19937_64 rng(seed);
    const uint32_t words = (log2_magnitude + 63) / 64;
    const uint32_t top_bits = log2_magnitude - 64 * (words - 1);
    const uint64_t top_mask = top_bits >= 64 ? ~0ULL : ((1ULL << top_bits) - 1);
    DCRTPoly::PolyLargeType noise(big.GetParams(), Format::COEFFICIENT, true);
    for (usint i = 0; i < noise.GetLength(); ++i) {
        BigInteger acc(0);
        for (uint32_t w = 0; w < words; ++w) {
            uint64_t r = rng();
            if (w == 0) r &= top_mask;
            acc = acc * two64 + BigInteger(std::to_string(r));
        }
        noise[i] = (acc * P).Mod(Q);
    }
    big += noise;
    big = big.Mod(Q);
    DCRTPoly replaced(big, c0.GetParams());
    replaced.SetFormat(fmt);
    ct->GetElements()[0] = replaced;
    return new CT(ct);
    TBGV_CATCH(nullptr)
}

/* ---- raw residue transport ----------------------------------------------- */

uint32_t tbgv_context_num_towers(TbgvContext ctx) {
    return static_cast<uint32_t>(cc_of(ctx)->GetCryptoParameters()->GetElementParams()->GetParams().size());
}

int tbgv_context_moduli(TbgvContext ctx, uint64_t* out, size_t out_len) {
    TBGV_TRY
    const auto& towers = cc_of(ctx)->GetCryptoParameters()->GetElementParams()->GetParams();
    if (out == nullptr || out_len != towers.size()) { set_error("moduli buffer has the wrong length"); return 0; }
    for (size_t t = 0; t < towers.size(); ++t) out[t] = towers[t]->GetModulus().ConvertToInt<uint64_t>();
    return 1;
    TBGV_CATCH(0)
}

int tbgv_ciphertext_meta(TbgvCiphertext h, uint32_t* num_elements, uint32_t* num_towers,
                         uint32_t* level, uint32_t* noise_scale_deg, uint64_t* scaling_factor_int) {
    TBGV_TRY
    const CT& ct = ct_of(h);
    const auto& elems = ct->GetElements();
    if (elems.empty()) { set_error("ciphertext has no elements"); return 0; }
    const size_t towers = elems[0].GetNumOfElements();
    for (const auto& e : elems) {
        if (e.GetNumOfElements() != towers) { set_error("ciphertext elements disagree on their tower count"); return 0; }
        if (e.GetFormat() != Format::EVALUATION) { set_error("ciphertext element is not in EVALUATION format"); return 0; }
    }
    *num_elements = static_cast<uint32_t>(elems.size());
    *num_towers = static_cast<uint32_t>(towers);
    *level = static_cast<uint32_t>(ct->GetLevel());
    *noise_scale_deg = static_cast<uint32_t>(ct->GetNoiseScaleDeg());
    *scaling_factor_int = ct->GetScalingFactorInt().ConvertToInt<uint64_t>();
    return 1;
    TBGV_CATCH(0)
}

int tbgv_ciphertext_export(TbgvCiphertext h, uint64_t* out, size_t out_len) {
    TBGV_TRY
    const CT& ct = ct_of(h);
    const auto& elems = ct->GetElements();
    if (elems.empty()) { set_error("ciphertext has no elements"); return 0; }
    const size_t towers = elems[0].GetNumOfElements();
    const size_t n = elems[0].GetRingDimension();
    if (out == nullptr || out_len != elems.size() * towers * n) { set_error("residue buffer has the wrong length"); return 0; }
    size_t k = 0;
    for (const auto& e : elems) {
        if (e.GetNumOfElements() != towers || e.GetFormat() != Format::EVALUATION) { set_error("inconsistent ciphertext elements"); return 0; }
        for (size_t t = 0; t < towers; ++t) {
            const auto& vals = e.GetElementAtIndex(t).GetValues();
            if (vals.GetLength() != n) { set_error("tower has the wrong length"); return 0; }
            for (size_t i = 0; i < n; ++i) out[k++] = vals[i].ConvertToInt<uint64_t>();
        }
    }
    return 1;
    TBGV_CATCH(0)
}

TbgvCiphertext tbgv_ciphertext_build(TbgvContext ctx, TbgvCiphertext reference, uint32_t num_elements,
                                     uint32_t num_towers, uint32_t level, uint32_t noise_scale_deg,
                                     uint64_t scaling_factor_int, const uint64_t* values, size_t len) {
    TBGV_TRY
    if (reference == nullptr || values == nullptr) { set_error("null argument"); return nullptr; }
    const CT& ref = ct_of(reference);
    if (ref->GetCryptoContext().get() != cc_of(ctx).get()) { set_error("reference belongs to a different context"); return nullptr; }
    const auto& ref_elems = ref->GetElements();
    if (ref_elems.empty()) { set_error("reference has no elements"); return nullptr; }
    const DCRTPoly& full = ref_elems[0];
    const size_t L = full.GetNumOfElements();
    const size_t n = full.GetRingDimension();
    if (L != cc_of(ctx)->GetCryptoParameters()->GetElementParams()->GetParams().size()) { set_error("reference is not a fresh full-chain ciphertext"); return nullptr; }
    if (full.GetFormat() != Format::EVALUATION) { set_error("reference is not in EVALUATION format"); return nullptr; }
    // Every metadata value is checked before any OpenFHE object is built.
    if (num_elements < 1 || num_elements > 2) { set_error("num_elements must be 1 or 2"); return nullptr; }
    if (num_towers < 1 || num_towers > L) { set_error("num_towers out of range"); return nullptr; }
    if (static_cast<size_t>(level) + num_towers != L) { set_error("level is inconsistent with the tower count"); return nullptr; }
    if (noise_scale_deg < 1 || noise_scale_deg > 2) { set_error("noise_scale_deg out of range"); return nullptr; }
    const uint64_t t = cc_of(ctx)->GetCryptoParameters()->GetPlaintextModulus();
    if (scaling_factor_int < 1 || scaling_factor_int >= t) { set_error("scaling_factor_int out of range"); return nullptr; }
    if (len != static_cast<size_t>(num_elements) * num_towers * n) { set_error("residue count does not match the metadata"); return nullptr; }
    for (size_t e = 0; e < num_elements; ++e)
        for (size_t tw = 0; tw < num_towers; ++tw) {
            const uint64_t q = full.GetElementAtIndex(tw).GetModulus().ConvertToInt<uint64_t>();
            const uint64_t* v = values + (e * num_towers + tw) * n;
            for (size_t i = 0; i < n; ++i)
                if (v[i] >= q) { set_error("residue is not below its tower modulus"); return nullptr; }
        }
    if (ref_elems.size() < num_elements) { set_error("reference has fewer elements than requested"); return nullptr; }
    for (const auto& re : ref_elems)
        if (re.GetNumOfElements() != L || re.GetFormat() != Format::EVALUATION) { set_error("reference elements are inconsistent"); return nullptr; }
    // Element e is built from the reference's own element e, so each
    // element keeps its own tower-parameter objects exactly as OpenFHE lays
    // them out (the rebuilt object then serializes byte for byte like the
    // original, which the tests check).
    std::vector<DCRTPoly> elems;
    elems.reserve(num_elements);
    for (size_t e = 0; e < num_elements; ++e) {
        DCRTPoly x = ref_elems[e];
        if (num_towers < L) x.DropLastElements(L - num_towers);
        elems.push_back(std::move(x));
    }
    for (size_t e = 0; e < num_elements; ++e)
        for (size_t tw = 0; tw < num_towers; ++tw) {
            auto poly = elems[e].GetElementAtIndex(tw);
            NativeVector vec(n, poly.GetModulus());
            const uint64_t* v = values + (e * num_towers + tw) * n;
            for (size_t i = 0; i < n; ++i) vec[i] = NativeInteger(v[i]);
            poly.SetValues(std::move(vec), Format::EVALUATION);
            elems[e].SetElementAtIndex(tw, std::move(poly));
        }
    CT out = ref->Clone();
    out->SetElements(std::move(elems));
    out->SetLevel(level);
    out->SetNoiseScaleDeg(noise_scale_deg);
    out->SetScalingFactorInt(NativeInteger(scaling_factor_int));
    return new CT(out);
    TBGV_CATCH(nullptr)
}

/* ---- threshold decryption ---------------------------------------------- */

TbgvCiphertext tbgv_partial_decrypt(TbgvContext ctx, TbgvCiphertext ct, TbgvSecretKey sk, int is_lead) {
    TBGV_TRY
    std::vector<CT> in{ct_of(ct)};
    std::vector<CT> out = is_lead ? cc_of(ctx)->MultipartyDecryptLead(in, sk_of(sk))
                                  : cc_of(ctx)->MultipartyDecryptMain(in, sk_of(sk));
    if (out.size() != 1 || !out[0]) { set_error("partial decryption returned nothing"); return nullptr; }
    return new CT(out[0]);
    TBGV_CATCH(nullptr)
}

size_t tbgv_fuse(TbgvContext ctx, const TbgvCiphertext* partials, size_t n, int64_t* out, size_t out_len) {
    TBGV_TRY
    std::vector<CT> parts;
    parts.reserve(n);
    for (size_t i = 0; i < n; ++i) parts.push_back(ct_of(partials[i]));
    Plaintext result;
    DecryptResult r = cc_of(ctx)->MultipartyDecryptFusion(parts, &result);
    if (!r.isValid) { set_error("MultipartyDecryptFusion reported invalid result"); return 0; }
    result->SetLength(out_len);
    const std::vector<int64_t>& v = result->GetPackedValue();
    size_t m = v.size() < out_len ? v.size() : out_len;
    for (size_t i = 0; i < m; ++i) out[i] = v[i];
    return m;
    TBGV_CATCH(0)
}

size_t tbgv_decrypt_single(TbgvContext ctx, TbgvSecretKey sk, TbgvCiphertext ct, int64_t* out, size_t out_len) {
    TBGV_TRY
    Plaintext result;
    DecryptResult r = cc_of(ctx)->Decrypt(sk_of(sk), ct_of(ct), &result);
    if (!r.isValid) { set_error("Decrypt reported invalid result"); return 0; }
    result->SetLength(out_len);
    const std::vector<int64_t>& v = result->GetPackedValue();
    size_t m = v.size() < out_len ? v.size() : out_len;
    for (size_t i = 0; i < m; ++i) out[i] = v[i];
    return m;
    TBGV_CATCH(0)
}

}  // extern "C"

/* ---- loaded library identification -------------------------------------- */

static int collect_openfhe_objects(struct dl_phdr_info* info, size_t, void* data) {
    auto* out = static_cast<std::vector<std::string>*>(data);
    if (info->dlpi_name != nullptr && std::strstr(info->dlpi_name, "libOPENFHE") != nullptr) {
        char resolved[PATH_MAX];
        out->push_back(realpath(info->dlpi_name, resolved) != nullptr ? std::string(resolved) : std::string(info->dlpi_name));
    }
    return 0;
}

char* tbgv_loaded_openfhe_libraries(void) {
    TBGV_TRY
    std::vector<std::string> libs;
    dl_iterate_phdr(collect_openfhe_objects, &libs);
    std::string joined;
    for (size_t i = 0; i < libs.size(); ++i) {
        if (i) joined += '\n';
        joined += libs[i];
    }
    char* out = dup_string(joined);
    if (out == nullptr) set_error("malloc failed");
    return out;
    TBGV_CATCH(nullptr)
}
