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
    TBGV_TRY
    // OpenFHE keeps only the indices present in both maps; a contribution
    // missing an index would silently drop that key from the joint set.
    const auto& ma = *rk_of(a);
    const auto& mb = *rk_of(b);
    if (ma.size() != mb.size()) { set_error("rotation key maps cover different indices"); return nullptr; }
    for (const auto& kv : ma)
        if (mb.find(kv.first) == mb.end()) { set_error("rotation key maps cover different indices"); return nullptr; }
    return new RotMap(cc_of(ctx)->MultiAddEvalAutomorphismKeys(rk_of(a), rk_of(b), tag));
    TBGV_CATCH(nullptr)
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

/* ---- distributed key ceremony ------------------------------------------ */

namespace {

using ParamsPtr = std::shared_ptr<DCRTPoly::Params>;

std::shared_ptr<CryptoParametersRNS> rns_params(TbgvContext ctx) {
    auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(cc_of(ctx)->GetCryptoParameters());
    if (!cp) throw std::runtime_error("not an RNS context");
    if (cp->GetKeySwitchTechnique() != HYBRID) throw std::runtime_error("the ceremony expects hybrid key switching");
    return cp;
}

ParamsPtr basis_params(TbgvContext ctx, uint32_t basis) {
    auto cp = rns_params(ctx);
    ParamsPtr p = basis == 0 ? cp->GetParamsPK() : basis == 1 ? cp->GetParamsQP() : nullptr;
    if (!p) throw std::runtime_error("unknown or absent key basis");
    return p;
}

// Every residue of `count` polynomials over `params` below its tower modulus.
bool residues_ok(const ParamsPtr& params, const uint64_t* v, size_t len, size_t count) {
    const auto& towers = params->GetParams();
    const size_t n = params->GetRingDimension();
    if (v == nullptr || len != count * towers.size() * n) { set_error("residue count does not match the key shape"); return false; }
    for (size_t c = 0; c < count; ++c)
        for (size_t t = 0; t < towers.size(); ++t) {
            const uint64_t q = towers[t]->GetModulus().ConvertToInt<uint64_t>();
            const uint64_t* x = v + (c * towers.size() + t) * n;
            for (size_t i = 0; i < n; ++i)
                if (x[i] >= q) { set_error("residue is not below its tower modulus"); return false; }
        }
    return true;
}

DCRTPoly poly_from(const ParamsPtr& params, const uint64_t* v) {
    DCRTPoly x(params, Format::EVALUATION, true);
    const size_t n = params->GetRingDimension();
    for (size_t t = 0; t < params->GetParams().size(); ++t) {
        auto tower = x.GetElementAtIndex(t);
        NativeVector vec(n, tower.GetModulus());
        for (size_t i = 0; i < n; ++i) vec[i] = NativeInteger(v[t * n + i]);
        tower.SetValues(std::move(vec), Format::EVALUATION);
        x.SetElementAtIndex(t, std::move(tower));
    }
    return x;
}

// Writes `x` (over `params`, EVALUATION format) at `out`.
bool poly_to(const DCRTPoly& x, const ParamsPtr& params, uint64_t* out) {
    const size_t n = params->GetRingDimension();
    if (x.GetFormat() != Format::EVALUATION || x.GetNumOfElements() != params->GetParams().size() || x.GetRingDimension() != n) {
        set_error("key polynomial does not have the expected shape");
        return false;
    }
    for (size_t t = 0; t < x.GetNumOfElements(); ++t) {
        const auto& tw = x.GetElementAtIndex(t);
        if (tw.GetModulus() != params->GetParams()[t]->GetModulus()) { set_error("key polynomial is over another basis"); return false; }
        const auto& vals = tw.GetValues();
        for (size_t i = 0; i < n; ++i) out[t * n + i] = vals[i].ConvertToInt<uint64_t>();
    }
    return true;
}

std::vector<DCRTPoly> polys_from(const ParamsPtr& params, const uint64_t* v, size_t count) {
    std::vector<DCRTPoly> out;
    out.reserve(count);
    const size_t stride = params->GetParams().size() * params->GetRingDimension();
    for (size_t c = 0; c < count; ++c) out.push_back(poly_from(params, v + c * stride));
    return out;
}

}  // namespace

uint32_t tbgv_key_basis_towers(TbgvContext ctx, uint32_t basis) {
    TBGV_TRY return static_cast<uint32_t>(basis_params(ctx, basis)->GetParams().size()); TBGV_CATCH(0)
}
int tbgv_key_basis_moduli(TbgvContext ctx, uint32_t basis, uint64_t* out, size_t out_len) {
    TBGV_TRY
    const auto p = basis_params(ctx, basis);
    if (out == nullptr || out_len != p->GetParams().size()) { set_error("moduli buffer has the wrong length"); return 0; }
    for (size_t t = 0; t < out_len; ++t) out[t] = p->GetParams()[t]->GetModulus().ConvertToInt<uint64_t>();
    return 1;
    TBGV_CATCH(0)
}
uint32_t tbgv_key_num_parts(TbgvContext ctx) {
    TBGV_TRY return rns_params(ctx)->GetNumPartQ(); TBGV_CATCH(0)
}

TbgvPublicKey tbgv_pubkey_template(TbgvContext ctx, const uint64_t* a, size_t len) {
    TBGV_TRY
    const auto params = basis_params(ctx, 0);
    if (!residues_ok(params, a, len, 1)) return nullptr;
    PK pk = std::make_shared<PublicKeyImpl<DCRTPoly>>(cc_of(ctx));
    pk->SetPublicElements(std::vector<DCRTPoly>{DCRTPoly(params, Format::EVALUATION, true), poly_from(params, a)});
    return new PK(pk);
    TBGV_CATCH(nullptr)
}
int tbgv_keygen_share(TbgvContext ctx, TbgvPublicKey tmpl, TbgvPublicKey* out_pk, TbgvSecretKey* out_sk) {
    TBGV_TRY
    // fresh = true: b = e - a*s against the template's a, nothing added.
    auto kp = cc_of(ctx)->MultipartyKeyGen(pk_of(tmpl), false, true);
    if (!kp.good()) { set_error("MultipartyKeyGen failed"); return 0; }
    *out_pk = new PK(kp.publicKey);
    *out_sk = new SK(kp.secretKey);
    return 1;
    TBGV_CATCH(0)
}
int tbgv_pubkey_export(TbgvContext ctx, TbgvPublicKey pk, uint32_t element, uint64_t* out, size_t out_len) {
    TBGV_TRY
    const auto params = basis_params(ctx, 0);
    const auto& el = pk_of(pk)->GetPublicElements();
    if (el.size() != 2 || element > 1) { set_error("public key element out of range"); return 0; }
    if (out == nullptr || out_len != params->GetParams().size() * params->GetRingDimension()) { set_error("residue buffer has the wrong length"); return 0; }
    return poly_to(el[element], params, out) ? 1 : 0;
    TBGV_CATCH(0)
}
TbgvPublicKey tbgv_pubkey_with_b(TbgvContext ctx, TbgvPublicKey tmpl, const uint64_t* b, size_t len) {
    TBGV_TRY
    const auto params = basis_params(ctx, 0);
    if (!residues_ok(params, b, len, 1)) return nullptr;
    const auto& el = pk_of(tmpl)->GetPublicElements();
    if (el.size() != 2) { set_error("template is not a public key"); return nullptr; }
    PK pk = std::make_shared<PublicKeyImpl<DCRTPoly>>(cc_of(ctx));
    pk->SetPublicElements(std::vector<DCRTPoly>{poly_from(params, b), el[1]});
    return new PK(pk);
    TBGV_CATCH(nullptr)
}
TbgvPublicKey tbgv_pubkey_add(TbgvContext ctx, TbgvPublicKey p1, TbgvPublicKey p2, const char* tag) {
    TBGV_TRY
    // OpenFHE keeps the first key's a; the shares must have been made against the same one.
    const auto& e1 = pk_of(p1)->GetPublicElements();
    const auto& e2 = pk_of(p2)->GetPublicElements();
    if (e1.size() != 2 || e2.size() != 2 || !(e1[1] == e2[1])) { set_error("public key shares were made against different a"); return nullptr; }
    return new PK(cc_of(ctx)->MultiAddPubKeys(pk_of(p1), pk_of(p2), tag));
    TBGV_CATCH(nullptr)
}

TbgvEvalKey tbgv_evalkey_template(TbgvContext ctx, const uint64_t* a, size_t len) {
    TBGV_TRY
    const auto params = basis_params(ctx, 1);
    const size_t parts = rns_params(ctx)->GetNumPartQ();
    if (!residues_ok(params, a, len, parts)) return nullptr;
    EK ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc_of(ctx));
    ek->SetAVector(polys_from(params, a, parts));
    ek->SetBVector(std::vector<DCRTPoly>(parts, DCRTPoly(params, Format::EVALUATION, true)));
    return new EK(ek);
    TBGV_CATCH(nullptr)
}
int tbgv_evalkey_export(TbgvContext ctx, TbgvEvalKey key, uint32_t which, uint64_t* out, size_t out_len) {
    TBGV_TRY
    const auto params = basis_params(ctx, 1);
    const size_t parts = rns_params(ctx)->GetNumPartQ();
    const size_t stride = params->GetParams().size() * params->GetRingDimension();
    if (which > 1) { set_error("eval key vector out of range"); return 0; }
    const auto& v = which == 0 ? ek_of(key)->GetAVector() : ek_of(key)->GetBVector();
    if (v.size() != parts) { set_error("eval key has the wrong number of parts"); return 0; }
    if (out == nullptr || out_len != parts * stride) { set_error("residue buffer has the wrong length"); return 0; }
    for (size_t c = 0; c < parts; ++c)
        if (!poly_to(v[c], params, out + c * stride)) return 0;
    return 1;
    TBGV_CATCH(0)
}
TbgvEvalKey tbgv_evalkey_build(TbgvContext ctx, const uint64_t* a, size_t a_len, const uint64_t* b, size_t b_len) {
    TBGV_TRY
    const auto params = basis_params(ctx, 1);
    const size_t parts = rns_params(ctx)->GetNumPartQ();
    if (!residues_ok(params, a, a_len, parts) || !residues_ok(params, b, b_len, parts)) return nullptr;
    EK ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc_of(ctx));
    ek->SetAVector(polys_from(params, a, parts));
    ek->SetBVector(polys_from(params, b, parts));
    return new EK(ek);
    TBGV_CATCH(nullptr)
}
TbgvEvalKey tbgv_evalkey_with_b(TbgvContext ctx, TbgvEvalKey tmpl, const uint64_t* b, size_t b_len) {
    TBGV_TRY
    const auto params = basis_params(ctx, 1);
    const size_t parts = rns_params(ctx)->GetNumPartQ();
    if (ek_of(tmpl)->GetAVector().size() != parts) { set_error("template has the wrong number of parts"); return nullptr; }
    if (!residues_ok(params, b, b_len, parts)) return nullptr;
    EK ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc_of(ctx));
    ek->SetAVector(ek_of(tmpl)->GetAVector());
    ek->SetBVector(polys_from(params, b, parts));
    return new EK(ek);
    TBGV_CATCH(nullptr)
}
int tbgv_evalkey_same_a(TbgvEvalKey k1, TbgvEvalKey k2) {
    TBGV_TRY
    const auto& a1 = ek_of(k1)->GetAVector();
    const auto& a2 = ek_of(k2)->GetAVector();
    if (a1.size() != a2.size()) return 0;
    for (size_t i = 0; i < a1.size(); ++i)
        if (!(a1[i] == a2[i])) return 0;
    return 1;
    TBGV_CATCH(-1)
}
TbgvRotKeys tbgv_rotkeys_single(TbgvContext ctx, int32_t index, TbgvEvalKey key) {
    TBGV_TRY
    const uint32_t m = cc_of(ctx)->GetCyclotomicOrder();
    auto map = std::make_shared<std::map<uint32_t, EK>>();
    (*map)[FindAutomorphismIndex2n(index, m)] = ek_of(key);
    return new RotMap(map);
    TBGV_CATCH(nullptr)
}
TbgvEvalKey tbgv_rotkeys_get(TbgvContext ctx, TbgvRotKeys keys, int32_t index) {
    TBGV_TRY
    const uint32_t m = cc_of(ctx)->GetCyclotomicOrder();
    const auto& map = *rk_of(keys);
    auto it = map.find(FindAutomorphismIndex2n(index, m));
    if (map.size() != 1 || it == map.end()) { set_error("rotation key map does not hold exactly this index"); return nullptr; }
    return new EK(it->second);
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

/* ---- verifiable decryption --------------------------------------------- */

namespace {

// Negacyclic shift of a coefficient-form tower by k in [0, 2N): X^k * p.
NativePoly monomial_times(const NativePoly& p, uint32_t k) {
    const size_t n = p.GetRingDimension();
    const NativeInteger q = p.GetModulus();
    const auto& v = p.GetValues();
    NativeVector out(n, q);
    const bool flip_all = k >= n;
    const size_t s = k % n;
    for (size_t i = 0; i < n; ++i) {
        size_t j = i + s;
        bool neg = flip_all;
        if (j >= n) {
            j -= n;
            neg = !neg;
        }
        out[j] = (neg && v[i] != NativeInteger(0)) ? q - v[i] : v[i];
    }
    NativePoly r = p;
    r.SetValues(std::move(out), Format::COEFFICIENT);
    return r;
}

// A DCRTPoly over `params` from small signed coefficients.
DCRTPoly small_poly(const std::shared_ptr<DCRTPoly::Params>& params, const int8_t* c) {
    DCRTPoly x(params, Format::COEFFICIENT, true);
    const size_t n = params->GetRingDimension();
    for (size_t t = 0; t < x.GetNumOfElements(); ++t) {
        auto tower = x.GetElementAtIndex(t);
        const NativeInteger q = tower.GetModulus();
        NativeVector vec(n, q);
        for (size_t i = 0; i < n; ++i) {
            const int64_t a = c[i];
            vec[i] = a >= 0 ? NativeInteger(static_cast<uint64_t>(a)) : q - NativeInteger(static_cast<uint64_t>(-a));
        }
        tower.SetValues(std::move(vec), Format::COEFFICIENT);
        x.SetElementAtIndex(t, std::move(tower));
    }
    x.SetFormat(Format::EVALUATION);
    return x;
}

}  // namespace

TbgvCiphertext tbgv_ciphertext_mult_monomial(TbgvContext ctx, TbgvCiphertext h, uint32_t k) {
    TBGV_TRY
    const CT& ct = ct_of(h);
    if (ct->GetCryptoContext().get() != cc_of(ctx).get()) { set_error("ciphertext belongs to a different context"); return nullptr; }
    const auto& el = ct->GetElements();
    if (el.empty()) { set_error("ciphertext has no elements"); return nullptr; }
    const uint32_t n = el[0].GetRingDimension();
    if (k >= 2 * n) { set_error("monomial exponent must be below 2N"); return nullptr; }
    std::vector<DCRTPoly> out;
    out.reserve(el.size());
    for (const auto& e : el) {
        if (e.GetFormat() != Format::EVALUATION) { set_error("ciphertext element not in EVALUATION format"); return nullptr; }
        DCRTPoly x = e;
        x.SetFormat(Format::COEFFICIENT);
        for (size_t t = 0; t < x.GetNumOfElements(); ++t) x.SetElementAtIndex(t, monomial_times(x.GetElementAtIndex(t), k));
        x.SetFormat(Format::EVALUATION);
        out.push_back(std::move(x));
    }
    CT r = ct->Clone();
    r->SetElements(std::move(out));
    return new CT(r);
    TBGV_CATCH(nullptr)
}

TbgvCiphertext tbgv_zero_encryption(TbgvContext ctx, TbgvPublicKey pk, TbgvCiphertext reference, const int8_t* u,
                                    const int8_t* e0, const int8_t* e1, size_t n) {
    TBGV_TRY
    if (u == nullptr || e0 == nullptr || e1 == nullptr) { set_error("null argument"); return nullptr; }
    const CT& ref = ct_of(reference);
    if (ref->GetCryptoContext().get() != cc_of(ctx).get()) { set_error("reference belongs to a different context"); return nullptr; }
    const auto& rel = ref->GetElements();
    if (rel.size() != 2) { set_error("reference must have two elements"); return nullptr; }
    if (n != rel[0].GetRingDimension()) { set_error("coefficient vectors must have the ring dimension"); return nullptr; }
    const auto& pke = pk_of(pk)->GetPublicElements();
    if (pke.size() != 2) { set_error("not a public key"); return nullptr; }
    const size_t towers = rel[0].GetNumOfElements();
    if (pke[0].GetNumOfElements() < towers) { set_error("public key has fewer towers than the reference"); return nullptr; }
    for (size_t t = 0; t < towers; ++t)
        if (pke[0].GetElementAtIndex(t).GetModulus() != rel[0].GetElementAtIndex(t).GetModulus()) {
            set_error("public key towers do not match the reference's");
            return nullptr;
        }
    DCRTPoly b = pke[0];
    DCRTPoly a = pke[1];
    if (b.GetNumOfElements() > towers) {
        b.DropLastElements(b.GetNumOfElements() - towers);
        a.DropLastElements(a.GetNumOfElements() - towers);
    }
    const auto params = rel[0].GetParams();
    const DCRTPoly up = small_poly(params, u);
    const DCRTPoly t = small_poly(params, e0);
    const DCRTPoly s = small_poly(params, e1);
    const NativeInteger pt(cc_of(ctx)->GetCryptoParameters()->GetPlaintextModulus());
    // (b u + t e0, a u + t e1): an encryption of zero, BGV noise a multiple of t
    DCRTPoly c0 = b * up + t.Times(pt);
    DCRTPoly c1 = a * up + s.Times(pt);
    CT r = ref->Clone();
    r->SetElements({std::move(c0), std::move(c1)});
    return new CT(r);
    TBGV_CATCH(nullptr)
}

int tbgv_monomial_slots(TbgvContext ctx, uint64_t* out, size_t out_len) {
    TBGV_TRY
    const CC& cc = cc_of(ctx);
    const auto ep = cc->GetEncodingParams();
    const uint64_t t = ep->GetPlaintextModulus();
    const uint32_t m = cc->GetCyclotomicOrder();
    const size_t n = m / 2;
    if (out == nullptr || out_len != n) { set_error("output must hold the ring dimension"); return 0; }
    auto vp = std::make_shared<NativePoly::Params>(m, NativeInteger(t), NativeInteger(1));
    Plaintext pt = PlaintextFactory::MakePlaintext(PACKED_ENCODING, vp, ep);
    NativeVector coeffs(n, NativeInteger(t));
    coeffs[1] = NativeInteger(1);
    NativePoly x(vp, Format::COEFFICIENT, true);
    x.SetValues(std::move(coeffs), Format::COEFFICIENT);
    pt->GetElement<NativePoly>() = std::move(x);
    pt->SetScalingFactorInt(NativeInteger(1));
    pt->Decode();
    const auto& v = pt->GetPackedValue();
    if (v.size() < n) { set_error("decoded fewer slots than the ring dimension"); return 0; }
    for (size_t i = 0; i < n; ++i) out[i] = v[i] >= 0 ? static_cast<uint64_t>(v[i]) : t - static_cast<uint64_t>(-v[i]);
    return 1;
    TBGV_CATCH(0)
}

int tbgv_fuse_magnitude(TbgvContext ctx, const TbgvCiphertext* partials, size_t n, uint64_t* max_abs, uint64_t* q0) {
    TBGV_TRY
    if (n == 0 || partials == nullptr || max_abs == nullptr || q0 == nullptr) { set_error("bad arguments"); return 0; }
    const auto cp = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(cc_of(ctx)->GetCryptoParameters());
    if (!cp) { set_error("not a BGV-RNS context"); return 0; }
    // exactly the first half of MultipartyBGVRNS::MultipartyDecryptFusion
    DCRTPoly b = ct_of(partials[0])->GetElements().at(0);
    for (size_t i = 1; i < n; ++i) b += ct_of(partials[i])->GetElements().at(0);
    b.SetFormat(Format::COEFFICIENT);
    const size_t sizeQl = b.GetNumOfElements();
    for (size_t i = sizeQl - 1; i > 0; --i) {
        b.ModReduce(cp->GetPlaintextModulus(), cp->GettModqPrecon(), cp->GetNegtInvModq(i), cp->GetNegtInvModqPrecon(i),
                    cp->GetqlInvModq(i), cp->GetqlInvModqPrecon(i));
    }
    const NativePoly& p0 = b.GetElementAtIndex(0);
    const NativeInteger q = p0.GetModulus();
    const NativeInteger half = q >> 1;
    uint64_t mx = 0;
    const auto& v = p0.GetValues();
    for (size_t i = 0; i < v.GetLength(); ++i) {
        const NativeInteger x = v[i];
        const uint64_t a = (x > half ? q - x : x).ConvertToInt<uint64_t>();
        if (a > mx) mx = a;
    }
    *max_abs = mx;
    *q0 = q.ConvertToInt<uint64_t>();
    return 1;
    TBGV_CATCH(0)
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

/* ---- full-precision decryption values --------------------------------------
 * Every partial decryption is revealed at the ciphertext's full modulus Q_l,
 * so whoever fuses them can form sum_i partial_i = m + t (noise + flooding)
 * over Q_l, before OpenFHE's fusion reduces it to q0. These functions
 * measure that value: its largest centered coefficient, and optionally every
 * coefficient divided by t. */

/* log2 of a BigInteger of any size (a double overflows above 2^1024). */
static double big_log2(const BigInteger& x) {
    const usint msb = x.GetMSB();
    if (msb == 0) return -INFINITY;
    if (msb <= 900) return std::log2(x.ConvertToDouble());
    const usint shift = msb - 64;
    return std::log2((x >> shift).ConvertToDouble()) + static_cast<double>(shift);
}

static double centered_stats(DCRTPoly x, uint64_t t, double* out_over_t, size_t out_len, double* log2_q) {
    x.SetFormat(Format::COEFFICIENT);
    DCRTPoly::PolyLargeType big = x.CRTInterpolate();
    const BigInteger Q = big.GetModulus();
    const BigInteger half = Q >> 1;
    const double td = static_cast<double>(t);
    BigInteger mx(0);
    for (usint i = 0; i < big.GetLength(); ++i) {
        const BigInteger& v = big[i];
        const bool neg = v > half;
        const BigInteger a = neg ? Q - v : v;
        if (a > mx) mx = a;
        if (out_over_t != nullptr && i < out_len) {
            const double d = a.ConvertToDouble() / td;
            out_over_t[i] = neg ? -d : d;
        }
    }
    if (log2_q != nullptr) *log2_q = big_log2(Q);
    return mx > BigInteger(0) ? big_log2(mx) : 0.0;
}

double tbgv_flooding_sigma(TbgvContext ctx) {
    TBGV_TRY
    const auto cp = std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(cc_of(ctx)->GetCryptoParameters());
    if (!cp) { set_error("not an RLWE context"); return -1.0; }
    return cp->GetFloodingDistributionParameter();
    TBGV_CATCH(-1.0)
}

int tbgv_fuse_raw(TbgvContext ctx, const TbgvCiphertext* partials, size_t n, double* out_over_t, size_t out_len, double* log2_max,
                  double* log2_q) {
    TBGV_TRY
    if (n == 0 || partials == nullptr || log2_max == nullptr || log2_q == nullptr) { set_error("bad arguments"); return 0; }
    DCRTPoly b = ct_of(partials[0])->GetElements().at(0);
    for (size_t i = 1; i < n; ++i) b += ct_of(partials[i])->GetElements().at(0);
    *log2_max = centered_stats(b, cc_of(ctx)->GetCryptoParameters()->GetPlaintextModulus(), out_over_t, out_len, log2_q);
    return 1;
    TBGV_CATCH(0)
}

int tbgv_raw_decrypt_for_tests(TbgvContext ctx, TbgvCiphertext h, const TbgvSecretKey* sks, size_t n, double* out_over_t,
                               size_t out_len, double* log2_max, double* log2_q) {
    TBGV_TRY
    if (n == 0 || sks == nullptr || log2_max == nullptr || log2_q == nullptr) { set_error("bad arguments"); return 0; }
    const CT& ct = ct_of(h);
    const auto& el = ct->GetElements();
    if (el.size() != 2) { set_error("raw decryption expects a relinearized ciphertext"); return 0; }
    const size_t towers = el[0].GetNumOfElements();
    DCRTPoly s = sk_of(sks[0])->GetPrivateElement();
    for (size_t i = 1; i < n; ++i) s += sk_of(sks[i])->GetPrivateElement();
    if (s.GetNumOfElements() < towers) { set_error("secret has fewer towers than the ciphertext"); return 0; }
    s.DropLastElements(s.GetNumOfElements() - towers);
    s.SetFormat(el[1].GetFormat());
    DCRTPoly x = el[1] * s;
    x += el[0];
    *log2_max = centered_stats(x, cc_of(ctx)->GetCryptoParameters()->GetPlaintextModulus(), out_over_t, out_len, log2_q);
    return 1;
    TBGV_CATCH(0)
}

TbgvPublicKey tbgv_pubkey_inflate_for_tests(TbgvContext ctx, TbgvPublicKey h, uint32_t log2_k, uint64_t seed, int constant) {
    TBGV_TRY
    const auto& el = pk_of(h)->GetPublicElements();
    if (el.size() != 2) { set_error("not a public key"); return nullptr; }
    const uint64_t t = cc_of(ctx)->GetCryptoParameters()->GetPlaintextModulus();
    if (!constant && log2_k > 62) { set_error("random inflation is limited to 62 bits"); return nullptr; }
    DCRTPoly e(el[0].GetParams(), Format::COEFFICIENT, true);
    std::mt19937_64 rng(seed);
    const uint32_t N = el[0].GetRingDimension();
    std::vector<int64_t> r(N, 0);
    if (!constant) {
        const uint64_t mask = (1ULL << log2_k) - 1;
        for (auto& x : r) {
            x = static_cast<int64_t>(rng() & mask);
            if (rng() & 1) x = -x;
        }
    }
    for (size_t j = 0; j < e.GetNumOfElements(); ++j) {
        NativePoly& p = e.GetAllElements()[j];
        const NativeInteger q = p.GetModulus();
        const NativeInteger tq = NativeInteger(t).Mod(q);
        if (constant) {
            p[0] = NativeInteger(2).ModExp(NativeInteger(log2_k), q).ModMul(tq, q);  // E = 2^k (the constant polynomial)
        } else {
            for (uint32_t i = 0; i < N; ++i) {
                const NativeInteger mag = NativeInteger(static_cast<uint64_t>(r[i] < 0 ? -r[i] : r[i])).Mod(q).ModMul(tq, q);
                p[i] = r[i] < 0 ? q.ModSub(mag, q) : mag;
            }
        }
    }
    e.SetFormat(el[0].GetFormat());
    DCRTPoly b = el[0];
    b += e;
    PK pk = std::make_shared<PublicKeyImpl<DCRTPoly>>(cc_of(ctx));
    pk->SetPublicElements(std::vector<DCRTPoly>{b, el[1]});
    pk->SetKeyTag(pk_of(h)->GetKeyTag());
    return new PK(pk);
    TBGV_CATCH(nullptr)
}

/* Q' = Q_l / q0: the range of OpenFHE's flooding in NOISE_FLOODING_MULTIPARTY
 * (MultipartyRNS::MultipartyDecryptMain/Lead sample it uniformly modulo the
 * product of every tower but the first and add t times it). */
static BigInteger q_prime(const std::shared_ptr<ILDCRTParams<BigInteger>>& params) {
    BigInteger p(1);
    const auto& ps = params->GetParams();
    for (size_t i = 1; i < ps.size(); ++i) p *= BigInteger(ps[i]->GetModulus().ConvertToInt<uint64_t>());
    return p;
}

static BigInteger big_of(uint64_t x) { return BigInteger(std::to_string(x)); }

/* The DCRTPoly (with `like`'s towers, EVALUATION format) whose coefficients are
 * the signed integers `vals` (centered, |v| < Q_l / 2). */
static DCRTPoly dcrt_from_signed(const DCRTPoly& like, const std::vector<BigInteger>& mag, const std::vector<bool>& neg) {
    DCRTPoly coef = like;
    coef.SetFormat(Format::COEFFICIENT);
    DCRTPoly::PolyLargeType big = coef.CRTInterpolate();
    const BigInteger Q = big.GetModulus();
    for (usint i = 0; i < big.GetLength(); ++i) {
        const BigInteger m = mag[i].Mod(Q);
        big[i] = (neg[i] && m != BigInteger(0)) ? Q - m : m;
    }
    DCRTPoly out(big, like.GetParams());
    out.SetFormat(Format::EVALUATION);
    return out;
}

int tbgv_fuse_flooding_check(TbgvContext ctx, const TbgvCiphertext* partials, size_t n, uint32_t slack_bits, int* within,
                             double* ratio) {
    TBGV_TRY
    if (n == 0 || partials == nullptr || within == nullptr || ratio == nullptr) { set_error("bad arguments"); return 0; }
    DCRTPoly b = ct_of(partials[0])->GetElements().at(0);
    for (size_t i = 1; i < n; ++i) b += ct_of(partials[i])->GetElements().at(0);
    const auto params = b.GetParams();
    if (params->GetParams().size() < 3) { set_error("fewer than three towers: no flooding range"); return 0; }
    b.SetFormat(Format::COEFFICIENT);
    DCRTPoly::PolyLargeType big = b.CRTInterpolate();
    const BigInteger Q = big.GetModulus();
    const BigInteger half = Q >> 1;
    const BigInteger qp = q_prime(params);
    const BigInteger t = big_of(cc_of(ctx)->GetCryptoParameters()->GetPlaintextModulus());
    // each party floods with |e| <= Q'/2; honest noise and the message fit in Q' 2^-slack + 1
    const BigInteger floods = t * big_of(n) * (qp >> 1);
    const BigInteger bound = floods + t * (qp >> slack_bits) + t;
    BigInteger mx(0);
    for (usint i = 0; i < big.GetLength(); ++i) {
        const BigInteger& v = big[i];
        const BigInteger a = v > half ? Q - v : v;
        if (a > mx) mx = a;
    }
    *within = mx <= bound ? 1 : 0;
    *ratio = std::exp2(big_log2(mx) - big_log2(floods));
    return 1;
    TBGV_CATCH(0)
}

TbgvCiphertext tbgv_partial_decrypt_shaped_for_tests(TbgvContext ctx, TbgvCiphertext h, TbgvSecretKey sk, int is_lead,
                                                     uint64_t num, uint64_t den, uint64_t seed) {
    TBGV_TRY
    if (den == 0) { set_error("den must be positive"); return nullptr; }
    const CT& ct = ct_of(h);
    const auto& el = ct->GetElements();
    if (el.size() != 2) { set_error("expects a relinearized ciphertext"); return nullptr; }
    const size_t towers = el[0].GetNumOfElements();
    DCRTPoly s = sk_of(sk)->GetPrivateElement();
    s.DropLastElements(s.GetNumOfElements() - towers);
    s.SetFormat(el[1].GetFormat());
    DCRTPoly x = el[1] * s;
    if (is_lead) x += el[0];
    // flooding uniform in [-W, W], W = floor(Q' num / (2 den)), instead of OpenFHE's [-Q'/2, Q'/2]
    const BigInteger w = (q_prime(el[0].GetParams()) * big_of(num)) / (big_of(den) * BigInteger(2));
    const uint32_t N = el[0].GetRingDimension();
    std::vector<BigInteger> mag(N);
    std::vector<bool> neg(N, false);
    if (w > BigInteger(0)) {
        DiscreteUniformGeneratorImpl<BigVector> dug;
        const BigVector r = dug.GenerateVector(N, w * BigInteger(2) + BigInteger(1));
        for (uint32_t i = 0; i < N; ++i) {
            const BigInteger ri = r[i];
            if (ri >= w) mag[i] = ri - w; else { mag[i] = w - ri; neg[i] = true; }
        }
    }
    (void)seed;
    const uint64_t t = cc_of(ctx)->GetCryptoParameters()->GetPlaintextModulus();
    for (uint32_t i = 0; i < N; ++i) mag[i] = mag[i] * big_of(t);
    x += dcrt_from_signed(el[0], mag, neg);
    auto result = ct->CloneEmpty();
    result->SetElements(std::vector<DCRTPoly>{x});
    return new CT(result);
    TBGV_CATCH(nullptr)
}

TbgvPublicKey tbgv_pubkey_inflate_ratio_for_tests(TbgvContext ctx, TbgvPublicKey h, uint64_t num, uint64_t den) {
    TBGV_TRY
    if (den == 0) { set_error("den must be positive"); return nullptr; }
    const auto& el = pk_of(h)->GetPublicElements();
    if (el.size() != 2) { set_error("not a public key"); return nullptr; }
    // E = floor(Q' num / den), the constant polynomial, Q' = Q / q0 of the
    // ciphertext modulus (the key itself also has the key-switching towers P)
    const auto qparams = cc_of(ctx)->GetCryptoParameters()->GetElementParams();
    const BigInteger e = (q_prime(qparams) * big_of(num)) / big_of(den);
    const uint64_t t = cc_of(ctx)->GetCryptoParameters()->GetPlaintextModulus();
    const uint32_t N = el[0].GetRingDimension();
    std::vector<BigInteger> mag(N, BigInteger(0));
    std::vector<bool> neg(N, false);
    mag[0] = e * big_of(t);
    DCRTPoly b = el[0];
    DCRTPoly add = dcrt_from_signed(el[0], mag, neg);
    add.SetFormat(b.GetFormat());
    b += add;
    PK pk = std::make_shared<PublicKeyImpl<DCRTPoly>>(cc_of(ctx));
    pk->SetPublicElements(std::vector<DCRTPoly>{b, el[1]});
    pk->SetKeyTag(pk_of(h)->GetKeyTag());
    return new PK(pk);
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
