// C ABI wrapper around OpenFHE CKKS (single-key, no multiparty).
// Exposes opaque handles so Rust can drive encryption/decryption/evaluation.

#include "capi.h"

#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

using namespace lbcrypto;

using CtxType = CryptoContext<DCRTPoly>;
using KpType = KeyPair<DCRTPoly>;
using CtType = Ciphertext<DCRTPoly>;

namespace {

template <typename T>
uint8_t* serialize_to_bytes(const T& obj, size_t* len) {
    try {
        std::ostringstream ss;
        Serial::Serialize(obj, ss, SerType::BINARY);
        std::string s = ss.str();
        auto* buf = static_cast<uint8_t*>(std::malloc(s.size()));
        std::memcpy(buf, s.data(), s.size());
        if (len) {
            *len = s.size();
        }
        return buf;
    } catch (...) {
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

template <typename T>
bool deserialize_from_bytes(T& obj, const uint8_t* data, size_t len) {
    try {
        std::string s(reinterpret_cast<const char*>(data), len);
        std::istringstream ss(s);
        Serial::Deserialize(obj, ss, SerType::BINARY);
        return true;
    } catch (...) {
        return false;
    }
}

}  // namespace

extern "C" {

fhe_ctx fhe_ckks_new(uint32_t mult_depth, uint32_t scale_mod_size,
                     uint32_t batch_size, uint32_t first_mod_size) {
    try {
        CCParams<CryptoContextCKKSRNS> params;
        params.SetMultiplicativeDepth(mult_depth);
        params.SetScalingModSize(scale_mod_size);
        params.SetBatchSize(batch_size);
        if (first_mod_size > 0) {
            params.SetFirstModSize(first_mod_size);
        }
        auto cc = GenCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(MULTIPARTY);
        return new CtxType(cc);
    } catch (...) {
        return nullptr;
    }
}

fhe_keypair fhe_keygen(fhe_ctx ctx) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        return new KpType(cc->KeyGen());
    } catch (...) {
        return nullptr;
    }
}

fhe_ciphertext fhe_encrypt(fhe_ctx ctx, fhe_keypair kp, const double* data,
                           size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& kpr = *static_cast<KpType*>(kp);
        std::vector<double> vec(data, data + len);
        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(vec);
        return new CtType(cc->Encrypt(kpr.publicKey, ptxt));
    } catch (...) {
        return nullptr;
    }
}

size_t fhe_decrypt(fhe_ctx ctx, fhe_keypair kp, fhe_ciphertext ct, double* out,
                   size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& kpr = *static_cast<KpType*>(kp);
        auto& ctr = *static_cast<CtType*>(ct);
        Plaintext ptxt;
        cc->Decrypt(kpr.secretKey, ctr, &ptxt);
        ptxt->SetLength(len);
        std::vector<double> values = ptxt->GetRealPackedValue();
        size_t n = values.size() < len ? values.size() : len;
        for (size_t i = 0; i < n; i++) {
            out[i] = values[i];
        }
        return n;
    } catch (...) {
        return 0;
    }
}

fhe_ciphertext fhe_eval_add(fhe_ctx ctx, fhe_ciphertext a, fhe_ciphertext b) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& ar = *static_cast<CtType*>(a);
        auto& br = *static_cast<CtType*>(b);
        return new CtType(cc->EvalAdd(ar, br));
    } catch (...) {
        return nullptr;
    }
}

fhe_ciphertext fhe_eval_mult(fhe_ctx ctx, fhe_ciphertext a, fhe_ciphertext b) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& ar = *static_cast<CtType*>(a);
        auto& br = *static_cast<CtType*>(b);
        return new CtType(cc->EvalMult(ar, br));
    } catch (...) {
        return nullptr;
    }
}

uint8_t* fhe_serialize_ciphertext(fhe_ciphertext ct, size_t* len) {
    try {
        auto& ctr = *static_cast<CtType*>(ct);
        return serialize_to_bytes(ctr, len);
    } catch (...) {
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

fhe_ciphertext fhe_deserialize_ciphertext(fhe_ctx ctx, const uint8_t* data, size_t len) {
    try {
        CtType ct;
        if (!deserialize_from_bytes(ct, data, len)) {
            return nullptr;
        }
        return new CtType(ct);
    } catch (...) {
        return nullptr;
    }
}

uint8_t* fhe_serialize_pubkey(fhe_keypair kp, size_t* len) {
    try {
        auto& kpr = *static_cast<KpType*>(kp);
        return serialize_to_bytes(kpr.publicKey, len);
    } catch (...) {
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

uint8_t* fhe_serialize_seckey(fhe_keypair kp, size_t* len) {
    try {
        auto& kpr = *static_cast<KpType*>(kp);
        return serialize_to_bytes(kpr.secretKey, len);
    } catch (...) {
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

fhe_keypair fhe_multiparty_keygen_first(fhe_ctx ctx) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        return new KpType(cc->KeyGen());
    } catch (...) {
        return nullptr;
    }
}

fhe_keypair fhe_multiparty_keygen_next(fhe_ctx ctx, const uint8_t* prev_pubkey,
                                       size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        PublicKey<DCRTPoly> prev_pk;
        if (!deserialize_from_bytes(prev_pk, prev_pubkey, len)) {
            return nullptr;
        }
        return new KpType(cc->MultipartyKeyGen(prev_pk));
    } catch (...) {
        return nullptr;
    }
}

fhe_keypair fhe_multiparty_keygen_next_kp(fhe_ctx ctx, fhe_keypair prev_kp) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& prev = *static_cast<KpType*>(prev_kp);
        return new KpType(cc->MultipartyKeyGen(prev.publicKey));
    } catch (...) {
        return nullptr;
    }
}

uint8_t* fhe_multiparty_decrypt_lead(fhe_ctx ctx, fhe_ciphertext ct,
                                     fhe_keypair kp, size_t* len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& kpr = *static_cast<KpType*>(kp);
        auto& ctr = *static_cast<CtType*>(ct);
        auto partial = cc->MultipartyDecryptLead({ctr}, kpr.secretKey);
        return serialize_to_bytes(partial[0], len);
    } catch (...) {
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

uint8_t* fhe_multiparty_decrypt_main(fhe_ctx ctx, fhe_ciphertext ct,
                                     fhe_keypair kp, size_t* len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& kpr = *static_cast<KpType*>(kp);
        auto& ctr = *static_cast<CtType*>(ct);
        auto partial = cc->MultipartyDecryptMain({ctr}, kpr.secretKey);
        return serialize_to_bytes(partial[0], len);
    } catch (...) {
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

size_t fhe_multiparty_decrypt_fusion(fhe_ctx ctx, const uint8_t* const* partials,
                                     const size_t* lens, size_t n_partials,
                                     double* out, size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        std::vector<Ciphertext<DCRTPoly>> partial_vec;
        partial_vec.reserve(n_partials);
        for (size_t i = 0; i < n_partials; i++) {
            Ciphertext<DCRTPoly> p;
            if (!deserialize_from_bytes(p, partials[i], lens[i])) {
                return 0;
            }
            partial_vec.push_back(p);
        }
        Plaintext ptxt;
        cc->MultipartyDecryptFusion(partial_vec, &ptxt);
        ptxt->SetLength(len);
        std::vector<double> values = ptxt->GetRealPackedValue();
        size_t n = values.size() < len ? values.size() : len;
        for (size_t i = 0; i < n; i++) {
            out[i] = values[i];
        }
        return n;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "fusion: %s\n", e.what());
        return 0;
    }
}

size_t fhe_bfv_fusion(fhe_ctx ctx, const uint8_t* const* partials,
                      const size_t* lens, size_t n_partials,
                      int64_t* out, size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        std::vector<Ciphertext<DCRTPoly>> partial_vec;
        partial_vec.reserve(n_partials);
        for (size_t i = 0; i < n_partials; i++) {
            Ciphertext<DCRTPoly> p;
            if (!deserialize_from_bytes(p, partials[i], lens[i])) {
                return 0;
            }
            partial_vec.push_back(p);
        }
        Plaintext ptxt;
        cc->MultipartyDecryptFusion(partial_vec, &ptxt);
        ptxt->SetLength(len);
        const auto& values = ptxt->GetPackedValue();
        size_t n = values.size() < len ? values.size() : len;
        for (size_t i = 0; i < n; i++) {
            out[i] = values[i];
        }
        return n;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bfv fusion: %s\n", e.what());
        return 0;
    }
}

uint8_t* fhe_extract_secret_coeffs(fhe_ctx ctx, fhe_keypair kp, size_t* len) {
    try {
        auto& kpr = *static_cast<KpType*>(kp);
        auto s = kpr.secretKey->GetPrivateElement();
        s.SetFormat(Format::COEFFICIENT);
        std::vector<uint64_t> coeffs;
        for (const auto& poly : s.GetAllElements()) {
            const auto& values = poly.GetValues();
            for (size_t i = 0; i < values.GetLength(); i++) {
                coeffs.push_back(values[i].ConvertToInt());
            }
        }
        size_t byte_len = coeffs.size() * sizeof(uint64_t);
        auto* buf = static_cast<uint8_t*>(std::malloc(byte_len));
        std::memcpy(buf, coeffs.data(), byte_len);
        if (len) {
            *len = byte_len;
        }
        return buf;
    } catch (...) {
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

uint8_t* fhe_extract_moduli(fhe_ctx ctx, fhe_keypair kp, size_t* len) {
    try {
        auto& kpr = *static_cast<KpType*>(kp);
        auto s = kpr.secretKey->GetPrivateElement();
        const auto& elements = s.GetAllElements();
        size_t n = elements.size();
        auto* buf = static_cast<uint64_t*>(std::malloc(n * sizeof(uint64_t)));
        for (size_t i = 0; i < n; i++) {
            buf[i] = elements[i].GetModulus().ConvertToInt();
        }
        if (len) {
            *len = n * sizeof(uint64_t);
        }
        return reinterpret_cast<uint8_t*>(buf);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "extract_moduli: %s\n", e.what());
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

fhe_keypair fhe_make_secret_from_coeffs(fhe_ctx ctx, const uint8_t* data, size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        size_t n = len / sizeof(uint64_t);
        std::vector<uint64_t> coeffs(n);
        std::memcpy(coeffs.data(), data, len);

        auto kp = cc->KeyGen();
        auto s = kp.secretKey->GetPrivateElement();
        // Bring all elements to coefficient form first so SetValues(COEFFICIENT)
        // writes plain coefficients, then convert back to evaluation (NTT) form.
        s.SetFormat(Format::COEFFICIENT);
        auto& elements = s.GetAllElements();
        size_t num_moduli = elements.size();
        size_t ring_dim = n / num_moduli;
        for (size_t j = 0; j < num_moduli; j++) {
            auto modulus = elements[j].GetModulus();
            NativeVector values(ring_dim, modulus);
            for (size_t i = 0; i < ring_dim; i++) {
                values[i] = coeffs[j * ring_dim + i];
            }
            elements[j].SetValues(values, Format::COEFFICIENT);
        }
        s.SetFormat(Format::EVALUATION);
        kp.secretKey->SetPrivateElement(s);
        return new KpType(kp);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "make_secret_from_coeffs: %s\n", e.what());
        return nullptr;
    }
}

uint8_t* fhe_bfv_partial(fhe_ctx ctx, fhe_ciphertext ct, fhe_keypair kp,
                         size_t* len) {
    try {
        auto& ctr = *static_cast<CtType*>(ct);
        auto& kpr = *static_cast<KpType*>(kp);
        const auto& cv = ctr->GetElements();
        auto s(kpr.secretKey->GetPrivateElement());
        size_t sizeQ = s.GetParams()->GetParams().size();
        size_t sizeQl = cv[0].GetParams()->GetParams().size();
        size_t diffQl = sizeQ - sizeQl;
        s.DropLastElements(diffQl);
        // No noise flooding: exact c_0 + s·c_1, safe for Lagrange combination.
        DCRTPoly b = cv[0] + s * cv[1];
        auto result = ctr->CloneEmpty();
        result->SetElement(std::move(b));
        return serialize_to_bytes(result, len);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bfv_partial: %s\n", e.what());
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

size_t fhe_bfv_shamir_decrypt(fhe_ctx ctx, fhe_ciphertext ct, fhe_keypair* kps,
                              const uint64_t* lambdas, const int64_t* masks, size_t n_keys,
                              int64_t* out, size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& ctr = *static_cast<CtType*>(ct);
        const auto& cv = ctr->GetElements();
        const auto cryptoParams =
            std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ctr->GetCryptoParameters());

        DCRTPoly b = cv[0] * NativeInteger(0);
        for (size_t i = 0; i < n_keys; i++) {
            auto& kpr = *static_cast<KpType*>(kps[i]);
            auto s(kpr.secretKey->GetPrivateElement());
            size_t sizeQ = s.GetParams()->GetParams().size();
            size_t sizeQl = cv[0].GetParams()->GetParams().size();
            if (sizeQ > sizeQl) {
                s.DropLastElements(sizeQ - sizeQl);
            }
            DCRTPoly bi = s * cv[1];
            // Per-modulus scaling: modulus j uses lambdas[j*n_keys + i].
            auto& bi_elements = bi.GetAllElements();
            for (size_t j = 0; j < bi_elements.size(); j++) {
                bi_elements[j] *= NativeInteger(lambdas[j * n_keys + i]);
            }
            // Subtract the plaintext-mask share `[r]_i` scaled by q/t.
            if (masks != nullptr) {
                std::vector<int64_t> vals(masks + i * len, masks + i * len + len);
                Plaintext mptxt = cc->MakePackedPlaintext(vals);
                DCRTPoly me = mptxt->GetElement<DCRTPoly>();
                auto mparams = me.GetParams();
                size_t sizeQfull = cryptoParams->GetElementParams()->GetParams().size();
                size_t sizeP = mparams->GetParams().size();
                size_t level = sizeQfull > sizeP ? sizeQfull - sizeP : 0;
                me.TimesQovert(mparams, cryptoParams->GettInvModq(),
                               cryptoParams->GetPlaintextModulus(),
                               cryptoParams->GetNegQModt(level),
                               cryptoParams->GetNegQModtPrecon(level));
                me.SetFormat(Format::EVALUATION);
                bi -= me;
            }
            b += bi;
        }
        b += cv[0];

        auto combined = ctr->CloneEmpty();
        combined->SetElement(std::move(b));

        std::vector<Ciphertext<DCRTPoly>> partial_vec;
        partial_vec.push_back(combined);
        Plaintext ptxt;
        cc->MultipartyDecryptFusion(partial_vec, &ptxt);
        ptxt->SetLength(len);
        const auto& values = ptxt->GetPackedValue();
        size_t n = values.size() < len ? values.size() : len;
        for (size_t i = 0; i < n; i++) {
            out[i] = values[i];
        }
        return n;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bfv_shamir_decrypt: %s\n", e.what());
        return 0;
    }
}

size_t fhe_bfv_shamir_fuse(fhe_ctx ctx, const uint8_t* const* partials, const size_t* lens,
                           const uint64_t* lambdas, size_t n_keys,
                           int64_t* out, size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        std::vector<Ciphertext<DCRTPoly>> pvec;
        pvec.reserve(n_keys);
        for (size_t i = 0; i < n_keys; i++) {
            Ciphertext<DCRTPoly> p;
            if (!deserialize_from_bytes(p, partials[i], lens[i])) {
                return 0;
            }
            pvec.push_back(p);
        }

        // b = Σ λ_i·p_i, where p_i = c_0 + s_i·c_1 (already contains c_0).
        DCRTPoly b = pvec[0]->GetElements()[0] * NativeInteger(0);
        for (size_t i = 0; i < n_keys; i++) {
            DCRTPoly bi = pvec[i]->GetElements()[0];
            auto& be = bi.GetAllElements();
            for (size_t j = 0; j < be.size(); j++) {
                be[j] *= NativeInteger(lambdas[j * n_keys + i]);
            }
            b += bi;
        }

        auto combined = pvec[0]->CloneEmpty();
        combined->SetElement(std::move(b));
        std::vector<Ciphertext<DCRTPoly>> partial_vec;
        partial_vec.push_back(combined);
        Plaintext ptxt;
        cc->MultipartyDecryptFusion(partial_vec, &ptxt);
        ptxt->SetLength(len);
        const auto& values = ptxt->GetPackedValue();
        size_t n = values.size() < len ? values.size() : len;
        for (size_t i = 0; i < n; i++) {
            out[i] = values[i];
        }
        return n;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bfv_shamir_fuse: %s\n", e.what());
        return 0;
    }
}

uint8_t* fhe_scale_partial(fhe_ctx ctx, fhe_ciphertext partial, uint64_t lambda,
                           size_t* len) {
    try {
        auto& p = *static_cast<CtType*>(partial);
        auto elements = p->GetElements();
        for (auto& e : elements) {
            e *= NativeInteger(lambda);
        }
        auto result = p->CloneEmpty();
        result->SetElements(elements);
        return serialize_to_bytes(result, len);
    } catch (...) {
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

uint8_t* fhe_add_partials(fhe_ctx ctx, fhe_ciphertext p1, fhe_ciphertext p2,
                          size_t* len) {
    try {
        auto& a = *static_cast<CtType*>(p1);
        auto& b = *static_cast<CtType*>(p2);
        auto ae = a->GetElements();
        auto be = b->GetElements();
        for (size_t i = 0; i < ae.size(); i++) {
            ae[i] += be[i];
        }
        auto result = a->CloneEmpty();
        result->SetElements(ae);
        return serialize_to_bytes(result, len);
    } catch (...) {
        if (len) {
            *len = 0;
        }
        return nullptr;
    }
}

fhe_ciphertext fhe_mod_reduce_to_level0(fhe_ctx ctx, fhe_ciphertext ct) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& ctr = *static_cast<CtType*>(ct);
        auto result = ctr;
        // Reduce to the lowest level that CKKS still supports (>= GetNoiseScaleDeg).
        size_t guard = 0;
        while (guard < 32) {
            try {
                result = cc->ModReduce(result);
                guard++;
            } catch (...) {
                break;
            }
        }
        return new CtType(result);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "mod_reduce: %s\n", e.what());
        return nullptr;
    }
}

fhe_ctx fhe_bfv_new(uint32_t mult_depth, uint32_t batch_size) {
    try {
        CCParams<CryptoContextBFVRNS> params;
        params.SetPlaintextModulus(65537);
        params.SetBatchSize(batch_size);
        params.SetMultiplicativeDepth(mult_depth);
        params.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);
        auto cc = GenCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(MULTIPARTY);
        return new CtxType(cc);
    } catch (...) {
        return nullptr;
    }
}

fhe_ciphertext fhe_bfv_encrypt_int(fhe_ctx ctx, fhe_keypair kp, const int64_t* data,
                                   size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& kpr = *static_cast<KpType*>(kp);
        std::vector<int64_t> vec(data, data + len);
        Plaintext ptxt = cc->MakePackedPlaintext(vec);
        return new CtType(cc->Encrypt(kpr.publicKey, ptxt));
    } catch (...) {
        return nullptr;
    }
}

size_t fhe_bfv_decrypt_int(fhe_ctx ctx, fhe_keypair kp, fhe_ciphertext ct, int64_t* out,
                           size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& kpr = *static_cast<KpType*>(kp);
        auto& ctr = *static_cast<CtType*>(ct);
        Plaintext ptxt;
        cc->Decrypt(kpr.secretKey, ctr, &ptxt);
        const auto& values = ptxt->GetPackedValue();
        size_t n = values.size() < len ? values.size() : len;
        for (size_t i = 0; i < n; i++) {
            out[i] = values[i];
        }
        return n;
    } catch (...) {
        return 0;
    }
}

size_t fhe_bfv_multiparty_decrypt(fhe_ctx ctx, fhe_ciphertext ct, fhe_keypair* kps,
                                  size_t n_keys, int64_t* out, size_t len) {
    try {
        auto cc = *static_cast<CtxType*>(ctx);
        auto& ctr = *static_cast<CtType*>(ct);
        std::vector<Ciphertext<DCRTPoly>> partial_vec;
        partial_vec.reserve(n_keys);
        for (size_t i = 0; i < n_keys; i++) {
            auto& kpr = *static_cast<KpType*>(kps[i]);
            Ciphertext<DCRTPoly> p;
            if (i == 0) {
                auto r = cc->MultipartyDecryptLead({ctr}, kpr.secretKey);
                p = r[0];
            } else {
                auto r = cc->MultipartyDecryptMain({ctr}, kpr.secretKey);
                p = r[0];
            }
            partial_vec.push_back(p);
        }
        Plaintext ptxt;
        cc->MultipartyDecryptFusion(partial_vec, &ptxt);
        ptxt->SetLength(len);
        const auto& values = ptxt->GetPackedValue();
        size_t n = values.size() < len ? values.size() : len;
        for (size_t i = 0; i < n; i++) {
            out[i] = values[i];
        }
        return n;
    } catch (...) {
        return 0;
    }
}

void fhe_free_ctx(fhe_ctx ctx) { delete static_cast<CtxType*>(ctx); }

void fhe_free_keypair(fhe_keypair kp) { delete static_cast<KpType*>(kp); }

void fhe_free_ciphertext(fhe_ciphertext ct) { delete static_cast<CtType*>(ct); }

void fhe_free_bytes(void* bytes) { std::free(bytes); }

}  // extern "C"
