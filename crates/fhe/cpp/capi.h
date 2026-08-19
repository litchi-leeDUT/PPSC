#ifndef PPSC_FHE_CAPI_H
#define PPSC_FHE_CAPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles to OpenFHE C++ objects. */
typedef void* fhe_ctx;
typedef void* fhe_keypair;
typedef void* fhe_ciphertext;

/* Create a CKKS CryptoContext.
 * mult_depth: multiplicative depth, scale_mod_size: scaling modulus bits,
 * batch_size: number of slots, first_mod_size: first modulus bits (0 = default).
 * Returns NULL on failure. */
fhe_ctx fhe_ckks_new(uint32_t mult_depth, uint32_t scale_mod_size,
                     uint32_t batch_size, uint32_t first_mod_size);

/* Generate a key pair. Returns NULL on failure. */
fhe_keypair fhe_keygen(fhe_ctx ctx);

/* Encrypt a vector of doubles (length = batch_size). Returns NULL on failure. */
fhe_ciphertext fhe_encrypt(fhe_ctx ctx, fhe_keypair kp, const double* data,
                           size_t len);

/* Decrypt into a vector of doubles. Returns number of slots written, 0 on failure. */
size_t fhe_decrypt(fhe_ctx ctx, fhe_keypair kp, fhe_ciphertext ct, double* out,
                   size_t len);

/* Homomorphic evaluation. */
fhe_ciphertext fhe_eval_add(fhe_ctx ctx, fhe_ciphertext a, fhe_ciphertext b);
fhe_ciphertext fhe_eval_mult(fhe_ctx ctx, fhe_ciphertext a, fhe_ciphertext b);

/* Serialize/deserialize (binary, malloc'ed).
 * The returned buffer must be released with fhe_free_bytes. */
uint8_t* fhe_serialize_ciphertext(fhe_ciphertext ct, size_t* len);
fhe_ciphertext fhe_deserialize_ciphertext(fhe_ctx ctx, const uint8_t* data, size_t len);

uint8_t* fhe_serialize_pubkey(fhe_keypair kp, size_t* len);
uint8_t* fhe_serialize_seckey(fhe_keypair kp, size_t* len);

/* Multiparty (threshold) key generation and decryption. */

/* First party: generate its key pair (starts the additive key sharing). */
fhe_keypair fhe_multiparty_keygen_first(fhe_ctx ctx);

/* Subsequent party: generate key pair from the previous party's public key. */
fhe_keypair fhe_multiparty_keygen_next(fhe_ctx ctx, const uint8_t* prev_pubkey,
                                       size_t len);

/* Subsequent party, from a keypair handle directly (avoids serialization). */
fhe_keypair fhe_multiparty_keygen_next_kp(fhe_ctx ctx, fhe_keypair prev_kp);

/* Partial decryption (lead / main). Returns a serialized partial ciphertext. */
uint8_t* fhe_multiparty_decrypt_lead(fhe_ctx ctx, fhe_ciphertext ct,
                                     fhe_keypair kp, size_t* len);
uint8_t* fhe_multiparty_decrypt_main(fhe_ctx ctx, fhe_ciphertext ct,
                                     fhe_keypair kp, size_t* len);

/* Shamir partial: `c_0 + s·c_1` (no noise flooding), serialized. */
uint8_t* fhe_bfv_partial(fhe_ctx ctx, fhe_ciphertext ct, fhe_keypair kp, size_t* len);

/* Shamir-threshold BFV decrypt: combined = Σ λ_i·(c_0 + s_i·c_1), then fuse.
 * masks (optional): per-party plaintext-mask slot shares [r]_i, so the fused result
 * is (x - r) instead of x. Layout: masks[i*len + k] = party i, slot k. */
size_t fhe_bfv_shamir_decrypt(fhe_ctx ctx, fhe_ciphertext ct, fhe_keypair* kps,
                              const uint64_t* lambdas, const int64_t* masks, size_t n_keys,
                              int64_t* out, size_t len);

/* Fuse already-computed Shamir partials (serialized single-element ciphertexts `c_0 + s_i·c_1`)
 * with per-modulus Lagrange coefficients. */
size_t fhe_bfv_shamir_fuse(fhe_ctx ctx, const uint8_t* const* partials, const size_t* lens,
                           const uint64_t* lambdas, size_t n_keys,
                           int64_t* out, size_t len);

/* Fuse partial decryptions into the plaintext. Returns slots written, 0 on failure. */
size_t fhe_multiparty_decrypt_fusion(fhe_ctx ctx, const uint8_t* const* partials,
                                     const size_t* lens, size_t n_partials,
                                     double* out, size_t len);

/* BFV fusion: same as above but with integer (GetPackedValue) plaintext output. */
size_t fhe_bfv_fusion(fhe_ctx ctx, const uint8_t* const* partials,
                      const size_t* lens, size_t n_partials,
                      int64_t* out, size_t len);

/* Shamir-threshold secret-key sharing (coefficient-wise over the first modulus,
 * i.e. the conversion level). */

/* Extract the secret-key coefficients (first modulus) as little-endian u64s. */
uint8_t* fhe_extract_secret_coeffs(fhe_ctx ctx, fhe_keypair kp, size_t* len);

/* Extract the RNS modulus list of the secret key, as u64s (one per modulus). */
uint8_t* fhe_extract_moduli(fhe_ctx ctx, fhe_keypair kp, size_t* len);

/* Build a secret key whose first-modulus coefficients equal the given u64s. */
fhe_keypair fhe_make_secret_from_coeffs(fhe_ctx ctx, const uint8_t* data, size_t len);

/* Scale a partial ciphertext by an integer Lagrange coefficient. */
uint8_t* fhe_scale_partial(fhe_ctx ctx, fhe_ciphertext partial, uint64_t lambda, size_t* len);

/* Add two partial ciphertexts. */
uint8_t* fhe_add_partials(fhe_ctx ctx, fhe_ciphertext p1, fhe_ciphertext p2, size_t* len);

/* Reduce a ciphertext to level 0 (single modulus q_0), matching the Shamir field. */
fhe_ciphertext fhe_mod_reduce_to_level0(fhe_ctx ctx, fhe_ciphertext ct);

/* BFV (integer plaintext, single modulus p = 65537). */
fhe_ctx fhe_bfv_new(uint32_t mult_depth, uint32_t batch_size);
fhe_ciphertext fhe_bfv_encrypt_int(fhe_ctx ctx, fhe_keypair kp, const int64_t* data,
                                   size_t len);
size_t fhe_bfv_decrypt_int(fhe_ctx ctx, fhe_keypair kp, fhe_ciphertext ct, int64_t* out,
                           size_t len);

/* BFV multiparty decrypt directly (partials kept in C++), output integer plaintext. */
size_t fhe_bfv_multiparty_decrypt(fhe_ctx ctx, fhe_ciphertext ct, fhe_keypair* kps,
                                  size_t n_keys, int64_t* out, size_t len);

/* Free an opaque handle. */
void fhe_free_ctx(fhe_ctx ctx);
void fhe_free_keypair(fhe_keypair kp);
void fhe_free_ciphertext(fhe_ciphertext ct);
void fhe_free_bytes(void* bytes);

#ifdef __cplusplus
}
#endif

#endif /* PPSC_FHE_CAPI_H */
