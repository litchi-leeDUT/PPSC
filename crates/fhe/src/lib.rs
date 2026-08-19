//! Rust FFI bindings for the OpenFHE CKKS backend (single-key).
//!
//! Calls OpenFHE through the `capi.h`/`capi.cpp` C ABI wrapper. `unsafe` appears only at the FFI
//! boundary; handle types are RAII-wrapped and released on `Drop`.

#![allow(unsafe_code)]

use std::os::raw::c_void;

pub mod bfv_shamir;
pub mod dynamic;
pub mod hybrid;
pub mod network_conversion;
pub mod real_transfer;
pub mod shamir_fhe;

#[link(name = "ppsc_fhe_capi")]
extern "C" {
    fn fhe_ckks_new(
        mult_depth: u32,
        scale_mod_size: u32,
        batch_size: u32,
        first_mod_size: u32,
    ) -> *mut c_void;
    fn fhe_keygen(ctx: *mut c_void) -> *mut c_void;
    fn fhe_encrypt(ctx: *mut c_void, kp: *mut c_void, data: *const f64, len: usize) -> *mut c_void;
    fn fhe_decrypt(
        ctx: *mut c_void,
        kp: *mut c_void,
        ct: *mut c_void,
        out: *mut f64,
        len: usize,
    ) -> usize;
    fn fhe_eval_add(ctx: *mut c_void, a: *mut c_void, b: *mut c_void) -> *mut c_void;
    fn fhe_eval_mult(ctx: *mut c_void, a: *mut c_void, b: *mut c_void) -> *mut c_void;
    fn fhe_serialize_ciphertext(ct: *mut c_void, len: *mut usize) -> *mut u8;
    fn fhe_deserialize_ciphertext(ctx: *mut c_void, data: *const u8, len: usize) -> *mut c_void;
    fn fhe_serialize_pubkey(kp: *mut c_void, len: *mut usize) -> *mut u8;
    fn fhe_serialize_seckey(kp: *mut c_void, len: *mut usize) -> *mut u8;
    fn fhe_multiparty_keygen_first(ctx: *mut c_void) -> *mut c_void;
    fn fhe_multiparty_keygen_next(
        ctx: *mut c_void,
        prev_pubkey: *const u8,
        len: usize,
    ) -> *mut c_void;
    fn fhe_multiparty_keygen_next_kp(ctx: *mut c_void, prev_kp: *mut c_void) -> *mut c_void;
    fn fhe_multiparty_decrypt_lead(
        ctx: *mut c_void,
        ct: *mut c_void,
        kp: *mut c_void,
        len: *mut usize,
    ) -> *mut u8;
    fn fhe_multiparty_decrypt_main(
        ctx: *mut c_void,
        ct: *mut c_void,
        kp: *mut c_void,
        len: *mut usize,
    ) -> *mut u8;
    fn fhe_bfv_partial(
        ctx: *mut c_void,
        ct: *mut c_void,
        kp: *mut c_void,
        len: *mut usize,
    ) -> *mut u8;
    fn fhe_bfv_shamir_decrypt(
        ctx: *mut c_void,
        ct: *mut c_void,
        kps: *mut *mut c_void,
        lambdas: *const u64,
        masks: *const i64,
        n_keys: usize,
        out: *mut i64,
        len: usize,
    ) -> usize;
    fn fhe_bfv_shamir_fuse(
        ctx: *mut c_void,
        partials: *const *const u8,
        lens: *const usize,
        lambdas: *const u64,
        n_keys: usize,
        out: *mut i64,
        len: usize,
    ) -> usize;
    fn fhe_multiparty_decrypt_fusion(
        ctx: *mut c_void,
        partials: *const *const u8,
        lens: *const usize,
        n_partials: usize,
        out: *mut f64,
        len: usize,
    ) -> usize;
    fn fhe_bfv_fusion(
        ctx: *mut c_void,
        partials: *const *const u8,
        lens: *const usize,
        n_partials: usize,
        out: *mut i64,
        len: usize,
    ) -> usize;
    fn fhe_extract_secret_coeffs(ctx: *mut c_void, kp: *mut c_void, len: *mut usize) -> *mut u8;
    fn fhe_extract_moduli(ctx: *mut c_void, kp: *mut c_void, len: *mut usize) -> *mut u8;
    fn fhe_make_secret_from_coeffs(ctx: *mut c_void, data: *const u8, len: usize) -> *mut c_void;
    fn fhe_scale_partial(
        ctx: *mut c_void,
        partial: *mut c_void,
        lambda: u64,
        len: *mut usize,
    ) -> *mut u8;
    fn fhe_add_partials(
        ctx: *mut c_void,
        p1: *mut c_void,
        p2: *mut c_void,
        len: *mut usize,
    ) -> *mut u8;
    fn fhe_mod_reduce_to_level0(ctx: *mut c_void, ct: *mut c_void) -> *mut c_void;
    fn fhe_bfv_new(mult_depth: u32, batch_size: u32) -> *mut c_void;
    fn fhe_bfv_encrypt_int(
        ctx: *mut c_void,
        kp: *mut c_void,
        data: *const i64,
        len: usize,
    ) -> *mut c_void;
    fn fhe_bfv_decrypt_int(
        ctx: *mut c_void,
        kp: *mut c_void,
        ct: *mut c_void,
        out: *mut i64,
        len: usize,
    ) -> usize;
    fn fhe_bfv_multiparty_decrypt(
        ctx: *mut c_void,
        ct: *mut c_void,
        kps: *const *mut c_void,
        n_keys: usize,
        out: *mut i64,
        len: usize,
    ) -> usize;
    fn fhe_free_ctx(ctx: *mut c_void);
    fn fhe_free_keypair(kp: *mut c_void);
    fn fhe_free_ciphertext(ct: *mut c_void);
    fn fhe_free_bytes(bytes: *mut c_void);
}

fn take_bytes(ptr: *mut u8, len: usize) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    let mut v = Vec::with_capacity(len);
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, v.as_mut_ptr(), len);
        v.set_len(len);
        fhe_free_bytes(ptr as *mut c_void);
    }
    v
}

/// CKKS CryptoContext（RAII）。
pub struct CkksContext {
    raw: *mut c_void,
}

impl CkksContext {
    pub fn new(mult_depth: u32, scale_mod_size: u32, batch_size: u32) -> Option<Self> {
        let raw = unsafe { fhe_ckks_new(mult_depth, scale_mod_size, batch_size, 0) };
        if raw.is_null() {
            None
        } else {
            Some(Self { raw })
        }
    }

    pub fn keygen(&self) -> Option<KeyPair> {
        let raw = unsafe { fhe_keygen(self.raw) };
        if raw.is_null() {
            None
        } else {
            Some(KeyPair { raw })
        }
    }

    pub fn encrypt(&self, kp: &KeyPair, data: &[f64]) -> Option<Ciphertext> {
        let raw = unsafe { fhe_encrypt(self.raw, kp.raw, data.as_ptr(), data.len()) };
        if raw.is_null() {
            None
        } else {
            Some(Ciphertext { raw })
        }
    }

    pub fn decrypt(&self, kp: &KeyPair, ct: &Ciphertext, len: usize) -> Option<Vec<f64>> {
        let mut out = vec![0.0_f64; len];
        let n = unsafe { fhe_decrypt(self.raw, kp.raw, ct.raw, out.as_mut_ptr(), len) };
        if n == 0 {
            None
        } else {
            out.truncate(n);
            Some(out)
        }
    }

    pub fn eval_add(&self, a: &Ciphertext, b: &Ciphertext) -> Option<Ciphertext> {
        let raw = unsafe { fhe_eval_add(self.raw, a.raw, b.raw) };
        if raw.is_null() {
            None
        } else {
            Some(Ciphertext { raw })
        }
    }

    pub fn eval_mult(&self, a: &Ciphertext, b: &Ciphertext) -> Option<Ciphertext> {
        let raw = unsafe { fhe_eval_mult(self.raw, a.raw, b.raw) };
        if raw.is_null() {
            None
        } else {
            Some(Ciphertext { raw })
        }
    }

    /// Threshold key generation: the first party (`KeyGen`, starts the additive key sharing).
    pub fn multiparty_keygen_first(&self) -> Option<KeyPair> {
        let raw = unsafe { fhe_multiparty_keygen_first(self.raw) };
        if raw.is_null() {
            None
        } else {
            Some(KeyPair { raw })
        }
    }

    /// Threshold key generation: a subsequent party (`MultipartyKeyGen`, based on the previous party's public key).
    pub fn multiparty_keygen_next(&self, prev_pubkey: &[u8]) -> Option<KeyPair> {
        let raw = unsafe {
            fhe_multiparty_keygen_next(self.raw, prev_pubkey.as_ptr(), prev_pubkey.len())
        };
        if raw.is_null() {
            None
        } else {
            Some(KeyPair { raw })
        }
    }

    /// Threshold key generation: a subsequent party, based directly on the previous party's key handle (avoids public-key serialization).
    pub fn multiparty_keygen_next_kp(&self, prev_kp: &KeyPair) -> Option<KeyPair> {
        let raw = unsafe { fhe_multiparty_keygen_next_kp(self.raw, prev_kp.raw) };
        if raw.is_null() {
            None
        } else {
            Some(KeyPair { raw })
        }
    }

    /// Threshold-decryption partial (lead party), returns the serialized partial ciphertext.
    pub fn multiparty_decrypt_lead(&self, ct: &Ciphertext, kp: &KeyPair) -> Option<Vec<u8>> {
        let mut len = 0_usize;
        let ptr = unsafe { fhe_multiparty_decrypt_lead(self.raw, ct.raw, kp.raw, &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some(take_bytes(ptr, len))
        }
    }

    /// Threshold-decryption partial (main party), returns the serialized partial ciphertext.
    pub fn multiparty_decrypt_main(&self, ct: &Ciphertext, kp: &KeyPair) -> Option<Vec<u8>> {
        let mut len = 0_usize;
        let ptr = unsafe { fhe_multiparty_decrypt_main(self.raw, ct.raw, kp.raw, &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some(take_bytes(ptr, len))
        }
    }

    /// Fuse multiple decryption partials into the plaintext.
    pub fn multiparty_decrypt_fusion(&self, partials: &[Vec<u8>], len: usize) -> Option<Vec<f64>> {
        let ptrs: Vec<*const u8> = partials.iter().map(|p| p.as_ptr()).collect();
        let lens: Vec<usize> = partials.iter().map(|p| p.len()).collect();
        let mut out = vec![0.0_f64; len];
        let n = unsafe {
            fhe_multiparty_decrypt_fusion(
                self.raw,
                ptrs.as_ptr(),
                lens.as_ptr(),
                partials.len(),
                out.as_mut_ptr(),
                len,
            )
        };
        if n == 0 {
            None
        } else {
            out.truncate(n);
            Some(out)
        }
    }

    /// BFV fusion of decryption partials into integer plaintext.
    pub fn bfv_fusion(&self, partials: &[Vec<u8>], len: usize) -> Option<Vec<i64>> {
        let ptrs: Vec<*const u8> = partials.iter().map(|p| p.as_ptr()).collect();
        let lens: Vec<usize> = partials.iter().map(|p| p.len()).collect();
        let mut out = vec![0_i64; len];
        let n = unsafe {
            fhe_bfv_fusion(
                self.raw,
                ptrs.as_ptr(),
                lens.as_ptr(),
                partials.len(),
                out.as_mut_ptr(),
                len,
            )
        };
        if n == 0 {
            None
        } else {
            out.truncate(n);
            Some(out)
        }
    }

    /// Shamir partial `c_0 + s·c_1` (no noise flooding), serialized.
    pub fn bfv_share_partial(&self, ct: &Ciphertext, kp: &KeyPair) -> Option<Vec<u8>> {
        let mut len = 0_usize;
        let ptr = unsafe { fhe_bfv_partial(self.raw, ct.raw, kp.raw, &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some(take_bytes(ptr, len))
        }
    }

    /// Shamir-threshold BFV decrypt: `Σ λ_i·(c_0 + s_i·c_1)` then fuse.
    /// If `masks` is `Some`, each party's plaintext-mask share `[r]_i` is subtracted
    /// (scaled by q/t), so the fused result is `x - r` instead of `x`.
    /// `lambdas` layout: `[modulus0's n_keys | modulus1's n_keys | ...]`.
    /// `masks` layout: `[party i slot k] = masks[i*len + k]`.
    pub fn bfv_shamir_decrypt(
        &self,
        ct: &Ciphertext,
        party_keys: &[KeyPair],
        lambdas: &[u64],
        masks: Option<&[i64]>,
        len: usize,
    ) -> Option<Vec<i64>> {
        let ptrs: Vec<*mut c_void> = party_keys.iter().map(|k| k.raw).collect();
        let masks_ptr = masks.map_or(std::ptr::null(), |m| m.as_ptr());
        let mut out = vec![0_i64; len];
        let n = unsafe {
            fhe_bfv_shamir_decrypt(
                self.raw,
                ct.raw,
                ptrs.as_ptr() as *mut *mut c_void,
                lambdas.as_ptr(),
                masks_ptr,
                party_keys.len(),
                out.as_mut_ptr(),
                len,
            )
        };
        if n == 0 {
            None
        } else {
            out.truncate(n);
            Some(out)
        }
    }

    /// Fuse already-computed Shamir partials with per-modulus Lagrange coefficients.
    /// `partials` are serialized single-element ciphertexts `c_0 + s_i·c_1`.
    /// `lambdas` layout: `[modulus0's n_keys | modulus1's n_keys | ...]`.
    pub fn bfv_shamir_fuse(
        &self,
        partials: &[Vec<u8>],
        lambdas: &[u64],
        len: usize,
    ) -> Option<Vec<i64>> {
        let ptrs: Vec<*const u8> = partials.iter().map(|p| p.as_ptr()).collect();
        let lens: Vec<usize> = partials.iter().map(|p| p.len()).collect();
        let mut out = vec![0_i64; len];
        let n = unsafe {
            fhe_bfv_shamir_fuse(
                self.raw,
                ptrs.as_ptr(),
                lens.as_ptr(),
                lambdas.as_ptr(),
                partials.len(),
                out.as_mut_ptr(),
                len,
            )
        };
        if n == 0 {
            None
        } else {
            out.truncate(n);
            Some(out)
        }
    }

    /// Extract the secret-key coefficients (first modulus, conversion layer), little-endian u64.
    pub fn extract_secret_coeffs(&self, kp: &KeyPair) -> Option<Vec<u64>> {
        let mut len = 0_usize;
        let ptr = unsafe { fhe_extract_secret_coeffs(self.raw, kp.raw, &mut len) };
        if ptr.is_null() {
            return None;
        }
        let bytes = take_bytes(ptr, len);
        let coeffs = bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes")))
            .collect();
        Some(coeffs)
    }

    /// Extract the RNS modulus list of the secret key, one u64 per modulus.
    pub fn extract_moduli(&self, kp: &KeyPair) -> Option<Vec<u64>> {
        let mut len = 0_usize;
        let ptr = unsafe { fhe_extract_moduli(self.raw, kp.raw, &mut len) };
        if ptr.is_null() {
            return None;
        }
        let bytes = take_bytes(ptr, len);
        let moduli = bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes")))
            .collect();
        Some(moduli)
    }

    /// Construct a secret key from coefficients (first modulus = given coefficients; for Shamir share keys).
    pub fn make_secret_from_coeffs(&self, coeffs: &[u64]) -> Option<KeyPair> {
        let bytes: Vec<u8> = coeffs.iter().flat_map(|c| c.to_le_bytes()).collect();
        let raw = unsafe { fhe_make_secret_from_coeffs(self.raw, bytes.as_ptr(), bytes.len()) };
        if raw.is_null() {
            None
        } else {
            Some(KeyPair { raw })
        }
    }

    /// Scale a partial ciphertext by a Lagrange coefficient.
    pub fn scale_partial(&self, partial: &[u8], lambda: u64) -> Option<Vec<u8>> {
        let p = Ciphertext::deserialize(self, partial)?;
        let mut len = 0_usize;
        let ptr = unsafe { fhe_scale_partial(self.raw, p.raw, lambda, &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some(take_bytes(ptr, len))
        }
    }

    /// Add two partial ciphertexts.
    pub fn add_partials(&self, p1: &[u8], p2: &[u8]) -> Option<Vec<u8>> {
        let a = Ciphertext::deserialize(self, p1)?;
        let b = Ciphertext::deserialize(self, p2)?;
        let mut len = 0_usize;
        let ptr = unsafe { fhe_add_partials(self.raw, a.raw, b.raw, &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some(take_bytes(ptr, len))
        }
    }

    /// Reduce the ciphertext to level 0 (single modulus q_0).
    pub fn mod_reduce_to_level0(&self, ct: &Ciphertext) -> Option<Ciphertext> {
        let raw = unsafe { fhe_mod_reduce_to_level0(self.raw, ct.raw) };
        if raw.is_null() {
            None
        } else {
            Some(Ciphertext { raw })
        }
    }

    /// BFV context (integer plaintext, single plaintext modulus p = 65537).
    pub fn bfv_new(mult_depth: u32, batch_size: u32) -> Option<Self> {
        let raw = unsafe { fhe_bfv_new(mult_depth, batch_size) };
        if raw.is_null() {
            None
        } else {
            Some(Self { raw })
        }
    }

    /// BFV-encrypt an integer vector.
    pub fn bfv_encrypt_int(&self, kp: &KeyPair, data: &[i64]) -> Option<Ciphertext> {
        let raw = unsafe { fhe_bfv_encrypt_int(self.raw, kp.raw, data.as_ptr(), data.len()) };
        if raw.is_null() {
            None
        } else {
            Some(Ciphertext { raw })
        }
    }

    /// BFV-decrypt an integer vector.
    pub fn bfv_decrypt_int(&self, kp: &KeyPair, ct: &Ciphertext, len: usize) -> Option<Vec<i64>> {
        let mut out = vec![0_i64; len];
        let n = unsafe { fhe_bfv_decrypt_int(self.raw, kp.raw, ct.raw, out.as_mut_ptr(), len) };
        if n == 0 {
            None
        } else {
            out.truncate(n);
            Some(out)
        }
    }

    /// BFV Multiparty fusion into integer plaintext.
    pub fn bfv_multiparty_decrypt(
        &self,
        ct: &Ciphertext,
        kps: &[KeyPair],
        len: usize,
    ) -> Option<Vec<i64>> {
        let ptrs: Vec<*mut c_void> = kps.iter().map(|k| k.raw).collect();
        let mut out = vec![0_i64; len];
        let n = unsafe {
            fhe_bfv_multiparty_decrypt(
                self.raw,
                ct.raw,
                ptrs.as_ptr(),
                kps.len(),
                out.as_mut_ptr(),
                len,
            )
        };
        if n == 0 {
            None
        } else {
            out.truncate(n);
            Some(out)
        }
    }
}

impl Drop for CkksContext {
    fn drop(&mut self) {
        unsafe { fhe_free_ctx(self.raw) };
    }
}

/// CKKS key pair (RAII).
pub struct KeyPair {
    raw: *mut c_void,
}

impl KeyPair {
    pub fn serialize_pubkey(&self) -> Option<Vec<u8>> {
        let mut len = 0_usize;
        let ptr = unsafe { fhe_serialize_pubkey(self.raw, &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some(take_bytes(ptr, len))
        }
    }

    pub fn serialize_seckey(&self) -> Option<Vec<u8>> {
        let mut len = 0_usize;
        let ptr = unsafe { fhe_serialize_seckey(self.raw, &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some(take_bytes(ptr, len))
        }
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        unsafe { fhe_free_keypair(self.raw) };
    }
}

/// CKKS ciphertext (RAII).
pub struct Ciphertext {
    raw: *mut c_void,
}

impl Ciphertext {
    pub fn serialize(&self) -> Option<Vec<u8>> {
        let mut len = 0_usize;
        let ptr = unsafe { fhe_serialize_ciphertext(self.raw, &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some(take_bytes(ptr, len))
        }
    }

    pub fn deserialize(ctx: &CkksContext, bytes: &[u8]) -> Option<Self> {
        let raw = unsafe { fhe_deserialize_ciphertext(ctx.raw, bytes.as_ptr(), bytes.len()) };
        if raw.is_null() {
            None
        } else {
            Some(Self { raw })
        }
    }
}

impl Drop for Ciphertext {
    fn drop(&mut self) {
        unsafe { fhe_free_ciphertext(self.raw) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ckks_encrypt_decrypt_round_trips() {
        let ctx = CkksContext::new(3, 50, 8).expect("context");
        let kp = ctx.keygen().expect("keygen");
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let ct = ctx.encrypt(&kp, &data).expect("encrypt");
        let dec = ctx.decrypt(&kp, &ct, data.len()).expect("decrypt");
        for (a, b) in dec.iter().zip(data.iter()) {
            assert!((a - b).abs() < 0.01, "{a} != {b}");
        }
    }

    #[test]
    fn ckks_serialize_round_trips() {
        let ctx = CkksContext::new(3, 50, 8).expect("context");
        let kp = ctx.keygen().expect("keygen");
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let ct = ctx.encrypt(&kp, &data).expect("encrypt");
        let bytes = ct.serialize().expect("serialize");
        let ct2 = Ciphertext::deserialize(&ctx, &bytes).expect("deserialize");
        let dec = ctx.decrypt(&kp, &ct2, data.len()).expect("decrypt");
        for (a, b) in dec.iter().zip(data.iter()) {
            assert!((a - b).abs() < 0.01, "{a} != {b}");
        }
    }

    #[test]
    fn ckks_eval_add_is_homomorphic() {
        let ctx = CkksContext::new(3, 50, 8).expect("context");
        let kp = ctx.keygen().expect("keygen");
        let a = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let b = vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0];
        let ca = ctx.encrypt(&kp, &a).expect("encrypt a");
        let cb = ctx.encrypt(&kp, &b).expect("encrypt b");
        let sum = ctx.eval_add(&ca, &cb).expect("add");
        let dec = ctx.decrypt(&kp, &sum, a.len()).expect("decrypt");
        for (d, (x, y)) in dec.iter().zip(a.iter().zip(b.iter())) {
            assert!((d - (x + y)).abs() < 0.01, "{d} != {} + {}", x, y);
        }
    }

    #[test]
    fn multiparty_threshold_decrypt() {
        let ctx = CkksContext::new(3, 50, 8).expect("context");

        let kp1 = ctx.multiparty_keygen_first().expect("kp1");
        let pk1 = kp1.serialize_pubkey().expect("pk1");
        let kp2 = ctx.multiparty_keygen_next(&pk1).expect("kp2");
        let pk2 = kp2.serialize_pubkey().expect("pk2");
        let kp3 = ctx.multiparty_keygen_next(&pk2).expect("kp3");

        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let ct = ctx.encrypt(&kp3, &data).expect("encrypt");

        let p1 = ctx.multiparty_decrypt_lead(&ct, &kp1).expect("lead");
        let p2 = ctx.multiparty_decrypt_main(&ct, &kp2).expect("main2");
        let p3 = ctx.multiparty_decrypt_main(&ct, &kp3).expect("main3");

        let dec = ctx
            .multiparty_decrypt_fusion(&[p1, p2, p3], data.len())
            .expect("fusion");
        for (a, b) in dec.iter().zip(data.iter()) {
            assert!((a - b).abs() < 0.01, "{a} != {b}");
        }
    }
}
