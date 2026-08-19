//! FHE↔MPC bridge: converting between real CKKS ciphertexts and Shamir sharings (paper §3.1 H2S/S2H).
//!
//! Single-key version: H2S decrypts with OpenFHE to a plaintext, quantizes, then Shamir-shares;
//! S2H reconstructs the sharing, dequantizes, then encrypts with OpenFHE. Fixed-point quantization
//! maps a double into `F` (`scale` is the scaling factor). Threshold (Multiparty) semantics are
//! to be plugged in later, at which point the plaintext is no longer reconstructed.

use ark_ff::{BigInteger, PrimeField};
use ppsc_crypto::mpc::{Committee, ShamirShare};
use rand::Rng;

use crate::{Ciphertext, CkksContext, KeyPair};

/// FHE ciphertext → Shamir sharing (H2S): decrypt, quantize, Shamir-share.
pub fn fhe_to_sharing<F: PrimeField>(
    ctx: &CkksContext,
    kp: &KeyPair,
    ct: &Ciphertext,
    committee: &Committee<F>,
    scale: u64,
    rng: &mut impl Rng,
) -> Option<Vec<ShamirShare<F>>> {
    let vals = ctx.decrypt(kp, ct, 1)?;
    let m = (vals[0] * scale as f64).round() as i64;
    let f = i64_to_field(m);
    committee.split(f, rng).ok()
}

/// Shamir sharing → FHE ciphertext (S2H): reconstruct, dequantize, encrypt.
pub fn sharing_to_fhe<F: PrimeField>(
    ctx: &CkksContext,
    kp: &KeyPair,
    shares: &[ShamirShare<F>],
    committee: &Committee<F>,
    scale: u64,
) -> Option<Ciphertext> {
    let f = committee.reconstruct(shares).ok()?;
    let m = field_to_i64(f);
    let x = m as f64 / scale as f64;
    ctx.encrypt(kp, &[x])
}

fn i64_to_field<F: PrimeField>(m: i64) -> F {
    if m >= 0 {
        F::from_le_bytes_mod_order(&m.to_le_bytes())
    } else {
        -F::from_le_bytes_mod_order(&m.unsigned_abs().to_le_bytes())
    }
}

fn field_to_i64<F: PrimeField>(f: F) -> i64 {
    let big = f.into_bigint();
    if big > F::MODULUS_MINUS_ONE_DIV_TWO {
        let mut mag = F::MODULUS;
        let _ = mag.sub_with_borrow(&big);
        -bigint_to_i64::<F>(mag)
    } else {
        bigint_to_i64::<F>(big)
    }
}

fn bigint_to_i64<F: PrimeField>(big: F::BigInt) -> i64 {
    let bytes = big.to_bytes_le();
    let mut buf = [0_u8; 8];
    let n = bytes.len().min(8);
    buf[..n].copy_from_slice(&bytes[..n]);
    i64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CkksContext;
    use ark_bn254::Fr;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x0F0E_0D0C)
    }

    #[test]
    fn fhe_sharing_round_trips() {
        let ctx = CkksContext::new(3, 50, 8).expect("context");
        let kp = ctx.keygen().expect("keygen");
        let committee = Committee::<Fr>::new(2, 5).expect("committee");
        let scale = 1_000_000_u64;

        let x = 123.456_f64;
        let ct = ctx.encrypt(&kp, &[x]).expect("encrypt");

        let shares = fhe_to_sharing(&ctx, &kp, &ct, &committee, scale, &mut rng()).expect("h2s");
        let ct2 = sharing_to_fhe(&ctx, &kp, &shares, &committee, scale).expect("s2h");
        let dec = ctx.decrypt(&kp, &ct2, 1).expect("decrypt");

        assert!((dec[0] - x).abs() < 0.01, "{} != {}", dec[0], x);
    }
}
