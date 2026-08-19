//! Shamir threshold FHE (t-of-n; the Shamir key sharing of paper §2.1/§3.1).
//!
//! Coefficient-wise Shamir sharing over the prime field `Fp60` matching OpenFHE's first modulus
//! `q_0` (MODULUS = q_0 = 1152921504606748673 for batch_size=8). Each party constructs a secret
//! key from its share, computes a partial, then Lagrange-weight-combines them into the plaintext.

use ark_ff::{BigInt, Fp, MontBackend, MontConfig, PrimeField};
use ppsc_crypto::mpc::Committee;
use rand::Rng;
use std::marker::PhantomData;

use crate::{Ciphertext, CkksContext, KeyPair};

/// 60-bit prime field, modulus = OpenFHE CKKS's first modulus q_0 (batch_size=8).
pub struct Fp60Config;

impl MontConfig<1> for Fp60Config {
    const MODULUS: BigInt<1> = BigInt::new([1152921504606748673_u64]);
    const GENERATOR: Fp<MontBackend<Self, 1>, 1> = Fp(BigInt::new([2_u64]), PhantomData);
    // Shamir sharing only needs +,-,*,inverse; no 2-adic root of unity needed, use any non-zero value.
    const TWO_ADIC_ROOT_OF_UNITY: Fp<MontBackend<Self, 1>, 1> =
        Fp(BigInt::new([1_u64]), PhantomData);
}

pub type Fp60 = Fp<MontBackend<Fp60Config, 1>, 1>;

pub fn fp60_to_u64(f: Fp60) -> u64 {
    f.into_bigint().0[0]
}

/// Ring dimension N (CKKS ring dimension = 16384 for batch_size=8).
const RING_DIM: usize = 16384;

/// Coefficient-wise Shamir-share the full secret key (first modulus q_0 only);
/// the remaining (noise) moduli keep their original coefficients. Returns each party's share key.
pub fn share_secret_key(
    ctx: &CkksContext,
    kp: &KeyPair,
    committee: &Committee<Fp60>,
    rng: &mut impl Rng,
) -> Option<Vec<KeyPair>> {
    let coeffs = ctx.extract_secret_coeffs(kp)?;
    let n = committee.size();
    let mut party_coeffs = vec![coeffs.clone(); n];
    for (idx, &c) in coeffs[..RING_DIM].iter().enumerate() {
        let f = Fp60::from(c);
        let shares = committee.split(f, rng).ok()?;
        for (i, share) in shares.iter().enumerate() {
            party_coeffs[i][idx] = fp60_to_u64(share.value());
        }
    }
    let mut result = Vec::with_capacity(n);
    for c in &party_coeffs {
        result.push(ctx.make_secret_from_coeffs(c)?);
    }
    Some(result)
}

/// Lagrange coefficients at `X=0` of the first `threshold + 1` points (the qualified set).
pub fn lagrange_coeffs(committee: &Committee<Fp60>, threshold: usize) -> Vec<Fp60> {
    let points = &committee.points[..threshold + 1];
    points
        .iter()
        .enumerate()
        .map(|(i, &pi)| {
            let mut li = Fp60::from(1_u64);
            for (j, &pj) in points.iter().enumerate() {
                if i != j {
                    li *= -pj / (pi - pj);
                }
            }
            li
        })
        .collect()
}

/// Shamir threshold decryption: the first `threshold + 1` parties compute partials with their shares, then Lagrange-combine into the plaintext.
///
/// Note: currently unusable because of OpenFHE's RNS multi-modulus (CKKS) — Lagrange combination
/// is incorrect on non-first moduli; see `bfv_shamir.rs` for the plaintext-space scheme.
pub fn threshold_decrypt(
    ctx: &CkksContext,
    ct: &Ciphertext,
    party_keys: &[KeyPair],
    committee: &Committee<Fp60>,
    threshold: usize,
    len: usize,
) -> Option<Vec<f64>> {
    let lambdas = lagrange_coeffs(committee, threshold);

    let mut combined: Option<Vec<u8>> = None;
    for (i, kp) in party_keys.iter().take(threshold + 1).enumerate() {
        let partial = ctx.multiparty_decrypt_main(ct, kp)?;
        let scaled = ctx.scale_partial(&partial, fp60_to_u64(lambdas[i]))?;
        combined = match combined {
            None => Some(scaled),
            Some(prev) => ctx.add_partials(&prev, &scaled),
        };
    }
    let combined = combined?;
    ctx.multiparty_decrypt_fusion(&[combined], len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x1234_5678)
    }

    #[test]
    fn fp60_field_axioms() {
        let a = Fp60::from(12345_u64);
        let b = Fp60::from(67890_u64);
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);
        assert_eq!(a * a.inverse().expect("inv"), Fp60::from(1_u64));
    }

    #[test]
    #[ignore = "OpenFHE CKKS's RNS multi-modulus makes Lagrange combination incorrect on non-first moduli; use the bfv_shamir plaintext-space scheme instead"]
    fn shamir_threshold_decrypt() {
        let ctx = CkksContext::new(3, 50, 8).expect("context");
        let kp = ctx.keygen().expect("keygen");
        let committee = Committee::<Fp60>::new(2, 5).expect("committee");

        let party_keys = share_secret_key(&ctx, &kp, &committee, &mut rng()).expect("share");
        assert_eq!(party_keys.len(), 5);

        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let ct = ctx.encrypt(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        let dec = threshold_decrypt(&ctx, &ct0, &party_keys, &committee, 2, data.len())
            .expect("threshold decrypt");
        for (a, b) in dec.iter().zip(data.iter()) {
            assert!((a - b).abs() < 0.5, "{a} != {b}");
        }
    }
}
