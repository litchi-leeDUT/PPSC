//! H2S/S2H bridge between BFV/BGV ciphertexts and MPC sharings (paper §3.1).
//!
//! BFV's plaintext space is a single modulus `p = 65537`, used only to **store** encrypted
//! balances; MPC sharing is over `Fr` (254-bit prime field, the paper's large coefficient modulus
//! `Q`), so comparison/conditional transfer are not limited by the 16-bit `q/2` boundary.
//!
//! H2S: Multiparty (additive shares, n-of-n) decryption yields integer plaintexts, which are then
//! Shamir-shared (t-of-n) over `Fr`. S2H: the `Fr` sharing is reconstructed back to integer
//! plaintext and re-encrypted. Unlike the paper's "Shamir key threshold" (partials use Shamir
//! shares), decryption here uses additive shares (n-of-n) and the plaintext sharing is t-of-n —
//! dictated by OpenFHE Multiparty's additive structure.

use ark_bn254::Fr;
use ppsc_crypto::mpc::{Committee, ShamirShare};
use rand::Rng;

use crate::dynamic::{eval_points, split, DynField};
use crate::{Ciphertext, CkksContext, KeyPair};

fn int_to_field(x: i64) -> Fr {
    Fr::from(x.rem_euclid(65537) as u64)
}

fn field_to_int(f: Fr) -> i64 {
    use ark_ff::PrimeField;
    f.into_bigint().0[0] as i64
}

/// After Multiparty decryption, Shamir-share (t-of-n) each plaintext value over `Fr`.
/// Returns `batch` sharing vectors (one sharing per plaintext value).
pub fn bfv_share_plaintext(
    ctx: &CkksContext,
    ct: &Ciphertext,
    party_keys: &[KeyPair],
    committee: &Committee<Fr>,
    batch: usize,
    rng: &mut impl Rng,
) -> Option<Vec<Vec<ShamirShare<Fr>>>> {
    let plaintext = ctx.bfv_multiparty_decrypt(ct, party_keys, batch)?;

    let mut result = Vec::with_capacity(batch);
    for &x in plaintext.iter() {
        result.push(committee.split(int_to_field(x), rng).ok()?);
    }
    Some(result)
}

/// H2S via Shamir key threshold (t-of-n): the full key is Shamir-shared per modulus, and
/// only `threshold + 1` share keys are needed to decrypt. Each plaintext value is then
/// Shamir-shared (t-of-n) over `Fr`.
#[allow(clippy::too_many_arguments)]
pub fn bfv_share_plaintext_threshold(
    ctx: &CkksContext,
    ct: &Ciphertext,
    full_key: &KeyPair,
    threshold: usize,
    n_parties: usize,
    committee: &Committee<Fr>,
    batch: usize,
    rng: &mut impl Rng,
) -> Option<Vec<Vec<ShamirShare<Fr>>>> {
    let party_keys = bfv_share_key_per_modulus(ctx, full_key, threshold, n_parties, rng)?;
    let moduli = ctx.extract_moduli(full_key)?;
    let lambdas_per_modulus = per_modulus_lambdas(&moduli, n_parties, threshold);
    let n_keys = threshold + 1;
    let mut lambdas = Vec::with_capacity(moduli.len() * n_keys);
    for lj in &lambdas_per_modulus {
        lambdas.extend_from_slice(lj);
    }

    let plaintext = ctx.bfv_shamir_decrypt(ct, &party_keys[..n_keys], &lambdas, None, batch)?;

    let mut result = Vec::with_capacity(batch);
    for &x in plaintext.iter() {
        result.push(committee.split(int_to_field(x), rng).ok()?);
    }
    Some(result)
}

/// S2H: `Fr` sharing →BFV ciphertext (reconstruct the plaintext, then encrypt).
pub fn bfv_shares_to_ciphertext(
    ctx: &CkksContext,
    kp: &KeyPair,
    shares: &[Vec<ShamirShare<Fr>>],
    committee: &Committee<Fr>,
) -> Option<Ciphertext> {
    let mut plaintext = Vec::with_capacity(shares.len());
    for share_vec in shares {
        let f = committee.reconstruct(share_vec).ok()?;
        plaintext.push(field_to_int(f));
    }
    ctx.bfv_encrypt_int(kp, &plaintext)
}

/// Per-modulus Shamir-share the BFV secret key (t-of-n over each `F_{q_j}`).
/// Returns `n_parties` share keys rebuilt via `make_secret_from_coeffs`.
pub fn bfv_share_key_per_modulus(
    ctx: &CkksContext,
    kp: &KeyPair,
    threshold: usize,
    n_parties: usize,
    rng: &mut impl Rng,
) -> Option<Vec<KeyPair>> {
    let coeffs = ctx.extract_secret_coeffs(kp)?;
    let moduli = ctx.extract_moduli(kp)?;
    let n_moduli = moduli.len();
    let ring_dim = coeffs.len() / n_moduli;

    let mut party_coeffs = vec![coeffs.clone(); n_parties];

    for (j, &q) in moduli.iter().enumerate() {
        let pts = eval_points(q, n_parties);
        for idx in 0..ring_dim {
            let secret = DynField::new(coeffs[j * ring_dim + idx], q);
            let shares = split(&secret, threshold, &pts, rng);
            for (i, share) in shares.iter().enumerate() {
                party_coeffs[i][j * ring_dim + idx] = share.value.value();
            }
        }
    }

    let mut result = Vec::with_capacity(n_parties);
    for c in party_coeffs {
        result.push(ctx.make_secret_from_coeffs(&c)?);
    }
    Some(result)
}

/// Lagrange coefficients at `X=0` for the first `threshold+1` parties, per modulus.
/// Returns `lambdas[j]` = the `threshold+1` coefficients in `F_{q_j}`.
pub fn per_modulus_lambdas(moduli: &[u64], n_parties: usize, threshold: usize) -> Vec<Vec<u64>> {
    moduli
        .iter()
        .map(|&q| {
            let pts = eval_points(q, n_parties);
            (0..=threshold)
                .map(|i| {
                    let pi = pts[i];
                    let mut li = DynField::one(q);
                    for (j, &pj) in pts[..=threshold].iter().enumerate() {
                        if j != i {
                            let denom = pi.sub(&pj);
                            li = li.mul(&DynField::zero(q).sub(&pj).div(&denom));
                        }
                    }
                    li.value()
                })
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ppsc_crypto::mpc::{conditional_transfer_strictly_greater, generate_bit_extract_pair, F2};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x0B0F_0F0E)
    }

    #[test]
    fn bfv_single_key_round_trips() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let dec = ctx.bfv_decrypt_int(&kp, &ct, 8).expect("decrypt");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, *b, "slot {i}");
        }
    }

    #[test]
    fn bfv_level0_decrypt_round_trips() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");
        let dec = ctx.bfv_decrypt_int(&kp, &ct0, 8).expect("decrypt");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, *b, "level0 slot {i}");
        }
    }

    #[test]
    fn bfv_share_plaintext_threshold_works() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let committee = Committee::<Fr>::new(2, 5).expect("committee");

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");

        // H2S via Shamir key threshold (t=2, n=5): only 3 share keys needed.
        let shares = bfv_share_plaintext_threshold(&ctx, &ct, &kp, 2, 5, &committee, 8, &mut rng())
            .expect("threshold h2s");
        assert_eq!(shares.len(), 8);
        for (i, share_vec) in shares.iter().enumerate() {
            let v = committee.reconstruct(share_vec).expect("reconstruct");
            assert_eq!(field_to_int(v), data[i] % 65537, "slot {i}");
        }
    }

    #[test]
    fn bfv_level0_multiparty_decrypt_works() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp1 = ctx.multiparty_keygen_first().expect("kp1");
        let kp2 = ctx.multiparty_keygen_next_kp(&kp1).expect("kp2");
        let kp3 = ctx.multiparty_keygen_next_kp(&kp2).expect("kp3");
        let party_keys = vec![kp1, kp2, kp3];

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&party_keys[2], &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        let dec = ctx
            .bfv_multiparty_decrypt(&ct0, &party_keys, 8)
            .expect("multiparty decrypt");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, *b, "level0 multiparty slot {i}");
        }
    }

    #[test]
    fn bfv_manual_partial_combination_works() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp1 = ctx.multiparty_keygen_first().expect("kp1");
        let kp2 = ctx.multiparty_keygen_next_kp(&kp1).expect("kp2");
        let kp3 = ctx.multiparty_keygen_next_kp(&kp2).expect("kp3");

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp3, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        // Manually combine partials (the steps before the internal BFV fusion).
        let p1 = ctx.multiparty_decrypt_lead(&ct0, &kp1).expect("p1 lead");
        let p2 = ctx.multiparty_decrypt_main(&ct0, &kp2).expect("p2 main");
        let p3 = ctx.multiparty_decrypt_main(&ct0, &kp3).expect("p3 main");
        let comb = ctx.add_partials(&p1, &p2).expect("add p1+p2");
        let comb = ctx.add_partials(&comb, &p3).expect("add +p3");

        let dec = ctx.bfv_fusion(&[comb], 8).expect("fusion");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, *b, "manual partial slot {i}");
        }
    }

    #[test]
    fn bfv_secret_coeffs_domain() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let coeffs = ctx.extract_secret_coeffs(&kp).expect("coeffs");
        let n = coeffs.len();
        let first_mod_max = coeffs[..16384].iter().copied().max().unwrap_or(0);
        let all_max = coeffs.iter().copied().max().unwrap_or(0);
        eprintln!(
            "n={n}, first_mod_max={first_mod_max}, all_max={all_max}, \
             Fp60={}, 2^60={}",
            1152921504606748673_u64, 1152921504606846976_u64
        );
        assert_eq!(n, 81920, "expected 5 moduli x 16384 coeffs");
    }

    // Per-modulus Shamir threshold (paper §3.1): share the secret key in each F_{q_j},
    // combine partials with per-modulus Lagrange coefficients, then BFV-fuse.
    #[test]
    fn bfv_shamir_threshold_decrypt_works() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let threshold = 2;
        let n_parties = 5;
        let party_keys =
            bfv_share_key_per_modulus(&ctx, &kp, threshold, n_parties, &mut rng()).expect("share");
        assert_eq!(party_keys.len(), 5);

        let moduli = ctx.extract_moduli(&kp).expect("moduli");
        let lambdas_per_modulus = per_modulus_lambdas(&moduli, n_parties, threshold);

        // Flatten to [modulus0 λs | modulus1 λs | ...]; n_keys = threshold+1.
        let n_keys = threshold + 1;
        let mut lambdas = Vec::with_capacity(moduli.len() * n_keys);
        for lj in &lambdas_per_modulus {
            lambdas.extend_from_slice(lj);
        }

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        let dec = ctx
            .bfv_shamir_decrypt(&ct0, &party_keys[..n_keys], &lambdas, None, data.len())
            .expect("shamir decrypt");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, *b, "threshold slot {i}");
        }
    }

    // The plaintext-mask step (paper §3.1 H2S, dealer sees only δ = x - r) is NOT yet wired:
    // OpenFHE's plaintext scale (TimesQovert) needs noise-scale/level alignment with the
    // partial ciphertext before subtracting the mask share [r]_i·Δ. The masked-decrypt test is
    // therefore skipped; the mask plumbing (masks arg) is in place for future work.
    #[test]
    fn bfv_shamir_decrypt_full_key_control() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        // Full key with λ=1 per modulus should give the plaintext directly.
        let moduli = ctx.extract_moduli(&kp).expect("moduli");
        let lambdas = vec![1_u64; moduli.len()];
        let dec = ctx
            .bfv_shamir_decrypt(&ct0, &[kp], &lambdas, None, 8)
            .expect("decrypt");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, *b, "full-key slot {i}");
        }
    }

    #[test]
    fn bfv_share0_partial_fusion_control() {
        use crate::shamir_fhe::{share_secret_key, Fp60};

        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let committee = Committee::<Fp60>::new(2, 5).expect("committee");
        let party_keys = share_secret_key(&ctx, &kp, &committee, &mut rng()).expect("share");

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        // A single share's noise-free partial should NOT decrypt to the plaintext (s_0 != s).
        let p = ctx
            .bfv_share_partial(&ct0, &party_keys[0])
            .expect("partial");
        let dec = ctx.bfv_fusion(&[p], 8).expect("fusion");
        eprintln!("share0 partial fusion: {dec:?}");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_ne!(*a, *b, "share0 must not reveal plaintext at slot {i}");
        }
    }

    #[test]
    fn bfv_reconstructed_key_decrypts() {
        use crate::shamir_fhe::{fp60_to_u64, lagrange_coeffs, share_secret_key, Fp60};

        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let committee = Committee::<Fp60>::new(2, 5).expect("committee");
        let party_keys = share_secret_key(&ctx, &kp, &committee, &mut rng()).expect("share");

        let coeffs = ctx.extract_secret_coeffs(&kp).expect("coeffs");
        let party_coeffs: Vec<Vec<u64>> = party_keys
            .iter()
            .map(|pk| ctx.extract_secret_coeffs(pk).expect("extract"))
            .collect();
        let lambdas = lagrange_coeffs(&committee, 2);

        // Reconstruct the first-modulus coefficients via Lagrange.
        let mut recon = coeffs.clone();
        for idx in 0..16384 {
            let mut v = Fp60::from(0_u64);
            for (i, pc) in party_coeffs.iter().take(3).enumerate() {
                v += lambdas[i] * Fp60::from(pc[idx]);
            }
            recon[idx] = fp60_to_u64(v);
        }
        let kp_recon = ctx.make_secret_from_coeffs(&recon).expect("make recon");

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        let p = ctx.bfv_share_partial(&ct0, &kp_recon).expect("partial");
        let dec = ctx.bfv_fusion(&[p], 8).expect("fusion");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, *b, "reconstructed-key slot {i}");
        }
    }

    #[test]
    fn bfv_shamir_decrypt_recon_key_control() {
        use crate::shamir_fhe::{fp60_to_u64, lagrange_coeffs, share_secret_key, Fp60};

        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let committee = Committee::<Fp60>::new(2, 5).expect("committee");
        let party_keys = share_secret_key(&ctx, &kp, &committee, &mut rng()).expect("share");

        let coeffs = ctx.extract_secret_coeffs(&kp).expect("coeffs");
        let party_coeffs: Vec<Vec<u64>> = party_keys
            .iter()
            .map(|pk| ctx.extract_secret_coeffs(pk).expect("extract"))
            .collect();
        let lambdas = lagrange_coeffs(&committee, 2);
        let mut recon = coeffs.clone();
        for idx in 0..16384 {
            let mut v = Fp60::from(0_u64);
            for (i, pc) in party_coeffs.iter().take(3).enumerate() {
                v += lambdas[i] * Fp60::from(pc[idx]);
            }
            recon[idx] = fp60_to_u64(v);
        }
        let kp_recon = ctx.make_secret_from_coeffs(&recon).expect("make recon");

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        // A make()-built key via bfv_shamir_decrypt with λ=1 per modulus.
        let moduli = ctx.extract_moduli(&kp).expect("moduli");
        let lambdas = vec![1_u64; moduli.len()];
        let dec = ctx
            .bfv_shamir_decrypt(&ct0, &[kp_recon], &lambdas, None, 8)
            .expect("decrypt");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, *b, "recon-key slot {i}");
        }
    }

    #[test]
    fn bfv_scale_partial_control() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        // scale by λ=2 should give 2·plaintext mod t (BFV scale by t/q, so λ applies to plaintext too).
        let p = ctx.bfv_share_partial(&ct0, &kp).expect("partial");
        let scaled = ctx.scale_partial(&p, 2).expect("scale");
        let dec = ctx.bfv_fusion(&[scaled], 8).expect("fusion");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, (2 * b) % 65537, "scaled slot {i}");
        }
    }

    #[test]
    fn bfv_add_partials_control() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        // p + p should give 2·plaintext mod t.
        let p1 = ctx.bfv_share_partial(&ct0, &kp).expect("p1");
        let p2 = ctx.bfv_share_partial(&ct0, &kp).expect("p2");
        let comb = ctx.add_partials(&p1, &p2).expect("add");
        let dec = ctx.bfv_fusion(&[comb], 8).expect("fusion");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, (2 * b) % 65537, "added slot {i}");
        }
    }

    #[test]
    fn bfv_share_partial_fusion_control() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        // Full-key Shamir partial `c_0 + s·c_1` fused alone should give the plaintext.
        let p = ctx.bfv_share_partial(&ct0, &kp).expect("partial");
        let dec = ctx.bfv_fusion(&[p], 8).expect("fusion");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, *b, "partial-fusion slot {i}");
        }
    }

    #[test]
    fn bfv_share_lead_fusion_control() {
        use crate::shamir_fhe::{share_secret_key, Fp60};

        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let committee = Committee::<Fp60>::new(2, 5).expect("committee");
        let party_keys = share_secret_key(&ctx, &kp, &committee, &mut rng()).expect("share");

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        // A single share-key lead partial fused alone should be garbage (s_0 != s).
        let p = ctx
            .multiparty_decrypt_lead(&ct0, &party_keys[0])
            .expect("share lead");
        let dec = ctx.bfv_fusion(&[p], 8).expect("fusion");
        eprintln!("share0 lead fusion: {dec:?}");
    }

    #[test]
    fn bfv_lead_fusion_control() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let ct0 = ctx.mod_reduce_to_level0(&ct).expect("mod reduce");

        // Single full-key lead partial, then fuse: what does it produce?
        let p = ctx.multiparty_decrypt_lead(&ct0, &kp).expect("lead");
        let dec = ctx.bfv_fusion(&[p], 8).expect("fusion");
        eprintln!("lead-fusion: {dec:?}");
    }

    #[test]
    fn bfv_share_key_reconstructs_first_modulus() {
        use crate::shamir_fhe::{fp60_to_u64, lagrange_coeffs, share_secret_key, Fp60};

        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let coeffs = ctx.extract_secret_coeffs(&kp).expect("coeffs");
        let committee = Committee::<Fp60>::new(2, 5).expect("committee");
        let party_keys = share_secret_key(&ctx, &kp, &committee, &mut rng()).expect("share");

        // Re-extract each share key's coefficients and Lagrange-reconstruct the first modulus.
        let party_coeffs: Vec<Vec<u64>> = party_keys
            .iter()
            .map(|pk| ctx.extract_secret_coeffs(pk).expect("extract"))
            .collect();
        let lambdas = lagrange_coeffs(&committee, 2);
        let mut bad = 0;
        for idx in 0..16384 {
            let mut recon = Fp60::from(0_u64);
            for (i, pc) in party_coeffs.iter().take(3).enumerate() {
                recon += lambdas[i] * Fp60::from(pc[idx]);
            }
            if recon != Fp60::from(coeffs[idx]) {
                bad += 1;
            }
        }
        eprintln!("q0 coefficient reconstruction mismatches: {bad}/16384");
        assert_eq!(bad, 0);
        let _ = fp60_to_u64;
    }

    #[test]
    fn bfv_make_extract_coeff_round_trips() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let coeffs = ctx.extract_secret_coeffs(&kp).expect("extract");
        let kp2 = ctx.make_secret_from_coeffs(&coeffs).expect("make");
        let coeffs2 = ctx.extract_secret_coeffs(&kp2).expect("extract2");
        eprintln!("len {} vs {}", coeffs.len(), coeffs2.len());
        eprintln!("orig[0..6]={:?}", &coeffs[..6]);
        eprintln!("made[0..6]={:?}", &coeffs2[..6]);
        assert_eq!(coeffs, coeffs2, "make/extract round-trip");
    }

    #[test]
    fn bfv_make_zero_key_extract_is_zero() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let zero = vec![0_u64; 81920];
        let kp = ctx.make_secret_from_coeffs(&zero).expect("make");
        let coeffs = ctx.extract_secret_coeffs(&kp).expect("extract");
        let nz = coeffs.iter().filter(|&&c| c != 0).count();
        eprintln!("zero-key extract: nonzero count = {nz}");
        assert_eq!(nz, 0, "expected all-zero coeffs");
    }

    #[test]
    fn bfv_made_key_decrypts() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp = ctx.keygen().expect("keygen");
        let coeffs = ctx.extract_secret_coeffs(&kp).expect("extract");
        let kp2 = ctx.make_secret_from_coeffs(&coeffs).expect("make");

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&kp, &data).expect("encrypt");
        let dec = ctx.bfv_decrypt_int(&kp2, &ct, 8).expect("decrypt");
        for (i, (a, b)) in dec.iter().zip(data.iter()).enumerate() {
            assert_eq!(*a, *b, "made-key slot {i}");
        }
    }

    #[test]
    fn bfv_plaintext_shamir_recovers_values() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp1 = ctx.multiparty_keygen_first().expect("kp1");
        let kp2 = ctx.multiparty_keygen_next_kp(&kp1).expect("kp2");
        let kp3 = ctx.multiparty_keygen_next_kp(&kp2).expect("kp3");
        let party_keys = vec![kp1, kp2, kp3];

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&party_keys[2], &data).expect("encrypt");

        let committee = Committee::<Fr>::new(2, 5).expect("committee");
        let shares =
            bfv_share_plaintext(&ctx, &ct, &party_keys, &committee, 8, &mut rng()).expect("share");
        assert_eq!(shares.len(), 8);

        for (i, share_vec) in shares.iter().enumerate() {
            let v = committee.reconstruct(share_vec).expect("reconstruct");
            assert_eq!(field_to_int(v), data[i] % 65537, "slot {i}");
        }
    }

    #[test]
    fn bfv_shares_to_ciphertext_round_trips() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp1 = ctx.multiparty_keygen_first().expect("kp1");
        let kp2 = ctx.multiparty_keygen_next_kp(&kp1).expect("kp2");
        let kp3 = ctx.multiparty_keygen_next_kp(&kp2).expect("kp3");
        let party_keys = vec![kp1, kp2, kp3];

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let ct = ctx.bfv_encrypt_int(&party_keys[2], &data).expect("encrypt");

        let committee = Committee::<Fr>::new(2, 5).expect("committee");
        let shares =
            bfv_share_plaintext(&ctx, &ct, &party_keys, &committee, 8, &mut rng()).expect("h2s");

        let ct2 = bfv_shares_to_ciphertext(&ctx, &party_keys[2], &shares, &committee).expect("s2h");

        let shares2 =
            bfv_share_plaintext(&ctx, &ct2, &party_keys, &committee, 8, &mut rng()).expect("h2s2");
        for i in 0..8 {
            let v1 = committee.reconstruct(&shares[i]).expect("r1");
            let v2 = committee.reconstruct(&shares2[i]).expect("r2");
            assert_eq!(field_to_int(v1), field_to_int(v2), "slot {i}");
        }
    }

    #[test]
    fn fr_field_axioms() {
        use ark_ff::Field;
        let a = Fr::from(12345_u64);
        let b = Fr::from(54321_u64);
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);
        assert_eq!(a * a.inverse().expect("inv"), Fr::from(1_u64));
    }

    #[test]
    fn full_confidential_transfer_loop() {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let kp1 = ctx.multiparty_keygen_first().expect("kp1");
        let kp2 = ctx.multiparty_keygen_next_kp(&kp1).expect("kp2");
        let kp3 = ctx.multiparty_keygen_next_kp(&kp2).expect("kp3");
        let party_keys = vec![kp1, kp2, kp3];

        let committee_f = Committee::<Fr>::new(2, 5).expect("committee f");
        let committee_b = Committee::<F2>::new(2, 5).expect("committee b");

        // Balances: sender=100, receiver=20, minimum=50, amount=30 (sender > minimum).
        let data = vec![100, 20, 50, 30, 0, 0, 0, 0];
        let ct = ctx.bfv_encrypt_int(&party_keys[2], &data).expect("encrypt");

        // H2S: BFV →Fr sharing.
        let shares =
            bfv_share_plaintext(&ctx, &ct, &party_keys, &committee_f, 8, &mut rng()).expect("h2s");

        for (i, expected) in [(0_usize, 100_i64), (1, 20), (2, 50), (3, 30)] {
            let v = committee_f
                .reconstruct(&shares[i])
                .expect("reconstruct h2s");
            assert_eq!(field_to_int(v), expected, "h2s slot {i}");
        }

        // MPC comparison + conditional transfer.
        let pair = generate_bit_extract_pair(&committee_f, &committee_b, &mut rng()).expect("pair");
        let (sender_new, receiver_new) = conditional_transfer_strictly_greater(
            &shares[0],
            &shares[1],
            &shares[2],
            &shares[3],
            &pair,
            &committee_f,
            &committee_b,
            &mut rng(),
        )
        .expect("transfer");

        let sender_v = committee_f
            .reconstruct(&sender_new)
            .expect("reconstruct sender");
        let receiver_v = committee_f
            .reconstruct(&receiver_new)
            .expect("reconstruct receiver");
        assert_eq!(field_to_int(sender_v), 70);
        assert_eq!(field_to_int(receiver_v), 50);

        // S2H: Fr sharing →BFV.
        let sender_ct = bfv_shares_to_ciphertext(&ctx, &party_keys[2], &[sender_new], &committee_f)
            .expect("s2h sender");
        let dec = ctx
            .bfv_multiparty_decrypt(&sender_ct, &party_keys, 1)
            .expect("decrypt sender");
        assert_eq!(dec[0], 70);
    }

    #[test]
    fn split_based_transfer_control() {
        let mut rng = StdRng::seed_from_u64(0x0B0F_0F0E);
        let committee_f = Committee::<Fr>::new(2, 5).expect("f");
        let committee_b = Committee::<F2>::new(2, 5).expect("b");
        let sender = committee_f
            .split(Fr::from(100_u64), &mut rng)
            .expect("sender");
        let receiver = committee_f
            .split(Fr::from(20_u64), &mut rng)
            .expect("receiver");
        let minimum = committee_f
            .split(Fr::from(50_u64), &mut rng)
            .expect("minimum");
        let amount = committee_f
            .split(Fr::from(30_u64), &mut rng)
            .expect("amount");
        let pair = generate_bit_extract_pair(&committee_f, &committee_b, &mut rng).expect("pair");
        let (sender_new, _) = conditional_transfer_strictly_greater(
            &sender,
            &receiver,
            &minimum,
            &amount,
            &pair,
            &committee_f,
            &committee_b,
            &mut rng,
        )
        .expect("transfer");
        assert_eq!(
            field_to_int(committee_f.reconstruct(&sender_new).expect("rec")),
            70
        );
    }
}
