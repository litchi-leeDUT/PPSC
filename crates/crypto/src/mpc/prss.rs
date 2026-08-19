//! PRSS preprocessing: `Π^t_RandShare` and `Π^{t1,t2}_ResharePair`.
//!
//! Each holder set `A in H_degree` (`|A| = n - degree`) holds a common PRSS seed, with
//! `r_A = PRF_{kappa_A}(tau)`. The single-process implementation centralizes seed
//! generation locally, only to verify algebraic correctness; a real deployment holds
//! seeds distributively across members.

use super::field::ShareField;
use super::shamir::{holder_basis, holder_sets, split, Committee, ShamirShare};
use super::MpcError;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A PRSS seed (32 bytes); HMAC-SHA256 is the PRF that derives field elements.
pub struct PrssSeed([u8; 32]);

impl PrssSeed {
    pub fn random(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0_u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// `PRF_kappa(nonce)`, deterministically mapped into field `F`.
    pub fn derive_element<F: ShareField>(&self, nonce: &[u8]) -> F {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts 32-byte keys");
        mac.update(nonce);
        let tag = mac.finalize().into_bytes();
        F::from_le_bytes(&tag)
    }

    /// A small integer within the plaintext range derived from `PRF_kappa(nonce)`
    /// (low 8 HMAC bytes mod `bound`).
    ///
    /// Used for the "plaintext mask" (paper §3.1): each component `r_A` is small so that
    /// `r = Σ r_A` stays within the plaintext range, while retaining PRSS's distributed
    /// generation (no single party knows `r`).
    pub fn derive_small(&self, nonce: &[u8], bound: u64) -> u64 {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts 32-byte keys");
        mac.update(nonce);
        let tag = mac.finalize().into_bytes();
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(&tag[..8]);
        let low = u64::from_le_bytes(buf);
        if bound == 0 {
            0
        } else {
            low % bound
        }
    }
}

/// `Π^t_RandShare`: produce a degree-`t` random sharing whose secret `r = sum_A r_A` is never reconstructed.
pub fn rand_share<F: ShareField>(
    committee: &Committee<F>,
    nonce: &[u8],
    rng: &mut impl RngCore,
) -> Result<Vec<ShamirShare<F>>, MpcError> {
    let n = committee.size();
    let degree = committee.threshold;
    let holders = holder_sets(n, degree);

    let mut values = vec![F::zero(); n];
    for holder in &holders {
        let seed = PrssSeed::random(rng);
        let r_a: F = seed.derive_element(nonce);
        for (i, value) in values.iter_mut().enumerate() {
            if holder.contains(&i) {
                *value += r_a * holder_basis(holder, &committee.points, committee.points[i]);
            }
        }
    }

    Ok(committee
        .points
        .iter()
        .enumerate()
        .map(|(i, &p)| ShamirShare::new(p, values[i]))
        .collect())
}

/// Plaintext-range variant of `Π^t_RandShare`: each component `r_A` is a small integer in
/// `[0, bound)`, so the secret `r = Σ r_A` stays in the plaintext range (bounded by
/// `|H|·bound`), still preserving the Shamir structure and distributed generation.
pub fn rand_share_small<F: ShareField>(
    committee: &Committee<F>,
    nonce: &[u8],
    bound: u64,
    rng: &mut impl RngCore,
) -> Result<Vec<ShamirShare<F>>, MpcError> {
    let n = committee.size();
    let degree = committee.threshold;
    let holders = holder_sets(n, degree);

    let mut values = vec![F::zero(); n];
    for holder in &holders {
        let seed = PrssSeed::random(rng);
        let r_a = F::from_u64(seed.derive_small(nonce, bound));
        for (i, value) in values.iter_mut().enumerate() {
            if holder.contains(&i) {
                *value += r_a * holder_basis(holder, &committee.points, committee.points[i]);
            }
        }
    }

    Ok(committee
        .points
        .iter()
        .enumerate()
        .map(|(i, &p)| ShamirShare::new(p, values[i]))
        .collect())
}

/// `Π^{t1,t2}_ResharePair`: produce a correlated source/destination sharing pair of the
/// same random value `r`.
///
/// `src_degree`/`dst_degree` explicitly specify each side's sharing degree; basic handoff
/// uses `(t1,t2)`, multiplication degree reduction uses `(2t1,t2)`.
pub fn reshare_pair<F: ShareField>(
    src: &Committee<F>,
    src_degree: usize,
    dst: &Committee<F>,
    dst_degree: usize,
    nonce: &[u8],
    rng: &mut impl RngCore,
) -> Result<super::HandoffMask<F>, MpcError> {
    let n1 = src.size();
    let n2 = dst.size();
    if src_degree >= n1 || dst_degree >= n2 {
        return Err(MpcError::InvalidThreshold);
    }

    let holders1 = holder_sets(n1, src_degree);
    let holders2 = holder_sets(n2, dst_degree);

    let mut row = vec![F::zero(); holders1.len()];
    let mut col = vec![F::zero(); holders2.len()];

    for (i, _h1) in holders1.iter().enumerate() {
        for (j, _h2) in holders2.iter().enumerate() {
            let seed = PrssSeed::random(rng);
            let zeta: F = seed.derive_element(nonce);
            row[i] += zeta;
            col[j] += zeta;
        }
    }

    let mut source = vec![F::zero(); n1];
    for (idx, h1) in holders1.iter().enumerate() {
        for (i, value) in source.iter_mut().enumerate() {
            if h1.contains(&i) {
                *value += row[idx] * holder_basis(h1, &src.points, src.points[i]);
            }
        }
    }

    let mut destination = vec![F::zero(); n2];
    for (idx, h2) in holders2.iter().enumerate() {
        for (i, value) in destination.iter_mut().enumerate() {
            if h2.contains(&i) {
                *value += col[idx] * holder_basis(h2, &dst.points, dst.points[i]);
            }
        }
    }

    Ok(super::HandoffMask {
        source: src
            .points
            .iter()
            .enumerate()
            .map(|(i, &p)| ShamirShare::new(p, source[i]))
            .collect(),
        source_degree: src_degree,
        destination: dst
            .points
            .iter()
            .enumerate()
            .map(|(i, &p)| ShamirShare::new(p, destination[i]))
            .collect(),
        destination_degree: dst_degree,
    })
}

/// Plaintext-range variant of `Π^{t1,t2}_ResharePair`: each `ζ_{i,j}` is a small integer in
/// `[0, bound)`, so the secret `r = Σ ζ` stays in the plaintext range (bounded by
/// `|H1|·|H2|·bound`).
pub fn reshare_pair_small<F: ShareField>(
    src: &Committee<F>,
    src_degree: usize,
    dst: &Committee<F>,
    dst_degree: usize,
    nonce: &[u8],
    bound: u64,
    rng: &mut impl RngCore,
) -> Result<super::HandoffMask<F>, MpcError> {
    let n1 = src.size();
    let n2 = dst.size();
    if src_degree >= n1 || dst_degree >= n2 {
        return Err(MpcError::InvalidThreshold);
    }

    let holders1 = holder_sets(n1, src_degree);
    let holders2 = holder_sets(n2, dst_degree);

    let mut row = vec![F::zero(); holders1.len()];
    let mut col = vec![F::zero(); holders2.len()];

    for (i, _h1) in holders1.iter().enumerate() {
        for (j, _h2) in holders2.iter().enumerate() {
            let seed = PrssSeed::random(rng);
            let zeta = F::from_u64(seed.derive_small(nonce, bound));
            row[i] += zeta;
            col[j] += zeta;
        }
    }

    let mut source = vec![F::zero(); n1];
    for (idx, h1) in holders1.iter().enumerate() {
        for (i, value) in source.iter_mut().enumerate() {
            if h1.contains(&i) {
                *value += row[idx] * holder_basis(h1, &src.points, src.points[i]);
            }
        }
    }

    let mut destination = vec![F::zero(); n2];
    for (idx, h2) in holders2.iter().enumerate() {
        for (i, value) in destination.iter_mut().enumerate() {
            if h2.contains(&i) {
                *value += col[idx] * holder_basis(h2, &dst.points, dst.points[i]);
            }
        }
    }

    Ok(super::HandoffMask {
        source: src
            .points
            .iter()
            .enumerate()
            .map(|(i, &p)| ShamirShare::new(p, source[i]))
            .collect(),
        source_degree: src_degree,
        destination: dst
            .points
            .iter()
            .enumerate()
            .map(|(i, &p)| ShamirShare::new(p, destination[i]))
            .collect(),
        destination_degree: dst_degree,
    })
}

/// Trusted-dealer variant of `Π^{t1,t2}_ResharePair` used by large-threshold benchmarks.
///
/// Samples the mask `r` once and Shamir-splits it on both sides (`O(n·t)`), avoiding the
/// `O(C(n,t)²)` holder-set cost of the PRSS construction when `t ≈ n/2`. Algebraically
/// equivalent to `reshare_pair`: the destination-side `r` shares are a fresh sharing of the
/// same `r` as the source side. The PRSS version additionally hides `r` from every single
/// party; this helper assumes a trusted dealer (acceptable for performance measurement).
pub fn reshare_pair_dealer<F: ShareField>(
    src: &Committee<F>,
    src_degree: usize,
    dst: &Committee<F>,
    dst_degree: usize,
    rng: &mut impl RngCore,
) -> Result<super::HandoffMask<F>, MpcError> {
    if src_degree >= src.size() || dst_degree >= dst.size() {
        return Err(MpcError::InvalidThreshold);
    }
    let r = F::rand(rng);
    let source = split(r, src_degree, &src.points, rng)?;
    let destination = split(r, dst_degree, &dst.points, rng)?;
    Ok(super::HandoffMask {
        source,
        source_degree: src_degree,
        destination,
        destination_degree: dst_degree,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xABCD_1234)
    }

    #[test]
    fn rand_share_is_degree_t_consistent() {
        let committee = Committee::<Fr>::new(2, 5).expect("valid committee");
        let shares = rand_share(&committee, b"epoch-0", &mut rng()).expect("rand share");
        assert_eq!(shares.len(), 5);
        let from_first = committee.reconstruct(&shares[..3]).expect("reconstruct");
        let from_last = committee.reconstruct(&shares[2..]).expect("reconstruct");
        assert_eq!(from_first, from_last);
    }

    #[test]
    fn rand_share_small_is_bounded_and_consistent() {
        let committee = Committee::<Fr>::new(2, 5).expect("valid committee");
        let bound = 1_000_000_u64;
        let shares = rand_share_small(&committee, b"small", bound, &mut rng()).expect("rand small");
        assert_eq!(shares.len(), 5);

        let r = committee.reconstruct(&shares).expect("reconstruct");
        let bytes = r.into_bigint().to_bytes_le();
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(&bytes[..8]);
        let r_u64 = u64::from_le_bytes(buf);
        // |H| = C(5, 2) = 10，r < 10 * bound
        assert!(r_u64 < 10 * bound);

        let from_first = committee.reconstruct(&shares[..3]).expect("reconstruct");
        let from_last = committee.reconstruct(&shares[2..]).expect("reconstruct");
        assert_eq!(from_first, from_last);
    }

    #[test]
    fn reshare_pair_small_is_bounded_and_consistent() {
        let src = Committee::<Fr>::new(2, 5).expect("src");
        let dst = Committee::<Fr>::new(3, 6).expect("dst");
        let bound = 1_000_000_u64;
        let mask = reshare_pair_small(&src, 2, &dst, 3, b"small", bound, &mut rng())
            .expect("reshare small");

        let rs = src.reconstruct(&mask.source).expect("src reconstruct");
        let rd = dst.reconstruct(&mask.destination).expect("dst reconstruct");
        assert_eq!(rs, rd);

        let bytes = rs.into_bigint().to_bytes_le();
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(&bytes[..8]);
        let r_u64 = u64::from_le_bytes(buf);
        // |H1| = C(5,2) = 10, |H2| = C(6,3) = 20，r < 10 * 20 * bound
        assert!(r_u64 < 10 * 20 * bound);
    }

    #[test]
    fn prf_is_deterministic_per_seed_and_nonce() {
        let seed = PrssSeed::from_bytes([7_u8; 32]);
        assert_eq!(
            seed.derive_element::<Fr>(b"tau"),
            seed.derive_element::<Fr>(b"tau")
        );
        assert_ne!(
            seed.derive_element::<Fr>(b"tau"),
            seed.derive_element::<Fr>(b"tau-2")
        );
    }

    #[test]
    fn reshare_pair_reconstructs_same_value_across_committees() {
        let src = Committee::<Fr>::new(2, 5).expect("src");
        let dst = Committee::<Fr>::new(3, 6).expect("dst");
        let mask = reshare_pair(&src, 2, &dst, 3, b"tau", &mut rng()).expect("pair");
        let rs = src.reconstruct(&mask.source).expect("src reconstruct");
        let rd = dst.reconstruct(&mask.destination).expect("dst reconstruct");
        assert_eq!(rs, rd);
    }

    #[test]
    fn reshare_pair_degree_2t_source_is_consistent() {
        let src = Committee::<Fr>::new(2, 6).expect("src n=6>2t=4");
        let dst = Committee::<Fr>::new(2, 6).expect("dst");
        let mask = reshare_pair(&src, 4, &dst, 2, b"tau", &mut rng()).expect("pair");
        let rs = src.reconstruct(&mask.source).expect("src reconstruct 2t+1");
        let rd = dst.reconstruct(&mask.destination).expect("dst reconstruct");
        assert_eq!(rs, rd);
    }

    #[test]
    fn reshare_pair_dealer_matches_at_large_threshold() {
        // t = floor((n-1)/2) is the paper's honest-majority threshold; the PRSS holder-set
        // construction is infeasible here, so the dealer variant must agree on `r`.
        for &n in &[4_usize, 8, 16, 32, 64] {
            let t = (n - 1) / 2;
            let src = Committee::<Fr>::new(t, n).expect("src");
            let dst = Committee::<Fr>::new(t, n).expect("dst");
            let mask = reshare_pair_dealer(&src, t, &dst, t, &mut rng()).expect("dealer pair");
            let rs = src.reconstruct(&mask.source).expect("src reconstruct");
            let rd = dst.reconstruct(&mask.destination).expect("dst reconstruct");
            assert_eq!(rs, rd, "n={n}");
        }
    }

    #[test]
    fn reshare_pair_dealer_degree_2t_source_is_consistent() {
        let src = Committee::<Fr>::new(2, 6).expect("src");
        let dst = Committee::<Fr>::new(2, 6).expect("dst");
        let mask = reshare_pair_dealer(&src, 4, &dst, 2, &mut rng()).expect("pair");
        let rs = src.reconstruct(&mask.source).expect("src reconstruct 2t+1");
        let rd = dst.reconstruct(&mask.destination).expect("dst reconstruct");
        assert_eq!(rs, rd);
    }
}
