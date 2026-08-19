//! Authenticated MAC (paper §2.1 Authentication, §3.1 Case 3).
//!
//! An authenticated sharing `⟨x⟩_Q = ([x]_Q, [γ_x]_Q)` with `γ_x = α x`, where `α` is a
//! global secret MAC key (itself secret-shared). Linear combinations are local; handoff
//! and multiplication transfer both the value and MAC-tag sharings together; the MAC
//! relation is checked in the next round by opening with a random mask.

use super::handoff::{basic_handoff, multiply_and_handoff};
use super::shamir::{reconstruct, Committee, ShamirShare};
use super::{HandoffMask, MpcError};
use ark_ff::PrimeField;

/// An authenticated sharing: the value sharing `[x]` and the MAC sharing `[γ_x] = [α x]`.
///
/// Implements neither `Debug` nor `Display` nor `Clone`.
pub struct AuthenticatedSharing<F: PrimeField> {
    pub value: Vec<ShamirShare<F>>,
    pub mac: Vec<ShamirShare<F>>,
}

impl<F: PrimeField> AuthenticatedSharing<F> {
    pub fn new(value: Vec<ShamirShare<F>>, mac: Vec<ShamirShare<F>>) -> Self {
        Self { value, mac }
    }
}

/// Local addition: `⟨x⟩ + ⟨y⟩ = ⟨x+y⟩`.
pub fn auth_add<F: PrimeField>(
    a: &AuthenticatedSharing<F>,
    b: &AuthenticatedSharing<F>,
) -> Result<AuthenticatedSharing<F>, MpcError> {
    if a.value.len() != b.value.len() || a.mac.len() != b.mac.len() {
        return Err(MpcError::ShareCountMismatch);
    }
    Ok(AuthenticatedSharing {
        value: add_pointwise(&a.value, &b.value)?,
        mac: add_pointwise(&a.mac, &b.mac)?,
    })
}

/// Local scalar multiplication: `c · ⟨x⟩ = ⟨c x⟩`.
pub fn auth_scalar_mul<F: PrimeField>(
    c: F,
    a: &AuthenticatedSharing<F>,
) -> AuthenticatedSharing<F> {
    AuthenticatedSharing {
        value: a
            .value
            .iter()
            .map(|s| ShamirShare::new(s.point(), c * s.value()))
            .collect(),
        mac: a
            .mac
            .iter()
            .map(|s| ShamirShare::new(s.point(), c * s.value()))
            .collect(),
    }
}

/// `Π_auth-handoff`: hand the value and MAC-tag sharings from `src` to `dst`.
///
/// Two independent masks `mask_value` and `mask_mac` protect `x` and `xα` respectively.
pub fn authenticated_handoff<F: PrimeField>(
    x: &AuthenticatedSharing<F>,
    mask_value: &HandoffMask<F>,
    mask_mac: &HandoffMask<F>,
    src: &Committee<F>,
    dst: &Committee<F>,
) -> Result<AuthenticatedSharing<F>, MpcError> {
    Ok(AuthenticatedSharing {
        value: basic_handoff(&x.value, mask_value, src, dst)?,
        mac: basic_handoff(&x.mac, mask_mac, src, dst)?,
    })
}

/// `Π_auth-mult`: `⟨x⟩ · [y] = ⟨x·y⟩`, also performing degree reduction and cross-committee handoff.
///
/// The value path `[x]·[y]` and MAC path `[xα]·[y] = [(xα)y]` each use one degree-reduction multiplication.
pub fn authenticated_multiply<F: PrimeField>(
    x: &AuthenticatedSharing<F>,
    y: &[ShamirShare<F>],
    mask_value: &HandoffMask<F>,
    mask_mac: &HandoffMask<F>,
    src: &Committee<F>,
    dst: &Committee<F>,
) -> Result<AuthenticatedSharing<F>, MpcError> {
    Ok(AuthenticatedSharing {
        value: multiply_and_handoff(&x.value, y, mask_value, src, dst)?,
        mac: multiply_and_handoff(&x.mac, y, mask_mac, src, dst)?,
    })
}

/// Delayed authentication check (paper §3.1 Case 3, the Authentication step of Fig 6/7).
///
/// `comm2` holds provisional `[x]`, `[xα]` (claimed tag) and the MAC key `[α]`. When
/// handing off to `comm3`: use `Π_mult` to hand `[x]·[α]` to `comm3`, yielding the
/// recomputed `[z]=[xα]`; also hand the claimed tag `[xα]` to `comm3`; `comm3` masks the
/// difference with fresh random `[r_check]` and opens it — accepted iff `v=(z-xα)·r_check`
/// is zero.
#[allow(clippy::too_many_arguments)]
pub fn verify_mac<F: PrimeField>(
    value: &[ShamirShare<F>],
    mac: &[ShamirShare<F>],
    alpha: &[ShamirShare<F>],
    mask_mul: &HandoffMask<F>,
    mask_tag: &HandoffMask<F>,
    r_check: &[ShamirShare<F>],
    comm2: &Committee<F>,
    comm3: &Committee<F>,
) -> Result<bool, MpcError> {
    let z = multiply_and_handoff(value, alpha, mask_mul, comm2, comm3)?;
    let tag = basic_handoff(mac, mask_tag, comm2, comm3)?;
    let v_shares: Vec<ShamirShare<F>> = z
        .iter()
        .zip(tag.iter())
        .zip(r_check.iter())
        .map(|((zi, ti), ri)| {
            if zi.point() != ti.point() || zi.point() != ri.point() {
                return Err(MpcError::InconsistentShares);
            }
            Ok(ShamirShare::new(
                zi.point(),
                (zi.value() - ti.value()) * ri.value(),
            ))
        })
        .collect::<Result<_, MpcError>>()?;
    let v = reconstruct(&v_shares, 2 * comm3.threshold + 1)?;
    Ok(v == F::zero())
}

fn add_pointwise<F: PrimeField>(
    a: &[ShamirShare<F>],
    b: &[ShamirShare<F>],
) -> Result<Vec<ShamirShare<F>>, MpcError> {
    if a.len() != b.len() {
        return Err(MpcError::ShareCountMismatch);
    }
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| {
            if x.point() != y.point() {
                return Err(MpcError::InconsistentShares);
            }
            Ok(ShamirShare::new(x.point(), x.value() + y.value()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::{rand_share, reshare_pair};
    use ark_bn254::Fr;
    use ark_ff::One;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x0102_0304)
    }

    fn authenticated<F: PrimeField>(
        committee: &Committee<F>,
        value: F,
        alpha: F,
        rng: &mut StdRng,
    ) -> (AuthenticatedSharing<F>, Vec<ShamirShare<F>>) {
        let value_shares = committee.split(value, rng).expect("split value");
        let mac_shares = committee.split(value * alpha, rng).expect("split mac");
        let alpha_shares = committee.split(alpha, rng).expect("split alpha");
        (
            AuthenticatedSharing {
                value: value_shares,
                mac: mac_shares,
            },
            alpha_shares,
        )
    }

    #[test]
    fn linear_operations_preserve_mac_relation() {
        let committee = Committee::<Fr>::new(2, 5).expect("committee");
        let alpha = Fr::from(7_u64);
        let x = Fr::from(3_u64);
        let y = Fr::from(4_u64);
        let (ax, alpha_shares) = authenticated(&committee, x, alpha, &mut rng());
        let (ay, _) = authenticated(&committee, y, alpha, &mut rng());

        let sum = auth_add(&ax, &ay).expect("add");
        assert_eq!(committee.reconstruct(&sum.value).expect("v"), x + y);
        assert_eq!(committee.reconstruct(&sum.mac).expect("m"), (x + y) * alpha);

        let scaled = auth_scalar_mul(Fr::from(2_u64), &ax);
        assert_eq!(
            committee.reconstruct(&scaled.value).expect("v"),
            x * Fr::from(2_u64)
        );
        assert_eq!(
            committee.reconstruct(&scaled.mac).expect("m"),
            x * alpha * Fr::from(2_u64)
        );

        let _ = alpha_shares;
    }

    #[test]
    fn authenticated_handoff_preserves_value_and_tag() {
        let src = Committee::<Fr>::new(2, 5).expect("src");
        let dst = Committee::<Fr>::new(2, 5).expect("dst");
        let alpha = Fr::from(11_u64);
        let x = Fr::from(9_u64);
        let (auth, _) = authenticated(&src, x, alpha, &mut rng());
        let mv = reshare_pair(&src, 2, &dst, 2, b"mv", &mut rng()).expect("mask v");
        let mm = reshare_pair(&src, 2, &dst, 2, b"mm", &mut rng()).expect("mask m");

        let handed = authenticated_handoff(&auth, &mv, &mm, &src, &dst).expect("handoff");
        assert_eq!(dst.reconstruct(&handed.value).expect("v"), x);
        assert_eq!(dst.reconstruct(&handed.mac).expect("m"), x * alpha);
    }

    #[test]
    fn authenticated_multiply_computes_product_and_tag() {
        let src = Committee::<Fr>::new(2, 7).expect("src n=7>2t");
        let dst = Committee::<Fr>::new(2, 7).expect("dst");
        let alpha = Fr::from(5_u64);
        let x = Fr::from(6_u64);
        let y = Fr::from(7_u64);
        let (auth_x, _) = authenticated(&src, x, alpha, &mut rng());
        let y_shares = src.split(y, &mut rng()).expect("split y");
        let mv = reshare_pair(&src, 4, &dst, 2, b"mv", &mut rng()).expect("mask v");
        let mm = reshare_pair(&src, 4, &dst, 2, b"mm", &mut rng()).expect("mask m");

        let z = authenticated_multiply(&auth_x, &y_shares, &mv, &mm, &src, &dst).expect("mult");
        assert_eq!(dst.reconstruct(&z.value).expect("v"), x * y);
        assert_eq!(dst.reconstruct(&z.mac).expect("m"), x * y * alpha);
    }

    #[test]
    fn verify_mac_accepts_valid_and_rejects_tampered() {
        let comm2 = Committee::<Fr>::new(2, 7).expect("comm2 n=7>2t");
        let comm3 = Committee::<Fr>::new(2, 7).expect("comm3 n=7>2t");
        let alpha = Fr::from(13_u64);
        let x = Fr::from(17_u64);
        let value_shares = comm2.split(x, &mut rng()).expect("split value");
        let mac_shares = comm2.split(x * alpha, &mut rng()).expect("split mac");
        let alpha_shares = comm2.split(alpha, &mut rng()).expect("split alpha");
        let mask_mul = reshare_pair(&comm2, 4, &comm3, 2, b"mul", &mut rng()).expect("mask mul");
        let mask_tag = reshare_pair(&comm2, 2, &comm3, 2, b"tag", &mut rng()).expect("mask tag");
        let r_check = rand_share(&comm3, b"check", &mut rng()).expect("r_check");

        assert!(verify_mac(
            &value_shares,
            &mac_shares,
            &alpha_shares,
            &mask_mul,
            &mask_tag,
            &r_check,
            &comm2,
            &comm3,
        )
        .expect("verify"));

        let bad_mac = comm2
            .split(x * alpha + Fr::one(), &mut rng())
            .expect("bad mac");
        assert!(!verify_mac(
            &value_shares,
            &bad_mac,
            &alpha_shares,
            &mask_mul,
            &mask_tag,
            &r_check,
            &comm2,
            &comm3,
        )
        .expect("verify tampered"));
    }
}
