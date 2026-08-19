//! Shamir secret sharing and holder-basis polynomials.
//!
//! The paper §2.1 degree-`t` sharing: `f_x(X)=x+a_1 X+...+a_t X^t` over distinct
//! evaluation points `alpha_1..alpha_n in F_q\{0}`, `n > t`. Any `t+1` shares
//! Lagrange-reconstruct `x`, while any `t` shares are independent of `x`.

use super::field::ShareField;
use super::MpcError;
use rand::Rng;

/// One party's Shamir share: the public evaluation point `alpha_i` and the secret value `f(alpha_i)`.
///
/// Deliberately does not implement `Debug`, `Display`, or `Clone`, to keep secret shares
/// out of logs and prevent copying.
pub struct ShamirShare<F: ShareField> {
    point: F,
    value: F,
}

impl<F: ShareField> ShamirShare<F> {
    pub(crate) fn new(point: F, value: F) -> Self {
        Self { point, value }
    }

    /// Construct from an evaluation point and share value (for cross-crate (de)serialization).
    pub fn from_point_value(point: F, value: F) -> Self {
        Self { point, value }
    }

    pub fn point(&self) -> F {
        self.point
    }

    /// The share value (protocol-internal only; never log or output it).
    pub fn value(&self) -> F {
        self.value
    }
}

impl<F: ShareField> PartialEq for ShamirShare<F> {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point && self.value == other.value
    }
}

impl<F: ShareField> Eq for ShamirShare<F> {}

/// A committee: threshold `t` (the sharing-polynomial degree) plus each party's public evaluation point.
pub struct Committee<F: ShareField> {
    pub threshold: usize,
    pub points: Vec<F>,
}

impl<F: ShareField> Committee<F> {
    pub fn new(threshold: usize, participants: usize) -> Result<Self, MpcError> {
        validate_parameters(threshold, participants)?;
        Ok(Self {
            threshold,
            points: evaluation_points(participants),
        })
    }

    pub fn size(&self) -> usize {
        self.points.len()
    }

    pub fn split(&self, secret: F, rng: &mut impl Rng) -> Result<Vec<ShamirShare<F>>, MpcError> {
        split(secret, self.threshold, &self.points, rng)
    }

    pub fn reconstruct(&self, shares: &[ShamirShare<F>]) -> Result<F, MpcError> {
        reconstruct(shares, self.threshold + 1)
    }

    /// `u_A(X) = prod_{j notin A} (X - alpha_j) / (-alpha_j)`, degree `t`,
    /// with `u_A(0)=1` and `u_A(alpha_i)=0` for `i notin A`.
    pub fn holder_basis(&self, holder: &[usize], x: F) -> F {
        holder_basis(holder, &self.points, x)
    }
}

impl<F: ShareField> std::fmt::Debug for Committee<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Committee")
            .field("threshold", &self.threshold)
            .field("size", &self.points.len())
            .finish()
    }
}

fn validate_parameters(threshold: usize, participants: usize) -> Result<(), MpcError> {
    if threshold == 0 {
        return Err(MpcError::InvalidThreshold);
    }
    if participants <= threshold {
        return Err(MpcError::InsufficientParticipants);
    }
    Ok(())
}

fn small_field<F: ShareField>(n: u64) -> F {
    F::from_u64(n)
}

/// Public evaluation points `alpha_i = i` (`i in 1..=n`), distinct and non-zero.
pub fn evaluation_points<F: ShareField>(n: usize) -> Vec<F> {
    (1..=n).map(|i| small_field::<F>(i as u64)).collect()
}

fn eval_poly<F: ShareField>(coeffs: &[F], x: F) -> F {
    let mut acc = F::zero();
    for &c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Share a secret into `points.len()` shares of a degree-`threshold` polynomial.
pub fn split<F: ShareField>(
    secret: F,
    threshold: usize,
    points: &[F],
    rng: &mut impl Rng,
) -> Result<Vec<ShamirShare<F>>, MpcError> {
    validate_parameters(threshold, points.len())?;
    let mut coeffs = Vec::with_capacity(threshold + 1);
    coeffs.push(secret);
    for _ in 0..threshold {
        coeffs.push(F::rand(rng));
    }
    Ok(points
        .iter()
        .map(|&p| ShamirShare::new(p, eval_poly(&coeffs, p)))
        .collect())
}

/// Reconstruct at `X=0` via Lagrange interpolation of at least `min_shares` distinct shares.
pub fn reconstruct<F: ShareField>(
    shares: &[ShamirShare<F>],
    min_shares: usize,
) -> Result<F, MpcError> {
    let points: Vec<F> = shares.iter().map(ShamirShare::point).collect();
    let values: Vec<F> = shares.iter().map(ShamirShare::value).collect();
    interpolate(&points, &values, min_shares)
}

/// Reconstruct from `(point, value)` pairs, for cross-crate message-driven protocols
/// whose messages carry only evaluation-point indices and share values, not `ShamirShare` objects.
pub fn reconstruct_from_parts<F: ShareField>(
    points: &[F],
    values: &[F],
    min_shares: usize,
) -> Result<F, MpcError> {
    if points.len() != values.len() {
        return Err(MpcError::ShareCountMismatch);
    }
    interpolate(points, values, min_shares)
}

fn interpolate<F: ShareField>(
    points: &[F],
    values: &[F],
    min_shares: usize,
) -> Result<F, MpcError> {
    if points.len() < min_shares {
        return Err(MpcError::InsufficientShares);
    }
    for i in 0..points.len() {
        for j in (i + 1)..points.len() {
            if points[i] == points[j] {
                return Err(MpcError::DuplicateShare);
            }
        }
    }
    let mut acc = F::zero();
    for (i, &pi) in points.iter().enumerate() {
        let mut li = F::one();
        for (j, &pj) in points.iter().enumerate() {
            if i != j {
                li *= -pj / (pi - pj);
            }
        }
        acc += li * values[i];
    }
    Ok(acc)
}

/// `u_A(X)` evaluated at `x` (the holder-basis polynomial; see `Committee::holder_basis`).
pub fn holder_basis<F: ShareField>(holder: &[usize], points: &[F], x: F) -> F {
    let mut acc = F::one();
    for (j, &a) in points.iter().enumerate() {
        if !holder.contains(&j) {
            acc *= (x - a) / (-a);
        }
    }
    acc
}

/// All holder sets of size `n - degree` (PRSS's `H_degree` family).
pub fn holder_sets(n: usize, degree: usize) -> Vec<Vec<usize>> {
    combinations(n, n - degree)
}

/// Enumerate all `k`-subsets of `{0..n}`.
pub fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    if k > n {
        return Vec::new();
    }
    if k == 0 {
        return vec![Vec::new()];
    }
    let mut result = Vec::new();
    let mut current: Vec<usize> = (0..k).collect();
    loop {
        result.push(current.clone());
        let mut i = k;
        loop {
            if i == 0 {
                return result;
            }
            i -= 1;
            let max_for_i = n - k + i;
            if current[i] < max_for_i {
                current[i] += 1;
                for j in (i + 1)..k {
                    current[j] = current[j - 1] + 1;
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xDEAD_BEEF)
    }

    #[test]
    fn split_reconstruct_round_trips() {
        let committee = Committee::<Fr>::new(2, 5).expect("valid committee");
        let secret = Fr::from(12345_u64);
        let shares = committee.split(secret, &mut rng()).expect("split");
        assert_eq!(shares.len(), 5);
        assert_eq!(
            committee.reconstruct(&shares[..3]).expect("reconstruct"),
            secret
        );
    }

    #[test]
    fn any_t_plus_one_shares_reconstruct() {
        let committee = Committee::<Fr>::new(3, 7).expect("valid committee");
        let secret = Fr::from(42_u64);
        let shares = committee.split(secret, &mut rng()).expect("split");
        for window in shares.windows(4) {
            assert_eq!(committee.reconstruct(window).expect("reconstruct"), secret);
        }
    }

    #[test]
    fn rejects_invalid_parameters() {
        assert!(matches!(
            Committee::<Fr>::new(0, 3),
            Err(MpcError::InvalidThreshold)
        ));
        assert!(matches!(
            Committee::<Fr>::new(3, 3),
            Err(MpcError::InsufficientParticipants)
        ));
    }

    #[test]
    fn rejects_duplicate_and_insufficient_shares() {
        let committee = Committee::<Fr>::new(2, 5).expect("valid committee");
        let secret = Fr::from(7_u64);
        let shares = committee.split(secret, &mut rng()).expect("split");

        let dup = vec![
            ShamirShare::new(shares[0].point(), shares[0].value()),
            ShamirShare::new(shares[0].point(), shares[0].value()),
            ShamirShare::new(shares[1].point(), shares[1].value()),
        ];
        assert!(matches!(
            committee.reconstruct(&dup),
            Err(MpcError::DuplicateShare)
        ));

        let short = &shares[..1];
        assert!(matches!(
            committee.reconstruct(short),
            Err(MpcError::InsufficientShares)
        ));
    }

    #[test]
    fn linearity_is_local() {
        let committee = Committee::<Fr>::new(2, 5).expect("valid committee");
        let a = Fr::from(11_u64);
        let b = Fr::from(19_u64);
        let sa = committee.split(a, &mut rng()).expect("split a");
        let sb = committee.split(b, &mut rng()).expect("split b");

        let summed: Vec<ShamirShare<Fr>> = sa
            .iter()
            .zip(sb.iter())
            .map(|(x, y)| ShamirShare::new(x.point(), x.value() + y.value()))
            .collect();
        assert_eq!(committee.reconstruct(&summed).expect("reconstruct"), a + b);
    }

    #[test]
    fn evaluation_points_are_distinct_nonzero() {
        let points = evaluation_points::<Fr>(6);
        assert_eq!(points.len(), 6);
        assert!(!points.iter().any(|p| *p == Fr::zero()));
        let mut seen = Vec::new();
        for p in points {
            assert!(!seen.contains(&p));
            seen.push(p);
        }
    }

    #[test]
    fn holder_basis_matches_definition() {
        let committee = Committee::<Fr>::new(2, 5).expect("valid committee");
        let holder = vec![0, 1, 2];
        assert_eq!(committee.holder_basis(&holder, Fr::zero()), Fr::one());
        assert_eq!(
            committee.holder_basis(&holder, committee.points[3]),
            Fr::zero()
        );
        assert_eq!(
            committee.holder_basis(&holder, committee.points[4]),
            Fr::zero()
        );
    }

    #[test]
    fn combinations_enumerates_subsets() {
        assert_eq!(combinations(4, 2).len(), 6);
        assert_eq!(combinations(5, 5).len(), 1);
        assert_eq!(combinations(3, 0), vec![Vec::<usize>::new()]);
        assert!(combinations(2, 3).is_empty());
    }
}
