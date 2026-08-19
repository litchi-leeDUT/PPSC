//! Packed secret sharing (paper §3.3).
//!
//! A degree-`D = t+L-1` polynomial encodes `L` slot values at `L` packing points `β_j`.
//! `Π_pack_Pair` generates a correlated degree-`D`/degree-`2D` pair of the same vector `ρ`;
//! packed degree reduction compresses a product sharing from degree `2D` back to degree `D`.
//! Constraint: `n > 2D`.

use super::prss::PrssSeed;
use super::shamir::{holder_sets, Committee, ShamirShare};
use super::MpcError;
use ark_ff::PrimeField;
use rand::Rng;

/// Packed sharing parameters: threshold `t`, slot count `L`, degree `D = t+L-1`.
pub struct PackedParams<F: PrimeField> {
    pub committee: Committee<F>,
    pub slots: usize,
    pub degree: usize,
    pub packing_points: Vec<F>,
}

impl<F: PrimeField> PackedParams<F> {
    pub fn new(threshold: usize, participants: usize, slots: usize) -> Result<Self, MpcError> {
        if threshold == 0 || slots == 0 {
            return Err(MpcError::InvalidPackingParameters);
        }
        if participants <= 2 * threshold {
            return Err(MpcError::TooFewParties);
        }
        let degree = threshold + slots - 1;
        if participants <= 2 * degree || 2 * slots > participants - 2 * threshold + 1 {
            return Err(MpcError::InvalidPackingParameters);
        }
        let committee = Committee::new(threshold, participants)?;
        let packing_points = (1..=slots)
            .map(|j| small_field::<F>(participants as u64 + j as u64))
            .collect();
        Ok(Self {
            committee,
            slots,
            degree,
            packing_points,
        })
    }

    /// `τ = 2D+1-L`, the holder-set size parameter for the high-degree sharing.
    pub fn tau(&self) -> usize {
        2 * self.degree + 1 - self.slots
    }
}

/// A degree-`D` / degree-`2D` packed correlated pair encoding the same vector `ρ`.
pub struct PackedPair<F: PrimeField> {
    pub low: Vec<ShamirShare<F>>,
    pub high: Vec<ShamirShare<F>>,
}

fn small_field<F: PrimeField>(n: u64) -> F {
    F::from_le_bytes_mod_order(&n.to_le_bytes())
}

fn lagrange_basis_at<F: PrimeField>(points: &[F], j: usize, x: F) -> F {
    let mut acc = F::one();
    for (j2, &p) in points.iter().enumerate() {
        if j2 != j {
            acc *= (x - p) / (points[j] - p);
        }
    }
    acc
}

fn interpolate_at<F: PrimeField>(points: &[F], values: &[F], x: F) -> F {
    let mut acc = F::zero();
    for i in 0..points.len() {
        let mut li = F::one();
        for j in 0..points.len() {
            if i != j {
                li *= (x - points[j]) / (points[i] - points[j]);
            }
        }
        acc += li * values[i];
    }
    acc
}

/// `g_{A,j}^{(D)}(x) = L_j^{(β)}(x) · ∏_{m∉A} (x - α_m)/(β_j - α_m)`.
fn g_poly_at<F: PrimeField>(params: &PackedParams<F>, holder: &[usize], j: usize, x: F) -> F {
    let base = lagrange_basis_at(&params.packing_points, j, x);
    let mut prod = F::one();
    for (m, &alpha) in params.committee.points.iter().enumerate() {
        if !holder.contains(&m) {
            prod *= (x - alpha) / (params.packing_points[j] - alpha);
        }
    }
    base * prod
}

fn is_subset(sub: &[usize], sup: &[usize]) -> bool {
    sub.iter().all(|x| sup.contains(x))
}

/// `Π_pack_Pair`: generate a degree-`D`/degree-`2D` packed correlated pair encoding the same random vector `ρ`.
///
/// Correlated randomness `ζ_{A,B,j}` is derived from PRSS seeds (shared by the same holder set), consistent with `reshare_pair`.
pub fn packed_pairgen<F: PrimeField>(
    params: &PackedParams<F>,
    nonce: &[u8],
    rng: &mut impl Rng,
) -> Result<PackedPair<F>, MpcError> {
    let n = params.committee.size();
    let l = params.slots;
    let holders_d = holder_sets(n, params.committee.threshold);
    let holders_2d = holder_sets(n, params.tau());

    let mut row = vec![vec![F::zero(); l]; holders_d.len()];
    let mut col = vec![vec![F::zero(); l]; holders_2d.len()];

    for (ai, a) in holders_d.iter().enumerate() {
        for (bi, b) in holders_2d.iter().enumerate() {
            if is_subset(b, a) {
                for j in 0..l {
                    let seed = PrssSeed::random(rng);
                    let zeta: F = seed.derive_element(nonce);
                    row[ai][j] += zeta;
                    col[bi][j] += zeta;
                }
            }
        }
    }

    let mut low = vec![F::zero(); n];
    for (ai, a) in holders_d.iter().enumerate() {
        for (i, value) in low.iter_mut().enumerate() {
            if a.contains(&i) {
                for (j, &rj) in row[ai].iter().enumerate() {
                    *value += rj * g_poly_at(params, a, j, params.committee.points[i]);
                }
            }
        }
    }

    let mut high = vec![F::zero(); n];
    for (bi, b) in holders_2d.iter().enumerate() {
        for (i, value) in high.iter_mut().enumerate() {
            if b.contains(&i) {
                for (j, &cj) in col[bi].iter().enumerate() {
                    *value += cj * g_poly_at(params, b, j, params.committee.points[i]);
                }
            }
        }
    }

    Ok(PackedPair {
        low: low
            .iter()
            .enumerate()
            .map(|(i, &v)| ShamirShare::new(params.committee.points[i], v))
            .collect(),
        high: high
            .iter()
            .enumerate()
            .map(|(i, &v)| ShamirShare::new(params.committee.points[i], v))
            .collect(),
    })
}

/// packed degree reduction: `F_x · F_y` (degree `2D`) → degree `D`, with slot values `z_j = x_j · y_j`.
pub fn packed_degree_reduce<F: PrimeField>(
    x_shares: &[ShamirShare<F>],
    y_shares: &[ShamirShare<F>],
    pair: &PackedPair<F>,
    params: &PackedParams<F>,
) -> Result<Vec<ShamirShare<F>>, MpcError> {
    let n = params.committee.size();
    if x_shares.len() != n || y_shares.len() != n || pair.low.len() != n || pair.high.len() != n {
        return Err(MpcError::ShareCountMismatch);
    }

    let h_w: Vec<F> = x_shares
        .iter()
        .zip(y_shares.iter())
        .zip(pair.high.iter())
        .map(|((x, y), r)| x.value() * y.value() + r.value())
        .collect();

    let mut w = Vec::with_capacity(params.slots);
    for &beta in &params.packing_points {
        w.push(interpolate_at(&params.committee.points, &h_w, beta));
    }

    let mut out = Vec::with_capacity(n);
    for (i, &alpha) in params.committee.points.iter().enumerate() {
        let mut ww = F::zero();
        for (j, &wj) in w.iter().enumerate() {
            ww += wj * lagrange_basis_at(&params.packing_points, j, alpha);
        }
        out.push(ShamirShare::new(alpha, ww - pair.low[i].value()));
    }
    Ok(out)
}

/// Encode `L` slot values into a degree-`D` packed sharing (`F(β_j) = values[j]`).
pub fn packed_split<F: PrimeField>(
    values: &[F],
    params: &PackedParams<F>,
    rng: &mut impl Rng,
) -> Result<Vec<ShamirShare<F>>, MpcError> {
    if values.len() != params.slots {
        return Err(MpcError::InvalidPackingParameters);
    }
    let t = params.committee.threshold;
    let r_coeffs: Vec<F> = (0..t).map(|_| F::rand(rng)).collect();
    let mut shares = Vec::with_capacity(params.committee.size());
    for i in 0..params.committee.size() {
        let alpha = params.committee.points[i];
        let mut base = F::zero();
        for (j, &v) in values.iter().enumerate() {
            base += v * lagrange_basis_at(&params.packing_points, j, alpha);
        }
        let mut vanish = F::one();
        for &beta in &params.packing_points {
            vanish *= alpha - beta;
        }
        let mut r_at = F::zero();
        for &c in r_coeffs.iter().rev() {
            r_at = r_at * alpha + c;
        }
        shares.push(ShamirShare::new(alpha, base + vanish * r_at));
    }
    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x0A1B_2C3D)
    }

    fn slot<F: PrimeField>(shares: &[ShamirShare<F>], params: &PackedParams<F>, j: usize) -> F {
        let values: Vec<F> = shares.iter().map(|s| s.value()).collect();
        interpolate_at(&params.committee.points, &values, params.packing_points[j])
    }

    #[test]
    fn pairgen_encodes_same_vector_in_both_degrees() {
        let params = PackedParams::<Fr>::new(1, 5, 2).expect("params");
        let pair = packed_pairgen(&params, b"pp", &mut rng()).expect("pairgen");
        for j in 0..params.slots {
            assert_eq!(slot(&pair.low, &params, j), slot(&pair.high, &params, j));
        }
    }

    #[test]
    fn degree_reduce_multiplies_slot_wise() {
        let params = PackedParams::<Fr>::new(1, 5, 2).expect("params");
        let x = vec![Fr::from(3_u64), Fr::from(4_u64)];
        let y = vec![Fr::from(5_u64), Fr::from(6_u64)];
        let xs = packed_split(&x, &params, &mut rng()).expect("split x");
        let ys = packed_split(&y, &params, &mut rng()).expect("split y");
        let pair = packed_pairgen(&params, b"pp", &mut rng()).expect("pairgen");

        let z = packed_degree_reduce(&xs, &ys, &pair, &params).expect("reduce");
        assert_eq!(slot(&z, &params, 0), x[0] * y[0]);
        assert_eq!(slot(&z, &params, 1), x[1] * y[1]);
    }

    #[test]
    fn packed_split_recovers_slot_values() {
        let params = PackedParams::<Fr>::new(1, 5, 2).expect("params");
        let values = vec![Fr::from(7_u64), Fr::from(8_u64)];
        let shares = packed_split(&values, &params, &mut rng()).expect("split");
        for (j, &v) in values.iter().enumerate() {
            assert_eq!(slot(&shares, &params, j), v);
        }
    }
}
