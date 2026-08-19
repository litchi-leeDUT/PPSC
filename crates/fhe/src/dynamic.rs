//! Dynamic-modulus field and per-modulus Shamir sharing for OpenFHE's RNS moduli.
//!
//! OpenFHE BFV ciphertexts live over several runtime prime moduli `q_0..q_{L-1}`.
//! A paper-style "Shamir key threshold" must share the secret key coefficient-wise in
//! each modulus `F_{q_j}` independently. Ark-ff fields are compile-time constants, so we
//! provide a tiny runtime-modulus field here (`DynField`) with u128 arithmetic (safe for
//! `q < 2^60`, since `q·q < 2^120`) plus Shamir split/reconstruct over its own modulus.

use rand::Rng;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DynField {
    value: u64,
    q: u64,
}

impl DynField {
    pub fn new(value: u64, q: u64) -> Self {
        debug_assert!(q > 1, "modulus must be prime > 1");
        Self {
            value: value % q,
            q,
        }
    }

    pub fn zero(q: u64) -> Self {
        Self { value: 0, q }
    }

    pub fn one(q: u64) -> Self {
        Self { value: 1, q }
    }

    pub fn modulus(&self) -> u64 {
        self.q
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn add(&self, o: &Self) -> Self {
        debug_assert_eq!(self.q, o.q, "modulus mismatch");
        Self::new(self.value + o.value, self.q)
    }

    pub fn sub(&self, o: &Self) -> Self {
        debug_assert_eq!(self.q, o.q, "modulus mismatch");
        Self::new(self.value + self.q - o.value, self.q)
    }

    pub fn neg(&self) -> Self {
        Self::new(self.q - self.value, self.q)
    }

    pub fn mul(&self, o: &Self) -> Self {
        debug_assert_eq!(self.q, o.q, "modulus mismatch");
        let m = (self.value as u128 * o.value as u128) % self.q as u128;
        Self::new(m as u64, self.q)
    }

    pub fn inv(&self) -> Self {
        debug_assert_ne!(self.value, 0, "inverse of zero");
        // Extended Euclid over i128 (q < 2^60 keeps intermediates well within range).
        let mut t = 0_i128;
        let mut new_t = 1_i128;
        let mut r = self.q as i128;
        let mut new_r = self.value as i128;
        while new_r != 0 {
            let quotient = r / new_r;
            (t, new_t) = (new_t, t - quotient * new_t);
            (r, new_r) = (new_r, r - quotient * new_r);
        }
        debug_assert_eq!(r, 1, "modulus must be prime");
        if t < 0 {
            t += self.q as i128;
        }
        Self::new(t as u64, self.q)
    }

    pub fn div(&self, o: &Self) -> Self {
        self.mul(&o.inv())
    }

    pub fn rand(q: u64, rng: &mut impl Rng) -> Self {
        Self::new(rng.gen::<u64>(), q)
    }
}

impl std::fmt::Debug for DynField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DynField({} mod {})", self.value, self.q)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DynShare {
    pub point: DynField,
    pub value: DynField,
}

impl std::fmt::Debug for DynShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DynShare({} mod {})", self.value.value, self.value.q)
    }
}

/// Evaluation points `alpha_i = i` (`i in 1..=n`) in `F_q`.
pub fn eval_points(q: u64, n: usize) -> Vec<DynField> {
    (1..=n).map(|i| DynField::new(i as u64, q)).collect()
}

fn eval_poly(coeffs: &[DynField], x: DynField) -> DynField {
    let mut acc = DynField::zero(x.q);
    for c in coeffs.iter().rev() {
        acc = acc.mul(&x).add(c);
    }
    acc
}

/// Share `secret` into `points.len()` shares of a degree-`threshold` polynomial in `F_q`.
pub fn split(
    secret: &DynField,
    threshold: usize,
    points: &[DynField],
    rng: &mut impl Rng,
) -> Vec<DynShare> {
    let q = secret.q;
    let mut coeffs = Vec::with_capacity(threshold + 1);
    coeffs.push(*secret);
    for _ in 0..threshold {
        coeffs.push(DynField::rand(q, rng));
    }
    points
        .iter()
        .map(|&p| DynShare {
            point: p,
            value: eval_poly(&coeffs, p),
        })
        .collect()
}

/// Reconstruct at `X=0` via Lagrange interpolation of `shares` (each with its point).
pub fn reconstruct(shares: &[DynShare]) -> DynField {
    let q = shares[0].point.q;
    let mut acc = DynField::zero(q);
    for (i, si) in shares.iter().enumerate() {
        let mut li = DynField::one(q);
        for (j, sj) in shares.iter().enumerate() {
            if i != j {
                let denom = si.point.sub(&sj.point);
                li = li.mul(&(DynField::zero(q).sub(&sj.point).div(&denom)));
            }
        }
        acc = acc.add(&li.mul(&si.value));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn field_axioms() {
        let q = 1152921504606748673_u64;
        let a = DynField::new(12345, q);
        let b = DynField::new(67890, q);
        assert_eq!(a.add(&b), b.add(&a));
        assert_eq!(a.mul(&b), b.mul(&a));
        assert_eq!(a.mul(&a.inv()), DynField::one(q));
        assert_eq!(a.sub(&a), DynField::zero(q));
        assert_eq!(a.div(&a), DynField::one(q));
    }

    #[test]
    fn split_reconstruct_round_trips() {
        let q = 1152921504606748673_u64;
        let mut rng = StdRng::seed_from_u64(0);
        let points = eval_points(q, 5);
        let secret = DynField::new(42, q);
        let shares = split(&secret, 2, &points, &mut rng);
        assert_eq!(shares.len(), 5);
        assert_eq!(reconstruct(&shares[..3]), secret);
        assert_eq!(reconstruct(&shares[1..]), secret);
    }
}
