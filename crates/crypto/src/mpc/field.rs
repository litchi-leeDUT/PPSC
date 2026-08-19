//! Share-field abstraction: lets Shamir/PRSS/degree-reduction protocols serve both
//! arithmetic prime fields and characteristic-2 boolean fields.
//!
//! `PrimeField` satisfies `ShareField` via a blanket impl; `F2` (GF(2^8)) backs the
//! boolean shares of the paper's `Π_S2B`, making `XOR` a local addition and only `AND`
//! requiring degree-reduction multiplication.

// In a characteristic-2 field, add/subtract is XOR and division is inverse-multiplication;
// this is a correct GF(2^8) implementation.
#![allow(clippy::suspicious_arithmetic_impl)]

use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use rand::Rng;
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

pub trait ShareField:
    Sized
    + Copy
    + Clone
    + PartialEq
    + Eq
    + Send
    + Sync
    + 'static
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + Neg<Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
{
    fn zero() -> Self;
    fn one() -> Self;
    fn from_u64(n: u64) -> Self;
    fn inverse(&self) -> Self;
    fn rand(rng: &mut impl Rng) -> Self;
    /// Deterministically map arbitrary bytes to a field element (for PRF derivation).
    fn from_le_bytes(bytes: &[u8]) -> Self;
}

impl<F: PrimeField> ShareField for F {
    fn zero() -> Self {
        <F as Zero>::zero()
    }

    fn one() -> Self {
        <F as One>::one()
    }

    fn from_u64(n: u64) -> Self {
        F::from_le_bytes_mod_order(&n.to_le_bytes())
    }

    fn inverse(&self) -> Self {
        <F as Field>::inverse(self).expect("inverse of non-zero field element")
    }

    fn rand(rng: &mut impl Rng) -> Self {
        <F as UniformRand>::rand(rng)
    }

    fn from_le_bytes(bytes: &[u8]) -> Self {
        F::from_le_bytes_mod_order(bytes)
    }
}

/// GF(2^8) element under the irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (the AES polynomial).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct F2(pub u8);

const GF2_POLY: u8 = 0x1B;

fn gf2_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0_u8;
    while a != 0 && b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= GF2_POLY;
        }
        b >>= 1;
    }
    p
}

fn gf2_pow(mut base: u8, mut exp: u32) -> u8 {
    let mut result = 1_u8;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf2_mul(result, base);
        }
        base = gf2_mul(base, base);
        exp >>= 1;
    }
    result
}

impl std::fmt::Debug for F2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "F2(0x{:02x})", self.0)
    }
}

impl Add for F2 {
    type Output = F2;
    fn add(self, rhs: F2) -> F2 {
        F2(self.0 ^ rhs.0)
    }
}

impl Sub for F2 {
    type Output = F2;
    fn sub(self, rhs: F2) -> F2 {
        F2(self.0 ^ rhs.0)
    }
}

impl Mul for F2 {
    type Output = F2;
    fn mul(self, rhs: F2) -> F2 {
        F2(gf2_mul(self.0, rhs.0))
    }
}

impl Div for F2 {
    type Output = F2;
    fn div(self, rhs: F2) -> F2 {
        self * rhs.inverse()
    }
}

impl Neg for F2 {
    type Output = F2;
    fn neg(self) -> F2 {
        self
    }
}

impl AddAssign for F2 {
    fn add_assign(&mut self, rhs: F2) {
        *self = *self + rhs;
    }
}

impl SubAssign for F2 {
    fn sub_assign(&mut self, rhs: F2) {
        *self = *self - rhs;
    }
}

impl MulAssign for F2 {
    fn mul_assign(&mut self, rhs: F2) {
        *self = *self * rhs;
    }
}

impl ShareField for F2 {
    fn zero() -> Self {
        F2(0)
    }

    fn one() -> Self {
        F2(1)
    }

    fn from_u64(n: u64) -> Self {
        F2(n as u8)
    }

    fn inverse(&self) -> Self {
        assert!(self.0 != 0, "inverse of zero in GF(2^8)");
        F2(gf2_pow(self.0, 254))
    }

    fn rand(rng: &mut impl Rng) -> Self {
        F2(rng.next_u32() as u8)
    }

    fn from_le_bytes(bytes: &[u8]) -> Self {
        F2(bytes.iter().fold(0_u8, |acc, b| acc ^ b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf2_field_axioms() {
        let a = F2(0x53);
        let b = F2(0xCA);
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);
        assert_eq!(a + F2::zero(), a);
        assert_eq!(a * F2::one(), a);
        let inv = a.inverse();
        assert_eq!(a * inv, F2::one());
        assert_eq!(a - a, F2::zero());
        assert_eq!(a / a, F2::one());
    }

    #[test]
    fn gf2_poly_reduces_correctly() {
        // (x+1) * (x+1) = x^2 + 1 in GF(2^8)
        assert_eq!(F2(0x03) * F2(0x03), F2(0x05));
        // (x^7 + x^6 + ... + 1) * x mod poly wraps
        assert_eq!(F2(0x80) * F2(0x02), F2(0x1B));
    }
}
