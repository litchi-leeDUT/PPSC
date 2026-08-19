//! Arithmetic→boolean share conversion `Π_S2B` (paper §3.2, appendix).
//!
//! Arithmetic shares live in a prime field `F`, boolean shares in a characteristic-2 field
//! `B` (default `F2 = GF(2^8)`). In characteristic 2, `XOR` is addition (local), and only
//! `AND` (`[a]·[b]`) needs degree-reduction multiplication `Π_DN-Mult`, faithfully matching
//! the paper's "XOR local, AND interactive" structure. BitExtract pairs are trusted offline
//! preprocessing.

use super::field::ShareField;
use super::handoff::{masked_difference_shares, multiply_and_handoff};
use super::prss::reshare_pair_dealer;
use super::shamir::{reconstruct, Committee, ShamirShare};
use super::MpcError;
use ark_ff::{BigInteger, PrimeField};
use rand::Rng;

type BitShares<B> = Vec<ShamirShare<B>>;
type SumCarry<B> = (Vec<BitShares<B>>, BitShares<B>);
type BitPair<B> = (BitShares<B>, BitShares<B>);

/// A one-time BitExtract pair: the arithmetic sharing `[r]` and boolean sharings `[r_k]` of its bits.
pub struct BitExtractPair<F: PrimeField, B: ShareField> {
    pub arithmetic: Vec<ShamirShare<F>>,
    pub bits: Vec<Vec<ShamirShare<B>>>,
}

/// Offline generation of a BitExtract pair (sample random `r`, share `r` and each of its bits).
pub fn generate_bit_extract_pair<F: PrimeField, B: ShareField>(
    committee_f: &Committee<F>,
    committee_b: &Committee<B>,
    rng: &mut impl Rng,
) -> Result<BitExtractPair<F, B>, MpcError> {
    let r = F::rand(rng);
    let arithmetic = committee_f.split(r, rng)?;
    let bits = bigint_bits_le::<F>(r)
        .into_iter()
        .map(|bit| {
            let value = if bit { B::one() } else { B::zero() };
            committee_b.split(value, rng)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BitExtractPair { arithmetic, bits })
}

/// `Π_S2B`: `[x]^{t,q}` → boolean sharing `([x_0],...,[x_{ℓ-1}])` with `x = Σ 2^k x_k`.
pub fn s2b<F: PrimeField, B: ShareField>(
    x_shares: &[ShamirShare<F>],
    pair: &BitExtractPair<F, B>,
    committee_f: &Committee<F>,
    committee_b: &Committee<B>,
    rng: &mut impl Rng,
) -> Result<Vec<Vec<ShamirShare<B>>>, MpcError> {
    if committee_f.size() != committee_b.size() || committee_f.threshold != committee_b.threshold {
        return Err(MpcError::InconsistentShares);
    }
    if committee_b.size() <= 2 * committee_b.threshold {
        return Err(MpcError::TooFewParties);
    }
    if x_shares.len() != committee_f.size() || pair.arithmetic.len() != committee_f.size() {
        return Err(MpcError::ShareCountMismatch);
    }
    let bit_len = F::MODULUS_BIT_SIZE as usize;
    if pair.bits.len() != bit_len {
        return Err(MpcError::InvalidBitLength);
    }

    // 1. δ = (x - r) mod q, public.
    let delta_shares = masked_difference_shares(x_shares, &pair.arithmetic)?;
    let delta = reconstruct(&delta_shares, committee_f.threshold + 1)?;
    let delta_bits = bigint_bits_le::<F>(delta);

    let mut counter = 0_u64;

    // 2. s = δ + r (ripple-carry full adder; XOR local, AND interactive).
    let (sum_bits, carry) = ripple_add(&delta_bits, &pair.bits, committee_b, rng, &mut counter)?;
    let mut s_full = sum_bits;
    s_full.push(carry);

    // 3. d = s - q and its borrow (q public).
    let q_bits: Vec<bool> = F::MODULUS.to_bits_le().into_iter().take(bit_len).collect();
    let mut q_full = q_bits;
    q_full.push(false);
    let (diff_bits, borrow) = ripple_sub(&s_full, &q_full, committee_b, rng, &mut counter)?;

    // 4. select = s ≥ q = 1 + borrow (negation in characteristic 2); out_k = s_k + select·(d_k + s_k).
    let select: Vec<ShamirShare<B>> = borrow
        .iter()
        .map(|s| ShamirShare::new(s.point(), B::one() + s.value()))
        .collect();
    let mut out = Vec::with_capacity(bit_len);
    for k in 0..bit_len {
        let d_xor_s: Vec<ShamirShare<B>> = diff_bits[k]
            .iter()
            .zip(s_full[k].iter())
            .map(|(d, s)| ShamirShare::new(d.point(), d.value() + s.value()))
            .collect();
        let t = secret_and(&select, &d_xor_s, committee_b, rng, &mut counter)?;
        let out_k: Vec<ShamirShare<B>> = s_full[k]
            .iter()
            .zip(t.iter())
            .map(|(s, tt)| ShamirShare::new(s.point(), s.value() + tt.value()))
            .collect();
        out.push(out_k);
    }
    Ok(out)
}

fn ripple_add<B: ShareField>(
    delta_bits: &[bool],
    r_bits: &[Vec<ShamirShare<B>>],
    committee: &Committee<B>,
    rng: &mut impl Rng,
    counter: &mut u64,
) -> Result<SumCarry<B>, MpcError> {
    let mut carry = committee.split(B::zero(), rng)?;
    let mut sum = Vec::with_capacity(delta_bits.len());
    for k in 0..delta_bits.len() {
        let (s, c) = full_adder(delta_bits[k], &r_bits[k], &carry, committee, rng, counter)?;
        sum.push(s);
        carry = c;
    }
    Ok((sum, carry))
}

fn full_adder<B: ShareField>(
    a: bool,
    b: &[ShamirShare<B>],
    c: &[ShamirShare<B>],
    committee: &Committee<B>,
    rng: &mut impl Rng,
    counter: &mut u64,
) -> Result<BitPair<B>, MpcError> {
    let a_f = if a { B::one() } else { B::zero() };
    let t = secret_and(b, c, committee, rng, counter)?;
    let mut sum = Vec::with_capacity(b.len());
    let mut carry = Vec::with_capacity(b.len());
    for i in 0..b.len() {
        let bi = b[i].value();
        let ci = c[i].value();
        let ti = t[i].value();
        let point = b[i].point();
        sum.push(ShamirShare::new(point, a_f + bi + ci));
        carry.push(ShamirShare::new(point, a_f * (bi + ci) + ti));
    }
    Ok((sum, carry))
}

fn ripple_sub<B: ShareField>(
    s_bits: &[Vec<ShamirShare<B>>],
    q_bits: &[bool],
    committee: &Committee<B>,
    rng: &mut impl Rng,
    counter: &mut u64,
) -> Result<SumCarry<B>, MpcError> {
    let mut borrow = committee.split(B::zero(), rng)?;
    let mut diff = Vec::with_capacity(s_bits.len());
    for k in 0..s_bits.len() {
        let (d, b_out) = full_subtractor(&s_bits[k], q_bits[k], &borrow, committee, rng, counter)?;
        diff.push(d);
        borrow = b_out;
    }
    Ok((diff, borrow))
}

fn full_subtractor<B: ShareField>(
    a: &[ShamirShare<B>],
    b: bool,
    b_in: &[ShamirShare<B>],
    committee: &Committee<B>,
    rng: &mut impl Rng,
    counter: &mut u64,
) -> Result<BitPair<B>, MpcError> {
    let b_f = if b { B::one() } else { B::zero() };
    let u = secret_and(a, b_in, committee, rng, counter)?;
    let mut diff = Vec::with_capacity(a.len());
    let mut borrow = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        let ai = a[i].value();
        let bi = b_in[i].value();
        let ui = u[i].value();
        let point = a[i].point();
        // diff = a ⊕ b ⊕ b_in = a + b + b_in (characteristic 2)
        diff.push(ShamirShare::new(point, ai + b_f + bi));
        // borrow = (¬a)b ⊕ (¬a)b_in ⊕ b·b_in = b + b·a + b_in + a·b_in + b·b_in
        borrow.push(ShamirShare::new(point, b_f + b_f * ai + bi + ui + b_f * bi));
    }
    Ok((diff, borrow))
}

fn secret_and<B: ShareField>(
    a: &[ShamirShare<B>],
    b: &[ShamirShare<B>],
    committee: &Committee<B>,
    rng: &mut impl Rng,
    counter: &mut u64,
) -> Result<Vec<ShamirShare<B>>, MpcError> {
    *counter += 1;
    let mask = reshare_pair_dealer(
        committee,
        2 * committee.threshold,
        committee,
        committee.threshold,
        rng,
    )?;
    multiply_and_handoff(a, b, &mask, committee, committee)
}

fn bigint_bits_le<F: PrimeField>(x: F) -> Vec<bool> {
    x.into_bigint()
        .to_bits_le()
        .into_iter()
        .take(F::MODULUS_BIT_SIZE as usize)
        .collect()
}

/// Centered lift of a field element to `(-q/2, q/2)`, returned as `i128`.
///
/// For a bounded value `x ∈ [0, 2^ℓ)` with `ℓ ≤ 63`, a masked difference `x - r` satisfies
/// `|x - r| < 2^ℓ < q/2`, so its `mod q` representative is either `x - r` (small) or `q - (r - x)`
/// (near `q`); the lift recovers the exact signed value, whose magnitude fits in a `u64` limb.
fn centered_lift<F: PrimeField>(f: F) -> i128 {
    let bi = f.into_bigint();
    let mut half = F::MODULUS;
    half.div2();
    if bi > half {
        let mut mag = F::MODULUS;
        let borrow = mag.sub_with_borrow(&bi);
        debug_assert!(!borrow, "modulus must exceed the lifted value");
        -(mag.as_ref()[0] as i128)
    } else {
        bi.as_ref()[0] as i128
    }
}

/// Two's-complement representation of `delta` in `bit_len` bits (for `|delta| < 2^{bit_len-1}`).
fn two_complement_bits(delta: i128, bit_len: usize) -> Vec<bool> {
    let modulus = 1_i128 << bit_len;
    let canonical = if delta < 0 { modulus + delta } else { delta };
    (0..bit_len).map(|k| ((canonical >> k) & 1) == 1).collect()
}

/// Offline `BitExtract` pair for a **bounded** `bit_len`-bit mask `r ∈ [0, 2^bit_len)`.
///
/// Unlike the full-width pair, the mask is drawn from the small range so that `x - r` stays
/// within `(-2^bit_len, 2^bit_len)` for `x ∈ [0, 2^bit_len)` (no `mod q` wrap past half).
pub fn generate_bit_extract_pair_bounded<F: PrimeField, B: ShareField>(
    committee_f: &Committee<F>,
    committee_b: &Committee<B>,
    bit_len: usize,
    rng: &mut impl Rng,
) -> Result<BitExtractPair<F, B>, MpcError> {
    debug_assert!(bit_len < 64, "bounded pair supports up to 63 bits");
    let mask = (1_u64 << bit_len) - 1;
    let r = rng.gen::<u64>() & mask;
    let arithmetic = committee_f.split(F::from(r), rng)?;
    let bits = (0..bit_len)
        .map(|k| {
            let value = if (r >> k) & 1 == 1 {
                B::one()
            } else {
                B::zero()
            };
            committee_b.split(value, rng)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BitExtractPair { arithmetic, bits })
}

/// `Π_S2B` for a **bounded** value `x ∈ [0, 2^bit_len)`: decompose into `bit_len` boolean shares.
///
/// The mask `r ∈ [0, 2^bit_len)` keeps `δ = x - r` in `(-2^bit_len, 2^bit_len)`, so no canonical
/// `mod q` reduction is needed: the two's-complement `δ` bits are ripple-added to `r`'s bits,
/// yielding exactly `x`'s `bit_len` bits.
pub fn s2b_bounded<F: PrimeField, B: ShareField>(
    x_shares: &[ShamirShare<F>],
    pair: &BitExtractPair<F, B>,
    bit_len: usize,
    committee_f: &Committee<F>,
    committee_b: &Committee<B>,
    rng: &mut impl Rng,
) -> Result<Vec<Vec<ShamirShare<B>>>, MpcError> {
    if committee_f.size() != committee_b.size() || committee_f.threshold != committee_b.threshold {
        return Err(MpcError::InconsistentShares);
    }
    if committee_b.size() <= 2 * committee_b.threshold {
        return Err(MpcError::TooFewParties);
    }
    if x_shares.len() != committee_f.size() || pair.arithmetic.len() != committee_f.size() {
        return Err(MpcError::ShareCountMismatch);
    }
    if pair.bits.len() != bit_len {
        return Err(MpcError::InvalidBitLength);
    }

    let delta_shares = masked_difference_shares(x_shares, &pair.arithmetic)?;
    let delta_f = reconstruct(&delta_shares, committee_f.threshold + 1)?;
    let delta = centered_lift::<F>(delta_f);
    let delta_bits = two_complement_bits(delta, bit_len);

    let mut counter = 0_u64;
    let (sum_bits, _carry) = ripple_add(&delta_bits, &pair.bits, committee_b, rng, &mut counter)?;
    Ok(sum_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::F2;
    use ark_bn254::Fr;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x0F0E_0D0C)
    }

    #[test]
    fn s2b_recovers_canonical_bits() {
        let committee_f = Committee::<Fr>::new(2, 5).expect("committee f n=5>2t");
        let committee_b = Committee::<F2>::new(2, 5).expect("committee b n=5>2t");
        let x = Fr::from(123_456_789_u64);
        let x_shares = committee_f.split(x, &mut rng()).expect("split x");
        let pair = generate_bit_extract_pair(&committee_f, &committee_b, &mut rng()).expect("pair");
        let out = s2b(&x_shares, &pair, &committee_f, &committee_b, &mut rng()).expect("s2b");

        let mut recovered = Fr::zero();
        let mut two_pow = Fr::one();
        for bit_shares in &out {
            let bit = committee_b
                .reconstruct(bit_shares)
                .expect("reconstruct bit");
            assert!(bit == F2::zero() || bit == F2::one());
            if bit == F2::one() {
                recovered += two_pow;
            }
            two_pow += two_pow;
        }
        assert_eq!(recovered, x);
    }
}
