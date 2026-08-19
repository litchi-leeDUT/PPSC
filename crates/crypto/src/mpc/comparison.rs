//! MPC comparison primitive: `Π_GEQ`, yielding a boolean sharing for the balance comparison
//! of confidential transfer.
//!
//! Built on `Π_S2B`: bit-decompose the difference `a - b`, then negate the top (sign) bit.
//! Precondition: `a, b` both lie in `[0, 2^{ℓ-1})` (less than half the field modulus), so the
//! top bit of the canonical representation of `a - b mod q` is the comparison result.

use super::field::ShareField;
use super::s2b::{s2b, s2b_bounded, BitExtractPair};
use super::shamir::{Committee, ShamirShare};
use super::MpcError;
use ark_ff::PrimeField;
use rand::Rng;

/// Boolean sharing of `a >= b`: returns `[1]` for true, `[0]` for false (shares over `B`).
pub fn greater_than_or_equal<F: PrimeField, B: ShareField>(
    a: &[ShamirShare<F>],
    b: &[ShamirShare<F>],
    pair: &BitExtractPair<F, B>,
    committee_f: &Committee<F>,
    committee_b: &Committee<B>,
    rng: &mut impl Rng,
) -> Result<Vec<ShamirShare<B>>, MpcError> {
    if a.len() != b.len() || a.len() != committee_f.size() {
        return Err(MpcError::ShareCountMismatch);
    }
    let diff: Vec<ShamirShare<F>> = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| {
            if x.point() != y.point() {
                return Err(MpcError::InconsistentShares);
            }
            Ok(ShamirShare::new(x.point(), x.value() - y.value()))
        })
        .collect::<Result<_, MpcError>>()?;

    let bits = s2b(&diff, pair, committee_f, committee_b, rng)?;
    let sign = &bits[bits.len() - 1];
    // ge = NOT sign (negation in characteristic 2 is +1).
    Ok(sign
        .iter()
        .map(|s| ShamirShare::new(s.point(), s.value() + B::one()))
        .collect())
}

/// Bounded comparison `a >= b` for `a, b ∈ [0, 2^bit_len)` (e.g. `bit_len = 32` for u32 balances).
///
/// Computes `w = a - b + 2^bit_len ∈ [0, 2^{bit_len+1})` (no wrap, since `q ≫ 2^{bit_len+1}`),
/// then returns the `bit_len`-th bit of `w`, which is `1` iff `a >= b`. Uses only `bit_len + 1`
/// interactive bits instead of the full-width `Π_S2B`.
#[allow(clippy::too_many_arguments)]
pub fn greater_than_or_equal_bounded<F: PrimeField, B: ShareField>(
    a: &[ShamirShare<F>],
    b: &[ShamirShare<F>],
    pair: &BitExtractPair<F, B>,
    bit_len: usize,
    committee_f: &Committee<F>,
    committee_b: &Committee<B>,
    rng: &mut impl Rng,
) -> Result<Vec<ShamirShare<B>>, MpcError> {
    if a.len() != b.len() || a.len() != committee_f.size() {
        return Err(MpcError::ShareCountMismatch);
    }
    let two_pow = F::from(1_u64 << bit_len);
    let w: Vec<ShamirShare<F>> = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| {
            if x.point() != y.point() {
                return Err(MpcError::InconsistentShares);
            }
            Ok(ShamirShare::new(x.point(), x.value() - y.value() + two_pow))
        })
        .collect::<Result<_, MpcError>>()?;

    let bits = s2b_bounded(&w, pair, bit_len + 1, committee_f, committee_b, rng)?;
    bits.into_iter()
        .nth(bit_len)
        .ok_or(MpcError::InvalidBitLength)
}

/// A correlated random bit: arithmetic and boolean sharings of the same `r ∈ {0,1}`, for B2A.
pub struct RandomBitPair<F: PrimeField, B: ShareField> {
    pub arithmetic: Vec<ShamirShare<F>>,
    pub boolean: Vec<ShamirShare<B>>,
}

/// Offline generation of a correlated random bit (arithmetic/boolean double sharing of `r ∈ {0,1}`).
pub fn generate_random_bit<F: PrimeField, B: ShareField>(
    committee_f: &Committee<F>,
    committee_b: &Committee<B>,
    rng: &mut impl Rng,
) -> Result<RandomBitPair<F, B>, MpcError> {
    let bit = rng.gen::<bool>();
    let r_f = if bit { F::one() } else { F::zero() };
    let r_b = if bit { B::one() } else { B::zero() };
    Ok(RandomBitPair {
        arithmetic: committee_f.split(r_f, rng)?,
        boolean: committee_b.split(r_b, rng)?,
    })
}

/// Boolean sharing `[b]` (`b ∈ {0,1}`) → arithmetic sharing `[b]` (over `F`).
///
/// Mask with a random bit `r`, open `c = b ⊕ r`, then locally recover
/// `[b] = [r] + c - 2c·[r]` (the arithmetic expression of XOR).
pub fn b2a<F: PrimeField, B: ShareField>(
    bit: &[ShamirShare<B>],
    random_bit: &RandomBitPair<F, B>,
    committee_b: &Committee<B>,
) -> Result<Vec<ShamirShare<F>>, MpcError> {
    if bit.len() != random_bit.boolean.len() {
        return Err(MpcError::ShareCountMismatch);
    }
    let c_shares: Vec<ShamirShare<B>> = bit
        .iter()
        .zip(random_bit.boolean.iter())
        .map(|(b, r)| {
            if b.point() != r.point() {
                return Err(MpcError::InconsistentShares);
            }
            Ok(ShamirShare::new(b.point(), b.value() + r.value()))
        })
        .collect::<Result<_, MpcError>>()?;
    let c = committee_b.reconstruct(&c_shares)?;
    let c_f = if c == B::one() { F::one() } else { F::zero() };
    let two_c = c_f + c_f;
    Ok(random_bit
        .arithmetic
        .iter()
        .map(|r| ShamirShare::new(r.point(), r.value() + c_f - two_c * r.value()))
        .collect())
}

/// Conditional select: `[bit] ? [x] : [y]`, i.e. `[y] + [bit]·([x] - [y])`.
#[allow(clippy::too_many_arguments)]
pub fn conditional_select<F: PrimeField, B: ShareField>(
    bit: &[ShamirShare<B>],
    x: &[ShamirShare<F>],
    y: &[ShamirShare<F>],
    random_bit: &RandomBitPair<F, B>,
    mask: &super::HandoffMask<F>,
    committee_f: &Committee<F>,
    committee_b: &Committee<B>,
) -> Result<Vec<ShamirShare<F>>, MpcError> {
    if x.len() != y.len() || x.len() != committee_f.size() {
        return Err(MpcError::ShareCountMismatch);
    }
    let bit_arith = b2a(bit, random_bit, committee_b)?;
    let diff: Vec<ShamirShare<F>> = x
        .iter()
        .zip(y.iter())
        .map(|(xx, yy)| {
            if xx.point() != yy.point() {
                return Err(MpcError::InconsistentShares);
            }
            Ok(ShamirShare::new(xx.point(), xx.value() - yy.value()))
        })
        .collect::<Result<_, MpcError>>()?;
    let t =
        super::handoff::multiply_and_handoff(&bit_arith, &diff, mask, committee_f, committee_f)?;
    Ok(y.iter()
        .zip(t.iter())
        .map(|(yy, tt)| ShamirShare::new(yy.point(), yy.value() + tt.value()))
        .collect())
}

/// confidential transfer core: if `sender > minimum`, move `amount` from sender to receiver,
/// otherwise leave both unchanged. The comparison bit stays secret and is never opened.
pub type ConditionalTransferOutput<F> = (Vec<ShamirShare<F>>, Vec<ShamirShare<F>>);

#[allow(clippy::too_many_arguments)]
pub fn conditional_transfer_strictly_greater<F: PrimeField, B: ShareField>(
    sender: &[ShamirShare<F>],
    receiver: &[ShamirShare<F>],
    minimum: &[ShamirShare<F>],
    amount: &[ShamirShare<F>],
    pair: &BitExtractPair<F, B>,
    committee_f: &Committee<F>,
    committee_b: &Committee<B>,
    rng: &mut impl Rng,
) -> Result<ConditionalTransferOutput<F>, MpcError> {
    if sender.len() != receiver.len()
        || sender.len() != minimum.len()
        || sender.len() != amount.len()
        || sender.len() != committee_f.size()
    {
        return Err(MpcError::ShareCountMismatch);
    }

    // gt = sender > minimum = NOT (minimum >= sender)。
    let geq_min = greater_than_or_equal(minimum, sender, pair, committee_f, committee_b, rng)?;
    let gt: Vec<ShamirShare<B>> = geq_min
        .iter()
        .map(|s| ShamirShare::new(s.point(), s.value() + B::one()))
        .collect();

    let sender_minus: Vec<ShamirShare<F>> = sender
        .iter()
        .zip(amount.iter())
        .map(|(s, a)| ShamirShare::new(s.point(), s.value() - a.value()))
        .collect();
    let receiver_plus: Vec<ShamirShare<F>> = receiver
        .iter()
        .zip(amount.iter())
        .map(|(r, a)| ShamirShare::new(r.point(), r.value() + a.value()))
        .collect();

    let threshold = committee_f.threshold;
    let rb1 = generate_random_bit(committee_f, committee_b, rng)?;
    let mask1 = super::prss::reshare_pair(
        committee_f,
        2 * threshold,
        committee_f,
        threshold,
        b"cnd-sel-1",
        rng,
    )?;
    let sender_new = conditional_select(
        &gt,
        &sender_minus,
        sender,
        &rb1,
        &mask1,
        committee_f,
        committee_b,
    )?;

    let rb2 = generate_random_bit(committee_f, committee_b, rng)?;
    let mask2 = super::prss::reshare_pair(
        committee_f,
        2 * threshold,
        committee_f,
        threshold,
        b"cnd-sel-2",
        rng,
    )?;
    let receiver_new = conditional_select(
        &gt,
        &receiver_plus,
        receiver,
        &rb2,
        &mask2,
        committee_f,
        committee_b,
    )?;

    Ok((sender_new, receiver_new))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::{
        generate_bit_extract_pair, generate_bit_extract_pair_bounded, reshare_pair, F2,
    };
    use ark_bn254::Fr;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x0F0E_0D0C)
    }

    fn geq(a: u64, b: u64) -> bool {
        let committee_f = Committee::<Fr>::new(2, 5).expect("committee f n=5>2t");
        let committee_b = Committee::<F2>::new(2, 5).expect("committee b n=5>2t");
        let a_shares = committee_f.split(Fr::from(a), &mut rng()).expect("split a");
        let b_shares = committee_f.split(Fr::from(b), &mut rng()).expect("split b");
        let pair = generate_bit_extract_pair(&committee_f, &committee_b, &mut rng()).expect("pair");
        let geq_shares = greater_than_or_equal(
            &a_shares,
            &b_shares,
            &pair,
            &committee_f,
            &committee_b,
            &mut rng(),
        )
        .expect("geq");
        let bit = committee_b
            .reconstruct(&geq_shares)
            .expect("reconstruct bit");
        bit == F2::one()
    }

    #[test]
    fn geq_agrees_with_plaintext_comparison() {
        assert!(geq(5, 3));
        assert!(!geq(3, 5));
        assert!(geq(5, 5));
        assert!(geq(0, 0));
        assert!(geq(100, 99));
        assert!(!geq(99, 100));
    }

    #[test]
    fn geq_bounded_agrees_with_plaintext_comparison() {
        let committee_f = Committee::<Fr>::new(2, 5).expect("committee f n=5>2t");
        let committee_b = Committee::<F2>::new(2, 5).expect("committee b n=5>2t");
        for (a, b) in [
            (5_u64, 3_u64),
            (3, 5),
            (5, 5),
            (0, 0),
            (100, 99),
            (99, 100),
            (1_u64 << 31, (1_u64 << 31) - 1),
            (1, 1_u64 << 31),
            (0, (1_u64 << 32) - 1),
        ] {
            let a_shares = committee_f.split(Fr::from(a), &mut rng()).expect("split a");
            let b_shares = committee_f.split(Fr::from(b), &mut rng()).expect("split b");
            let pair =
                generate_bit_extract_pair_bounded(&committee_f, &committee_b, 33, &mut rng())
                    .expect("pair");
            let geq_shares = greater_than_or_equal_bounded(
                &a_shares,
                &b_shares,
                &pair,
                32,
                &committee_f,
                &committee_b,
                &mut rng(),
            )
            .expect("geq");
            let bit = committee_b
                .reconstruct(&geq_shares)
                .expect("reconstruct bit");
            assert_eq!(bit == F2::one(), a >= b, "a={a} b={b}");
        }
    }

    #[test]
    fn b2a_recovers_boolean_bit_as_arithmetic() {
        let committee_f = Committee::<Fr>::new(2, 5).expect("committee f");
        let committee_b = Committee::<F2>::new(2, 5).expect("committee b");

        for truth in [false, true] {
            let bit = committee_b
                .split(if truth { F2::one() } else { F2::zero() }, &mut rng())
                .expect("split bit");
            let random_bit =
                generate_random_bit(&committee_f, &committee_b, &mut rng()).expect("random bit");
            let arith = b2a(&bit, &random_bit, &committee_b).expect("b2a");
            let recovered = committee_f.reconstruct(&arith).expect("reconstruct");
            let expect = if truth { Fr::one() } else { Fr::zero() };
            assert_eq!(recovered, expect);
        }
    }

    #[test]
    fn conditional_select_returns_correct_branch() {
        let committee_f = Committee::<Fr>::new(2, 5).expect("committee f n=5>2t");
        let committee_b = Committee::<F2>::new(2, 5).expect("committee b");
        let x = Fr::from(10_u64);
        let y = Fr::from(3_u64);
        let x_shares = committee_f.split(x, &mut rng()).expect("split x");
        let y_shares = committee_f.split(y, &mut rng()).expect("split y");

        for (truth, expect) in [(true, x), (false, y)] {
            let bit = committee_b
                .split(if truth { F2::one() } else { F2::zero() }, &mut rng())
                .expect("split bit");
            let random_bit =
                generate_random_bit(&committee_f, &committee_b, &mut rng()).expect("random bit");
            let mask =
                reshare_pair(&committee_f, 4, &committee_f, 2, b"sel", &mut rng()).expect("mask");
            let selected = conditional_select(
                &bit,
                &x_shares,
                &y_shares,
                &random_bit,
                &mask,
                &committee_f,
                &committee_b,
            )
            .expect("select");
            assert_eq!(
                committee_f.reconstruct(&selected).expect("reconstruct"),
                expect
            );
        }
    }

    #[test]
    fn conditional_transfer_updates_only_when_sender_exceeds_minimum() {
        let committee_f = Committee::<Fr>::new(2, 5).expect("committee f n=5>2t");
        let committee_b = Committee::<F2>::new(2, 5).expect("committee b");

        for (sender, minimum, expect_sender, expect_receiver) in [
            (100_u64, 50_u64, 70_u64, 50_u64),
            (40_u64, 50_u64, 40_u64, 20_u64),
        ] {
            let sender_shares = committee_f
                .split(Fr::from(sender), &mut rng())
                .expect("sender");
            let receiver_shares = committee_f
                .split(Fr::from(20_u64), &mut rng())
                .expect("receiver");
            let minimum_shares = committee_f
                .split(Fr::from(minimum), &mut rng())
                .expect("minimum");
            let amount_shares = committee_f
                .split(Fr::from(30_u64), &mut rng())
                .expect("amount");
            let pair =
                generate_bit_extract_pair(&committee_f, &committee_b, &mut rng()).expect("pair");

            let (sender_new, receiver_new) = conditional_transfer_strictly_greater(
                &sender_shares,
                &receiver_shares,
                &minimum_shares,
                &amount_shares,
                &pair,
                &committee_f,
                &committee_b,
                &mut rng(),
            )
            .expect("transfer");

            assert_eq!(
                committee_f
                    .reconstruct(&sender_new)
                    .expect("reconstruct sender"),
                Fr::from(expect_sender)
            );
            assert_eq!(
                committee_f
                    .reconstruct(&receiver_new)
                    .expect("reconstruct receiver"),
                Fr::from(expect_receiver)
            );
        }
    }

    #[test]
    fn conditional_transfer_robust_across_seeds() {
        for seed in 0..8_u64 {
            let mut rng = StdRng::seed_from_u64(seed);
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
            let pair =
                generate_bit_extract_pair(&committee_f, &committee_b, &mut rng).expect("pair");
            let (sender_new, receiver_new) = conditional_transfer_strictly_greater(
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
                committee_f.reconstruct(&sender_new).expect("sender"),
                Fr::from(70_u64),
                "sender seed {seed}"
            );
            assert_eq!(
                committee_f.reconstruct(&receiver_new).expect("receiver"),
                Fr::from(50_u64),
                "receiver seed {seed}"
            );
        }
    }
}
