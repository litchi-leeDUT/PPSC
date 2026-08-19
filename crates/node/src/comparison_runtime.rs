//! Networked MPC comparison and conditional transfer for end-to-end benchmarks.
//!
//! Reuses `ppsc-crypto`'s local Shamir arithmetic while routing every "open" (masked reveal)
//! through a `MemoryMailbox` with RTT latency, so per-invocation latency reflects the real
//! communication rounds under LAN/MAN/WAN profiles. Uses the bounded 32-bit comparison
//! (`Π_S2B` over `bit_len + 1` bits) for u32 balances/bids.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ppsc_core::NodeId;
use ppsc_crypto::mpc::{
    apply_difference, generate_random_bit, masked_difference_shares, reconstruct_from_parts,
    reshare_pair_dealer, BitExtractPair, Committee, HandoffMask, RandomBitPair, ShamirShare,
    ShareField, F2,
};
use ppsc_network::memory::{MemoryMailbox, NetworkProfile};
use rand::Rng;

/// Balance/bid value width: values lie in `[0, 2^BALANCE_BITS)`, so comparison only decomposes
/// `BALANCE_BITS + 1` bits instead of the full 254-bit field.
pub const BALANCE_BITS: usize = 32;

/// Centered lift of a field element to `(-q/2, q/2)` as `i128` (magnitude fits a `u64` limb).
fn centered_lift(f: Fr) -> i128 {
    let bi = f.into_bigint();
    let mut half = Fr::MODULUS;
    half.div2();
    if bi > half {
        let mut mag = Fr::MODULUS;
        let borrow = mag.sub_with_borrow(&bi);
        debug_assert!(!borrow);
        -(mag.as_ref()[0] as i128)
    } else {
        bi.as_ref()[0] as i128
    }
}

/// Two's-complement representation of `delta` in `bit_len` bits.
fn two_complement_bits(delta: i128, bit_len: usize) -> Vec<bool> {
    let modulus = 1_i128 << bit_len;
    let canonical = if delta < 0 { modulus + delta } else { delta };
    (0..bit_len).map(|k| ((canonical >> k) & 1) == 1).collect()
}

/// Open a sharing over the network: each party sends its share to the dealer (one one-way
/// latency), the dealer reconstructs and broadcasts `delta` (a second one-way latency).
fn open_shares<F: ShareField>(
    shares: &[ShamirShare<F>],
    committee: &Committee<F>,
    nodes: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
    required: usize,
) -> F {
    let mailbox = MemoryMailbox::<(usize, F)>::with_latency(profile.one_way_latency());
    for (i, s) in shares.iter().enumerate() {
        mailbox.send(dealer, (i, s.value()));
    }
    let subs = mailbox.drain(dealer);
    let points: Vec<F> = subs.iter().map(|(i, _)| committee.points[*i]).collect();
    let values: Vec<F> = subs.iter().map(|(_, v)| *v).collect();
    let delta = reconstruct_from_parts(&points, &values, required).expect("open reconstruct");
    for &n in nodes {
        mailbox.send(n, (usize::MAX, delta));
    }
    for &n in nodes {
        let _ = mailbox.drain(n);
    }
    delta
}

/// Degree-reducing multiplication with a networked open (source and destination share the
/// same committee; the mask `r` is pre-generated offline by `reshare_pair_dealer`).
fn multiply_open<F: ShareField>(
    a: &[ShamirShare<F>],
    b: &[ShamirShare<F>],
    mask: &HandoffMask<F>,
    committee: &Committee<F>,
    nodes: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
) -> Vec<ShamirShare<F>> {
    let delta_shares: Vec<ShamirShare<F>> = a
        .iter()
        .zip(b.iter())
        .zip(mask.source.iter())
        .map(|((ai, bi), ri)| {
            ShamirShare::from_point_value(ai.point(), ai.value() * bi.value() - ri.value())
        })
        .collect();
    let delta = open_shares(
        &delta_shares,
        committee,
        nodes,
        dealer,
        profile,
        2 * committee.threshold + 1,
    );
    apply_difference(delta, &mask.destination)
}

fn secret_and_network(
    a: &[ShamirShare<F2>],
    b: &[ShamirShare<F2>],
    committee: &Committee<F2>,
    nodes: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
    rng: &mut impl Rng,
) -> Vec<ShamirShare<F2>> {
    let mask = reshare_pair_dealer(
        committee,
        2 * committee.threshold,
        committee,
        committee.threshold,
        rng,
    )
    .expect("and mask");
    multiply_open(a, b, &mask, committee, nodes, dealer, profile)
}

#[allow(clippy::too_many_arguments)]
fn full_adder_network(
    a: bool,
    b: &[ShamirShare<F2>],
    c: &[ShamirShare<F2>],
    committee: &Committee<F2>,
    nodes: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
    rng: &mut impl Rng,
) -> (Vec<ShamirShare<F2>>, Vec<ShamirShare<F2>>) {
    let t = secret_and_network(b, c, committee, nodes, dealer, profile, rng);
    let a_f = if a { F2::one() } else { F2::zero() };
    let mut sum = Vec::with_capacity(b.len());
    let mut carry = Vec::with_capacity(b.len());
    for i in 0..b.len() {
        let bi = b[i].value();
        let ci = c[i].value();
        let ti = t[i].value();
        let point = b[i].point();
        sum.push(ShamirShare::from_point_value(point, a_f + bi + ci));
        carry.push(ShamirShare::from_point_value(point, a_f * (bi + ci) + ti));
    }
    (sum, carry)
}

fn ripple_add_network(
    delta_bits: &[bool],
    r_bits: &[Vec<ShamirShare<F2>>],
    committee: &Committee<F2>,
    nodes: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
    rng: &mut impl Rng,
) -> (Vec<Vec<ShamirShare<F2>>>, Vec<ShamirShare<F2>>) {
    let mut carry = committee.split(F2::zero(), rng).expect("carry");
    let mut sum = Vec::with_capacity(delta_bits.len());
    for k in 0..delta_bits.len() {
        let (s, c) = full_adder_network(
            delta_bits[k],
            &r_bits[k],
            &carry,
            committee,
            nodes,
            dealer,
            profile,
            rng,
        );
        sum.push(s);
        carry = c;
    }
    (sum, carry)
}

/// Bounded `Π_S2B` over `bit_len` bits, with networked opens.
#[allow(clippy::too_many_arguments)]
fn s2b_bounded_network(
    x_shares: &[ShamirShare<Fr>],
    pair: &BitExtractPair<Fr, F2>,
    bit_len: usize,
    committee_f: &Committee<Fr>,
    committee_b: &Committee<F2>,
    nodes_f: &[NodeId],
    nodes_b: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
    rng: &mut impl Rng,
) -> Vec<Vec<ShamirShare<F2>>> {
    let delta_shares = masked_difference_shares(x_shares, &pair.arithmetic).expect("diff");
    let delta_f = open_shares(
        &delta_shares,
        committee_f,
        nodes_f,
        dealer,
        profile,
        committee_f.threshold + 1,
    );
    let delta = centered_lift(delta_f);
    let delta_bits = two_complement_bits(delta, bit_len);

    let (sum_bits, _carry) = ripple_add_network(
        &delta_bits,
        &pair.bits,
        committee_b,
        nodes_b,
        dealer,
        profile,
        rng,
    );
    sum_bits
}

/// Boolean→arithmetic with a networked open (`c = b ⊕ r`).
fn b2a_network(
    bit: &[ShamirShare<F2>],
    random_bit: &RandomBitPair<Fr, F2>,
    committee_b: &Committee<F2>,
    nodes_b: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
) -> Vec<ShamirShare<Fr>> {
    let c_shares: Vec<ShamirShare<F2>> = bit
        .iter()
        .zip(random_bit.boolean.iter())
        .map(|(b, r)| ShamirShare::from_point_value(b.point(), b.value() + r.value()))
        .collect();
    let c = open_shares(
        &c_shares,
        committee_b,
        nodes_b,
        dealer,
        profile,
        committee_b.threshold + 1,
    );
    let c_f = if c == F2::one() {
        Fr::one()
    } else {
        Fr::zero()
    };
    let two_c = c_f + c_f;
    random_bit
        .arithmetic
        .iter()
        .map(|r| ShamirShare::from_point_value(r.point(), r.value() + c_f - two_c * r.value()))
        .collect()
}

/// Networked conditional select `[bit] ? [x] : [y]`.
#[allow(clippy::too_many_arguments)]
pub fn conditional_select_network(
    bit: &[ShamirShare<F2>],
    x: &[ShamirShare<Fr>],
    y: &[ShamirShare<Fr>],
    random_bit: &RandomBitPair<Fr, F2>,
    mask: &HandoffMask<Fr>,
    committee_f: &Committee<Fr>,
    committee_b: &Committee<F2>,
    nodes_f: &[NodeId],
    nodes_b: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
) -> Vec<ShamirShare<Fr>> {
    let bit_arith = b2a_network(bit, random_bit, committee_b, nodes_b, dealer, profile);
    let diff: Vec<ShamirShare<Fr>> = x
        .iter()
        .zip(y.iter())
        .map(|(xx, yy)| ShamirShare::from_point_value(xx.point(), xx.value() - yy.value()))
        .collect();
    let t = multiply_open(
        &bit_arith,
        &diff,
        mask,
        committee_f,
        nodes_f,
        dealer,
        profile,
    );
    y.iter()
        .zip(t.iter())
        .map(|(yy, tt)| ShamirShare::from_point_value(yy.point(), yy.value() + tt.value()))
        .collect()
}

/// Bounded `a >= b` for `a, b ∈ [0, 2^bit_len)`, with networked opens.
#[allow(clippy::too_many_arguments)]
pub fn geq_bounded_network(
    a: &[ShamirShare<Fr>],
    b: &[ShamirShare<Fr>],
    pair: &BitExtractPair<Fr, F2>,
    bit_len: usize,
    committee_f: &Committee<Fr>,
    committee_b: &Committee<F2>,
    nodes_f: &[NodeId],
    nodes_b: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
    rng: &mut impl Rng,
) -> Vec<ShamirShare<F2>> {
    let two_pow = Fr::from(1_u64 << bit_len);
    let w: Vec<ShamirShare<Fr>> = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| ShamirShare::from_point_value(x.point(), x.value() - y.value() + two_pow))
        .collect();
    let bits = s2b_bounded_network(
        &w,
        pair,
        bit_len + 1,
        committee_f,
        committee_b,
        nodes_f,
        nodes_b,
        dealer,
        profile,
        rng,
    );
    bits.into_iter().nth(bit_len).expect("sign bit")
}

/// Networked confidential-transfer core (bounded comparison, secret bit never opened).
#[allow(clippy::too_many_arguments)]
pub fn conditional_transfer_network(
    sender: &[ShamirShare<Fr>],
    receiver: &[ShamirShare<Fr>],
    minimum: &[ShamirShare<Fr>],
    amount: &[ShamirShare<Fr>],
    pair: &BitExtractPair<Fr, F2>,
    committee_f: &Committee<Fr>,
    committee_b: &Committee<F2>,
    nodes_f: &[NodeId],
    nodes_b: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
    rng: &mut impl Rng,
) -> (Vec<ShamirShare<Fr>>, Vec<ShamirShare<Fr>>) {
    let geq_min = geq_bounded_network(
        minimum,
        sender,
        pair,
        BALANCE_BITS,
        committee_f,
        committee_b,
        nodes_f,
        nodes_b,
        dealer,
        profile,
        rng,
    );
    let gt: Vec<ShamirShare<F2>> = geq_min
        .iter()
        .map(|s| ShamirShare::from_point_value(s.point(), s.value() + F2::one()))
        .collect();

    let sender_minus: Vec<ShamirShare<Fr>> = sender
        .iter()
        .zip(amount.iter())
        .map(|(s, a)| ShamirShare::from_point_value(s.point(), s.value() - a.value()))
        .collect();
    let receiver_plus: Vec<ShamirShare<Fr>> = receiver
        .iter()
        .zip(amount.iter())
        .map(|(r, a)| ShamirShare::from_point_value(r.point(), r.value() + a.value()))
        .collect();

    let t = committee_f.threshold;
    let rb1 = generate_random_bit(committee_f, committee_b, rng).expect("rb1");
    let mask1 = reshare_pair_dealer(committee_f, 2 * t, committee_f, t, rng).expect("mask1");
    let sender_new = conditional_select_network(
        &gt,
        &sender_minus,
        sender,
        &rb1,
        &mask1,
        committee_f,
        committee_b,
        nodes_f,
        nodes_b,
        dealer,
        profile,
    );

    let rb2 = generate_random_bit(committee_f, committee_b, rng).expect("rb2");
    let mask2 = reshare_pair_dealer(committee_f, 2 * t, committee_f, t, rng).expect("mask2");
    let receiver_new = conditional_select_network(
        &gt,
        &receiver_plus,
        receiver,
        &rb2,
        &mask2,
        committee_f,
        committee_b,
        nodes_f,
        nodes_b,
        dealer,
        profile,
    );

    (sender_new, receiver_new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ppsc_crypto::mpc::generate_bit_extract_pair_bounded;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn node(v: u8) -> NodeId {
        NodeId::from_bytes([v; 32])
    }

    fn field_to_int(f: Fr) -> i64 {
        f.into_bigint().as_ref()[0] as i64
    }

    #[test]
    fn conditional_transfer_network_preserves_balances() {
        let mut rng = StdRng::seed_from_u64(0x1234_5678);
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
        let pair = generate_bit_extract_pair_bounded(
            &committee_f,
            &committee_b,
            BALANCE_BITS + 1,
            &mut rng,
        )
        .expect("pair");

        let nodes_f: Vec<NodeId> = (0u8..5).map(node).collect();
        let nodes_b: Vec<NodeId> = (10u8..15).map(node).collect();
        let dealer = node(0xEE);

        let (sender_new, receiver_new) = conditional_transfer_network(
            &sender,
            &receiver,
            &minimum,
            &amount,
            &pair,
            &committee_f,
            &committee_b,
            &nodes_f,
            &nodes_b,
            dealer,
            NetworkProfile::Lan,
            &mut rng,
        );

        assert_eq!(
            field_to_int(committee_f.reconstruct(&sender_new).expect("sender")),
            70
        );
        assert_eq!(
            field_to_int(committee_f.reconstruct(&receiver_new).expect("receiver")),
            50
        );
    }
}
