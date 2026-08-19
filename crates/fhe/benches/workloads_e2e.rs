//! End-to-end contract workload benchmarks (RQ3): per-invocation latency of three operator
//! mixes under LAN/MAN/WAN profiles and honest-majority thresholds `t = floor((n-1)/2)`.
//!
//! - `transfer`: BFV H2S (threshold) -> MPC comparison + conditional transfer -> BFV S2H.
//! - `auction`: sealed-bid argmax over 4 bids (MPC comparisons + conditional selects).
//! - `analytics`: local sum of 8 values + one bounded threshold comparison.
//!
//! All MPC opens are routed through a `MemoryMailbox` with RTT latency (see
//! `ppsc_node::comparison_runtime`), and comparisons use the bounded 32-bit `Π_S2B`.

use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_core::NodeId;
use ppsc_crypto::mpc::{
    generate_bit_extract_pair_bounded, generate_random_bit, reshare_pair_dealer, Committee,
    ShamirShare, F2,
};
use ppsc_fhe::bfv_shamir::{bfv_share_key_per_modulus, per_modulus_lambdas};
use ppsc_fhe::network_conversion::{h2s_threshold_with_network, s2h_with_network};
use ppsc_fhe::{Ciphertext, CkksContext, KeyPair};
use ppsc_network::memory::NetworkProfile;
use ppsc_node::comparison_runtime::{
    conditional_select_network, conditional_transfer_network, geq_bounded_network, BALANCE_BITS,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

const NS: [usize; 5] = [4, 8, 16, 32, 64];

fn threshold(n: usize) -> usize {
    (n - 1) / 2
}

fn node(v: u8) -> NodeId {
    NodeId::from_bytes([v; 32])
}

fn nodes(n: usize, base: u8) -> Vec<NodeId> {
    (0..n).map(|i| node(base + i as u8)).collect()
}

fn profile_name(profile: NetworkProfile) -> &'static str {
    match profile {
        NetworkProfile::Lan => "lan",
        NetworkProfile::Man => "man",
        NetworkProfile::Wan => "wan",
    }
}

fn bid_shares(
    committee: &Committee<Fr>,
    values: &[u64],
    rng: &mut StdRng,
) -> Vec<Vec<ShamirShare<Fr>>> {
    values
        .iter()
        .map(|&v| committee.split(Fr::from(v), rng).expect("split"))
        .collect()
}

// ---------------------------------------------------------------------------
// transfer (FHE H2S -> MPC -> FHE S2H)
// ---------------------------------------------------------------------------

struct TransferSetup {
    ctx: CkksContext,
    full_key: KeyPair,
    ct: Ciphertext,
    party_keys: Vec<KeyPair>,
    lambdas: Vec<u64>,
    committee_f: Committee<Fr>,
    committee_b: Committee<F2>,
    t: usize,
}

fn transfer_setup(n: usize) -> TransferSetup {
    let t = threshold(n);
    let ctx = CkksContext::bfv_new(2, 8).expect("bfv");
    let full_key = ctx.keygen().expect("keygen");
    let data = vec![100, 20, 50, 30, 0, 0, 0, 0];
    let ct = ctx.bfv_encrypt_int(&full_key, &data).expect("encrypt");
    let committee_f = Committee::<Fr>::new(t, n).expect("f");
    let committee_b = Committee::<F2>::new(t, n).expect("b");
    let mut rng = StdRng::seed_from_u64(0);
    let party_keys =
        bfv_share_key_per_modulus(&ctx, &full_key, t, n, &mut rng).expect("share keys");
    let moduli = ctx.extract_moduli(&full_key).expect("moduli");
    let lambdas_per_modulus = per_modulus_lambdas(&moduli, n, t);
    let n_keys = t + 1;
    let mut lambdas = Vec::with_capacity(moduli.len() * n_keys);
    for lj in &lambdas_per_modulus {
        lambdas.extend_from_slice(lj);
    }
    TransferSetup {
        ctx,
        full_key,
        ct,
        party_keys,
        lambdas,
        committee_f,
        committee_b,
        t,
    }
}

fn run_transfer(s: &TransferSetup, profile: NetworkProfile, dealer: NodeId, rng: &mut StdRng) {
    let nodes_f = nodes(s.committee_f.size(), 0);
    let nodes_b = nodes(s.committee_b.size(), 0x80);

    let shares = h2s_threshold_with_network(
        &s.ctx,
        &s.ct,
        &s.party_keys,
        &s.lambdas,
        s.t,
        &s.committee_f,
        4,
        profile,
        dealer,
        rng,
    )
    .expect("h2s");
    let pair =
        generate_bit_extract_pair_bounded(&s.committee_f, &s.committee_b, BALANCE_BITS + 1, rng)
            .expect("pair");
    let (sender_new, receiver_new) = conditional_transfer_network(
        &shares[0],
        &shares[1],
        &shares[2],
        &shares[3],
        &pair,
        &s.committee_f,
        &s.committee_b,
        &nodes_f,
        &nodes_b,
        dealer,
        profile,
        rng,
    );
    s2h_with_network(
        &s.ctx,
        &s.full_key,
        &[sender_new, receiver_new],
        &s.committee_f,
        profile,
        dealer,
    )
    .expect("s2h");
}

fn bench_transfer(c: &mut Criterion) {
    let setups: Vec<TransferSetup> = NS.iter().map(|&n| transfer_setup(n)).collect();
    for profile in [
        NetworkProfile::Lan,
        NetworkProfile::Man,
        NetworkProfile::Wan,
    ] {
        let mut group = c.benchmark_group(format!("transfer_{}", profile_name(profile)));
        for (i, &n) in NS.iter().enumerate() {
            let s = &setups[i];
            let dealer = node(0xEE);
            group.bench_function(BenchmarkId::new("n", n), |b| {
                let mut rng = StdRng::seed_from_u64(0);
                b.iter(|| run_transfer(s, profile, dealer, &mut rng));
            });
        }
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// auction (sealed-bid argmax over 4 bids)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn argmax_network(
    bids: Vec<Vec<ShamirShare<Fr>>>,
    committee_f: &Committee<Fr>,
    committee_b: &Committee<F2>,
    nodes_f: &[NodeId],
    nodes_b: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
    rng: &mut StdRng,
) -> Vec<ShamirShare<Fr>> {
    let mut bids = bids.into_iter();
    let mut max = bids.next().expect("at least one bid");
    for bid in bids {
        let pair =
            generate_bit_extract_pair_bounded(committee_f, committee_b, BALANCE_BITS + 1, rng)
                .expect("pair");
        let gt = geq_bounded_network(
            &bid,
            &max,
            &pair,
            BALANCE_BITS,
            committee_f,
            committee_b,
            nodes_f,
            nodes_b,
            dealer,
            profile,
            rng,
        );
        let random_bit = generate_random_bit(committee_f, committee_b, rng).expect("bit");
        let mask = reshare_pair_dealer(
            committee_f,
            2 * committee_f.threshold,
            committee_f,
            committee_f.threshold,
            rng,
        )
        .expect("mask");
        max = conditional_select_network(
            &gt,
            &bid,
            &max,
            &random_bit,
            &mask,
            committee_f,
            committee_b,
            nodes_f,
            nodes_b,
            dealer,
            profile,
        );
    }
    max
}

fn bench_auction(c: &mut Criterion) {
    for profile in [
        NetworkProfile::Lan,
        NetworkProfile::Man,
        NetworkProfile::Wan,
    ] {
        let mut group = c.benchmark_group(format!("auction_{}", profile_name(profile)));
        for n in NS {
            let t = threshold(n);
            let committee_f = Committee::<Fr>::new(t, n).expect("f");
            let committee_b = Committee::<F2>::new(t, n).expect("b");
            let nodes_f = nodes(n, 0);
            let nodes_b = nodes(n, 0x80);
            let dealer = node(0xEE);
            group.bench_function(BenchmarkId::new("n", n), |b| {
                let mut rng = StdRng::seed_from_u64(0);
                b.iter_with_large_drop(|| {
                    let bids = bid_shares(&committee_f, &[10, 30, 20, 5], &mut rng);
                    argmax_network(
                        bids,
                        &committee_f,
                        &committee_b,
                        &nodes_f,
                        &nodes_b,
                        dealer,
                        profile,
                        &mut rng,
                    )
                });
            });
        }
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// analytics (sum of 8 values + one threshold comparison)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn analytics_threshold_network(
    values: Vec<Vec<ShamirShare<Fr>>>,
    bound: Vec<ShamirShare<Fr>>,
    committee_f: &Committee<Fr>,
    committee_b: &Committee<F2>,
    nodes_f: &[NodeId],
    nodes_b: &[NodeId],
    dealer: NodeId,
    profile: NetworkProfile,
    rng: &mut StdRng,
) -> Vec<ShamirShare<F2>> {
    let mut iter = values.into_iter();
    let mut sum = iter.next().expect("at least one value");
    for v in iter {
        sum = sum
            .iter()
            .zip(v.iter())
            .map(|(a, b)| ShamirShare::from_point_value(a.point(), a.value() + b.value()))
            .collect();
    }
    let pair = generate_bit_extract_pair_bounded(committee_f, committee_b, BALANCE_BITS + 1, rng)
        .expect("pair");
    geq_bounded_network(
        &sum,
        &bound,
        &pair,
        BALANCE_BITS,
        committee_f,
        committee_b,
        nodes_f,
        nodes_b,
        dealer,
        profile,
        rng,
    )
}

fn bench_analytics(c: &mut Criterion) {
    for profile in [
        NetworkProfile::Lan,
        NetworkProfile::Man,
        NetworkProfile::Wan,
    ] {
        let mut group = c.benchmark_group(format!("analytics_{}", profile_name(profile)));
        for n in NS {
            let t = threshold(n);
            let committee_f = Committee::<Fr>::new(t, n).expect("f");
            let committee_b = Committee::<F2>::new(t, n).expect("b");
            let nodes_f = nodes(n, 0);
            let nodes_b = nodes(n, 0x80);
            let dealer = node(0xEE);
            group.bench_function(BenchmarkId::new("n", n), |b| {
                let mut rng = StdRng::seed_from_u64(0);
                b.iter_with_large_drop(|| {
                    let values = bid_shares(&committee_f, &[1, 2, 3, 4, 5, 6, 7, 8], &mut rng);
                    let bound = committee_f
                        .split(Fr::from(20_u64), &mut rng)
                        .expect("bound");
                    analytics_threshold_network(
                        values,
                        bound,
                        &committee_f,
                        &committee_b,
                        &nodes_f,
                        &nodes_b,
                        dealer,
                        profile,
                        &mut rng,
                    )
                });
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_transfer, bench_auction, bench_analytics);
criterion_main!(benches);
