//! RQ5 (first part): hybrid ablation. Measures the "All-SS" placement (every operator in
//! secret sharing / MPC) for the three workloads under LAN, n=16, t=7. The "Hybrid" placement
//! is measured by `fhe/benches/workloads_e2e.rs`; the "All-FHE" placement is reported in the
//! paper as unsupported for comparison operators (BFV has no comparison).

use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_core::NodeId;
use ppsc_crypto::mpc::{
    generate_bit_extract_pair_bounded, generate_random_bit, reshare_pair_dealer, Committee,
    ShamirShare, F2,
};
use ppsc_network::memory::NetworkProfile;
use ppsc_node::comparison_runtime::{
    conditional_select_network, conditional_transfer_network, geq_bounded_network, BALANCE_BITS,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

const N: usize = 16;
const T: usize = 7;

fn node(v: u8) -> NodeId {
    NodeId::from_bytes([v; 32])
}

fn nodes(n: usize, base: u8) -> Vec<NodeId> {
    (0..n).map(|i| node(base + i as u8)).collect()
}

struct AllSsSetup {
    committee_f: Committee<Fr>,
    committee_b: Committee<F2>,
    nodes_f: Vec<NodeId>,
    nodes_b: Vec<NodeId>,
    dealer: NodeId,
}

fn setup() -> AllSsSetup {
    AllSsSetup {
        committee_f: Committee::<Fr>::new(T, N).expect("f"),
        committee_b: Committee::<F2>::new(T, N).expect("b"),
        nodes_f: nodes(N, 0),
        nodes_b: nodes(N, 0x80),
        dealer: node(0xEE),
    }
}

fn all_ss_transfer(s: &AllSsSetup, profile: NetworkProfile, rng: &mut StdRng) {
    let cf = &s.committee_f;
    let cb = &s.committee_b;
    let sender = cf.split(Fr::from(100_u64), rng).expect("sender");
    let receiver = cf.split(Fr::from(20_u64), rng).expect("receiver");
    let minimum = cf.split(Fr::from(50_u64), rng).expect("minimum");
    let amount = cf.split(Fr::from(30_u64), rng).expect("amount");
    let pair = generate_bit_extract_pair_bounded(cf, cb, BALANCE_BITS + 1, rng).expect("pair");
    let _ = conditional_transfer_network(
        &sender, &receiver, &minimum, &amount, &pair, cf, cb, &s.nodes_f, &s.nodes_b, s.dealer,
        profile, rng,
    );
}

fn all_ss_selection(s: &AllSsSetup, profile: NetworkProfile, rng: &mut StdRng) {
    let cf = &s.committee_f;
    let cb = &s.committee_b;
    let mut bids = Vec::new();
    for v in [10_u64, 30, 20, 5] {
        bids.push(cf.split(Fr::from(v), rng).expect("split"));
    }
    let mut bids = bids.into_iter();
    let mut max = bids.next().expect("bid");
    for bid in bids {
        let pair = generate_bit_extract_pair_bounded(cf, cb, BALANCE_BITS + 1, rng).expect("pair");
        let gt = geq_bounded_network(
            &bid,
            &max,
            &pair,
            BALANCE_BITS,
            cf,
            cb,
            &s.nodes_f,
            &s.nodes_b,
            s.dealer,
            profile,
            rng,
        );
        let random_bit = generate_random_bit(cf, cb, rng).expect("bit");
        let mask = reshare_pair_dealer(cf, 2 * T, cf, T, rng).expect("mask");
        max = conditional_select_network(
            &gt,
            &bid,
            &max,
            &random_bit,
            &mask,
            cf,
            cb,
            &s.nodes_f,
            &s.nodes_b,
            s.dealer,
            profile,
        );
    }
}

fn all_ss_analytics(s: &AllSsSetup, profile: NetworkProfile, rng: &mut StdRng) {
    let cf = &s.committee_f;
    let cb = &s.committee_b;
    let mut values = Vec::new();
    for v in [1_u64, 2, 3, 4, 5, 6, 7, 8] {
        values.push(cf.split(Fr::from(v), rng).expect("split"));
    }
    let mut values = values.into_iter();
    let mut sum = values.next().expect("value");
    for v in values {
        sum = sum
            .iter()
            .zip(v.iter())
            .map(|(a, b)| ShamirShare::from_point_value(a.point(), a.value() + b.value()))
            .collect();
    }
    let bound = cf.split(Fr::from(20_u64), rng).expect("bound");
    let pair = generate_bit_extract_pair_bounded(cf, cb, BALANCE_BITS + 1, rng).expect("pair");
    let _ = geq_bounded_network(
        &sum,
        &bound,
        &pair,
        BALANCE_BITS,
        cf,
        cb,
        &s.nodes_f,
        &s.nodes_b,
        s.dealer,
        profile,
        rng,
    );
}

fn bench_all_ss(c: &mut Criterion) {
    let s = setup();
    let profile = NetworkProfile::Lan;

    let mut g = c.benchmark_group("all_ss");
    g.bench_function(BenchmarkId::new("transfer", "n16"), |b| {
        let mut rng = StdRng::seed_from_u64(0);
        b.iter(|| all_ss_transfer(&s, profile, &mut rng));
    });
    g.bench_function(BenchmarkId::new("selection", "n16"), |b| {
        let mut rng = StdRng::seed_from_u64(0);
        b.iter(|| all_ss_selection(&s, profile, &mut rng));
    });
    g.bench_function(BenchmarkId::new("analytics", "n16"), |b| {
        let mut rng = StdRng::seed_from_u64(0);
        b.iter(|| all_ss_analytics(&s, profile, &mut rng));
    });
    g.finish();
}

criterion_group!(benches, bench_all_ss);
criterion_main!(benches);
