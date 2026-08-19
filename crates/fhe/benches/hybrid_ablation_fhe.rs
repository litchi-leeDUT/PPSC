//! RQ5 (first part): Hybrid selection and analytics with FHE inputs. Selection performs H2S
//! (threshold decrypt of 4 sealed bids) then MPC argmax; analytics performs H2S (threshold
//! decrypt of 8 values) then an MPC sum and one threshold comparison. The transfer hybrid
//! workload is measured by `workloads_e2e.rs`; All-SS by `hybrid_ablation.rs`; All-FHE is
//! reported as unsupported for comparisons.

use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_core::NodeId;
use ppsc_crypto::mpc::{
    generate_bit_extract_pair_bounded, generate_random_bit, reshare_pair_dealer, Committee,
    ShamirShare, F2,
};
use ppsc_fhe::bfv_shamir::{bfv_share_key_per_modulus, per_modulus_lambdas};
use ppsc_fhe::network_conversion::h2s_threshold_with_network;
use ppsc_fhe::{Ciphertext, CkksContext, KeyPair};
use ppsc_network::memory::NetworkProfile;
use ppsc_node::comparison_runtime::{
    conditional_select_network, geq_bounded_network, BALANCE_BITS,
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

struct Setup {
    ctx: CkksContext,
    ct: Ciphertext,
    party_keys: Vec<KeyPair>,
    lambdas: Vec<u64>,
    committee_f: Committee<Fr>,
    committee_b: Committee<F2>,
    nodes_f: Vec<NodeId>,
    nodes_b: Vec<NodeId>,
    dealer: NodeId,
}

fn setup(data: &[i64]) -> Setup {
    let ctx = CkksContext::bfv_new(2, 8).expect("bfv");
    let full_key = ctx.keygen().expect("keygen");
    let mut padded = data.to_vec();
    padded.resize(8, 0);
    let ct = ctx.bfv_encrypt_int(&full_key, &padded).expect("encrypt");
    let committee_f = Committee::<Fr>::new(T, N).expect("f");
    let committee_b = Committee::<F2>::new(T, N).expect("b");
    let mut rng = StdRng::seed_from_u64(0);
    let party_keys =
        bfv_share_key_per_modulus(&ctx, &full_key, T, N, &mut rng).expect("share keys");
    let moduli = ctx.extract_moduli(&full_key).expect("moduli");
    let lpm = per_modulus_lambdas(&moduli, N, T);
    let mut lambdas = Vec::with_capacity(moduli.len() * (T + 1));
    for lj in &lpm {
        lambdas.extend_from_slice(lj);
    }
    Setup {
        ctx,
        ct,
        party_keys,
        lambdas,
        committee_f,
        committee_b,
        nodes_f: nodes(N, 0),
        nodes_b: nodes(N, 0x80),
        dealer: node(0xEE),
    }
}

fn hybrid_selection(s: &Setup, profile: NetworkProfile, rng: &mut StdRng) {
    let shares = h2s_threshold_with_network(
        &s.ctx,
        &s.ct,
        &s.party_keys,
        &s.lambdas,
        T,
        &s.committee_f,
        4,
        profile,
        s.dealer,
        rng,
    )
    .expect("h2s");
    let mut bids = shares.into_iter();
    let mut max = bids.next().expect("bid");
    for bid in bids {
        let pair = generate_bit_extract_pair_bounded(
            &s.committee_f,
            &s.committee_b,
            BALANCE_BITS + 1,
            rng,
        )
        .expect("pair");
        let gt = geq_bounded_network(
            &bid,
            &max,
            &pair,
            BALANCE_BITS,
            &s.committee_f,
            &s.committee_b,
            &s.nodes_f,
            &s.nodes_b,
            s.dealer,
            profile,
            rng,
        );
        let rb = generate_random_bit(&s.committee_f, &s.committee_b, rng).expect("bit");
        let mask =
            reshare_pair_dealer(&s.committee_f, 2 * T, &s.committee_f, T, rng).expect("mask");
        max = conditional_select_network(
            &gt,
            &bid,
            &max,
            &rb,
            &mask,
            &s.committee_f,
            &s.committee_b,
            &s.nodes_f,
            &s.nodes_b,
            s.dealer,
            profile,
        );
    }
    let _ = max;
}

fn hybrid_analytics(s: &Setup, profile: NetworkProfile, rng: &mut StdRng) {
    let shares = h2s_threshold_with_network(
        &s.ctx,
        &s.ct,
        &s.party_keys,
        &s.lambdas,
        T,
        &s.committee_f,
        8,
        profile,
        s.dealer,
        rng,
    )
    .expect("h2s");
    let mut values = shares.into_iter();
    let mut sum = values.next().expect("value");
    for v in values {
        sum = sum
            .iter()
            .zip(v.iter())
            .map(|(a, b)| ShamirShare::from_point_value(a.point(), a.value() + b.value()))
            .collect();
    }
    let bound = s.committee_f.split(Fr::from(20_u64), rng).expect("bound");
    let pair =
        generate_bit_extract_pair_bounded(&s.committee_f, &s.committee_b, BALANCE_BITS + 1, rng)
            .expect("pair");
    let _ = geq_bounded_network(
        &sum,
        &bound,
        &pair,
        BALANCE_BITS,
        &s.committee_f,
        &s.committee_b,
        &s.nodes_f,
        &s.nodes_b,
        s.dealer,
        profile,
        rng,
    );
}

fn bench_hybrid(c: &mut Criterion) {
    let profile = NetworkProfile::Lan;
    let sel = setup(&[10, 30, 20, 5]);
    let ana = setup(&[1, 2, 3, 4, 5, 6, 7, 8]);

    let mut g = c.benchmark_group("hybrid");
    g.bench_function(BenchmarkId::new("selection", "n16"), |b| {
        let mut rng = StdRng::seed_from_u64(0);
        b.iter(|| hybrid_selection(&sel, profile, &mut rng));
    });
    g.bench_function(BenchmarkId::new("analytics", "n16"), |b| {
        let mut rng = StdRng::seed_from_u64(0);
        b.iter(|| hybrid_analytics(&ana, profile, &mut rng));
    });
    g.finish();
}

fn bench_all_fhe_arith(c: &mut Criterion) {
    let ctx = CkksContext::bfv_new(2, 8).expect("bfv");
    let kp = ctx.keygen().expect("keygen");
    let a_ct = ctx
        .bfv_encrypt_int(&kp, &[1_i64, 2, 3, 4, 5, 6, 7, 8])
        .expect("a");
    let b_ct = ctx
        .bfv_encrypt_int(&kp, &[1_i64, 1, 1, 1, 1, 1, 1, 1])
        .expect("b");

    let mut g = c.benchmark_group("all_fhe_arith");
    g.bench_function("add", |b| {
        b.iter(|| ctx.eval_add(&a_ct, &b_ct).expect("add"));
    });
    g.finish();
}

criterion_group!(benches, bench_hybrid, bench_all_fhe_arith);
criterion_main!(benches);
