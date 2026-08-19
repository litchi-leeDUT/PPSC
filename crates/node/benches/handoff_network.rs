use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_core::{CommitteeId, ExecutionId, NodeId};
use ppsc_crypto::mpc::{reshare_pair_dealer, Committee};
use ppsc_network::memory::NetworkProfile;
use ppsc_node::handoff_runtime::{run_handoff_with_latency, run_mult_with_latency};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn node(v: u8) -> NodeId {
    NodeId::from_bytes([v; 32])
}

fn profile_name(profile: NetworkProfile) -> &'static str {
    match profile {
        NetworkProfile::Lan => "lan",
        NetworkProfile::Man => "man",
        NetworkProfile::Wan => "wan",
    }
}

fn bench_handoff_network(c: &mut Criterion) {
    for profile in [
        NetworkProfile::Lan,
        NetworkProfile::Man,
        NetworkProfile::Wan,
    ] {
        let mut group = c.benchmark_group(format!("handoff_{}", profile_name(profile)));
        for n in [4_usize, 8, 16, 32, 64] {
            let t = (n - 1) / 2;
            let mut rng = StdRng::seed_from_u64(0);
            let src = Committee::<Fr>::new(t, n).expect("src");
            let dst = Committee::<Fr>::new(t, n).expect("dst");
            let x_shares = src.split(Fr::from(42_u64), &mut rng).expect("split");
            let mask = reshare_pair_dealer(&src, t, &dst, t, &mut rng).expect("mask");
            let execution_id = ExecutionId::from_bytes([1; 32]);
            let from = CommitteeId::from_bytes([2; 32]);
            let to = CommitteeId::from_bytes([3; 32]);
            let source_nodes: Vec<NodeId> = (0..n as u8).map(node).collect();
            let dealer = node(0xEE);
            let destination_nodes: Vec<NodeId> = (0x80..0x80 + n as u8).map(node).collect();
            group.bench_function(BenchmarkId::new("n", n), |b| {
                b.iter(|| {
                    run_handoff_with_latency(
                        execution_id,
                        from,
                        to,
                        &x_shares,
                        &mask,
                        &src,
                        &dst,
                        &source_nodes,
                        dealer,
                        &destination_nodes,
                        profile.one_way_latency(),
                    )
                    .expect("handoff")
                });
            });
        }
        group.finish();
    }
}

fn bench_mult_network(c: &mut Criterion) {
    for profile in [
        NetworkProfile::Lan,
        NetworkProfile::Man,
        NetworkProfile::Wan,
    ] {
        let mut group = c.benchmark_group(format!("mult_{}", profile_name(profile)));
        for n in [4_usize, 8, 16, 32, 64] {
            let t = (n - 1) / 2;
            let mut rng = StdRng::seed_from_u64(0);
            let src = Committee::<Fr>::new(t, n).expect("src");
            let dst = Committee::<Fr>::new(t, n).expect("dst");
            let xs = src.split(Fr::from(6_u64), &mut rng).expect("split x");
            let ys = src.split(Fr::from(7_u64), &mut rng).expect("split y");
            let mask = reshare_pair_dealer(&src, 2 * t, &dst, t, &mut rng).expect("mask");
            let execution_id = ExecutionId::from_bytes([1; 32]);
            let from = CommitteeId::from_bytes([2; 32]);
            let to = CommitteeId::from_bytes([3; 32]);
            let source_nodes: Vec<NodeId> = (0..n as u8).map(node).collect();
            let dealer = node(0xEE);
            let destination_nodes: Vec<NodeId> = (0x80..0x80 + n as u8).map(node).collect();
            group.bench_function(BenchmarkId::new("n", n), |b| {
                b.iter(|| {
                    run_mult_with_latency(
                        execution_id,
                        from,
                        to,
                        &xs,
                        &ys,
                        &mask,
                        &src,
                        &dst,
                        &source_nodes,
                        dealer,
                        &destination_nodes,
                        profile.one_way_latency(),
                    )
                    .expect("mult")
                });
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_handoff_network, bench_mult_network);
criterion_main!(benches);
