use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ppsc_crypto::mpc::{
    apply_difference, basic_handoff, masked_difference_shares, reconstruct_from_parts,
    reshare_pair, Committee,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn bench_basic_handoff(c: &mut Criterion) {
    let mut group = c.benchmark_group("basic_handoff");
    // Small fixed t keeps PRSS holder-sets combinatorial tractable; n=100 takes ~27s in
    // reshare_pair preprocessing (O(C(n,n-t)^2)), so it is benchmarked once for the
    // protocol body itself (preprocessing cost recorded separately).
    for n in [5_usize, 20, 100] {
        let t = 2;
        let mut rng = StdRng::seed_from_u64(0);
        let src = Committee::<Fr>::new(t, n).expect("src");
        let dst = Committee::<Fr>::new(t, n).expect("dst");
        let x_shares = src.split(Fr::from(42_u64), &mut rng).expect("split");
        let mask = reshare_pair(&src, t, &dst, t, b"bench", &mut rng).expect("mask");
        group.bench_function(BenchmarkId::new("n", n), |b| {
            b.iter(|| basic_handoff(&x_shares, &mask, &src, &dst).expect("handoff"));
        });
    }
    group.finish();
}

/// Per-party vs dealer breakdown of Basic Handoff (n=20, t=2).
fn bench_handoff_phases(c: &mut Criterion) {
    let mut group = c.benchmark_group("handoff_phases");
    let (n, t) = (20_usize, 2);
    let mut rng = StdRng::seed_from_u64(0);
    let src = Committee::<Fr>::new(t, n).expect("src");
    let dst = Committee::<Fr>::new(t, n).expect("dst");
    let x_shares = src.split(Fr::from(42_u64), &mut rng).expect("split");
    let mask = reshare_pair(&src, t, &dst, t, b"bench", &mut rng).expect("mask");

    // Source party: local masked difference.
    group.bench_function("source_masked_diff", |b| {
        b.iter(|| masked_difference_shares(&x_shares, &mask.source).expect("diff"));
    });
    // Dealer: reconstruct delta from t+1 shares.
    let delta_shares = masked_difference_shares(&x_shares, &mask.source).expect("diff setup");
    let points: Vec<Fr> = delta_shares.iter().take(t + 1).map(|s| s.point()).collect();
    let values: Vec<Fr> = delta_shares.iter().take(t + 1).map(|s| s.value()).collect();
    group.bench_function("dealer_reconstruct", |b| {
        b.iter(|| reconstruct_from_parts(&points, &values, t + 1).expect("reconstruct"));
    });
    // Destination party: local add of public delta.
    group.bench_function("destination_apply", |b| {
        b.iter(|| apply_difference(Fr::from(1_u64), &mask.destination));
    });
    group.finish();
}

fn bench_batch_handoff(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_handoff");
    // t=2 keeps per-value reshare_pair preprocessing fast (C(20,18)^2 = 36k HMACs).
    let (n, t) = (20_usize, 2);
    for batch in [1_usize, 10, 100, 1000] {
        let mut rng = StdRng::seed_from_u64(0);
        let src = Committee::<Fr>::new(t, n).expect("src");
        let dst = Committee::<Fr>::new(t, n).expect("dst");
        let inputs: Vec<_> = (0..batch)
            .map(|_| {
                let xs = src.split(Fr::from(42_u64), &mut rng).expect("split");
                let mask = reshare_pair(&src, t, &dst, t, b"batch", &mut rng).expect("mask");
                (xs, mask)
            })
            .collect();
        group.throughput(Throughput::Elements(batch as u64));
        group.bench_function(BenchmarkId::new("batch", batch), |b| {
            b.iter(|| {
                for (xs, mask) in &inputs {
                    basic_handoff(xs, mask, &src, &dst).expect("handoff");
                }
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_basic_handoff,
    bench_handoff_phases,
    bench_batch_handoff
);
criterion_main!(benches);
