use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_crypto::mpc::{rand_share, reshare_pair, Committee};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn bench_reshare_pair(c: &mut Criterion) {
    let mut group = c.benchmark_group("preprocessing_reshare_pair");
    for n in [5_usize, 20] {
        let t = 2;
        let src = Committee::<Fr>::new(t, n).expect("src");
        let dst = Committee::<Fr>::new(t, n).expect("dst");
        group.bench_function(BenchmarkId::new("n", n), |b| {
            let mut rng = StdRng::seed_from_u64(0);
            b.iter(|| reshare_pair(&src, t, &dst, t, b"rp", &mut rng).expect("pair"));
        });
    }
    group.finish();
}

fn bench_rand_share(c: &mut Criterion) {
    let mut group = c.benchmark_group("preprocessing_rand_share");
    for n in [5_usize, 20] {
        let t = 2;
        let committee = Committee::<Fr>::new(t, n).expect("committee");
        group.bench_function(BenchmarkId::new("n", n), |b| {
            let mut rng = StdRng::seed_from_u64(0);
            b.iter(|| rand_share(&committee, b"rs", &mut rng).expect("rand share"));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_reshare_pair, bench_rand_share);
criterion_main!(benches);
