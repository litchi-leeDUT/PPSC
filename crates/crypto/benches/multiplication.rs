use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_crypto::mpc::{multiply_and_handoff, reshare_pair, Committee};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn bench_multiply(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiply_and_handoff");
    // t=1 keeps 2t-degree PRSS holder-sets tractable; n=100 would need ~27s in reshare_pair.
    for n in [3_usize, 20] {
        let t = 1;
        let mut rng = StdRng::seed_from_u64(0);
        let src = Committee::<Fr>::new(t, n).expect("src");
        let dst = Committee::<Fr>::new(t, n).expect("dst");
        let xs = src.split(Fr::from(6_u64), &mut rng).expect("split x");
        let ys = src.split(Fr::from(7_u64), &mut rng).expect("split y");
        let mask = reshare_pair(&src, 2 * t, &dst, t, b"mul", &mut rng).expect("mask");
        group.bench_function(BenchmarkId::new("n", n), |b| {
            b.iter(|| multiply_and_handoff(&xs, &ys, &mask, &src, &dst).expect("mult"));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_multiply);
criterion_main!(benches);
