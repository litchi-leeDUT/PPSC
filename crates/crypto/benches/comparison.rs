use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_crypto::mpc::{
    conditional_transfer_strictly_greater, generate_bit_extract_pair, Committee, F2,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn bench_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("conditional_transfer");
    for n in [5_usize, 20] {
        let t = 2;
        let mut rng = StdRng::seed_from_u64(0);
        let cf = Committee::<Fr>::new(t, n).expect("cf");
        let cb = Committee::<F2>::new(t, n).expect("cb");
        let sender = cf.split(Fr::from(100_u64), &mut rng).expect("sender");
        let receiver = cf.split(Fr::from(20_u64), &mut rng).expect("receiver");
        let minimum = cf.split(Fr::from(50_u64), &mut rng).expect("minimum");
        let amount = cf.split(Fr::from(30_u64), &mut rng).expect("amount");
        let pair = generate_bit_extract_pair(&cf, &cb, &mut rng).expect("pair");
        group.bench_with_input(
            BenchmarkId::new("n", n),
            &(sender, receiver, minimum, amount, pair, cf, cb),
            |b, (sender, receiver, minimum, amount, pair, cf, cb)| {
                b.iter(|| {
                    conditional_transfer_strictly_greater(
                        sender, receiver, minimum, amount, pair, cf, cb, &mut rng,
                    )
                    .expect("transfer")
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_transfer);
criterion_main!(benches);
