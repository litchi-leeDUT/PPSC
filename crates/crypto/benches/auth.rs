use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_crypto::mpc::{
    authenticated_handoff, authenticated_multiply, rand_share, reshare_pair, verify_mac,
    AuthenticatedSharing, Committee,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn bench_auth_handoff(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_handoff");
    for n in [5_usize, 20] {
        let t = 2;
        let mut rng = StdRng::seed_from_u64(0);
        let src = Committee::<Fr>::new(t, n).expect("src");
        let dst = Committee::<Fr>::new(t, n).expect("dst");
        let alpha = Fr::from(7_u64);
        let x = Fr::from(3_u64);
        let auth = AuthenticatedSharing {
            value: src.split(x, &mut rng).expect("split x"),
            mac: src.split(x * alpha, &mut rng).expect("split mac"),
        };
        let mv = reshare_pair(&src, t, &dst, t, b"mv", &mut rng).expect("mask value");
        let mm = reshare_pair(&src, t, &dst, t, b"mm", &mut rng).expect("mask mac");
        group.bench_function(BenchmarkId::new("n", n), |b| {
            b.iter(|| authenticated_handoff(&auth, &mv, &mm, &src, &dst).expect("handoff"));
        });
    }
    group.finish();
}

fn bench_auth_multiply(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_multiply");
    for n in [3_usize, 20] {
        let t = 1;
        let mut rng = StdRng::seed_from_u64(0);
        let src = Committee::<Fr>::new(t, n).expect("src");
        let dst = Committee::<Fr>::new(t, n).expect("dst");
        let alpha = Fr::from(5_u64);
        let x = Fr::from(6_u64);
        let auth = AuthenticatedSharing {
            value: src.split(x, &mut rng).expect("split x"),
            mac: src.split(x * alpha, &mut rng).expect("split mac"),
        };
        let y = src.split(Fr::from(7_u64), &mut rng).expect("split y");
        let mv = reshare_pair(&src, 2 * t, &dst, t, b"mv", &mut rng).expect("mask value");
        let mm = reshare_pair(&src, 2 * t, &dst, t, b"mm", &mut rng).expect("mask mac");
        group.bench_function(BenchmarkId::new("n", n), |b| {
            b.iter(|| authenticated_multiply(&auth, &y, &mv, &mm, &src, &dst).expect("mult"));
        });
    }
    group.finish();
}

fn bench_verify_mac(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_mac");
    for n in [5_usize, 20] {
        let t = 2;
        let mut rng = StdRng::seed_from_u64(0);
        let comm2 = Committee::<Fr>::new(t, n).expect("comm2");
        let comm3 = Committee::<Fr>::new(t, n).expect("comm3");
        let alpha = Fr::from(13_u64);
        let x = Fr::from(17_u64);
        let value = comm2.split(x, &mut rng).expect("value");
        let mac = comm2.split(x * alpha, &mut rng).expect("mac");
        let alpha_shares = comm2.split(alpha, &mut rng).expect("alpha");
        let mask_mul = reshare_pair(&comm2, 2 * t, &comm3, t, b"mul", &mut rng).expect("mask mul");
        let mask_tag = reshare_pair(&comm2, t, &comm3, t, b"tag", &mut rng).expect("mask tag");
        let r_check = rand_share(&comm3, b"check", &mut rng).expect("r_check");
        group.bench_function(BenchmarkId::new("n", n), |b| {
            b.iter(|| {
                verify_mac(
                    &value,
                    &mac,
                    &alpha_shares,
                    &mask_mul,
                    &mask_tag,
                    &r_check,
                    &comm2,
                    &comm3,
                )
                .expect("verify")
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_auth_handoff,
    bench_auth_multiply,
    bench_verify_mac
);
criterion_main!(benches);
