use criterion::{criterion_group, criterion_main, Criterion};
use ppsc_fhe::real_transfer::RealTransferExecutor;

fn bench_transfer(c: &mut Criterion) {
    let mut executor = RealTransferExecutor::new();
    let packed = executor.encrypt_balance(&[100, 20, 50, 30]);

    // End-to-end confidential transfer latency (single value): BFV decrypt -> MPC compare +
    // conditional transfer -> BFV re-encrypt.
    c.bench_function("confidential_transfer_single", |b| {
        b.iter(|| {
            let (sender_ct, receiver_ct) = executor.transfer(&packed);
            (
                sender_ct.serialize().expect("s"),
                receiver_ct.serialize().expect("r"),
            )
        });
    });
}

criterion_group!(benches, bench_transfer);
criterion_main!(benches);
