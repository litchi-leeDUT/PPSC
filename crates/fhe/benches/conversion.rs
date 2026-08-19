use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, Criterion};
use ppsc_crypto::mpc::Committee;
use ppsc_fhe::bfv_shamir::{bfv_share_plaintext, bfv_shares_to_ciphertext};
use ppsc_fhe::{Ciphertext, CkksContext};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn bench_conversion(c: &mut Criterion) {
    let ctx = CkksContext::bfv_new(2, 8).expect("bfv");
    let kp1 = ctx.multiparty_keygen_first().expect("kp1");
    let kp2 = ctx.multiparty_keygen_next_kp(&kp1).expect("kp2");
    let kp3 = ctx.multiparty_keygen_next_kp(&kp2).expect("kp3");
    let party_keys = vec![kp1, kp2, kp3];
    let committee = Committee::<Fr>::new(2, 5).expect("committee");
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let ct = ctx.bfv_encrypt_int(&party_keys[2], &data).expect("encrypt");
    let shares = bfv_share_plaintext(
        &ctx,
        &ct,
        &party_keys,
        &committee,
        8,
        &mut StdRng::seed_from_u64(0),
    )
    .expect("h2s setup");

    let mut group = c.benchmark_group("bfv_conversion");
    group.bench_function("bfv_encrypt", |b| {
        b.iter(|| ctx.bfv_encrypt_int(&party_keys[2], &data).expect("encrypt"));
    });
    group.bench_function("bfv_decrypt", |b| {
        b.iter(|| {
            ctx.bfv_multiparty_decrypt(&ct, &party_keys, 8)
                .expect("decrypt")
        });
    });
    group.bench_function("h2s", |b| {
        let mut rng = StdRng::seed_from_u64(0);
        b.iter(|| {
            bfv_share_plaintext(&ctx, &ct, &party_keys, &committee, 8, &mut rng).expect("h2s")
        });
    });
    group.bench_function("s2h", |b| {
        b.iter(|| {
            bfv_shares_to_ciphertext(&ctx, &party_keys[2], &shares, &committee).expect("s2h")
        });
    });
    group.bench_function("bfv_serialize", |b| {
        b.iter(|| ct.serialize().expect("serialize"));
    });
    let ct_bytes = ct.serialize().expect("serialize bytes");
    group.bench_function("bfv_deserialize", |b| {
        b.iter(|| Ciphertext::deserialize(&ctx, &ct_bytes).expect("deserialize"));
    });
    group.finish();
}

criterion_group!(benches, bench_conversion);
criterion_main!(benches);
