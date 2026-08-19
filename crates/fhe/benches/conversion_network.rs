use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_core::NodeId;
use ppsc_crypto::mpc::Committee;
use ppsc_fhe::bfv_shamir::{bfv_share_key_per_modulus, per_modulus_lambdas};
use ppsc_fhe::network_conversion::{h2s_threshold_with_network, s2h_with_network};
use ppsc_fhe::{Ciphertext, CkksContext, KeyPair};
use ppsc_network::memory::NetworkProfile;
use rand::rngs::StdRng;
use rand::SeedableRng;

const NS: [usize; 5] = [4, 8, 16, 32, 64];

/// Honest-majority threshold: `t = floor((n-1)/2)`, satisfying the paper's `t < n/2` and `n > 2t`.
fn threshold(n: usize) -> usize {
    (n - 1) / 2
}

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

/// Per-`n` offline H2S setup (key, ciphertext, per-modulus key shares, Lagrange coefficients).
struct H2sSetup {
    ctx: CkksContext,
    ct: Ciphertext,
    party_keys: Vec<KeyPair>,
    lambdas: Vec<u64>,
    committee: Committee<Fr>,
    t: usize,
}

fn h2s_setup(n: usize) -> H2sSetup {
    let t = threshold(n);
    let ctx = CkksContext::bfv_new(2, 8).expect("bfv");
    let full_key = ctx.keygen().expect("keygen");
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let ct = ctx.bfv_encrypt_int(&full_key, &data).expect("encrypt");
    let committee = Committee::<Fr>::new(t, n).expect("committee");
    let mut rng = StdRng::seed_from_u64(0);
    let party_keys =
        bfv_share_key_per_modulus(&ctx, &full_key, t, n, &mut rng).expect("share keys");
    let moduli = ctx.extract_moduli(&full_key).expect("moduli");
    let lambdas_per_modulus = per_modulus_lambdas(&moduli, n, t);
    let n_keys = t + 1;
    let mut lambdas = Vec::with_capacity(moduli.len() * n_keys);
    for lj in &lambdas_per_modulus {
        lambdas.extend_from_slice(lj);
    }
    H2sSetup {
        ctx,
        ct,
        party_keys,
        lambdas,
        committee,
        t,
    }
}

fn bench_h2s_network(c: &mut Criterion) {
    // Offline setup is shared across the three network profiles.
    let setups: Vec<H2sSetup> = NS.iter().map(|&n| h2s_setup(n)).collect();

    for profile in [
        NetworkProfile::Lan,
        NetworkProfile::Man,
        NetworkProfile::Wan,
    ] {
        let mut group = c.benchmark_group(format!("h2s_{}", profile_name(profile)));
        for (i, &n) in NS.iter().enumerate() {
            let s = &setups[i];
            let dealer = node(0xEE);
            group.bench_function(BenchmarkId::new("n", n), |b| {
                let mut rng = StdRng::seed_from_u64(0);
                b.iter(|| {
                    h2s_threshold_with_network(
                        &s.ctx,
                        &s.ct,
                        &s.party_keys,
                        &s.lambdas,
                        s.t,
                        &s.committee,
                        8,
                        profile,
                        dealer,
                        &mut rng,
                    )
                    .expect("h2s")
                });
            });
        }
        group.finish();
    }
}

fn bench_s2h_network(c: &mut Criterion) {
    for profile in [
        NetworkProfile::Lan,
        NetworkProfile::Man,
        NetworkProfile::Wan,
    ] {
        let mut group = c.benchmark_group(format!("s2h_{}", profile_name(profile)));
        for n in NS {
            let t = threshold(n);
            let ctx = CkksContext::bfv_new(2, 8).expect("bfv");
            let kp = ctx.keygen().expect("keygen");
            let committee = Committee::<Fr>::new(t, n).expect("committee");
            let mut rng = StdRng::seed_from_u64(0);
            // batch=8 share vectors, each t-of-n over Fr.
            let shares: Vec<_> = (0..8)
                .map(|_| committee.split(Fr::from(42_u64), &mut rng).expect("split"))
                .collect();
            let dealer = node(0xEE);
            group.bench_function(BenchmarkId::new("n", n), |b| {
                b.iter(|| {
                    s2h_with_network(&ctx, &kp, &shares, &committee, profile, dealer).expect("s2h")
                });
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_h2s_network, bench_s2h_network);
criterion_main!(benches);
