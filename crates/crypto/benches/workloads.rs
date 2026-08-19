use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_crypto::mpc::{
    conditional_select, generate_bit_extract_pair, generate_random_bit, greater_than_or_equal,
    reshare_pair, Committee, ShamirShare, F2,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Sealed-bid selection (auction): privately pick the maximum of `k` bids via MPC comparison +
/// conditional select. Returns the max bid sharing.
fn argmax(
    bids: Vec<Vec<ShamirShare<Fr>>>,
    committee_f: &Committee<Fr>,
    committee_b: &Committee<F2>,
    rng: &mut StdRng,
) -> Vec<ShamirShare<Fr>> {
    let mut bids = bids.into_iter();
    let mut max = bids.next().expect("at least one bid");
    for bid in bids {
        let pair = generate_bit_extract_pair(committee_f, committee_b, rng).expect("pair");
        let gt = greater_than_or_equal(&bid, &max, &pair, committee_f, committee_b, rng)
            .expect("compare");
        let random_bit = generate_random_bit(committee_f, committee_b, rng).expect("random bit");
        let mask = reshare_pair(
            committee_f,
            2 * committee_f.threshold,
            committee_f,
            committee_f.threshold,
            b"argmax",
            rng,
        )
        .expect("mask");
        max = conditional_select(
            &gt,
            &bid,
            &max,
            &random_bit,
            &mask,
            committee_f,
            committee_b,
        )
        .expect("select");
    }
    max
}

/// Batched analytics: sum `k` values (local share-wise addition) and run one threshold
/// comparison against a bound. Returns the boolean sharing of `sum >= bound`.
fn analytics_threshold(
    values: Vec<Vec<ShamirShare<Fr>>>,
    bound: Vec<ShamirShare<Fr>>,
    committee_f: &Committee<Fr>,
    committee_b: &Committee<F2>,
    rng: &mut StdRng,
) -> Vec<ShamirShare<F2>> {
    let mut iter = values.into_iter();
    let mut sum = iter.next().expect("at least one value");
    for v in iter {
        for (s, vv) in sum.iter_mut().zip(v.iter()) {
            *s = ShamirShare::from_point_value(s.point(), s.value() + vv.value());
        }
    }
    let pair = generate_bit_extract_pair(committee_f, committee_b, rng).expect("pair");
    greater_than_or_equal(&sum, &bound, &pair, committee_f, committee_b, rng).expect("ge")
}

fn bench_auction(c: &mut Criterion) {
    let mut group = c.benchmark_group("auction_argmax");
    for k in [2_usize, 4, 8] {
        let committee_f = Committee::<Fr>::new(2, 5).expect("cf");
        let committee_b = Committee::<F2>::new(2, 5).expect("cb");
        group.bench_function(BenchmarkId::new("bids", k), |b| {
            b.iter_with_large_drop(|| {
                // Rebuild inputs per iteration (ShamirShare is not Clone).
                let mut r = StdRng::seed_from_u64(0);
                let bids: Vec<Vec<ShamirShare<Fr>>> = (0..k)
                    .map(|i| {
                        committee_f
                            .split(Fr::from(i as u64), &mut r)
                            .expect("split")
                    })
                    .collect();
                argmax(bids, &committee_f, &committee_b, &mut r)
            });
        });
    }
    group.finish();
}

fn bench_analytics(c: &mut Criterion) {
    let mut group = c.benchmark_group("analytics_threshold");
    for k in [2_usize, 4, 8] {
        let committee_f = Committee::<Fr>::new(2, 5).expect("cf");
        let committee_b = Committee::<F2>::new(2, 5).expect("cb");
        group.bench_function(BenchmarkId::new("values", k), |b| {
            b.iter_with_large_drop(|| {
                let mut r = StdRng::seed_from_u64(0);
                let values: Vec<Vec<ShamirShare<Fr>>> = (0..k)
                    .map(|i| {
                        committee_f
                            .split(Fr::from(i as u64), &mut r)
                            .expect("split")
                    })
                    .collect();
                let bound = committee_f.split(Fr::from(10_u64), &mut r).expect("bound");
                analytics_threshold(values, bound, &committee_f, &committee_b, &mut r)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_auction, bench_analytics);
criterion_main!(benches);
