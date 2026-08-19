//! RQ4: committee-rotation scalability. Measures the end-to-end latency of handing off
//! `m` live SS records between two committees under LAN/MAN/WAN, with all `m` shares packed
//! into one submission and one broadcast (amortizing the RTT over `m` records).

use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ppsc_core::NodeId;
use ppsc_crypto::mpc::{
    apply_difference, masked_difference_shares, reconstruct_from_parts, reshare_pair_dealer,
    Committee, HandoffMask, ShamirShare,
};
use ppsc_network::memory::{MemoryMailbox, NetworkProfile};
use rand::rngs::StdRng;
use rand::SeedableRng;

const N: usize = 16;
const T: usize = 7;
const MS: [usize; 5] = [1, 16, 64, 256, 1024];

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

struct RotationSetup {
    src: Committee<Fr>,
    x_shares: Vec<Vec<ShamirShare<Fr>>>,
    masks: Vec<HandoffMask<Fr>>,
}

fn setup(m: usize) -> RotationSetup {
    let src = Committee::<Fr>::new(T, N).expect("src");
    let dst = Committee::<Fr>::new(T, N).expect("dst");
    let mut rng = StdRng::seed_from_u64(0);
    let x_shares: Vec<Vec<ShamirShare<Fr>>> = (0..m)
        .map(|i| src.split(Fr::from(i as u64), &mut rng).expect("split"))
        .collect();
    let masks: Vec<HandoffMask<Fr>> = (0..m)
        .map(|_| reshare_pair_dealer(&src, T, &dst, T, &mut rng).expect("mask"))
        .collect();
    RotationSetup {
        src,
        x_shares,
        masks,
    }
}

/// Total traffic in bytes for `m` records: each of the `n` source parties submits `m` share
/// values (32 B each), and the dealer broadcasts `m` deltas (32 B each).
pub fn traffic_bytes(m: usize) -> usize {
    m * 32 * (N + 1)
}

/// One packed rotation: source parties each send one message carrying `m` delta shares; the
/// dealer reconstructs `m` deltas and broadcasts them in one message; destination parties apply.
fn run_rotation(
    s: &RotationSetup,
    profile: NetworkProfile,
    dealer: NodeId,
    source_nodes: &[NodeId],
    destination_nodes: &[NodeId],
) {
    let m = s.x_shares.len();
    let sub = MemoryMailbox::<(usize, Vec<Fr>)>::with_profile(profile);
    let bcast = MemoryMailbox::<Vec<Fr>>::with_profile(profile);

    // Source parties compute all `m` delta shares and submit them in one packed message.
    let delta_shares: Vec<Vec<ShamirShare<Fr>>> = s
        .x_shares
        .iter()
        .zip(s.masks.iter())
        .map(|(xs, mask)| masked_difference_shares(xs, &mask.source).expect("diff"))
        .collect();
    for i in 0..N {
        let payload: Vec<Fr> = delta_shares.iter().map(|ds| ds[i].value()).collect();
        sub.send_with_size(dealer, (i, payload), m * 32);
    }

    // Dealer reconstructs each of the `m` deltas from a qualified set of `t+1` shares.
    let submissions = sub.drain(dealer);
    let qualified = &submissions[..T + 1];
    let points: Vec<Fr> = qualified.iter().map(|(i, _)| s.src.points[*i]).collect();
    let mut deltas = vec![Fr::from(0_u64); m];
    for (j, d) in deltas.iter_mut().enumerate() {
        let values: Vec<Fr> = qualified.iter().map(|(_, v)| v[j]).collect();
        *d = reconstruct_from_parts(&points, &values, T + 1).expect("reconstruct");
    }
    // Dealer broadcasts the deltas to every destination party.
    for &dn in destination_nodes {
        bcast.send_with_size(dn, deltas.clone(), m * 32);
    }
    for &dn in destination_nodes {
        let _ = bcast.drain(dn);
    }
    for (d, mask) in deltas.iter().zip(s.masks.iter()) {
        let _ = apply_difference(*d, &mask.destination);
    }

    let _ = (source_nodes, destination_nodes);
}

fn bench_rotation(c: &mut Criterion) {
    for profile in [
        NetworkProfile::Lan,
        NetworkProfile::Man,
        NetworkProfile::Wan,
    ] {
        let mut group = c.benchmark_group(format!("rotation_{}", profile_name(profile)));
        for &m in MS.iter() {
            let s = setup(m);
            let source_nodes: Vec<NodeId> = (0..N as u8).map(node).collect();
            let destination_nodes: Vec<NodeId> = (0x80..0x80 + N as u8).map(node).collect();
            let dealer = node(0xEE);
            group.bench_function(BenchmarkId::new("m", m), |b| {
                b.iter(|| run_rotation(&s, profile, dealer, &source_nodes, &destination_nodes));
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_rotation);
criterion_main!(benches);
