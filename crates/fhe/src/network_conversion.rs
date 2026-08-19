//! H2S/S2H with a modeled network: BFV partials (H2S) or SS shares (S2H) are routed through a
//! `MemoryMailbox` with RTT latency and bandwidth, so the online conversion latency can be
//! measured under LAN/MAN/WAN profiles.
//!
//! H2S uses the Shamir key threshold (t-of-n): only `threshold + 1` parties compute partials and
//! the dealer Lagrange-combines them, matching the paper's §3.1 structure.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ppsc_core::NodeId;
use ppsc_crypto::mpc::{Committee, ShamirShare};
use ppsc_network::memory::{MemoryMailbox, NetworkProfile};
use rand::Rng;

use crate::{Ciphertext, CkksContext, KeyPair};

fn int_to_field(x: i64) -> Fr {
    Fr::from(x.rem_euclid(65_537) as u64)
}

fn field_to_int(f: Fr) -> i64 {
    f.into_bigint().0[0] as i64
}

/// H2S with network (Shamir key threshold, t-of-n): each of `threshold + 1` parties computes a
/// partial `c_0 + s_i·c_1` and sends it to the dealer; the dealer Lagrange-combines and fuses,
/// then Shamir-shares each plaintext value over `Fr`.
///
/// The already-shared keys (`party_keys`, from `bfv_share_key_per_modulus`) and the per-modulus
/// Lagrange coefficients (`lambdas`) are offline inputs, so only the online partial + network +
/// fuse is timed.
#[allow(clippy::too_many_arguments)]
pub fn h2s_threshold_with_network(
    ctx: &CkksContext,
    ct: &Ciphertext,
    party_keys: &[KeyPair],
    lambdas: &[u64],
    threshold: usize,
    committee: &Committee<Fr>,
    batch: usize,
    profile: NetworkProfile,
    dealer: NodeId,
    rng: &mut impl Rng,
) -> Option<Vec<Vec<ShamirShare<Fr>>>> {
    let n_keys = threshold + 1;

    // Each of the first `t+1` parties computes its partial locally.
    let mut partials = Vec::with_capacity(n_keys);
    for pk in party_keys.iter().take(n_keys) {
        partials.push(ctx.bfv_share_partial(ct, pk)?);
    }

    // Partials travel to the dealer over the network (RTT + bandwidth).
    let mailbox = MemoryMailbox::with_profile(profile);
    for p in partials.iter() {
        mailbox.send_with_size(dealer, p.clone(), p.len());
    }
    let collected = mailbox.drain(dealer);

    // Dealer Lagrange-combines (per modulus) and fuses into plaintext.
    let plaintext = ctx.bfv_shamir_fuse(&collected, lambdas, batch)?;

    let mut result = Vec::with_capacity(batch);
    for &x in plaintext.iter() {
        result.push(committee.split(int_to_field(x), rng).ok()?);
    }
    Some(result)
}

/// S2H with network: `threshold + 1` parties send their `Fr` share values to the dealer over the
/// network (RTT + bandwidth), the dealer reconstructs each plaintext and re-encrypts.
pub fn s2h_with_network(
    ctx: &CkksContext,
    kp: &KeyPair,
    shares: &[Vec<ShamirShare<Fr>>],
    committee: &Committee<Fr>,
    profile: NetworkProfile,
    dealer: NodeId,
) -> Option<Ciphertext> {
    let batch = shares.len();
    let t = committee.threshold;
    let mailbox = MemoryMailbox::with_profile(profile);

    for i in 0..=t {
        let mut payload = Vec::with_capacity(batch * 32);
        for share_vec in shares.iter().take(batch) {
            let bytes = share_vec[i].value().into_bigint().to_bytes_le();
            payload.extend_from_slice(&bytes);
        }
        mailbox.send_with_size(dealer, payload.clone(), payload.len());
    }
    let _collected = mailbox.drain(dealer);

    // Reconstruct from the first `t+1` parties (the ones that sent their shares).
    let mut plaintext = Vec::with_capacity(batch);
    for share_vec in shares.iter().take(batch) {
        let f = committee.reconstruct(&share_vec[..=t]).ok()?;
        plaintext.push(field_to_int(f));
    }
    ctx.bfv_encrypt_int(kp, &plaintext)
}
