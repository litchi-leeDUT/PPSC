//! In-memory multi-node dealer-mediated Basic Handoff closed loop.
//!
//! Simulates three kinds of nodes — source committee members, a dealer, and destination committee
//! members — passing messages through `MemoryMailbox`: source computes `delta_i` and submits it to
//! the dealer, the dealer reconstructs and broadcasts `delta`, and destination members each receive
//! it and apply `delta` to get their new share.
//!
//! The math is still provided by `ppsc_crypto::mpc`; this module only handles node roles and message routing.

use ppsc_core::{CommitteeId, ExecutionId, NodeId};
use ppsc_crypto::mpc::{
    apply_difference, masked_difference_shares, reconstruct_from_parts, reshare_pair, Committee,
    HandoffMask, ShamirShare, ShareField,
};
use ppsc_network::memory::MemoryMailbox;
use ppsc_protocol::handoff::{HandoffError, MaskedDeltaBroadcast, MaskedShareSubmission};
use rand::Rng;
use std::collections::HashSet;
use std::time::Duration;

pub struct HandoffOutcome<F: ShareField> {
    pub output: Vec<ShamirShare<F>>,
    pub delta: F,
}

#[allow(clippy::too_many_arguments)]
pub fn run_handoff<F: ShareField>(
    execution_id: ExecutionId,
    from: CommitteeId,
    to: CommitteeId,
    x_shares: &[ShamirShare<F>],
    mask: &HandoffMask<F>,
    src: &Committee<F>,
    dst: &Committee<F>,
    source_nodes: &[NodeId],
    dealer: NodeId,
    destination_nodes: &[NodeId],
) -> Result<HandoffOutcome<F>, HandoffError> {
    run_handoff_with_latency(
        execution_id,
        from,
        to,
        x_shares,
        mask,
        src,
        dst,
        source_nodes,
        dealer,
        destination_nodes,
        Duration::ZERO,
    )
}

/// `run_handoff` with a per-message one-way network latency (for LAN/MAN/WAN benchmarks).
#[allow(clippy::too_many_arguments)]
pub fn run_handoff_with_latency<F: ShareField>(
    execution_id: ExecutionId,
    from: CommitteeId,
    to: CommitteeId,
    x_shares: &[ShamirShare<F>],
    mask: &HandoffMask<F>,
    src: &Committee<F>,
    dst: &Committee<F>,
    source_nodes: &[NodeId],
    dealer: NodeId,
    destination_nodes: &[NodeId],
    latency: Duration,
) -> Result<HandoffOutcome<F>, HandoffError> {
    if x_shares.len() != src.size()
        || mask.source.len() != src.size()
        || source_nodes.len() != src.size()
    {
        return Err(HandoffError::ShareCountMismatch);
    }
    if mask.destination.len() != dst.size() || destination_nodes.len() != dst.size() {
        return Err(HandoffError::ShareCountMismatch);
    }

    let submissions_mailbox = MemoryMailbox::<MaskedShareSubmission<F>>::with_latency(latency);
    let broadcasts_mailbox = MemoryMailbox::<MaskedDeltaBroadcast<F>>::with_latency(latency);

    // 1. Source committee members locally compute delta_i and submit to the dealer.
    let delta_shares = masked_difference_shares(x_shares, &mask.source)?;
    for (i, d) in delta_shares.iter().enumerate() {
        submissions_mailbox.send(
            dealer,
            MaskedShareSubmission {
                execution_id,
                from_committee: from,
                to_committee: to,
                sender: source_nodes[i],
                share_index: i,
                degree: mask.source_degree,
                masked_share: d.value(),
            },
        );
    }

    // 2. The dealer collects and validates submissions, reconstructs delta = x - r.
    let submissions = submissions_mailbox.drain(dealer);
    let required = src.threshold + 1;
    if submissions.len() < required {
        return Err(HandoffError::InsufficientShares {
            received: submissions.len(),
            required,
        });
    }
    let mut seen = HashSet::new();
    for sub in &submissions {
        if sub.execution_id != execution_id {
            return Err(HandoffError::WrongExecution);
        }
        if sub.from_committee != from || sub.to_committee != to {
            return Err(HandoffError::WrongCommittee);
        }
        if sub.degree != mask.source_degree {
            return Err(HandoffError::WrongDegree);
        }
        if sub.share_index >= src.size() {
            return Err(HandoffError::InvalidShareIndex(sub.share_index));
        }
        if !seen.insert(sub.sender) {
            return Err(HandoffError::DuplicateSender(sub.sender));
        }
    }
    let points: Vec<F> = submissions
        .iter()
        .map(|s| src.points[s.share_index])
        .collect();
    let values: Vec<F> = submissions.iter().map(|s| s.masked_share).collect();
    let delta = reconstruct_from_parts(&points, &values, required)?;

    // 3. The dealer broadcasts delta to each destination committee member.
    let broadcast = MaskedDeltaBroadcast {
        execution_id,
        from_committee: from,
        to_committee: to,
        dealer,
        delta,
    };
    for &node in destination_nodes {
        broadcasts_mailbox.send(node, broadcast);
    }

    // 4. Destination members receive the broadcast, verify origin and execution id, then apply delta.
    for &node in destination_nodes {
        let received = broadcasts_mailbox.drain(node);
        let valid = received
            .iter()
            .any(|b| b.dealer == dealer && b.execution_id == execution_id && b.delta == delta);
        if !valid {
            return Err(HandoffError::InvalidState);
        }
    }
    let output = apply_difference(delta, &mask.destination);

    Ok(HandoffOutcome { output, delta })
}

/// Multi-node multiplication with degree reduction and handoff (`Π_mult`), with a
/// per-message one-way network latency. Each source party locally computes
/// `δ_i = x_i·y_i − r_i`; the dealer reconstructs `δ = x·y − r` from `2t+1` shares and
/// broadcasts it; destination parties add `δ` onto their `r` share.
#[allow(clippy::too_many_arguments)]
pub fn run_mult_with_latency<F: ShareField>(
    execution_id: ExecutionId,
    from: CommitteeId,
    to: CommitteeId,
    x: &[ShamirShare<F>],
    y: &[ShamirShare<F>],
    mask: &HandoffMask<F>,
    src: &Committee<F>,
    dst: &Committee<F>,
    source_nodes: &[NodeId],
    dealer: NodeId,
    destination_nodes: &[NodeId],
    latency: Duration,
) -> Result<HandoffOutcome<F>, HandoffError> {
    if x.len() != y.len()
        || x.len() != mask.source.len()
        || x.len() != src.size()
        || source_nodes.len() != src.size()
    {
        return Err(HandoffError::ShareCountMismatch);
    }
    if mask.destination.len() != dst.size() || destination_nodes.len() != dst.size() {
        return Err(HandoffError::ShareCountMismatch);
    }
    if src.size() <= 2 * src.threshold {
        return Err(HandoffError::InvalidState);
    }

    let submissions_mailbox = MemoryMailbox::<MaskedShareSubmission<F>>::with_latency(latency);
    let broadcasts_mailbox = MemoryMailbox::<MaskedDeltaBroadcast<F>>::with_latency(latency);

    for (i, ((xi, yi), ri)) in x.iter().zip(y.iter()).zip(mask.source.iter()).enumerate() {
        submissions_mailbox.send(
            dealer,
            MaskedShareSubmission {
                execution_id,
                from_committee: from,
                to_committee: to,
                sender: source_nodes[i],
                share_index: i,
                degree: mask.source_degree,
                masked_share: xi.value() * yi.value() - ri.value(),
            },
        );
    }

    let submissions = submissions_mailbox.drain(dealer);
    let required = 2 * src.threshold + 1;
    if submissions.len() < required {
        return Err(HandoffError::InsufficientShares {
            received: submissions.len(),
            required,
        });
    }
    let mut seen = HashSet::new();
    for sub in &submissions {
        if sub.execution_id != execution_id {
            return Err(HandoffError::WrongExecution);
        }
        if sub.from_committee != from || sub.to_committee != to {
            return Err(HandoffError::WrongCommittee);
        }
        if sub.degree != mask.source_degree {
            return Err(HandoffError::WrongDegree);
        }
        if sub.share_index >= src.size() {
            return Err(HandoffError::InvalidShareIndex(sub.share_index));
        }
        if !seen.insert(sub.sender) {
            return Err(HandoffError::DuplicateSender(sub.sender));
        }
    }
    let points: Vec<F> = submissions
        .iter()
        .map(|s| src.points[s.share_index])
        .collect();
    let values: Vec<F> = submissions.iter().map(|s| s.masked_share).collect();
    let delta = reconstruct_from_parts(&points, &values, required)?;

    let broadcast = MaskedDeltaBroadcast {
        execution_id,
        from_committee: from,
        to_committee: to,
        dealer,
        delta,
    };
    for &node in destination_nodes {
        broadcasts_mailbox.send(node, broadcast);
    }
    for &node in destination_nodes {
        let received = broadcasts_mailbox.drain(node);
        let valid = received
            .iter()
            .any(|b| b.dealer == dealer && b.execution_id == execution_id && b.delta == delta);
        if !valid {
            return Err(HandoffError::InvalidState);
        }
    }
    let output = apply_difference(delta, &mask.destination);

    Ok(HandoffOutcome { output, delta })
}

/// Simulates the on-chain `CommitteeSelected` event: carries the public parameters and secret value for one handoff.
pub struct HandoffEvent<F: ShareField> {
    pub execution_id: ExecutionId,
    pub from: CommitteeId,
    pub to: CommitteeId,
    pub src: Committee<F>,
    pub dst: Committee<F>,
    pub x: F,
    pub nonce: Vec<u8>,
    pub source_nodes: Vec<NodeId>,
    pub dealer: NodeId,
    pub destination_nodes: Vec<NodeId>,
}

pub struct HandoffResult<F: ShareField> {
    pub execution_id: ExecutionId,
    pub output: Vec<ShamirShare<F>>,
    pub delta: F,
}

/// In-memory handoff orchestration: on a chain event, completes one
/// "committee-selected → handoff → result" loop. The secret value never leaves the process and is
/// never serialized.
pub struct HandoffRuntime<R: Rng> {
    rng: R,
}

impl<R: Rng> HandoffRuntime<R> {
    pub fn new(rng: R) -> Self {
        Self { rng }
    }

    pub fn run<F: ShareField>(
        &mut self,
        event: HandoffEvent<F>,
    ) -> Result<HandoffResult<F>, HandoffError> {
        let x_shares = event.src.split(event.x, &mut self.rng)?;
        let mask = reshare_pair(
            &event.src,
            event.src.threshold,
            &event.dst,
            event.dst.threshold,
            &event.nonce,
            &mut self.rng,
        )?;
        let outcome = run_handoff(
            event.execution_id,
            event.from,
            event.to,
            &x_shares,
            &mask,
            &event.src,
            &event.dst,
            &event.source_nodes,
            event.dealer,
            &event.destination_nodes,
        )?;
        Ok(HandoffResult {
            execution_id: event.execution_id,
            output: outcome.output,
            delta: outcome.delta,
        })
    }

    /// Batch handoff: hand off a batch of values element-wise between the same committee pair.
    ///
    /// Each value is processed independently (element-wise protocol, not an inner product), sharing
    /// only the committee and node identities; each value derives its own correlated mask via
    /// `nonce_prefix || index`.
    #[allow(clippy::too_many_arguments)]
    pub fn run_batch<F: ShareField>(
        &mut self,
        execution_id: ExecutionId,
        from: CommitteeId,
        to: CommitteeId,
        xs: &[F],
        src: &Committee<F>,
        dst: &Committee<F>,
        source_nodes: &[NodeId],
        dealer: NodeId,
        destination_nodes: &[NodeId],
        nonce_prefix: &[u8],
    ) -> Result<Vec<Vec<ShamirShare<F>>>, HandoffError> {
        let mut outputs = Vec::with_capacity(xs.len());
        for (i, &x) in xs.iter().enumerate() {
            let x_shares = src.split(x, &mut self.rng)?;
            let mut nonce = nonce_prefix.to_vec();
            nonce.extend_from_slice(&i.to_le_bytes());
            let mask = reshare_pair(
                src,
                src.threshold,
                dst,
                dst.threshold,
                &nonce,
                &mut self.rng,
            )?;
            let outcome = run_handoff(
                execution_id,
                from,
                to,
                &x_shares,
                &mask,
                src,
                dst,
                source_nodes,
                dealer,
                destination_nodes,
            )?;
            outputs.push(outcome.output);
        }
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn node(v: u8) -> NodeId {
        NodeId::from_bytes([v; 32])
    }

    #[test]
    fn multi_node_handoff_preserves_secret_across_committees() {
        let mut rng = StdRng::seed_from_u64(0x1234_5678);
        let src = Committee::<Fr>::new(2, 5).expect("src");
        let dst = Committee::<Fr>::new(2, 5).expect("dst");
        let x = Fr::from(123_u64);
        let x_shares = src.split(x, &mut rng).expect("split");
        let mask = reshare_pair(&src, 2, &dst, 2, b"ho", &mut rng).expect("mask");

        let outcome = match run_handoff(
            ExecutionId::from_bytes([1; 32]),
            CommitteeId::from_bytes([2; 32]),
            CommitteeId::from_bytes([3; 32]),
            &x_shares,
            &mask,
            &src,
            &dst,
            &(0u8..5).map(node).collect::<Vec<_>>(),
            node(9),
            &(10u8..15).map(node).collect::<Vec<_>>(),
        ) {
            Ok(outcome) => outcome,
            Err(err) => panic!("run handoff failed: {err}"),
        };

        assert_eq!(
            dst.reconstruct(&outcome.output)
                .expect("reconstruct output"),
            x
        );
    }

    #[test]
    fn multi_node_handoff_rejects_source_count_mismatch() {
        let mut rng = StdRng::seed_from_u64(0x1234_5678);
        let src = Committee::<Fr>::new(2, 5).expect("src");
        let dst = Committee::<Fr>::new(2, 5).expect("dst");
        let x = Fr::from(7_u64);
        let x_shares = src.split(x, &mut rng).expect("split");
        let mask = reshare_pair(&src, 2, &dst, 2, b"ho", &mut rng).expect("mask");

        let err = match run_handoff(
            ExecutionId::from_bytes([1; 32]),
            CommitteeId::from_bytes([2; 32]),
            CommitteeId::from_bytes([3; 32]),
            &x_shares,
            &mask,
            &src,
            &dst,
            &[node(1), node(2)], // only 2 source nodes, should be 5
            node(9),
            &(10u8..15).map(node).collect::<Vec<_>>(),
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected error"),
        };

        assert!(matches!(err, HandoffError::ShareCountMismatch));
    }

    #[test]
    fn runtime_completes_committee_selected_to_result_loop() {
        let mut runtime = HandoffRuntime::new(StdRng::seed_from_u64(0x0BAD_CAFE));
        let dst = Committee::<Fr>::new(2, 5).expect("dst for assert");
        let x = Fr::from(321_u64);
        let event = HandoffEvent {
            execution_id: ExecutionId::from_bytes([9; 32]),
            from: CommitteeId::from_bytes([8; 32]),
            to: CommitteeId::from_bytes([7; 32]),
            src: Committee::<Fr>::new(2, 5).expect("src"),
            dst: Committee::<Fr>::new(2, 5).expect("dst"),
            x,
            nonce: b"epoch-0".to_vec(),
            source_nodes: (0u8..5).map(node).collect(),
            dealer: node(9),
            destination_nodes: (10u8..15).map(node).collect(),
        };

        let result = match runtime.run(event) {
            Ok(result) => result,
            Err(err) => panic!("runtime run failed: {err}"),
        };

        assert!(result.execution_id == ExecutionId::from_bytes([9; 32]));
        assert_eq!(
            dst.reconstruct(&result.output).expect("reconstruct output"),
            x
        );
    }

    #[test]
    fn batch_matches_single_element_execution() {
        let mut runtime = HandoffRuntime::new(StdRng::seed_from_u64(0x0BAD_CAFE));
        let src = Committee::<Fr>::new(2, 5).expect("src");
        let dst = Committee::<Fr>::new(2, 5).expect("dst");
        let xs = vec![Fr::from(1_u64), Fr::from(2_u64), Fr::from(3_u64)];

        let outputs = match runtime.run_batch(
            ExecutionId::from_bytes([4; 32]),
            CommitteeId::from_bytes([5; 32]),
            CommitteeId::from_bytes([6; 32]),
            &xs,
            &src,
            &dst,
            &(0u8..5).map(node).collect::<Vec<_>>(),
            node(9),
            &(10u8..15).map(node).collect::<Vec<_>>(),
            b"batch",
        ) {
            Ok(outputs) => outputs,
            Err(err) => panic!("run batch failed: {err}"),
        };

        assert_eq!(outputs.len(), 3);
        for (i, out) in outputs.iter().enumerate() {
            assert_eq!(dst.reconstruct(out).expect("reconstruct"), xs[i]);
        }
    }

    #[test]
    fn batch_single_element_equals_non_batch_result() {
        let src = Committee::<Fr>::new(2, 5).expect("src");
        let dst = Committee::<Fr>::new(2, 5).expect("dst");
        let x = Fr::from(42_u64);

        let mut runtime = HandoffRuntime::new(StdRng::seed_from_u64(0x0BAD_CAFE));
        let outputs = match runtime.run_batch(
            ExecutionId::from_bytes([1; 32]),
            CommitteeId::from_bytes([2; 32]),
            CommitteeId::from_bytes([3; 32]),
            &[x],
            &src,
            &dst,
            &(0u8..5).map(node).collect::<Vec<_>>(),
            node(9),
            &(10u8..15).map(node).collect::<Vec<_>>(),
            b"batch",
        ) {
            Ok(outputs) => outputs,
            Err(err) => panic!("run batch failed: {err}"),
        };
        assert_eq!(outputs.len(), 1);
        assert_eq!(dst.reconstruct(&outputs[0]).expect("reconstruct"), x);
    }
}
