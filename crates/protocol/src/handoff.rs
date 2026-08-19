//! Message-driven state machine for Dealer-mediated Basic Handoff (paper `Π_Handoff`).
//!
//! Separates "math operations" from "who sends what": the math is still provided by
//! `ppsc_crypto::mpc` (`masked_difference_shares` / `reconstruct_from_parts` / `apply_difference`);
//! this module only handles message shapes and state transitions.
//!
//! Flow (the stable version confirmed by the advisor):
//! ```text
//! S1's P_i computes delta_i = [x]_i - [r]_i
//! The dealer collects at least t+1 delta_i
//! The dealer reconstructs and broadcasts delta = x - r
//! S2's P_j sets [x]'_j = [r]'_j + delta
//! ```

use ppsc_core::{CommitteeId, ExecutionId, NodeId};
use ppsc_crypto::mpc::{
    apply_difference, masked_difference_shares, reconstruct_from_parts, Committee, HandoffMask,
    MpcError, ShamirShare, ShareField,
};
use std::{collections::HashSet, error::Error, fmt};

/// A masked share submitted by a source committee member to the dealer: `delta_i = [x]_i - [r]_i`.
///
/// `share_index` is the source committee's evaluation-point index (`src.points[share_index]`),
/// and `masked_share` is the local difference `delta_i`; neither carries a full `ShamirShare` object.
#[derive(Clone, Copy)]
pub struct MaskedShareSubmission<F: ShareField> {
    pub execution_id: ExecutionId,
    pub from_committee: CommitteeId,
    pub to_committee: CommitteeId,
    pub sender: NodeId,
    pub share_index: usize,
    pub degree: usize,
    pub masked_share: F,
}

/// The masked delta broadcast by the dealer to the destination committee: `delta = x - r`.
#[derive(Clone, Copy)]
pub struct MaskedDeltaBroadcast<F: ShareField> {
    pub execution_id: ExecutionId,
    pub from_committee: CommitteeId,
    pub to_committee: CommitteeId,
    pub dealer: NodeId,
    pub delta: F,
}

enum HandoffPhase<F: ShareField> {
    Initialized {
        x_shares: Vec<ShamirShare<F>>,
        mask: HandoffMask<F>,
    },
    Collecting {
        submissions: Vec<MaskedShareSubmission<F>>,
        dst_mask: Vec<ShamirShare<F>>,
    },
    Reconstructed {
        delta: F,
        dst_mask: Vec<ShamirShare<F>>,
    },
    OutputReady {
        output: Vec<ShamirShare<F>>,
    },
}

/// One execution session of `Π_Handoff`; methods consume `self` and advance the state.
pub struct HandoffSession<F: ShareField> {
    execution_id: ExecutionId,
    from: CommitteeId,
    to: CommitteeId,
    src: Committee<F>,
    dst: Committee<F>,
    source_degree: usize,
    dealer: NodeId,
    source_senders: Vec<NodeId>,
    phase: HandoffPhase<F>,
}

impl<F: ShareField> HandoffSession<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_id: ExecutionId,
        from: CommitteeId,
        to: CommitteeId,
        src: Committee<F>,
        dst: Committee<F>,
        x_shares: Vec<ShamirShare<F>>,
        mask: HandoffMask<F>,
        source_senders: Vec<NodeId>,
        dealer: NodeId,
    ) -> Result<Self, HandoffError> {
        if x_shares.len() != src.size()
            || mask.source.len() != src.size()
            || source_senders.len() != src.size()
        {
            return Err(HandoffError::ShareCountMismatch);
        }
        if mask.destination.len() != dst.size() {
            return Err(HandoffError::ShareCountMismatch);
        }
        let source_degree = mask.source_degree;
        Ok(Self {
            execution_id,
            from,
            to,
            src,
            dst,
            source_degree,
            dealer,
            source_senders,
            phase: HandoffPhase::Initialized { x_shares, mask },
        })
    }

    /// Stage 1: source committee members locally compute `delta_i` and produce submission messages.
    pub fn source_compute_masked_shares(self) -> Result<Self, HandoffError> {
        let Self {
            execution_id,
            from,
            to,
            src,
            dst,
            source_degree,
            dealer,
            source_senders,
            phase,
        } = self;
        let (x_shares, mask) = match phase {
            HandoffPhase::Initialized { x_shares, mask } => (x_shares, mask),
            _ => return Err(HandoffError::InvalidState),
        };
        let delta_shares = masked_difference_shares(&x_shares, &mask.source)?;
        let submissions = delta_shares
            .iter()
            .enumerate()
            .map(|(i, d)| MaskedShareSubmission {
                execution_id,
                from_committee: from,
                to_committee: to,
                sender: source_senders[i],
                share_index: i,
                degree: source_degree,
                masked_share: d.value(),
            })
            .collect();
        Ok(Self {
            execution_id,
            from,
            to,
            src,
            dst,
            source_degree,
            dealer,
            source_senders,
            phase: HandoffPhase::Collecting {
                submissions,
                dst_mask: mask.destination,
            },
        })
    }

    /// Stage 2: the dealer validates the submissions and reconstructs `delta = x - r`.
    pub fn dealer_reconstruct(self) -> Result<Self, HandoffError> {
        let Self {
            execution_id,
            from,
            to,
            src,
            dst,
            source_degree,
            dealer,
            source_senders,
            phase,
        } = self;
        let (submissions, dst_mask) = match phase {
            HandoffPhase::Collecting {
                submissions,
                dst_mask,
            } => (submissions, dst_mask),
            _ => return Err(HandoffError::InvalidState),
        };

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
            if sub.degree != source_degree {
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

        Ok(Self {
            execution_id,
            from,
            to,
            src,
            dst,
            source_degree,
            dealer,
            source_senders,
            phase: HandoffPhase::Reconstructed { delta, dst_mask },
        })
    }

    /// Stage 3: the dealer produces the broadcast message (borrows, does not consume the session).
    pub fn dealer_broadcast(&self) -> Result<MaskedDeltaBroadcast<F>, HandoffError> {
        match &self.phase {
            HandoffPhase::Reconstructed { delta, .. } => Ok(MaskedDeltaBroadcast {
                execution_id: self.execution_id,
                from_committee: self.from,
                to_committee: self.to,
                dealer: self.dealer,
                delta: *delta,
            }),
            _ => Err(HandoffError::InvalidState),
        }
    }

    /// Stage 4: destination committee members locally compute `[x]'_j = [r]'_j + delta`.
    pub fn destination_apply(self) -> Result<Self, HandoffError> {
        let Self {
            execution_id,
            from,
            to,
            src,
            dst,
            source_degree,
            dealer,
            source_senders,
            phase,
        } = self;
        let (delta, dst_mask) = match phase {
            HandoffPhase::Reconstructed { delta, dst_mask } => (delta, dst_mask),
            _ => return Err(HandoffError::InvalidState),
        };
        let output = apply_difference(delta, &dst_mask);
        Ok(Self {
            execution_id,
            from,
            to,
            src,
            dst,
            source_degree,
            dealer,
            source_senders,
            phase: HandoffPhase::OutputReady { output },
        })
    }

    /// Stage 5: produce the destination committee's new shares (reconstructable back to `x`).
    pub fn finalize(self) -> Result<Vec<ShamirShare<F>>, HandoffError> {
        match self.phase {
            HandoffPhase::OutputReady { output } => Ok(output),
            _ => Err(HandoffError::InvalidState),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    InvalidState,
    ShareCountMismatch,
    InsufficientShares { received: usize, required: usize },
    DuplicateSender(NodeId),
    WrongCommittee,
    WrongDegree,
    WrongExecution,
    InvalidShareIndex(usize),
    Crypto(MpcError),
}

impl From<MpcError> for HandoffError {
    fn from(value: MpcError) -> Self {
        HandoffError::Crypto(value)
    }
}

impl fmt::Debug for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandoffError::InvalidState => write!(f, "InvalidState"),
            HandoffError::ShareCountMismatch => write!(f, "ShareCountMismatch"),
            HandoffError::InsufficientShares { received, required } => {
                write!(
                    f,
                    "InsufficientShares {{ received: {received}, required: {required} }}"
                )
            }
            HandoffError::DuplicateSender(node) => {
                write!(f, "DuplicateSender({})", node_hex(node))
            }
            HandoffError::WrongCommittee => write!(f, "WrongCommittee"),
            HandoffError::WrongDegree => write!(f, "WrongDegree"),
            HandoffError::WrongExecution => write!(f, "WrongExecution"),
            HandoffError::InvalidShareIndex(i) => write!(f, "InvalidShareIndex({i})"),
            HandoffError::Crypto(e) => write!(f, "Crypto({e:?})"),
        }
    }
}

impl fmt::Display for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "handoff protocol failed: {self:?}")
    }
}

impl Error for HandoffError {}

fn node_hex(node: &NodeId) -> String {
    let mut out = String::with_capacity(18);
    for byte in node.as_bytes().iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out.push_str("..");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ppsc_crypto::mpc::reshare_pair;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xABCD_EF01)
    }

    fn node(v: u8) -> NodeId {
        NodeId::from_bytes([v; 32])
    }

    struct Ctx {
        execution_id: ExecutionId,
        from: CommitteeId,
        to: CommitteeId,
        src: Committee<Fr>,
        dst: Committee<Fr>,
        x: Fr,
        x_shares: Vec<ShamirShare<Fr>>,
        mask: HandoffMask<Fr>,
        source_senders: Vec<NodeId>,
        dealer: NodeId,
    }

    fn setup() -> Ctx {
        let src = Committee::<Fr>::new(2, 5).expect("src");
        let dst = Committee::<Fr>::new(2, 5).expect("dst");
        let x = Fr::from(99_u64);
        let x_shares = src.split(x, &mut rng()).expect("split");
        let mask = reshare_pair(&src, 2, &dst, 2, b"handoff", &mut rng()).expect("mask");
        Ctx {
            execution_id: ExecutionId::from_bytes([7; 32]),
            from: CommitteeId::from_bytes([1; 32]),
            to: CommitteeId::from_bytes([2; 32]),
            src,
            dst,
            x,
            x_shares,
            mask,
            source_senders: (0..5).map(node).collect(),
            dealer: node(9),
        }
    }

    fn session(ctx: Ctx) -> HandoffSession<Fr> {
        HandoffSession::new(
            ctx.execution_id,
            ctx.from,
            ctx.to,
            ctx.src,
            ctx.dst,
            ctx.x_shares,
            ctx.mask,
            ctx.source_senders,
            ctx.dealer,
        )
        .expect("session")
    }

    fn collecting(ctx: Ctx) -> HandoffSession<Fr> {
        session(ctx)
            .source_compute_masked_shares()
            .expect("collect")
    }

    fn mutate_collecting<G>(session: HandoffSession<Fr>, f: G) -> HandoffSession<Fr>
    where
        G: FnOnce(&mut Vec<MaskedShareSubmission<Fr>>),
    {
        let HandoffSession {
            execution_id,
            from,
            to,
            src,
            dst,
            source_degree,
            dealer,
            source_senders,
            phase,
        } = session;
        let (mut submissions, dst_mask) = match phase {
            HandoffPhase::Collecting {
                submissions,
                dst_mask,
            } => (submissions, dst_mask),
            _ => unreachable!(),
        };
        f(&mut submissions);
        HandoffSession {
            execution_id,
            from,
            to,
            src,
            dst,
            source_degree,
            dealer,
            source_senders,
            phase: HandoffPhase::Collecting {
                submissions,
                dst_mask,
            },
        }
    }

    #[test]
    fn full_flow_preserves_secret_across_committees() {
        let ctx = setup();
        let x = ctx.x;
        let dst = Committee::<Fr>::new(2, 5).expect("dst for assert");
        let session = session(ctx)
            .source_compute_masked_shares()
            .expect("collect")
            .dealer_reconstruct()
            .expect("reconstruct");
        let broadcast = session.dealer_broadcast().expect("broadcast");
        assert!(broadcast.dealer == node(9));
        let output = session
            .destination_apply()
            .expect("apply")
            .finalize()
            .expect("finalize");
        assert_eq!(dst.reconstruct(&output).expect("reconstruct output"), x);
    }

    #[test]
    fn dealer_rejects_insufficient_shares() {
        let session = mutate_collecting(collecting(setup()), |subs| subs.truncate(2));
        assert!(matches!(
            session.dealer_reconstruct(),
            Err(HandoffError::InsufficientShares {
                received: 2,
                required: 3
            })
        ));
    }

    #[test]
    fn dealer_rejects_duplicate_sender() {
        let session = mutate_collecting(collecting(setup()), |subs| {
            subs.truncate(3);
            subs[2].sender = subs[0].sender;
        });
        assert!(matches!(
            session.dealer_reconstruct(),
            Err(HandoffError::DuplicateSender(_))
        ));
    }

    #[test]
    fn dealer_rejects_wrong_degree() {
        let session = mutate_collecting(collecting(setup()), |subs| {
            subs.truncate(3);
            subs[0].degree = 99;
        });
        assert!(matches!(
            session.dealer_reconstruct(),
            Err(HandoffError::WrongDegree)
        ));
    }

    #[test]
    fn dealer_rejects_wrong_committee() {
        let session = mutate_collecting(collecting(setup()), |subs| {
            subs.truncate(3);
            subs[0].to_committee = CommitteeId::from_bytes([0xEE; 32]);
        });
        assert!(matches!(
            session.dealer_reconstruct(),
            Err(HandoffError::WrongCommittee)
        ));
    }

    #[test]
    fn dealer_rejects_wrong_execution() {
        let session = mutate_collecting(collecting(setup()), |subs| {
            subs.truncate(3);
            subs[1].execution_id = ExecutionId::from_bytes([0xBB; 32]);
        });
        assert!(matches!(
            session.dealer_reconstruct(),
            Err(HandoffError::WrongExecution)
        ));
    }

    #[test]
    fn dealer_rejects_out_of_range_share_index() {
        let session = mutate_collecting(collecting(setup()), |subs| {
            subs.truncate(3);
            subs[0].share_index = 999;
        });
        assert!(matches!(
            session.dealer_reconstruct(),
            Err(HandoffError::InvalidShareIndex(999))
        ));
    }
}
