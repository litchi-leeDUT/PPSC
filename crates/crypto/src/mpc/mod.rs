//! The paper's core MPC protocol layer: Shamir sharing, PRSS preprocessing,
//! cross-committee handoff, authentication, FHE↔SS conversion, S2B and packed sharing.
//!
//! Protocols are generic over `ShareField`: arithmetic in a prime field `F: PrimeField`
//! (e.g. `ark_bn254::Fr`), boolean sharing in the characteristic-2 field `F2 = GF(2^8)`.
//! Secret share types implement neither `Debug` nor `Display` nor `Clone`.

mod auth;
mod comparison;
mod conversion;
mod field;
mod handoff;
mod packed;
mod prss;
mod s2b;
mod shamir;

pub use auth::{
    auth_add, auth_scalar_mul, authenticated_handoff, authenticated_multiply, verify_mac,
    AuthenticatedSharing,
};
pub use comparison::{
    b2a, conditional_select, conditional_transfer_strictly_greater, generate_random_bit,
    greater_than_or_equal, greater_than_or_equal_bounded, ConditionalTransferOutput, RandomBitPair,
};
pub use conversion::{
    decrypt, encrypt, h2s, h2s_mask, s2h, s2h_mask, FheCiphertext, H2sMask, S2hMask,
};
pub use field::{ShareField, F2};
pub use handoff::{
    apply_difference, basic_handoff, masked_difference_shares, multiply_and_handoff,
};
pub use packed::{packed_degree_reduce, packed_pairgen, packed_split, PackedPair, PackedParams};
pub use prss::{
    rand_share, rand_share_small, reshare_pair, reshare_pair_dealer, reshare_pair_small, PrssSeed,
};
pub use s2b::{
    generate_bit_extract_pair, generate_bit_extract_pair_bounded, s2b, s2b_bounded, BitExtractPair,
};
pub use shamir::{reconstruct_from_parts, Committee, ShamirShare};

use std::{error::Error, fmt};

/// A cross-committee correlated sharing pair `([r]^{sd,src}, [r]^{dd,dst})`, produced by
/// `reshare_pair` and consumed once by handoff / multiplication degree reduction.
pub struct HandoffMask<F: ShareField> {
    pub source: Vec<ShamirShare<F>>,
    pub source_degree: usize,
    pub destination: Vec<ShamirShare<F>>,
    pub destination_degree: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcError {
    InvalidThreshold,
    InsufficientParticipants,
    DuplicateShare,
    InsufficientShares,
    ShareCountMismatch,
    InconsistentShares,
    TooFewParties,
    InvalidPackingParameters,
    InvalidBitLength,
    RangeCheckFailed,
}

impl fmt::Display for MpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mpc protocol failed: {self:?}")
    }
}

impl Error for MpcError {}
