#![doc = "Cryptographic capability port; concrete implementations must delegate to mature, audited libraries."]

use ppsc_core::{
    Commitment, CommitteeEpoch, CommitteeId, DataId, ExecutionId, NodeId, PublicBytes, SecretBytes,
    TaskId,
};
use std::{error::Error, fmt};

pub mod mpc;

pub struct Ciphertext(pub PublicBytes);
pub struct Proof(pub PublicBytes);
pub struct SecretShare(SecretBytes);
pub struct SortitionProof(pub PublicBytes);

pub struct ConversionParameters {
    pub ring_degree: u32,
    pub coefficient_modulus: PublicBytes,
    pub mpc_prime_modulus: PublicBytes,
    pub fhe_level: u32,
    pub ciphertext_scale: u64,
    pub logical_scale: u64,
    pub value_bound: u64,
    pub slot_layout_hash: Commitment,
    pub maximum_decoding_error: PublicBytes,
}

pub struct CorrelatedConversionMask {
    pub mask_share: SecretShare,
    pub mask_ciphertext: Ciphertext,
    pub correlation_commitment: Commitment,
}

impl SecretShare {
    pub fn from_secret(bytes: SecretBytes) -> Self {
        Self(bytes)
    }

    pub fn expose_for_protocol(&self) -> &[u8] {
        self.0.expose()
    }
}

pub struct EncryptionRequest<'a> {
    pub task_id: TaskId,
    pub recipient: NodeId,
    pub plaintext: &'a SecretBytes,
    pub associated_data: &'a [u8],
}

pub trait CryptoProvider: Send + Sync {
    fn encrypt(&self, request: EncryptionRequest<'_>) -> Result<Ciphertext, CryptoError>;
    fn decrypt(&self, task_id: TaskId, ciphertext: &Ciphertext)
        -> Result<SecretBytes, CryptoError>;
    fn split_secret(
        &self,
        task_id: TaskId,
        committee: CommitteeId,
        secret: &SecretBytes,
        threshold: u16,
        participants: u16,
    ) -> Result<Vec<SecretShare>, CryptoError>;
    fn combine_shares(
        &self,
        task_id: TaskId,
        shares: &[SecretShare],
    ) -> Result<SecretBytes, CryptoError>;
    fn evaluate(
        &self,
        task_id: TaskId,
        program: &[u8],
        inputs: &[Ciphertext],
    ) -> Result<Ciphertext, CryptoError>;

    /// C2S: raw decryption, decoding, rounding, range and wrap checks stay inside MPC.
    fn ciphertext_to_authenticated_sharing(
        &self,
        task_id: TaskId,
        ciphertext: &Ciphertext,
        key_reference: DataId,
        parameters: &ConversionParameters,
    ) -> Result<SecretShare, CryptoError>;

    /// S2C: the correlated mask is one-time and must be consumed atomically.
    fn authenticated_sharing_to_ciphertext(
        &self,
        task_id: TaskId,
        value: &SecretShare,
        key_reference: DataId,
        parameters: &ConversionParameters,
        mask: CorrelatedConversionMask,
    ) -> Result<Ciphertext, CryptoError>;
    fn commit(&self, task_id: TaskId, value: &[u8]) -> Result<Commitment, CryptoError>;
    fn prove(&self, task_id: TaskId, statement: &[u8]) -> Result<Proof, CryptoError>;
    fn verify(&self, task_id: TaskId, statement: &[u8], proof: &Proof) -> Result<(), CryptoError>;

    /// Produce an unforgeable node-selection proof using a committed random seed.
    fn prove_sortition(
        &self,
        execution_id: ExecutionId,
        epoch: CommitteeEpoch,
        seed: &[u8; 32],
        eligibility_weight: u64,
    ) -> Result<SortitionProof, CryptoError>;

    fn verify_sortition(
        &self,
        execution_id: ExecutionId,
        epoch: CommitteeEpoch,
        seed: &[u8; 32],
        node: NodeId,
        eligibility_weight: u64,
        proof: &SortitionProof,
    ) -> Result<(), CryptoError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKey,
    InvalidCiphertext,
    InvalidShare,
    InsufficientShares,
    VerificationFailed,
    InvalidSortitionProof,
    InvalidHandoff,
    InvalidConversionParameters,
    RangeCheckFailed,
    WraparoundDetected,
    PreprocessingAlreadyConsumed,
    UnsupportedOperation,
    ProviderFailure,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cryptographic operation failed: {self:?}")
    }
}

impl Error for CryptoError {}
