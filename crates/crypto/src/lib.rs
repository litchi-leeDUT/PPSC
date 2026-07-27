#![doc = "密码学能力端口；具体实现必须委托给成熟、经过审计的库。"]

use ppsc_core::{
    CommitteeEpoch, CommitteeId, Commitment, ExecutionId, NodeId, PublicBytes, SecretBytes,
    TaskId,
};
use std::{error::Error, fmt};

pub struct Ciphertext(pub PublicBytes);
pub struct Proof(pub PublicBytes);
pub struct SecretShare(SecretBytes);
pub struct SortitionProof(pub PublicBytes);
pub struct HandoffPackage(pub PublicBytes);

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
    fn commit(&self, task_id: TaskId, value: &[u8]) -> Result<Commitment, CryptoError>;
    fn prove(&self, task_id: TaskId, statement: &[u8]) -> Result<Proof, CryptoError>;
    fn verify(
        &self,
        task_id: TaskId,
        statement: &[u8],
        proof: &Proof,
    ) -> Result<(), CryptoError>;

    /// 使用已承诺的随机种子产生不可伪造的节点入选证明。
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

    /// 产生发往新委员会成员的重分享包；实现不得重构明文秘密。
    fn prepare_handoff(
        &self,
        execution_id: ExecutionId,
        from: CommitteeId,
        to: CommitteeId,
        local_share: &SecretShare,
        recipients: &[NodeId],
    ) -> Result<Vec<HandoffPackage>, CryptoError>;

    /// 组合经认证的重分享包，得到新委员会的本地份额。
    fn accept_handoff(
        &self,
        execution_id: ExecutionId,
        from: CommitteeId,
        to: CommitteeId,
        packages: &[HandoffPackage],
    ) -> Result<SecretShare, CryptoError>;
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
    UnsupportedOperation,
    ProviderFailure,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cryptographic operation failed: {self:?}")
    }
}

impl Error for CryptoError {}
