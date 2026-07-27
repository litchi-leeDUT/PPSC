#![doc = "链上合约端口；具体 Solidity ABI/RPC 实现在适配器中。"]

use ppsc_core::{
    CommitteeEpoch, CommitteeId, Commitment, ConfidentialityMode, ContractId, DataId,
    ExecutionId, NodeId, ProgramId, PublicBytes, TaskId,
};
use std::{error::Error, fmt, future::Future};

pub enum ChainEvent {
    ConfidentialContractPublished {
        contract_id: ContractId,
        manifest_hash: Commitment,
    },
    DataRegistered {
        data_id: DataId,
        commitment: Commitment,
        mode: ConfidentialityMode,
    },
    TaskRegistered {
        task_id: TaskId,
        committee_id: CommitteeId,
        public_program: PublicBytes,
    },
    ExecutionRequested {
        execution_id: ExecutionId,
        contract_id: ContractId,
        program_id: ProgramId,
        input_root: Commitment,
        state_root: Commitment,
    },
    CommitteeSelected {
        execution_id: ExecutionId,
        epoch: CommitteeEpoch,
        committee_id: CommitteeId,
    },
    CommitteeChanged {
        committee_id: CommitteeId,
        members: Vec<NodeId>,
        threshold: u16,
    },
    TaskCancelled {
        task_id: TaskId,
    },
}

/// 链上只保存定位和完整性元数据，不保存秘密份额或解密密钥。
pub struct DataLocationRecord {
    pub data_id: DataId,
    pub commitment: Commitment,
    pub mode: ConfidentialityMode,
    pub storage_set_root: Commitment,
    pub availability_threshold: u16,
    pub version: u64,
}

pub struct ProgramDescriptor {
    pub program_id: ProgramId,
    pub code_hash: Commitment,
    pub abi_hash: Commitment,
    pub runtime_hash: Commitment,
    pub location: PublicBytes,
}

pub struct CommitteeSelectionSubmission {
    pub execution_id: ExecutionId,
    pub epoch: CommitteeEpoch,
    pub committee_id: CommitteeId,
    pub member_root: Commitment,
    pub aggregate_proof: PublicBytes,
}

pub struct EventCursor {
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub log_index: u32,
}

pub struct ObservedEvent {
    pub cursor: EventCursor,
    pub event: ChainEvent,
}

pub struct ResultSubmission {
    pub task_id: TaskId,
    pub state_commitment: Commitment,
    pub result: PublicBytes,
    pub proof: PublicBytes,
}

pub trait ChainGateway: Send + Sync {
    fn events_after(
        &self,
        cursor: Option<&EventCursor>,
    ) -> impl Future<Output = Result<Vec<ObservedEvent>, ChainError>> + Send;
    fn submit_result(
        &self,
        submission: ResultSubmission,
    ) -> impl Future<Output = Result<[u8; 32], ChainError>> + Send;
    fn is_finalized(
        &self,
        cursor: &EventCursor,
    ) -> impl Future<Output = Result<bool, ChainError>> + Send;
    fn program(
        &self,
        program_id: ProgramId,
    ) -> impl Future<Output = Result<ProgramDescriptor, ChainError>> + Send;
    fn data_location(
        &self,
        data_id: DataId,
    ) -> impl Future<Output = Result<DataLocationRecord, ChainError>> + Send;
    fn submit_committee_selection(
        &self,
        selection: CommitteeSelectionSubmission,
    ) -> impl Future<Output = Result<[u8; 32], ChainError>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    RpcUnavailable,
    InvalidEvent,
    ContractReverted,
    TransactionRejected,
    FinalityViolation,
    UnsupportedChain,
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "chain interaction failed: {self:?}")
    }
}

impl Error for ChainError {}
