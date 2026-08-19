#![doc = "On-chain contract port; concrete Solidity ABI/RPC implementations live in adapters."]

use ppsc_core::{
    Commitment, CommitteeEpoch, CommitteeId, ContractId, DataId, DataRepresentation, ExecutionId,
    NodeId, OperatorDomain, OwnerId, ProgramId, PublicBytes, TaskId,
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
        representation: DataRepresentation,
    },
    DataLocationsRegistered {
        data_id: DataId,
        storage_nodes: Vec<NodeId>,
        version: u64,
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

/// On-chain only location and integrity metadata are stored, never secret shares or decryption keys.
/// Paper Definition 1: public address-registry entry for one protected value.
pub struct DataReference {
    pub data_id: DataId,
    pub owner: OwnerId,
    pub commitment: Commitment,
    pub representation: DataRepresentation,
    pub public_key_set_root: Commitment,
    /// SS privacy degree `t`; zero for a replicated FHE ciphertext.
    pub threshold: u16,
    /// Required for FHE values; absent for SS values.
    pub fhe_key_reference: Option<DataId>,
    pub version: u64,
}

pub struct ContractOperator {
    pub index: u32,
    pub opcode: u32,
    pub domain: OperatorDomain,
    pub input_schema_hash: Commitment,
    pub output_schema_hash: Commitment,
    pub fhe_key_reference: Option<DataId>,
    pub conversion_parameters_hash: Option<Commitment>,
}

pub struct InvocationRequest {
    pub execution_id: ExecutionId,
    pub contract_id: ContractId,
    pub program_id: ProgramId,
    pub function_selector: [u8; 4],
    pub input_references: Vec<DataId>,
    pub nonce: u64,
}

/// Authorized opening request. The signature covers domain, chain, registry,
/// request tag, data id, recipient, nonce and expiry.
pub struct PickRequest {
    pub data_id: DataId,
    pub recipient: PublicBytes,
    pub nonce: u64,
    pub expiry: u64,
    pub owner_signature: PublicBytes,
}

pub struct OutputRegistration {
    pub execution_id: ExecutionId,
    pub output_reference: DataReference,
    pub transcript_root: Commitment,
    pub committee_attestation: PublicBytes,
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

pub struct DataHandoffSubmission {
    pub data_id: DataId,
    pub execution_id: ExecutionId,
    pub new_storage_nodes: Vec<NodeId>,
    pub new_public_key_set_root: Commitment,
    pub committee_signatures: Vec<PublicBytes>,
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
    ) -> impl Future<Output = Result<DataReference, ChainError>> + Send;
    fn submit_committee_selection(
        &self,
        selection: CommitteeSelectionSubmission,
    ) -> impl Future<Output = Result<[u8; 32], ChainError>> + Send;
    fn invocation(
        &self,
        execution_id: ExecutionId,
    ) -> impl Future<Output = Result<InvocationRequest, ChainError>> + Send;
    fn register_output(
        &self,
        output: OutputRegistration,
    ) -> impl Future<Output = Result<[u8; 32], ChainError>> + Send;
    fn pick_request(
        &self,
        data_id: DataId,
    ) -> impl Future<Output = Result<Option<PickRequest>, ChainError>> + Send;
    fn submit_data_handoff(
        &self,
        handoff: DataHandoffSubmission,
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
