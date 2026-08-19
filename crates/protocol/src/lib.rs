#![doc = "Protocol state machine, independent of network and storage implementations."]

pub mod handoff;

use ppsc_core::{
    Commitment, CommitteeEpoch, CommitteeId, ContractId, ConversionDirection, DataId, ExecutionId,
    MessageId, NodeId, OperatorDomain, ProgramId, ProtocolRound, ProtocolVersion, PublicBytes,
    TaskId, TaskStatus,
};
use ppsc_crypto::CryptoProvider;
use std::{error::Error, fmt};

pub struct ProtocolTask {
    pub id: TaskId,
    pub committee_id: CommitteeId,
    pub version: ProtocolVersion,
    pub public_program: PublicBytes,
}

pub struct ConfidentialExecution {
    pub id: ExecutionId,
    pub contract_id: ContractId,
    pub program_id: ProgramId,
    pub operator_sequence_hash: Commitment,
    pub epoch: CommitteeEpoch,
    pub round: ProtocolRound,
    pub current_committee: CommitteeId,
    pub state_root: Commitment,
    pub input_root: Commitment,
}

pub struct OperatorStep {
    pub index: u32,
    pub domain: OperatorDomain,
    pub opcode: u32,
    pub inputs: Vec<DataId>,
    pub output: DataId,
    pub fhe_key_reference: Option<DataId>,
    pub conversion: Option<ConversionDirection>,
    pub parameters_hash: Commitment,
}

/// Everything private that must cross an epoch boundary as one atomic handoff.
pub struct EpochStateManifest {
    pub execution_id: ExecutionId,
    pub epoch: CommitteeEpoch,
    pub fhe_key_shares_root: Commitment,
    pub live_value_shares_root: Commitment,
    pub mac_state_root: Commitment,
    pub unused_preprocessing_root: Commitment,
    pub transcript_root: Commitment,
}

pub struct SortitionContext {
    pub execution_id: ExecutionId,
    pub next_epoch: CommitteeEpoch,
    pub seed: [u8; 32],
    pub registry_snapshot_root: Commitment,
    pub committee_size: u16,
    pub threshold: u16,
}

pub struct ProtocolMessage {
    pub id: MessageId,
    pub task_id: TaskId,
    pub sender: NodeId,
    pub round: u32,
    pub payload: PublicBytes,
}

pub enum ProtocolAction {
    Send {
        recipient: NodeId,
        message: ProtocolMessage,
    },
    PersistCheckpoint {
        task_id: TaskId,
        state: PublicBytes,
    },
    SubmitResult {
        task_id: TaskId,
        result: PublicBytes,
        proof: PublicBytes,
    },
    FetchProgram {
        program_id: ProgramId,
        expected_hash: Commitment,
    },
    StartSortition {
        context: SortitionContext,
    },
    PublishSortitionProof {
        execution_id: ExecutionId,
        proof: PublicBytes,
    },
    BeginHandoff {
        execution_id: ExecutionId,
        from: CommitteeId,
        to: CommitteeId,
    },
    AcknowledgeHandoff {
        execution_id: ExecutionId,
        epoch: CommitteeEpoch,
        share_commitment: Commitment,
    },
    ConsumePreprocessing {
        execution_id: ExecutionId,
        preprocessing_id: DataId,
        expected_commitment: Commitment,
    },
    RegisterOutput {
        execution_id: ExecutionId,
        output: DataId,
        representation: ppsc_core::DataRepresentation,
        transcript_root: Commitment,
    },
    ReleaseAuthorizedShares {
        data_id: DataId,
        recipient: PublicBytes,
    },
    EvaluateFunction {
        execution_id: ExecutionId,
        program: PublicBytes,
        operator_sequence: Vec<OperatorStep>,
    },
    Wait,
}

pub trait ProtocolEngine: Send + Sync {
    fn initialize(
        &self,
        task: &ProtocolTask,
        crypto: &dyn CryptoProvider,
    ) -> Result<Vec<ProtocolAction>, ProtocolError>;

    fn handle_message(
        &self,
        task: &ProtocolTask,
        current_status: TaskStatus,
        message: ProtocolMessage,
        crypto: &dyn CryptoProvider,
    ) -> Result<Vec<ProtocolAction>, ProtocolError>;

    fn resume(
        &self,
        task: &ProtocolTask,
        checkpoint: &[u8],
        crypto: &dyn CryptoProvider,
    ) -> Result<Vec<ProtocolAction>, ProtocolError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidMessage,
    WrongRound,
    UnauthorizedSender,
    InvalidProgram,
    InvalidCommitteeSelection,
    HandoffNotComplete,
    MacCheckFailed,
    RangeCheckFailed,
    PreprocessingReused,
    UnauthorizedPick,
    InvalidState,
    CryptoFailure,
    Aborted,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol execution failed: {self:?}")
    }
}

impl Error for ProtocolError {}
