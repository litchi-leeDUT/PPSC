#![doc = "持久化端口；数据库实现不得记录或打印敏感载荷。"]

use ppsc_core::{
    CommitteeEpoch, Commitment, ConfidentialityMode, DataId, MessageId, NodeId, PublicBytes,
    SecretBytes, TaskId, TaskStatus,
};
use ppsc_protocol::{ProtocolMessage, ProtocolTask};
use std::{error::Error, fmt, future::Future};

pub struct StoredTask {
    pub task: ProtocolTask,
    pub status: TaskStatus,
    pub checkpoint: Option<PublicBytes>,
}

pub trait TaskRepository: Send + Sync {
    fn insert(&self, task: ProtocolTask)
        -> impl Future<Output = Result<(), StorageError>> + Send;
    fn get(
        &self,
        id: TaskId,
    ) -> impl Future<Output = Result<Option<StoredTask>, StorageError>> + Send;
    fn transition(
        &self,
        id: TaskId,
        expected: TaskStatus,
        next: TaskStatus,
        checkpoint: Option<PublicBytes>,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

pub trait MessageRepository: Send + Sync {
    fn append_if_absent(
        &self,
        message: ProtocolMessage,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    fn contains(
        &self,
        id: MessageId,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
}

pub trait SecretStore: Send + Sync {
    fn put(
        &self,
        task_id: TaskId,
        value: SecretBytes,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    fn take(
        &self,
        task_id: TaskId,
    ) -> impl Future<Output = Result<Option<SecretBytes>, StorageError>> + Send;
}

pub struct StoredFragment {
    pub data_id: DataId,
    pub mode: ConfidentialityMode,
    pub version: u64,
    pub commitment: Commitment,
    pub custodian: NodeId,
    pub payload: SecretBytes,
}

pub struct FragmentMetadata {
    pub data_id: DataId,
    pub mode: ConfidentialityMode,
    pub version: u64,
    pub commitment: Commitment,
    pub custodian: NodeId,
    pub epoch: CommitteeEpoch,
}

/// 每个节点只处理发给自己的份额或允许复制的密文。
pub trait FragmentRepository: Send + Sync {
    fn put_if_newer(
        &self,
        fragment: StoredFragment,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    fn metadata(
        &self,
        data_id: DataId,
    ) -> impl Future<Output = Result<Option<FragmentMetadata>, StorageError>> + Send;
    fn take(
        &self,
        data_id: DataId,
        version: u64,
    ) -> impl Future<Output = Result<Option<SecretBytes>, StorageError>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    NotFound,
    Conflict,
    InvalidTransition,
    CorruptData,
    Unavailable,
    BackendFailure,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage operation failed: {self:?}")
    }
}

impl Error for StorageError {}
