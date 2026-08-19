#![doc = "Transport abstraction; gRPC/tonic implementations should live in adapter submodules."]

pub mod memory;

use ppsc_core::{MessageId, NodeId, ProtocolVersion, TaskId};
use ppsc_protocol::ProtocolMessage;
use std::{error::Error, fmt, future::Future};

pub struct MessageEnvelope {
    pub message_id: MessageId,
    pub task_id: TaskId,
    pub sender: NodeId,
    pub recipient: NodeId,
    pub version: ProtocolVersion,
    pub message: ProtocolMessage,
}

pub trait PeerTransport: Send + Sync {
    fn send(
        &self,
        envelope: MessageEnvelope,
    ) -> impl Future<Output = Result<(), NetworkError>> + Send;
}

pub trait IncomingMessageHandler: Send + Sync {
    fn handle(
        &self,
        envelope: MessageEnvelope,
    ) -> impl Future<Output = Result<(), NetworkError>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    Unauthenticated,
    UnauthorizedPeer,
    UnsupportedVersion,
    PayloadTooLarge,
    Timeout,
    Unavailable,
    TransportFailure,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer communication failed: {self:?}")
    }
}

impl Error for NetworkError {}
