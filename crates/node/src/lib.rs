#![doc = "节点应用编排层；所有依赖通过构造函数注入。"]

use ppsc_chain::ChainGateway;
use ppsc_crypto::CryptoProvider;
use ppsc_network::PeerTransport;
use ppsc_protocol::ProtocolEngine;
use ppsc_storage::{MessageRepository, TaskRepository};
use std::{error::Error, fmt};

pub struct NodeRuntime<C, K, P, N, T, M> {
    chain: C,
    crypto: K,
    protocol: P,
    network: N,
    tasks: T,
    messages: M,
}

impl<C, K, P, N, T, M> NodeRuntime<C, K, P, N, T, M>
where
    C: ChainGateway,
    K: CryptoProvider,
    P: ProtocolEngine,
    N: PeerTransport,
    T: TaskRepository,
    M: MessageRepository,
{
    pub fn new(chain: C, crypto: K, protocol: P, network: N, tasks: T, messages: M) -> Self {
        Self { chain, crypto, protocol, network, tasks, messages }
    }

    /// 暂为编排入口；事件循环将在适配器选型后实现。
    pub async fn run(self) -> Result<(), NodeError> {
        let _components = (
            self.chain,
            self.crypto,
            self.protocol,
            self.network,
            self.tasks,
            self.messages,
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    InvalidConfiguration,
    ChainFailure,
    ProtocolFailure,
    NetworkFailure,
    StorageFailure,
    Shutdown,
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node runtime failed: {self:?}")
    }
}

impl Error for NodeError {}

