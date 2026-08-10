use ppsc_core::{DataId, DataRepresentation, ExecutionId, NodeId, PublicBytes, SecretBytes};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
    sync::Mutex,
};

const DEV_SS_PREFIX: &[u8] = b"PPSC_DEV_SS_V1";
const DEV_FHE_PREFIX: &[u8] = b"PPSC_DEV_FHE_V1";

pub struct SecretFragment {
    pub node: NodeId,
    pub payload: SecretBytes,
}

struct StoredObject {
    representation: DataRepresentation,
    version: u64,
    payload: Vec<u8>,
}

#[derive(Default)]
pub struct InMemoryStorageNetwork {
    nodes: Mutex<BTreeMap<NodeId, BTreeMap<DataId, StoredObject>>>,
}

impl InMemoryStorageNetwork {
    pub fn upload_secret_shares(
        &self,
        data_id: DataId,
        version: u64,
        fragments: Vec<SecretFragment>,
    ) -> Result<(), WorkflowError> {
        if fragments.is_empty() || version == 0 {
            return Err(WorkflowError::InvalidInput);
        }
        let mut nodes = self
            .nodes
            .lock()
            .map_err(|_| WorkflowError::StorageUnavailable)?;
        for fragment in fragments {
            let records = nodes.entry(fragment.node).or_default();
            if records.contains_key(&data_id) {
                return Err(WorkflowError::DataAlreadyExists);
            }
            records.insert(
                data_id,
                StoredObject {
                    representation: DataRepresentation::SecretSharing,
                    version,
                    payload: fragment.payload.expose().to_vec(),
                },
            );
        }
        Ok(())
    }

    pub fn upload_fhe_ciphertext(
        &self,
        data_id: DataId,
        version: u64,
        ciphertext: &PublicBytes,
        storage_nodes: &[NodeId],
    ) -> Result<(), WorkflowError> {
        if storage_nodes.is_empty() || version == 0 || ciphertext.as_slice().is_empty() {
            return Err(WorkflowError::InvalidInput);
        }
        let mut nodes = self
            .nodes
            .lock()
            .map_err(|_| WorkflowError::StorageUnavailable)?;
        for node in storage_nodes {
            let records = nodes.entry(*node).or_default();
            if records.contains_key(&data_id) {
                return Err(WorkflowError::DataAlreadyExists);
            }
            records.insert(
                data_id,
                StoredObject {
                    representation: DataRepresentation::Homomorphic,
                    version,
                    payload: ciphertext.as_slice().to_vec(),
                },
            );
        }
        Ok(())
    }

    pub fn locations(&self, data_id: DataId) -> Result<Vec<NodeId>, WorkflowError> {
        let nodes = self
            .nodes
            .lock()
            .map_err(|_| WorkflowError::StorageUnavailable)?;
        Ok(nodes
            .iter()
            .filter_map(|(node, records)| records.contains_key(&data_id).then_some(*node))
            .collect())
    }

    pub fn handoff(
        &self,
        data_id: DataId,
        target_nodes: &[NodeId],
        backend: &dyn WorkflowCryptoBackend,
    ) -> Result<u64, WorkflowError> {
        if target_nodes.is_empty() {
            return Err(WorkflowError::InvalidInput);
        }
        let mut nodes = self
            .nodes
            .lock()
            .map_err(|_| WorkflowError::StorageUnavailable)?;
        let sources: Vec<(DataRepresentation, u64, Vec<u8>)> = nodes
            .values()
            .filter_map(|records| {
                records.get(&data_id).map(|record| {
                    (
                        record.representation,
                        record.version,
                        record.payload.clone(),
                    )
                })
            })
            .collect();
        let first = sources.first().ok_or(WorkflowError::DataNotFound)?;
        if sources
            .iter()
            .any(|(representation, version, _)| representation != &first.0 || version != &first.1)
        {
            return Err(WorkflowError::InconsistentFragments);
        }
        let source_payloads: Vec<&[u8]> = sources
            .iter()
            .map(|(_, _, payload)| payload.as_slice())
            .collect();
        let target_payloads = backend.handoff(first.0, &source_payloads, target_nodes.len())?;
        if target_payloads.len() != target_nodes.len() {
            return Err(WorkflowError::InvalidHandoff);
        }
        let next_version = first.1.checked_add(1).ok_or(WorkflowError::Overflow)?;
        for (node, payload) in target_nodes.iter().zip(target_payloads) {
            nodes.entry(*node).or_default().insert(
                data_id,
                StoredObject {
                    representation: first.0,
                    version: next_version,
                    payload,
                },
            );
        }
        let target_set: BTreeSet<NodeId> = target_nodes.iter().copied().collect();
        for (node, records) in nodes.iter_mut() {
            if !target_set.contains(node) {
                records.remove(&data_id);
            }
        }
        Ok(next_version)
    }

    fn payloads_at(
        &self,
        data_id: DataId,
        selected_nodes: &[NodeId],
    ) -> Result<(DataRepresentation, Vec<Vec<u8>>), WorkflowError> {
        let nodes = self
            .nodes
            .lock()
            .map_err(|_| WorkflowError::StorageUnavailable)?;
        let mut representation = None;
        let mut payloads = Vec::with_capacity(selected_nodes.len());
        for node in selected_nodes {
            let record = nodes
                .get(node)
                .and_then(|records| records.get(&data_id))
                .ok_or(WorkflowError::DataNotFound)?;
            if representation.is_some_and(|current| current != record.representation) {
                return Err(WorkflowError::InconsistentFragments);
            }
            representation = Some(record.representation);
            payloads.push(record.payload.clone());
        }
        Ok((representation.ok_or(WorkflowError::DataNotFound)?, payloads))
    }
}

pub trait WorkflowCryptoBackend: Send + Sync {
    fn encode_secret_shares(
        &self,
        value: u128,
        nodes: &[NodeId],
    ) -> Result<Vec<SecretFragment>, WorkflowError>;
    fn encode_fhe(&self, value: u128) -> Result<PublicBytes, WorkflowError>;
    fn decode(
        &self,
        representation: DataRepresentation,
        payloads: &[Vec<u8>],
    ) -> Result<u128, WorkflowError>;
    fn handoff(
        &self,
        representation: DataRepresentation,
        source_payloads: &[&[u8]],
        target_count: usize,
    ) -> Result<Vec<Vec<u8>>, WorkflowError>;
}

#[derive(Default)]
pub struct PlaintextWorkflowCrypto;

impl WorkflowCryptoBackend for PlaintextWorkflowCrypto {
    fn encode_secret_shares(
        &self,
        value: u128,
        nodes: &[NodeId],
    ) -> Result<Vec<SecretFragment>, WorkflowError> {
        if nodes.is_empty() {
            return Err(WorkflowError::InvalidInput);
        }
        Ok(nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let mut payload = DEV_SS_PREFIX.to_vec();
                payload.extend_from_slice(&value.to_be_bytes());
                payload.extend_from_slice(&(index as u64).to_be_bytes());
                SecretFragment {
                    node: *node,
                    payload: SecretBytes::new(payload),
                }
            })
            .collect())
    }

    fn encode_fhe(&self, value: u128) -> Result<PublicBytes, WorkflowError> {
        let mut payload = DEV_FHE_PREFIX.to_vec();
        payload.extend_from_slice(&value.to_be_bytes());
        Ok(PublicBytes::new(payload))
    }

    fn decode(
        &self,
        representation: DataRepresentation,
        payloads: &[Vec<u8>],
    ) -> Result<u128, WorkflowError> {
        let first = payloads.first().ok_or(WorkflowError::DataNotFound)?;
        let value = match representation {
            DataRepresentation::SecretSharing => decode_prefixed_u128(first, DEV_SS_PREFIX)?,
            DataRepresentation::Homomorphic => decode_prefixed_u128(first, DEV_FHE_PREFIX)?,
        };
        for payload in payloads.iter().skip(1) {
            let other = match representation {
                DataRepresentation::SecretSharing => decode_prefixed_u128(payload, DEV_SS_PREFIX)?,
                DataRepresentation::Homomorphic => decode_prefixed_u128(payload, DEV_FHE_PREFIX)?,
            };
            if other != value {
                return Err(WorkflowError::InconsistentFragments);
            }
        }
        Ok(value)
    }

    fn handoff(
        &self,
        representation: DataRepresentation,
        source_payloads: &[&[u8]],
        target_count: usize,
    ) -> Result<Vec<Vec<u8>>, WorkflowError> {
        let owned: Vec<Vec<u8>> = source_payloads
            .iter()
            .map(|payload| payload.to_vec())
            .collect();
        let value = self.decode(representation, &owned)?;
        match representation {
            DataRepresentation::SecretSharing => Ok((0..target_count)
                .map(|index| {
                    let mut payload = DEV_SS_PREFIX.to_vec();
                    payload.extend_from_slice(&value.to_be_bytes());
                    payload.extend_from_slice(&(index as u64).to_be_bytes());
                    payload
                })
                .collect()),
            DataRepresentation::Homomorphic => {
                let ciphertext = self.encode_fhe(value)?.into_vec();
                Ok((0..target_count).map(|_| ciphertext.clone()).collect())
            }
        }
    }
}

pub trait SortitionBackend: Send + Sync {
    fn select(
        &self,
        seed: &[u8; 32],
        eligible: &[NodeId],
        committee_size: usize,
    ) -> Result<Vec<NodeId>, WorkflowError>;
}

#[derive(Default)]
pub struct DeterministicDevSortition;

impl SortitionBackend for DeterministicDevSortition {
    fn select(
        &self,
        seed: &[u8; 32],
        eligible: &[NodeId],
        committee_size: usize,
    ) -> Result<Vec<NodeId>, WorkflowError> {
        if committee_size == 0 || eligible.len() < committee_size {
            return Err(WorkflowError::InsufficientEligibleNodes);
        }
        let unique: BTreeSet<NodeId> = eligible.iter().copied().collect();
        if unique.len() != eligible.len() {
            return Err(WorkflowError::InvalidInput);
        }
        let mut ranked: Vec<([u8; 32], NodeId)> = eligible
            .iter()
            .map(|node| {
                (
                    dev_digest(b"PPSC_DEV_SORTITION", &[seed, node.as_bytes()]),
                    *node,
                )
            })
            .collect();
        ranked.sort_by_key(|entry| entry.0);
        let mut selected: Vec<NodeId> = ranked
            .into_iter()
            .take(committee_size)
            .map(|(_, node)| node)
            .collect();
        selected.sort();
        Ok(selected)
    }
}

pub enum ComputeOperation {
    SumU128,
}

pub enum RuntimeChainEvent {
    DataPublished {
        data_id: DataId,
        representation: DataRepresentation,
        storage_nodes: Vec<NodeId>,
        version: u64,
    },
    ComputeRequested {
        execution_id: ExecutionId,
        input_data_ids: Vec<DataId>,
        eligible_nodes: Vec<NodeId>,
        committee_size: usize,
        seed: [u8; 32],
        operation: ComputeOperation,
        output_representation: DataRepresentation,
    },
}

pub struct DataHandoffUpdate {
    pub execution_id: ExecutionId,
    pub data_id: DataId,
    pub old_nodes: Vec<NodeId>,
    pub new_nodes: Vec<NodeId>,
    pub new_version: u64,
}

pub struct ComputationUpdate {
    pub execution_id: ExecutionId,
    pub output_data_id: DataId,
    pub output_nodes: Vec<NodeId>,
    pub output_representation: DataRepresentation,
}

pub trait ChainEventSource: Send + Sync {
    fn next_event(&self) -> Result<Option<RuntimeChainEvent>, WorkflowError>;
}

pub trait ChainUpdateSink: Send + Sync {
    fn record_handoff(&self, update: DataHandoffUpdate) -> Result<(), WorkflowError>;
    fn record_computation(&self, update: ComputationUpdate) -> Result<(), WorkflowError>;
}

#[derive(Default)]
pub struct InMemoryChain {
    events: Mutex<VecDeque<RuntimeChainEvent>>,
    handoffs: Mutex<Vec<DataHandoffUpdate>>,
    computations: Mutex<Vec<ComputationUpdate>>,
}

impl InMemoryChain {
    pub fn push_event(&self, event: RuntimeChainEvent) -> Result<(), WorkflowError> {
        self.events
            .lock()
            .map_err(|_| WorkflowError::ChainUnavailable)?
            .push_back(event);
        Ok(())
    }

    pub fn handoff_count(&self) -> Result<usize, WorkflowError> {
        Ok(self
            .handoffs
            .lock()
            .map_err(|_| WorkflowError::ChainUnavailable)?
            .len())
    }

    pub fn computation_count(&self) -> Result<usize, WorkflowError> {
        Ok(self
            .computations
            .lock()
            .map_err(|_| WorkflowError::ChainUnavailable)?
            .len())
    }

    pub fn latest_output_id(&self) -> Result<DataId, WorkflowError> {
        self.computations
            .lock()
            .map_err(|_| WorkflowError::ChainUnavailable)?
            .last()
            .map(|update| update.output_data_id)
            .ok_or(WorkflowError::DataNotFound)
    }

    pub fn handoffs(&self) -> Result<Vec<(DataId, Vec<NodeId>)>, WorkflowError> {
        Ok(self
            .handoffs
            .lock()
            .map_err(|_| WorkflowError::ChainUnavailable)?
            .iter()
            .map(|update| (update.data_id, update.new_nodes.clone()))
            .collect())
    }
}

impl ChainEventSource for InMemoryChain {
    fn next_event(&self) -> Result<Option<RuntimeChainEvent>, WorkflowError> {
        Ok(self
            .events
            .lock()
            .map_err(|_| WorkflowError::ChainUnavailable)?
            .pop_front())
    }
}

impl ChainUpdateSink for InMemoryChain {
    fn record_handoff(&self, update: DataHandoffUpdate) -> Result<(), WorkflowError> {
        self.handoffs
            .lock()
            .map_err(|_| WorkflowError::ChainUnavailable)?
            .push(update);
        Ok(())
    }

    fn record_computation(&self, update: ComputationUpdate) -> Result<(), WorkflowError> {
        self.computations
            .lock()
            .map_err(|_| WorkflowError::ChainUnavailable)?
            .push(update);
        Ok(())
    }
}

pub struct WorkflowRuntime<'a, C, S, R, K> {
    chain: &'a C,
    storage: &'a InMemoryStorageNetwork,
    sortition: &'a S,
    crypto: &'a R,
    updates: &'a K,
}

impl<'a, C, S, R, K> WorkflowRuntime<'a, C, S, R, K>
where
    C: ChainEventSource,
    S: SortitionBackend,
    R: WorkflowCryptoBackend,
    K: ChainUpdateSink,
{
    pub fn new(
        chain: &'a C,
        storage: &'a InMemoryStorageNetwork,
        sortition: &'a S,
        crypto: &'a R,
        updates: &'a K,
    ) -> Self {
        Self {
            chain,
            storage,
            sortition,
            crypto,
            updates,
        }
    }

    pub fn poll_once(&self) -> Result<bool, WorkflowError> {
        let Some(event) = self.chain.next_event()? else {
            return Ok(false);
        };
        match event {
            RuntimeChainEvent::DataPublished {
                data_id,
                representation,
                storage_nodes,
                version,
            } => {
                let actual_nodes = self.storage.locations(data_id)?;
                if actual_nodes != storage_nodes || version == 0 {
                    return Err(WorkflowError::LocationMismatch);
                }
                let (actual_representation, _) =
                    self.storage.payloads_at(data_id, &storage_nodes)?;
                if actual_representation != representation {
                    return Err(WorkflowError::LocationMismatch);
                }
            }
            RuntimeChainEvent::ComputeRequested {
                execution_id,
                input_data_ids,
                eligible_nodes,
                committee_size,
                seed,
                operation,
                output_representation,
            } => {
                if input_data_ids.is_empty() {
                    return Err(WorkflowError::InvalidInput);
                }
                let committee = self
                    .sortition
                    .select(&seed, &eligible_nodes, committee_size)?;
                let mut values = Vec::with_capacity(input_data_ids.len());
                for data_id in &input_data_ids {
                    let old_nodes = self.storage.locations(*data_id)?;
                    let new_version = self.storage.handoff(*data_id, &committee, self.crypto)?;
                    self.updates.record_handoff(DataHandoffUpdate {
                        execution_id,
                        data_id: *data_id,
                        old_nodes,
                        new_nodes: committee.clone(),
                        new_version,
                    })?;
                    let (representation, payloads) =
                        self.storage.payloads_at(*data_id, &committee)?;
                    values.push(self.crypto.decode(representation, &payloads)?);
                }
                let output_value = match operation {
                    ComputeOperation::SumU128 => {
                        values.into_iter().try_fold(0_u128, |sum, value| {
                            sum.checked_add(value).ok_or(WorkflowError::Overflow)
                        })?
                    }
                };
                let output_id = DataId::from_bytes(dev_digest(
                    b"PPSC_DEV_OUTPUT_ID",
                    &[
                        execution_id.as_bytes(),
                        &output_value.to_be_bytes(),
                        &[match output_representation {
                            DataRepresentation::SecretSharing => 0,
                            DataRepresentation::Homomorphic => 1,
                        }],
                    ],
                ));
                match output_representation {
                    DataRepresentation::SecretSharing => self.storage.upload_secret_shares(
                        output_id,
                        1,
                        self.crypto.encode_secret_shares(output_value, &committee)?,
                    )?,
                    DataRepresentation::Homomorphic => self.storage.upload_fhe_ciphertext(
                        output_id,
                        1,
                        &self.crypto.encode_fhe(output_value)?,
                        &committee,
                    )?,
                }
                self.updates.record_computation(ComputationUpdate {
                    execution_id,
                    output_data_id: output_id,
                    output_nodes: committee,
                    output_representation,
                })?;
            }
        }
        Ok(true)
    }

    pub fn run_until_idle(&self) -> Result<usize, WorkflowError> {
        let mut handled = 0;
        while self.poll_once()? {
            handled += 1;
        }
        Ok(handled)
    }
}

fn decode_prefixed_u128(payload: &[u8], prefix: &[u8]) -> Result<u128, WorkflowError> {
    if payload.len() < prefix.len() + 16 || !payload.starts_with(prefix) {
        return Err(WorkflowError::InvalidEncoding);
    }
    let bytes: [u8; 16] = payload[prefix.len()..prefix.len() + 16]
        .try_into()
        .map_err(|_| WorkflowError::InvalidEncoding)?;
    Ok(u128::from_be_bytes(bytes))
}

fn dev_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for lane in 0..4_u64 {
        let mut state = 0xcbf29ce484222325_u64 ^ lane;
        for byte in domain
            .iter()
            .copied()
            .chain(parts.iter().flat_map(|part| part.iter().copied()))
        {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x100000001b3);
        }
        output[(lane as usize) * 8..(lane as usize + 1) * 8].copy_from_slice(&state.to_be_bytes());
    }
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowError {
    InvalidInput,
    InvalidEncoding,
    DataAlreadyExists,
    DataNotFound,
    StorageUnavailable,
    ChainUnavailable,
    InconsistentFragments,
    InvalidHandoff,
    InsufficientEligibleNodes,
    LocationMismatch,
    Overflow,
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "runtime workflow failed: {self:?}")
    }
}

impl Error for WorkflowError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(value: u8) -> NodeId {
        NodeId::from_bytes([value; 32])
    }

    #[test]
    fn ss_and_fhe_publish_sortition_handoff_compute_and_location_update() {
        let chain = InMemoryChain::default();
        let storage = InMemoryStorageNetwork::default();
        let crypto = PlaintextWorkflowCrypto;
        let sortition = DeterministicDevSortition;
        let ss_id = DataId::from_bytes([1_u8; 32]);
        let fhe_id = DataId::from_bytes([2_u8; 32]);
        let ss_nodes = vec![node(1), node(2), node(3)];
        let fhe_nodes = vec![node(4), node(5)];
        let eligible = vec![node(6), node(7), node(8), node(9)];

        storage
            .upload_secret_shares(
                ss_id,
                1,
                crypto
                    .encode_secret_shares(40, &ss_nodes)
                    .expect("encode ss"),
            )
            .expect("upload ss");
        storage
            .upload_fhe_ciphertext(
                fhe_id,
                1,
                &crypto.encode_fhe(60).expect("encode fhe"),
                &fhe_nodes,
            )
            .expect("upload fhe");
        chain
            .push_event(RuntimeChainEvent::DataPublished {
                data_id: ss_id,
                representation: DataRepresentation::SecretSharing,
                storage_nodes: ss_nodes,
                version: 1,
            })
            .expect("ss event");
        chain
            .push_event(RuntimeChainEvent::DataPublished {
                data_id: fhe_id,
                representation: DataRepresentation::Homomorphic,
                storage_nodes: fhe_nodes,
                version: 1,
            })
            .expect("fhe event");
        chain
            .push_event(RuntimeChainEvent::ComputeRequested {
                execution_id: ExecutionId::from_bytes([3_u8; 32]),
                input_data_ids: vec![ss_id, fhe_id],
                eligible_nodes: eligible,
                committee_size: 3,
                seed: [4_u8; 32],
                operation: ComputeOperation::SumU128,
                output_representation: DataRepresentation::Homomorphic,
            })
            .expect("compute event");

        let runtime = WorkflowRuntime::new(&chain, &storage, &sortition, &crypto, &chain);
        assert_eq!(runtime.run_until_idle().expect("run workflow"), 3);
        assert_eq!(chain.handoff_count().expect("handoffs"), 2);
        assert_eq!(chain.computation_count().expect("computations"), 1);
        for (data_id, recorded_nodes) in chain.handoffs().expect("handoff updates") {
            assert!(storage.locations(data_id).expect("active locations") == recorded_nodes);
        }

        let output_id = chain.latest_output_id().expect("output id");
        let output_nodes = storage.locations(output_id).expect("output locations");
        let (representation, payloads) = storage
            .payloads_at(output_id, &output_nodes)
            .expect("output payloads");
        assert_eq!(representation, DataRepresentation::Homomorphic);
        assert_eq!(
            crypto.decode(representation, &payloads).expect("decode"),
            100
        );
    }
}
