//! Event-driven implementation of the published `privateTransfer` program.
//! Program logic only sees MPC/FHE backend handles; plaintext arithmetic exists
//! exclusively inside the development `PlaintextBackend` implementation.

use super::{AssetId, ConfidentialBackend, FheAmount, PrivateAccountId, RuntimeError};
use ppsc_core::{Commitment, DataId, ExecutionId, PublicBytes};

pub struct PrivateTransferRequest {
    pub execution_id: ExecutionId,
    pub old_state_root: Commitment,
    pub sender_variable_address: [u8; 32],
    pub receiver_variable_address: [u8; 32],
    pub sender_account: PrivateAccountId,
    pub receiver_account: PrivateAccountId,
    pub asset: AssetId,
    pub sender_balance_data_id: DataId,
    pub receiver_balance_data_id: DataId,
    pub minimum_balance_data_id: DataId,
    pub amount_data_id: DataId,
}

pub struct ConfidentialTransferOutput {
    pub execution_id: ExecutionId,
    pub output_data_id: DataId,
    pub sender_ciphertext: PublicBytes,
    pub receiver_ciphertext: PublicBytes,
    pub output_commitment: Commitment,
    pub new_state_root: Commitment,
    pub transcript_root: Commitment,
    pub sender_variable_address: [u8; 32],
    pub receiver_variable_address: [u8; 32],
}

pub trait PrivateTransferEventSource: Send + Sync {
    fn next_private_transfer(&self) -> Result<Option<PrivateTransferRequest>, RuntimeError>;
}

pub trait ConfidentialValueStore: Send + Sync {
    fn load_ciphertext(&self, data_id: DataId) -> Result<PublicBytes, RuntimeError>;
    fn store_transfer_output(
        &self,
        output: &ConfidentialTransferOutput,
    ) -> Result<(), RuntimeError>;
}

pub trait PrivateTransferResultSink: Send + Sync {
    /// Production adapters create the committee attestation and call
    /// `PpscControlPlane.submitResult` with these committed fields.
    fn submit_transfer_result(
        &self,
        output: &ConfidentialTransferOutput,
    ) -> Result<(), RuntimeError>;
}

pub struct PrivateTransferProgram<B> {
    backend: B,
}

impl<B> PrivateTransferProgram<B>
where
    B: ConfidentialBackend,
{
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn evaluate(
        &self,
        request: &PrivateTransferRequest,
        sender_ciphertext: PublicBytes,
        receiver_ciphertext: PublicBytes,
        minimum_ciphertext: PublicBytes,
        amount_ciphertext: PublicBytes,
    ) -> Result<ConfidentialTransferOutput, RuntimeError> {
        let sender_ciphertext = FheAmount::from_bytes(sender_ciphertext.into_vec());
        let receiver_ciphertext = FheAmount::from_bytes(receiver_ciphertext.into_vec());
        let minimum_ciphertext = FheAmount::from_bytes(minimum_ciphertext.into_vec());
        let amount_ciphertext = FheAmount::from_bytes(amount_ciphertext.into_vec());

        // C2S: values become MPC handles. The program cannot inspect them.
        let sender = self.backend.fhe_to_mpc(&sender_ciphertext)?;
        let receiver = self.backend.fhe_to_mpc(&receiver_ciphertext)?;
        let minimum = self.backend.fhe_to_mpc(&minimum_ciphertext)?;
        let amount = self.backend.fhe_to_mpc(&amount_ciphertext)?;

        // The comparison bit and branch stay inside the MPC backend.
        let (next_sender, next_receiver) = self
            .backend
            .conditional_transfer_strictly_greater(&sender, &receiver, &minimum, &amount)?;

        // S2C: persist new encrypted balances, not opened u128 values.
        let next_sender =
            self.backend
                .mpc_to_fhe(&next_sender, request.sender_account, request.asset)?;
        let next_receiver =
            self.backend
                .mpc_to_fhe(&next_receiver, request.receiver_account, request.asset)?;
        let output_commitment = self.backend.commit(
            b"PPSC_PRIVATE_TRANSFER_OUTPUT_V1",
            &[
                request.execution_id.as_bytes(),
                &request.sender_variable_address,
                &request.receiver_variable_address,
                request.sender_balance_data_id.as_bytes(),
                request.receiver_balance_data_id.as_bytes(),
                request.minimum_balance_data_id.as_bytes(),
                request.amount_data_id.as_bytes(),
                next_sender.as_bytes(),
                next_receiver.as_bytes(),
            ],
        );
        let output_data_id = DataId::from_bytes(*output_commitment.as_bytes());
        let new_state_root = self.backend.commit(
            b"PPSC_PRIVATE_TRANSFER_STATE_V1",
            &[
                request.old_state_root.as_bytes(),
                output_commitment.as_bytes(),
                request.sender_account.as_bytes(),
                request.receiver_account.as_bytes(),
                request.asset.as_bytes(),
            ],
        );
        let transcript_root = self.backend.commit(
            b"PPSC_PRIVATE_TRANSFER_TRANSCRIPT_V1",
            &[
                request.execution_id.as_bytes(),
                request.old_state_root.as_bytes(),
                new_state_root.as_bytes(),
                b"C2S->MPC(gt,conditional_sub_add)->S2C",
            ],
        );
        Ok(ConfidentialTransferOutput {
            execution_id: request.execution_id,
            output_data_id,
            sender_ciphertext: PublicBytes::new(next_sender.as_bytes().to_vec()),
            receiver_ciphertext: PublicBytes::new(next_receiver.as_bytes().to_vec()),
            output_commitment,
            new_state_root,
            transcript_root,
            sender_variable_address: request.sender_variable_address,
            receiver_variable_address: request.receiver_variable_address,
        })
    }
}

pub struct PrivateTransferExecutor<'a, E, V, S, B> {
    events: &'a E,
    values: &'a V,
    results: &'a S,
    program: PrivateTransferProgram<B>,
}

impl<'a, E, V, S, B> PrivateTransferExecutor<'a, E, V, S, B>
where
    E: PrivateTransferEventSource,
    V: ConfidentialValueStore,
    S: PrivateTransferResultSink,
    B: ConfidentialBackend,
{
    pub fn new(events: &'a E, values: &'a V, results: &'a S, backend: B) -> Self {
        Self {
            events,
            values,
            results,
            program: PrivateTransferProgram::new(backend),
        }
    }

    pub fn poll_once(&self) -> Result<bool, RuntimeError> {
        let Some(request) = self.events.next_private_transfer()? else {
            return Ok(false);
        };
        let sender = self
            .values
            .load_ciphertext(request.sender_balance_data_id)?;
        let receiver = self
            .values
            .load_ciphertext(request.receiver_balance_data_id)?;
        let minimum = self
            .values
            .load_ciphertext(request.minimum_balance_data_id)?;
        let amount = self.values.load_ciphertext(request.amount_data_id)?;
        let output = self
            .program
            .evaluate(&request, sender, receiver, minimum, amount)?;
        self.values.store_transfer_output(&output)?;
        self.results.submit_transfer_result(&output)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FheBackend, PlaintextBackend};
    use std::{collections::BTreeMap, sync::Mutex};

    type StoredOutput = (DataId, Vec<u8>, Vec<u8>, Commitment);

    struct Fixture {
        request: Mutex<Option<PrivateTransferRequest>>,
        values: Mutex<BTreeMap<DataId, Vec<u8>>>,
        output: Mutex<Option<StoredOutput>>,
    }

    impl PrivateTransferEventSource for Fixture {
        fn next_private_transfer(&self) -> Result<Option<PrivateTransferRequest>, RuntimeError> {
            self.request
                .lock()
                .map_err(|_| RuntimeError::StateUnavailable)
                .map(|mut request| request.take())
        }
    }

    impl ConfidentialValueStore for Fixture {
        fn load_ciphertext(&self, data_id: DataId) -> Result<PublicBytes, RuntimeError> {
            self.values
                .lock()
                .map_err(|_| RuntimeError::StateUnavailable)?
                .get(&data_id)
                .map(|value| PublicBytes::new(value.clone()))
                .ok_or(RuntimeError::BalanceNotFound)
        }

        fn store_transfer_output(
            &self,
            output: &ConfidentialTransferOutput,
        ) -> Result<(), RuntimeError> {
            *self
                .output
                .lock()
                .map_err(|_| RuntimeError::StateUnavailable)? = Some((
                output.output_data_id,
                output.sender_ciphertext.as_slice().to_vec(),
                output.receiver_ciphertext.as_slice().to_vec(),
                output.new_state_root,
            ));
            Ok(())
        }
    }

    impl PrivateTransferResultSink for Fixture {
        fn submit_transfer_result(
            &self,
            output: &ConfidentialTransferOutput,
        ) -> Result<(), RuntimeError> {
            if output.output_commitment.as_bytes() != output.output_data_id.as_bytes() {
                return Err(RuntimeError::CorruptPersistence);
            }
            Ok(())
        }
    }

    fn ciphertext(value: u128, account: PrivateAccountId, asset: AssetId) -> Vec<u8> {
        PlaintextBackend
            .encrypt_amount(value, account, asset)
            .expect("encrypt fixture")
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn event_executes_confidential_private_transfer_and_submits_commitments() {
        let sender_id = DataId::from_bytes([1; 32]);
        let receiver_id = DataId::from_bytes([2; 32]);
        let minimum_id = DataId::from_bytes([3; 32]);
        let amount_id = DataId::from_bytes([4; 32]);
        let sender = PrivateAccountId::from_bytes([10; 32]);
        let receiver = PrivateAccountId::from_bytes([11; 32]);
        let asset = AssetId::from_bytes([12; 20]);
        let fixture = Fixture {
            request: Mutex::new(Some(PrivateTransferRequest {
                execution_id: ExecutionId::from_bytes([6; 32]),
                old_state_root: Commitment::from_bytes([5; 32]),
                sender_variable_address: [7; 32],
                receiver_variable_address: [8; 32],
                sender_account: sender,
                receiver_account: receiver,
                asset,
                sender_balance_data_id: sender_id,
                receiver_balance_data_id: receiver_id,
                minimum_balance_data_id: minimum_id,
                amount_data_id: amount_id,
            })),
            values: Mutex::new(BTreeMap::from([
                (sender_id, ciphertext(100, sender, asset)),
                (receiver_id, ciphertext(20, receiver, asset)),
                (minimum_id, ciphertext(50, sender, asset)),
                (amount_id, ciphertext(30, sender, asset)),
            ])),
            output: Mutex::new(None),
        };
        let executor = PrivateTransferExecutor::new(&fixture, &fixture, &fixture, PlaintextBackend);
        assert!(executor.poll_once().expect("execute event"));
        assert!(!executor.poll_once().expect("queue drained"));

        let output = fixture.output.lock().expect("output stored");
        let (_, sender_ciphertext, receiver_ciphertext, new_root) =
            output.as_ref().expect("output exists");
        assert_eq!(
            PlaintextBackend
                .decrypt_for_owner(
                    &FheAmount::from_bytes(sender_ciphertext.clone()),
                    sender,
                    PlaintextBackend::authorization_for_tests(),
                )
                .expect("open sender"),
            70
        );
        assert_eq!(
            PlaintextBackend
                .decrypt_for_owner(
                    &FheAmount::from_bytes(receiver_ciphertext.clone()),
                    receiver,
                    PlaintextBackend::authorization_for_tests(),
                )
                .expect("open receiver"),
            50
        );
        assert_ne!(new_root.as_bytes(), &[5; 32]);
    }
}
