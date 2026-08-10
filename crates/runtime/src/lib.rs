#![doc = "PPSC execution runtime with pluggable MPC/FHE backends."]

use ppsc_core::{Commitment, DataId, PublicBytes, SecretBytes};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::Mutex,
};

pub mod postgres;
pub mod private_transfer;
pub mod workflow;

const DEV_FHE_PREFIX: &[u8] = b"PPSC_DEV_PLAINTEXT_FHE_V1";
const DEV_AUTHORIZATION: &[u8] = b"dev-authorized";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrivateAccountId([u8; 32]);

impl PrivateAccountId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetId([u8; 20]);

impl AssetId {
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

/// MPC value wrapper. Intentionally has no Debug/Display/Clone.
pub struct MpcAmount(SecretBytes);

impl MpcAmount {
    fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBytes::new(bytes))
    }

    fn expose_to_backend(&self) -> &[u8] {
        self.0.expose()
    }
}

/// FHE ciphertext wrapper. The development backend stores plaintext internally,
/// but production implementations must replace it with a real ciphertext.
pub struct FheAmount(PublicBytes);

impl FheAmount {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(PublicBytes::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub trait MpcBackend: Send + Sync {
    fn share_amount(&self, amount: u128) -> Result<MpcAmount, BackendError>;
    fn checked_add(&self, left: &MpcAmount, right: &MpcAmount) -> Result<MpcAmount, BackendError>;
    fn checked_sub(&self, left: &MpcAmount, right: &MpcAmount) -> Result<MpcAmount, BackendError>;
    fn greater_than_or_equal(
        &self,
        left: &MpcAmount,
        right: &MpcAmount,
    ) -> Result<bool, BackendError>;

    /// Compares and conditionally updates both balances inside the MPC backend.
    /// A production implementation must not reveal the comparison bit.
    fn conditional_transfer_strictly_greater(
        &self,
        sender: &MpcAmount,
        receiver: &MpcAmount,
        minimum: &MpcAmount,
        amount: &MpcAmount,
    ) -> Result<(MpcAmount, MpcAmount), BackendError>;
}

pub trait FheBackend: Send + Sync {
    fn encrypt_amount(
        &self,
        amount: u128,
        account: PrivateAccountId,
        asset: AssetId,
    ) -> Result<FheAmount, BackendError>;

    fn decrypt_for_owner(
        &self,
        ciphertext: &FheAmount,
        account: PrivateAccountId,
        authorization: &[u8],
    ) -> Result<u128, BackendError>;
}

pub trait HybridConversionBackend: Send + Sync {
    fn fhe_to_mpc(&self, ciphertext: &FheAmount) -> Result<MpcAmount, BackendError>;
    fn mpc_to_fhe(
        &self,
        value: &MpcAmount,
        account: PrivateAccountId,
        asset: AssetId,
    ) -> Result<FheAmount, BackendError>;
}

pub trait CommitmentBackend: Send + Sync {
    fn commit(&self, domain: &[u8], parts: &[&[u8]]) -> Commitment;
}

pub trait ConfidentialBackend:
    MpcBackend + FheBackend + HybridConversionBackend + CommitmentBackend
{
}

impl<T> ConfidentialBackend for T where
    T: MpcBackend + FheBackend + HybridConversionBackend + CommitmentBackend
{
}

/// Development-only backend. It performs every operation on plaintext u128 values.
/// It must never be enabled in a public or production deployment.
#[derive(Default)]
pub struct PlaintextBackend;

impl PlaintextBackend {
    pub const fn authorization_for_tests() -> &'static [u8] {
        DEV_AUTHORIZATION
    }

    fn encode_secret(amount: u128) -> MpcAmount {
        MpcAmount::new(amount.to_be_bytes().to_vec())
    }

    fn decode_secret(value: &MpcAmount) -> Result<u128, BackendError> {
        decode_u128(value.expose_to_backend())
    }

    fn encode_ciphertext(amount: u128) -> FheAmount {
        let mut encoded = Vec::with_capacity(DEV_FHE_PREFIX.len() + 16);
        encoded.extend_from_slice(DEV_FHE_PREFIX);
        encoded.extend_from_slice(&amount.to_be_bytes());
        FheAmount::from_bytes(encoded)
    }

    fn decode_ciphertext(value: &FheAmount) -> Result<u128, BackendError> {
        let bytes = value.as_bytes();
        if bytes.len() != DEV_FHE_PREFIX.len() + 16 || !bytes.starts_with(DEV_FHE_PREFIX) {
            return Err(BackendError::InvalidCiphertext);
        }
        decode_u128(&bytes[DEV_FHE_PREFIX.len()..])
    }
}

impl MpcBackend for PlaintextBackend {
    fn share_amount(&self, amount: u128) -> Result<MpcAmount, BackendError> {
        Ok(Self::encode_secret(amount))
    }

    fn checked_add(&self, left: &MpcAmount, right: &MpcAmount) -> Result<MpcAmount, BackendError> {
        let value = Self::decode_secret(left)?
            .checked_add(Self::decode_secret(right)?)
            .ok_or(BackendError::Overflow)?;
        Ok(Self::encode_secret(value))
    }

    fn checked_sub(&self, left: &MpcAmount, right: &MpcAmount) -> Result<MpcAmount, BackendError> {
        let value = Self::decode_secret(left)?
            .checked_sub(Self::decode_secret(right)?)
            .ok_or(BackendError::InsufficientBalance)?;
        Ok(Self::encode_secret(value))
    }

    fn greater_than_or_equal(
        &self,
        left: &MpcAmount,
        right: &MpcAmount,
    ) -> Result<bool, BackendError> {
        Ok(Self::decode_secret(left)? >= Self::decode_secret(right)?)
    }

    fn conditional_transfer_strictly_greater(
        &self,
        sender: &MpcAmount,
        receiver: &MpcAmount,
        minimum: &MpcAmount,
        amount: &MpcAmount,
    ) -> Result<(MpcAmount, MpcAmount), BackendError> {
        let sender = Self::decode_secret(sender)?;
        let receiver = Self::decode_secret(receiver)?;
        let minimum = Self::decode_secret(minimum)?;
        let amount = Self::decode_secret(amount)?;
        if sender <= minimum {
            return Ok((Self::encode_secret(sender), Self::encode_secret(receiver)));
        }
        let next_sender = sender
            .checked_sub(amount)
            .ok_or(BackendError::InsufficientBalance)?;
        let next_receiver = receiver.checked_add(amount).ok_or(BackendError::Overflow)?;
        Ok((
            Self::encode_secret(next_sender),
            Self::encode_secret(next_receiver),
        ))
    }
}

impl FheBackend for PlaintextBackend {
    fn encrypt_amount(
        &self,
        amount: u128,
        _account: PrivateAccountId,
        _asset: AssetId,
    ) -> Result<FheAmount, BackendError> {
        Ok(Self::encode_ciphertext(amount))
    }

    fn decrypt_for_owner(
        &self,
        ciphertext: &FheAmount,
        _account: PrivateAccountId,
        authorization: &[u8],
    ) -> Result<u128, BackendError> {
        if authorization != DEV_AUTHORIZATION {
            return Err(BackendError::Unauthorized);
        }
        Self::decode_ciphertext(ciphertext)
    }
}

impl HybridConversionBackend for PlaintextBackend {
    fn fhe_to_mpc(&self, ciphertext: &FheAmount) -> Result<MpcAmount, BackendError> {
        Ok(Self::encode_secret(Self::decode_ciphertext(ciphertext)?))
    }

    fn mpc_to_fhe(
        &self,
        value: &MpcAmount,
        _account: PrivateAccountId,
        _asset: AssetId,
    ) -> Result<FheAmount, BackendError> {
        Ok(Self::encode_ciphertext(Self::decode_secret(value)?))
    }
}

impl CommitmentBackend for PlaintextBackend {
    fn commit(&self, domain: &[u8], parts: &[&[u8]]) -> Commitment {
        // Deterministic development digest, deliberately not cryptographic.
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
            output[(lane as usize) * 8..(lane as usize + 1) * 8]
                .copy_from_slice(&state.to_be_bytes());
        }
        Commitment::from_bytes(output)
    }
}

pub struct DepositCommand {
    pub deposit_id: [u8; 32],
    pub account: PrivateAccountId,
    pub asset: AssetId,
    pub amount: u128,
    pub expected_old_state_root: Commitment,
}

pub struct WithdrawalCommand {
    pub nullifier: [u8; 32],
    pub account: PrivateAccountId,
    pub asset: AssetId,
    pub gross_amount: u128,
    pub expected_old_state_root: Commitment,
}

pub struct StateTransition {
    pub new_state_root: Commitment,
    pub encrypted_balance_data_id: DataId,
    pub transcript_root: Commitment,
    pub version: u64,
}

pub struct EncryptedBalanceView {
    pub data_id: DataId,
    pub ciphertext: PublicBytes,
    pub state_root: Commitment,
    pub version: u64,
}

struct BalanceRecord {
    ciphertext: FheAmount,
    data_id: DataId,
    version: u64,
}

struct RuntimeState {
    state_root: Commitment,
    balances: BTreeMap<(PrivateAccountId, AssetId), BalanceRecord>,
    processed_deposits: BTreeSet<[u8; 32]>,
    spent_nullifiers: BTreeSet<[u8; 32]>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            state_root: Commitment::from_bytes([0_u8; 32]),
            balances: BTreeMap::new(),
            processed_deposits: BTreeSet::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }
}

pub trait BalanceRuntimeApi {
    fn credit_deposit(&self, command: DepositCommand) -> Result<StateTransition, RuntimeError>;
    fn debit_withdrawal(&self, command: WithdrawalCommand)
        -> Result<StateTransition, RuntimeError>;
    fn encrypted_balance(
        &self,
        account: PrivateAccountId,
        asset: AssetId,
    ) -> Result<EncryptedBalanceView, RuntimeError>;
    fn open_balance_for_owner(
        &self,
        account: PrivateAccountId,
        asset: AssetId,
        authorization: &[u8],
    ) -> Result<u128, RuntimeError>;
    fn state_root(&self) -> Result<Commitment, RuntimeError>;
}

pub struct BalanceRuntime<B> {
    backend: B,
    state: Mutex<RuntimeState>,
}

impl<B> BalanceRuntime<B>
where
    B: ConfidentialBackend,
{
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            state: Mutex::new(RuntimeState::default()),
        }
    }

    fn next_record(
        &self,
        old_root: Commitment,
        account: PrivateAccountId,
        asset: AssetId,
        ciphertext: FheAmount,
        version: u64,
    ) -> (BalanceRecord, Commitment, Commitment) {
        let version_bytes = version.to_be_bytes();
        let new_root = self.backend.commit(
            b"PPSC_RUNTIME_STATE_V1",
            &[
                old_root.as_bytes(),
                account.as_bytes(),
                asset.as_bytes(),
                ciphertext.as_bytes(),
                &version_bytes,
            ],
        );
        let data_commitment = self.backend.commit(
            b"PPSC_BALANCE_DATA_V1",
            &[
                account.as_bytes(),
                asset.as_bytes(),
                ciphertext.as_bytes(),
                &version_bytes,
            ],
        );
        let data_id = DataId::from_bytes(*data_commitment.as_bytes());
        let transcript = self.backend.commit(
            b"PPSC_RUNTIME_TRANSCRIPT_V1",
            &[old_root.as_bytes(), new_root.as_bytes(), data_id.as_bytes()],
        );
        (
            BalanceRecord {
                ciphertext,
                data_id,
                version,
            },
            new_root,
            transcript,
        )
    }
}

impl<B> BalanceRuntimeApi for BalanceRuntime<B>
where
    B: ConfidentialBackend,
{
    fn credit_deposit(&self, command: DepositCommand) -> Result<StateTransition, RuntimeError> {
        if command.amount == 0 {
            return Err(RuntimeError::InvalidAmount);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::StateUnavailable)?;
        if state.state_root != command.expected_old_state_root {
            return Err(RuntimeError::StaleStateRoot);
        }
        if state.processed_deposits.contains(&command.deposit_id) {
            return Err(RuntimeError::DepositAlreadyProcessed);
        }

        let key = (command.account, command.asset);
        let (ciphertext, version) = match state.balances.get(&key) {
            Some(current) => {
                let current_value = self.backend.fhe_to_mpc(&current.ciphertext)?;
                let deposit_value = self.backend.share_amount(command.amount)?;
                let next_value = self.backend.checked_add(&current_value, &deposit_value)?;
                (
                    self.backend
                        .mpc_to_fhe(&next_value, command.account, command.asset)?,
                    current.version + 1,
                )
            }
            None => (
                self.backend
                    .encrypt_amount(command.amount, command.account, command.asset)?,
                1,
            ),
        };

        let (record, new_root, transcript_root) = self.next_record(
            state.state_root,
            command.account,
            command.asset,
            ciphertext,
            version,
        );
        let data_id = record.data_id;
        state.balances.insert(key, record);
        state.processed_deposits.insert(command.deposit_id);
        state.state_root = new_root;
        Ok(StateTransition {
            new_state_root: new_root,
            encrypted_balance_data_id: data_id,
            transcript_root,
            version,
        })
    }

    fn debit_withdrawal(
        &self,
        command: WithdrawalCommand,
    ) -> Result<StateTransition, RuntimeError> {
        if command.gross_amount == 0 {
            return Err(RuntimeError::InvalidAmount);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::StateUnavailable)?;
        if state.state_root != command.expected_old_state_root {
            return Err(RuntimeError::StaleStateRoot);
        }
        if state.spent_nullifiers.contains(&command.nullifier) {
            return Err(RuntimeError::NullifierAlreadySpent);
        }

        let key = (command.account, command.asset);
        let current = state
            .balances
            .get(&key)
            .ok_or(RuntimeError::BalanceNotFound)?;
        let current_value = self.backend.fhe_to_mpc(&current.ciphertext)?;
        let debit_value = self.backend.share_amount(command.gross_amount)?;
        if !self
            .backend
            .greater_than_or_equal(&current_value, &debit_value)?
        {
            return Err(RuntimeError::InsufficientBalance);
        }
        let next_value = self.backend.checked_sub(&current_value, &debit_value)?;
        let ciphertext = self
            .backend
            .mpc_to_fhe(&next_value, command.account, command.asset)?;
        let version = current.version + 1;
        let (record, new_root, transcript_root) = self.next_record(
            state.state_root,
            command.account,
            command.asset,
            ciphertext,
            version,
        );
        let data_id = record.data_id;
        state.balances.insert(key, record);
        state.spent_nullifiers.insert(command.nullifier);
        state.state_root = new_root;
        Ok(StateTransition {
            new_state_root: new_root,
            encrypted_balance_data_id: data_id,
            transcript_root,
            version,
        })
    }

    fn encrypted_balance(
        &self,
        account: PrivateAccountId,
        asset: AssetId,
    ) -> Result<EncryptedBalanceView, RuntimeError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::StateUnavailable)?;
        let record = state
            .balances
            .get(&(account, asset))
            .ok_or(RuntimeError::BalanceNotFound)?;
        Ok(EncryptedBalanceView {
            data_id: record.data_id,
            ciphertext: PublicBytes::new(record.ciphertext.as_bytes().to_vec()),
            state_root: state.state_root,
            version: record.version,
        })
    }

    fn open_balance_for_owner(
        &self,
        account: PrivateAccountId,
        asset: AssetId,
        authorization: &[u8],
    ) -> Result<u128, RuntimeError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::StateUnavailable)?;
        let record = state
            .balances
            .get(&(account, asset))
            .ok_or(RuntimeError::BalanceNotFound)?;
        Ok(self
            .backend
            .decrypt_for_owner(&record.ciphertext, account, authorization)?)
    }

    fn state_root(&self) -> Result<Commitment, RuntimeError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::StateUnavailable)?;
        Ok(state.state_root)
    }
}

fn decode_u128(bytes: &[u8]) -> Result<u128, BackendError> {
    let encoded: [u8; 16] = bytes
        .try_into()
        .map_err(|_| BackendError::InvalidEncoding)?;
    Ok(u128::from_be_bytes(encoded))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    InvalidEncoding,
    InvalidCiphertext,
    Unauthorized,
    Overflow,
    InsufficientBalance,
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "confidential backend failed: {self:?}")
    }
}

impl Error for BackendError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeError {
    InvalidAmount,
    StaleStateRoot,
    DepositAlreadyProcessed,
    NullifierAlreadySpent,
    BalanceNotFound,
    InsufficientBalance,
    Unauthorized,
    StateUnavailable,
    PersistenceFailure,
    CorruptPersistence,
    Backend(BackendError),
}

impl From<BackendError> for RuntimeError {
    fn from(value: BackendError) -> Self {
        match value {
            BackendError::InsufficientBalance => Self::InsufficientBalance,
            BackendError::Unauthorized => Self::Unauthorized,
            other => Self::Backend(other),
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "runtime operation failed: {self:?}")
    }
}

impl Error for RuntimeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> PrivateAccountId {
        PrivateAccountId::from_bytes([7_u8; 32])
    }

    fn asset() -> AssetId {
        AssetId::from_bytes([9_u8; 20])
    }

    #[test]
    fn deposit_query_and_withdrawal_flow() {
        let runtime = BalanceRuntime::new(PlaintextBackend);
        let initial_root = runtime.state_root().expect("initial state");
        let deposit = runtime
            .credit_deposit(DepositCommand {
                deposit_id: [1_u8; 32],
                account: account(),
                asset: asset(),
                amount: 100,
                expected_old_state_root: initial_root,
            })
            .expect("deposit");
        assert_eq!(deposit.version, 1);

        let encrypted = runtime
            .encrypted_balance(account(), asset())
            .expect("encrypted balance");
        assert_eq!(encrypted.version, 1);
        assert!(!encrypted.ciphertext.as_slice().is_empty());
        assert_eq!(
            runtime
                .open_balance_for_owner(
                    account(),
                    asset(),
                    PlaintextBackend::authorization_for_tests(),
                )
                .expect("open balance"),
            100
        );

        let withdrawal = runtime
            .debit_withdrawal(WithdrawalCommand {
                nullifier: [2_u8; 32],
                account: account(),
                asset: asset(),
                gross_amount: 40,
                expected_old_state_root: deposit.new_state_root,
            })
            .expect("withdrawal");
        assert_eq!(withdrawal.version, 2);
        assert_eq!(
            runtime
                .open_balance_for_owner(
                    account(),
                    asset(),
                    PlaintextBackend::authorization_for_tests(),
                )
                .expect("remaining balance"),
            60
        );
    }

    #[test]
    fn rejects_stale_root_and_replayed_nullifier() {
        let runtime = BalanceRuntime::new(PlaintextBackend);
        let initial_root = runtime.state_root().expect("initial state");
        let deposit = runtime
            .credit_deposit(DepositCommand {
                deposit_id: [3_u8; 32],
                account: account(),
                asset: asset(),
                amount: 50,
                expected_old_state_root: initial_root,
            })
            .expect("deposit");

        let stale = runtime.credit_deposit(DepositCommand {
            deposit_id: [4_u8; 32],
            account: account(),
            asset: asset(),
            amount: 1,
            expected_old_state_root: initial_root,
        });
        assert!(matches!(stale, Err(RuntimeError::StaleStateRoot)));

        let withdrawal = runtime
            .debit_withdrawal(WithdrawalCommand {
                nullifier: [5_u8; 32],
                account: account(),
                asset: asset(),
                gross_amount: 10,
                expected_old_state_root: deposit.new_state_root,
            })
            .expect("first withdrawal");
        let replay = runtime.debit_withdrawal(WithdrawalCommand {
            nullifier: [5_u8; 32],
            account: account(),
            asset: asset(),
            gross_amount: 10,
            expected_old_state_root: withdrawal.new_state_root,
        });
        assert!(matches!(replay, Err(RuntimeError::NullifierAlreadySpent)));
    }

    #[test]
    fn rejects_unauthorized_plaintext_open() {
        let runtime = BalanceRuntime::new(PlaintextBackend);
        let initial_root = runtime.state_root().expect("initial state");
        runtime
            .credit_deposit(DepositCommand {
                deposit_id: [6_u8; 32],
                account: account(),
                asset: asset(),
                amount: 12,
                expected_old_state_root: initial_root,
            })
            .expect("deposit");
        let result = runtime.open_balance_for_owner(account(), asset(), b"wrong");
        assert!(matches!(result, Err(RuntimeError::Unauthorized)));
    }

    #[test]
    fn conditional_transfer_keeps_balances_when_sender_is_not_above_minimum() {
        let backend = PlaintextBackend;
        let sender = backend.share_amount(40).expect("sender share");
        let receiver = backend.share_amount(20).expect("receiver share");
        let minimum = backend.share_amount(50).expect("minimum share");
        let amount = backend.share_amount(30).expect("amount share");
        let (next_sender, next_receiver) = backend
            .conditional_transfer_strictly_greater(&sender, &receiver, &minimum, &amount)
            .expect("conditional transfer");
        assert_eq!(
            PlaintextBackend::decode_secret(&next_sender).expect("sender value"),
            40
        );
        assert_eq!(
            PlaintextBackend::decode_secret(&next_receiver).expect("receiver value"),
            20
        );
    }
}
