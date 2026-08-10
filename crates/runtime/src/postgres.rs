//! PostgreSQL-backed runtime state. Each balance transition, replay marker and
//! global state-root compare-and-set is committed in one database transaction.

use super::{
    AssetId, BalanceRuntimeApi, ConfidentialBackend, DepositCommand, EncryptedBalanceView,
    FheAmount, PrivateAccountId, RuntimeError, StateTransition, TransferCommand,
    TransferTransition, WithdrawalCommand,
};
use postgres::{Client, NoTls, Transaction};
use ppsc_core::{Commitment, DataId, PublicBytes};
use std::sync::Mutex;

const MIGRATION: &str = include_str!("../migrations/0001_runtime.sql");

/// Owns the synchronous PostgreSQL connection used by a runtime instance.
/// Multiple runtime processes can safely share the same database: the singleton
/// state-root row serializes transitions and supplies optimistic concurrency.
pub struct PostgresRuntimeRepository {
    client: Mutex<Client>,
}

impl PostgresRuntimeRepository {
    pub fn connect(database_url: &str) -> Result<Self, RuntimeError> {
        let client = Client::connect(database_url, NoTls).map_err(db_error)?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }

    pub fn migrate(&self) -> Result<(), RuntimeError> {
        self.client
            .lock()
            .map_err(|_| RuntimeError::StateUnavailable)?
            .batch_execute(MIGRATION)
            .map_err(db_error)
    }

    fn transaction<T>(
        &self,
        operation: impl FnOnce(&mut Transaction<'_>) -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| RuntimeError::StateUnavailable)?;
        let mut transaction = client.transaction().map_err(db_error)?;
        let result = operation(&mut transaction)?;
        transaction.commit().map_err(db_error)?;
        Ok(result)
    }
}

/// Persistent equivalent of `BalanceRuntime`.
pub struct PostgresBalanceRuntime<B> {
    backend: B,
    repository: PostgresRuntimeRepository,
}

impl<B> PostgresBalanceRuntime<B>
where
    B: ConfidentialBackend,
{
    pub fn connect(database_url: &str, backend: B) -> Result<Self, RuntimeError> {
        let repository = PostgresRuntimeRepository::connect(database_url)?;
        repository.migrate()?;
        Ok(Self {
            backend,
            repository,
        })
    }

    pub fn from_repository(backend: B, repository: PostgresRuntimeRepository) -> Self {
        Self {
            backend,
            repository,
        }
    }

    fn derive_transition(
        &self,
        old_root: Commitment,
        account: PrivateAccountId,
        asset: AssetId,
        ciphertext: &FheAmount,
        version: u64,
    ) -> (DataId, Commitment, Commitment) {
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
        (data_id, new_root, transcript)
    }

    fn locked_root(transaction: &mut Transaction<'_>) -> Result<Commitment, RuntimeError> {
        let row = transaction
            .query_one(
                "SELECT state_root FROM ppsc_runtime_meta WHERE singleton = TRUE FOR UPDATE",
                &[],
            )
            .map_err(db_error)?;
        commitment_from_vec(row.get(0))
    }

    fn current_balance(
        transaction: &mut Transaction<'_>,
        account: PrivateAccountId,
        asset: AssetId,
    ) -> Result<Option<(FheAmount, u64)>, RuntimeError> {
        let row = transaction
            .query_opt(
                "SELECT ciphertext, version FROM ppsc_balance_records \
                 WHERE account_id = $1 AND asset_id = $2 FOR UPDATE",
                &[&account.as_bytes().as_slice(), &asset.as_bytes().as_slice()],
            )
            .map_err(db_error)?;
        row.map(|row| {
            let version: i64 = row.get(1);
            let version = u64::try_from(version).map_err(|_| RuntimeError::CorruptPersistence)?;
            Ok((FheAmount::from_bytes(row.get(0)), version))
        })
        .transpose()
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_transition(
        transaction: &mut Transaction<'_>,
        kind: &str,
        operation_id: &[u8; 32],
        account: PrivateAccountId,
        asset: AssetId,
        amount: u128,
        old_root: Commitment,
        ciphertext: &FheAmount,
        data_id: DataId,
        new_root: Commitment,
        transcript_root: Commitment,
        version: u64,
    ) -> Result<(), RuntimeError> {
        let version = i64::try_from(version).map_err(|_| RuntimeError::CorruptPersistence)?;
        transaction
            .execute(
                "INSERT INTO ppsc_balance_records \
                 (account_id, asset_id, data_id, version, ciphertext) VALUES ($1,$2,$3,$4,$5) \
                 ON CONFLICT (account_id, asset_id) DO UPDATE SET \
                 data_id=EXCLUDED.data_id, version=EXCLUDED.version, \
                 ciphertext=EXCLUDED.ciphertext, updated_at=now()",
                &[
                    &account.as_bytes().as_slice(),
                    &asset.as_bytes().as_slice(),
                    &data_id.as_bytes().as_slice(),
                    &version,
                    &ciphertext.as_bytes(),
                ],
            )
            .map_err(db_error)?;

        let marker_sql = if kind == "deposit" {
            "INSERT INTO ppsc_processed_deposits \
             (deposit_id, account_id, asset_id, amount_be, resulting_state_root) \
             VALUES ($1,$2,$3,$4,$5)"
        } else {
            "INSERT INTO ppsc_spent_nullifiers \
             (nullifier, account_id, asset_id, amount_be, resulting_state_root) \
             VALUES ($1,$2,$3,$4,$5)"
        };
        transaction
            .execute(
                marker_sql,
                &[
                    &operation_id.as_slice(),
                    &account.as_bytes().as_slice(),
                    &asset.as_bytes().as_slice(),
                    &amount.to_be_bytes().as_slice(),
                    &new_root.as_bytes().as_slice(),
                ],
            )
            .map_err(db_error)?;
        transaction
            .execute(
                "UPDATE ppsc_runtime_meta SET state_root=$1, updated_at=now() \
                 WHERE singleton=TRUE",
                &[&new_root.as_bytes().as_slice()],
            )
            .map_err(db_error)?;
        transaction
            .execute(
                "INSERT INTO ppsc_state_transitions \
                 (operation_kind, operation_id, account_id, asset_id, amount_be, old_state_root, \
                  new_state_root, data_id, transcript_root, version) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                &[
                    &kind,
                    &operation_id.as_slice(),
                    &account.as_bytes().as_slice(),
                    &asset.as_bytes().as_slice(),
                    &amount.to_be_bytes().as_slice(),
                    &old_root.as_bytes().as_slice(),
                    &new_root.as_bytes().as_slice(),
                    &data_id.as_bytes().as_slice(),
                    &transcript_root.as_bytes().as_slice(),
                    &version,
                ],
            )
            .map_err(db_error)?;
        Ok(())
    }

    fn marker_exists(
        transaction: &mut Transaction<'_>,
        table: &str,
        column: &str,
        id: &[u8; 32],
    ) -> Result<bool, RuntimeError> {
        // Table and column are selected exclusively from constants at call sites.
        let sql = format!("SELECT 1 FROM {table} WHERE {column}=$1");
        transaction
            .query_opt(&sql, &[&id.as_slice()])
            .map(|row| row.is_some())
            .map_err(db_error)
    }
}

impl<B> BalanceRuntimeApi for PostgresBalanceRuntime<B>
where
    B: ConfidentialBackend,
{
    fn credit_deposit(&self, command: DepositCommand) -> Result<StateTransition, RuntimeError> {
        if command.amount == 0 {
            return Err(RuntimeError::InvalidAmount);
        }
        self.repository.transaction(|transaction| {
            let old_root = Self::locked_root(transaction)?;
            if old_root != command.expected_old_state_root {
                return Err(RuntimeError::StaleStateRoot);
            }
            if Self::marker_exists(
                transaction,
                "ppsc_processed_deposits",
                "deposit_id",
                &command.deposit_id,
            )? {
                return Err(RuntimeError::DepositAlreadyProcessed);
            }
            let (ciphertext, version) =
                match Self::current_balance(transaction, command.account, command.asset)? {
                    Some((current, version)) => {
                        let left = self.backend.fhe_to_mpc(&current)?;
                        let right = self.backend.share_amount(command.amount)?;
                        let next = self.backend.checked_add(&left, &right)?;
                        (
                            self.backend
                                .mpc_to_fhe(&next, command.account, command.asset)?,
                            version
                                .checked_add(1)
                                .ok_or(RuntimeError::CorruptPersistence)?,
                        )
                    }
                    None => (
                        self.backend.encrypt_amount(
                            command.amount,
                            command.account,
                            command.asset,
                        )?,
                        1,
                    ),
                };
            let (data_id, new_root, transcript_root) = self.derive_transition(
                old_root,
                command.account,
                command.asset,
                &ciphertext,
                version,
            );
            Self::persist_transition(
                transaction,
                "deposit",
                &command.deposit_id,
                command.account,
                command.asset,
                command.amount,
                old_root,
                &ciphertext,
                data_id,
                new_root,
                transcript_root,
                version,
            )?;
            Ok(StateTransition {
                new_state_root: new_root,
                encrypted_balance_data_id: data_id,
                transcript_root,
                version,
            })
        })
    }

    fn debit_withdrawal(
        &self,
        command: WithdrawalCommand,
    ) -> Result<StateTransition, RuntimeError> {
        if command.gross_amount == 0 {
            return Err(RuntimeError::InvalidAmount);
        }
        self.repository.transaction(|transaction| {
            let old_root = Self::locked_root(transaction)?;
            if old_root != command.expected_old_state_root {
                return Err(RuntimeError::StaleStateRoot);
            }
            if Self::marker_exists(
                transaction,
                "ppsc_spent_nullifiers",
                "nullifier",
                &command.nullifier,
            )? {
                return Err(RuntimeError::NullifierAlreadySpent);
            }
            let (current, version) =
                Self::current_balance(transaction, command.account, command.asset)?
                    .ok_or(RuntimeError::BalanceNotFound)?;
            let current_value = self.backend.fhe_to_mpc(&current)?;
            let debit = self.backend.share_amount(command.gross_amount)?;
            if !self.backend.greater_than_or_equal(&current_value, &debit)? {
                return Err(RuntimeError::InsufficientBalance);
            }
            let next = self.backend.checked_sub(&current_value, &debit)?;
            let ciphertext = self
                .backend
                .mpc_to_fhe(&next, command.account, command.asset)?;
            let version = version
                .checked_add(1)
                .ok_or(RuntimeError::CorruptPersistence)?;
            let (data_id, new_root, transcript_root) = self.derive_transition(
                old_root,
                command.account,
                command.asset,
                &ciphertext,
                version,
            );
            Self::persist_transition(
                transaction,
                "withdrawal",
                &command.nullifier,
                command.account,
                command.asset,
                command.gross_amount,
                old_root,
                &ciphertext,
                data_id,
                new_root,
                transcript_root,
                version,
            )?;
            Ok(StateTransition {
                new_state_root: new_root,
                encrypted_balance_data_id: data_id,
                transcript_root,
                version,
            })
        })
    }

    fn transfer(&self, command: TransferCommand) -> Result<TransferTransition, RuntimeError> {
        if command.amount == 0 || command.sender == command.receiver {
            return Err(RuntimeError::InvalidAmount);
        }
        self.repository.transaction(|transaction| {
            let old_root = Self::locked_root(transaction)?;
            if old_root != command.expected_old_state_root {
                return Err(RuntimeError::StaleStateRoot);
            }
            if Self::marker_exists(
                transaction,
                "ppsc_processed_transfers",
                "transfer_id",
                &command.transfer_id,
            )? {
                return Err(RuntimeError::NullifierAlreadySpent);
            }
            let (sender_ciphertext, sender_version) =
                Self::current_balance(transaction, command.sender, command.asset)?
                    .ok_or(RuntimeError::BalanceNotFound)?;
            let receiver_current =
                Self::current_balance(transaction, command.receiver, command.asset)?;
            let sender_secret = self.backend.fhe_to_mpc(&sender_ciphertext)?;
            let receiver_secret = match &receiver_current {
                Some((ciphertext, _)) => self.backend.fhe_to_mpc(ciphertext)?,
                None => self.backend.share_amount(0)?,
            };
            let amount = self.backend.share_amount(command.amount)?;
            if !self.backend.greater_than_or_equal(&sender_secret, &amount)? {
                return Err(RuntimeError::InsufficientBalance);
            }
            let sender_next = self.backend.checked_sub(&sender_secret, &amount)?;
            let receiver_next = self.backend.checked_add(&receiver_secret, &amount)?;
            let sender_version = sender_version
                .checked_add(1)
                .ok_or(RuntimeError::CorruptPersistence)?;
            let receiver_version = receiver_current
                .as_ref()
                .map_or(1, |(_, version)| version.saturating_add(1));
            let sender_output =
                self.backend.mpc_to_fhe(&sender_next, command.sender, command.asset)?;
            let receiver_output =
                self.backend.mpc_to_fhe(&receiver_next, command.receiver, command.asset)?;
            let (sender_data_id, intermediate_root, _) = self.derive_transition(
                old_root,
                command.sender,
                command.asset,
                &sender_output,
                sender_version,
            );
            let (receiver_data_id, new_root, transcript_root) = self.derive_transition(
                intermediate_root,
                command.receiver,
                command.asset,
                &receiver_output,
                receiver_version,
            );
            for (account, data_id, version, ciphertext) in [
                (command.sender, sender_data_id, sender_version, &sender_output),
                (command.receiver, receiver_data_id, receiver_version, &receiver_output),
            ] {
                let version =
                    i64::try_from(version).map_err(|_| RuntimeError::CorruptPersistence)?;
                transaction.execute(
                    "INSERT INTO ppsc_balance_records \
                     (account_id,asset_id,data_id,version,ciphertext) VALUES($1,$2,$3,$4,$5) \
                     ON CONFLICT(account_id,asset_id) DO UPDATE SET data_id=EXCLUDED.data_id, \
                     version=EXCLUDED.version,ciphertext=EXCLUDED.ciphertext,updated_at=now()",
                    &[&account.as_bytes().as_slice(), &command.asset.as_bytes().as_slice(),
                      &data_id.as_bytes().as_slice(), &version, &ciphertext.as_bytes()],
                ).map_err(db_error)?;
            }
            transaction.execute(
                "INSERT INTO ppsc_processed_transfers \
                 (transfer_id,sender_account_id,receiver_account_id,asset_id,amount_be,resulting_state_root) \
                 VALUES($1,$2,$3,$4,$5,$6)",
                &[&command.transfer_id.as_slice(), &command.sender.as_bytes().as_slice(),
                  &command.receiver.as_bytes().as_slice(), &command.asset.as_bytes().as_slice(),
                  &command.amount.to_be_bytes().as_slice(), &new_root.as_bytes().as_slice()],
            ).map_err(db_error)?;
            transaction.execute(
                "UPDATE ppsc_runtime_meta SET state_root=$1,updated_at=now() WHERE singleton=TRUE",
                &[&new_root.as_bytes().as_slice()],
            ).map_err(db_error)?;
            Ok(TransferTransition {
                new_state_root: new_root,
                sender_data_id,
                receiver_data_id,
                transcript_root,
                sender_version,
                receiver_version,
            })
        })
    }

    fn encrypted_balance(
        &self,
        account: PrivateAccountId,
        asset: AssetId,
    ) -> Result<EncryptedBalanceView, RuntimeError> {
        self.repository.transaction(|transaction| {
            let state_root = Self::locked_root(transaction)?;
            let row = transaction
                .query_opt(
                    "SELECT data_id, ciphertext, version FROM ppsc_balance_records \
                     WHERE account_id=$1 AND asset_id=$2",
                    &[&account.as_bytes().as_slice(), &asset.as_bytes().as_slice()],
                )
                .map_err(db_error)?
                .ok_or(RuntimeError::BalanceNotFound)?;
            let version: i64 = row.get(2);
            Ok(EncryptedBalanceView {
                data_id: data_id_from_vec(row.get(0))?,
                ciphertext: PublicBytes::new(row.get(1)),
                state_root,
                version: u64::try_from(version).map_err(|_| RuntimeError::CorruptPersistence)?,
            })
        })
    }

    fn open_balance_for_owner(
        &self,
        account: PrivateAccountId,
        asset: AssetId,
        authorization: &[u8],
    ) -> Result<u128, RuntimeError> {
        let ciphertext = self.encrypted_balance(account, asset)?.ciphertext;
        Ok(self.backend.decrypt_for_owner(
            &FheAmount::from_bytes(ciphertext.as_slice().to_vec()),
            account,
            authorization,
        )?)
    }

    fn state_root(&self) -> Result<Commitment, RuntimeError> {
        self.repository.transaction(Self::locked_root)
    }
}

fn commitment_from_vec(bytes: Vec<u8>) -> Result<Commitment, RuntimeError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| RuntimeError::CorruptPersistence)?;
    Ok(Commitment::from_bytes(bytes))
}

fn data_id_from_vec(bytes: Vec<u8>) -> Result<DataId, RuntimeError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| RuntimeError::CorruptPersistence)?;
    Ok(DataId::from_bytes(bytes))
}

fn db_error(_: postgres::Error) -> RuntimeError {
    RuntimeError::PersistenceFailure
}
