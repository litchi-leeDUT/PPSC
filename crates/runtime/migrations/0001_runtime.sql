CREATE TABLE IF NOT EXISTS ppsc_runtime_meta (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    state_root BYTEA NOT NULL CHECK (octet_length(state_root) = 32),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO ppsc_runtime_meta (singleton, state_root)
VALUES (TRUE, decode(repeat('00', 32), 'hex'))
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS ppsc_balance_records (
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 32),
    asset_id BYTEA NOT NULL CHECK (octet_length(asset_id) = 20),
    data_id BYTEA NOT NULL CHECK (octet_length(data_id) = 32),
    version BIGINT NOT NULL CHECK (version > 0),
    ciphertext BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, asset_id)
);

CREATE TABLE IF NOT EXISTS ppsc_processed_deposits (
    deposit_id BYTEA PRIMARY KEY CHECK (octet_length(deposit_id) = 32),
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 32),
    asset_id BYTEA NOT NULL CHECK (octet_length(asset_id) = 20),
    amount_be BYTEA NOT NULL CHECK (octet_length(amount_be) = 16),
    resulting_state_root BYTEA NOT NULL CHECK (octet_length(resulting_state_root) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ppsc_spent_nullifiers (
    nullifier BYTEA PRIMARY KEY CHECK (octet_length(nullifier) = 32),
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 32),
    asset_id BYTEA NOT NULL CHECK (octet_length(asset_id) = 20),
    amount_be BYTEA NOT NULL CHECK (octet_length(amount_be) = 16),
    resulting_state_root BYTEA NOT NULL CHECK (octet_length(resulting_state_root) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ppsc_state_transitions (
    sequence BIGSERIAL PRIMARY KEY,
    operation_kind TEXT NOT NULL CHECK (operation_kind IN ('deposit', 'withdrawal')),
    operation_id BYTEA NOT NULL UNIQUE CHECK (octet_length(operation_id) = 32),
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 32),
    asset_id BYTEA NOT NULL CHECK (octet_length(asset_id) = 20),
    amount_be BYTEA NOT NULL CHECK (octet_length(amount_be) = 16),
    old_state_root BYTEA NOT NULL CHECK (octet_length(old_state_root) = 32),
    new_state_root BYTEA NOT NULL CHECK (octet_length(new_state_root) = 32),
    data_id BYTEA NOT NULL CHECK (octet_length(data_id) = 32),
    transcript_root BYTEA NOT NULL CHECK (octet_length(transcript_root) = 32),
    version BIGINT NOT NULL CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ppsc_state_transitions_account_asset_idx
    ON ppsc_state_transitions (account_id, asset_id, sequence DESC);
