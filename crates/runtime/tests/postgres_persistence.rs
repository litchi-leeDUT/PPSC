use ppsc_runtime::{
    postgres::PostgresBalanceRuntime, AssetId, BalanceRuntimeApi, DepositCommand, PlaintextBackend,
    PrivateAccountId, RuntimeError, WithdrawalCommand,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_id(tag: u8) -> [u8; 32] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos()
        .to_be_bytes();
    let mut id = [tag; 32];
    id[..16].copy_from_slice(&nanos);
    id[16..20].copy_from_slice(&std::process::id().to_be_bytes());
    id
}

#[test]
fn state_survives_restart_and_replay_markers_are_persistent() {
    let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("skipping PostgreSQL integration test: TEST_DATABASE_URL is not set");
        return;
    };
    let account = PrivateAccountId::from_bytes(unique_id(7));
    let asset_bytes = unique_id(9);
    let asset = AssetId::from_bytes(asset_bytes[..20].try_into().expect("asset bytes"));
    let deposit_id = unique_id(1);
    let nullifier = unique_id(2);

    let deposit_root = {
        let runtime = PostgresBalanceRuntime::connect(&database_url, PlaintextBackend)
            .expect("connect and migrate");
        let initial_root = runtime.state_root().expect("initial root");
        runtime
            .credit_deposit(DepositCommand {
                deposit_id,
                account,
                asset,
                amount: 100,
                expected_old_state_root: initial_root,
            })
            .expect("persistent deposit")
            .new_state_root
    };

    let runtime = PostgresBalanceRuntime::connect(&database_url, PlaintextBackend)
        .expect("reconnect after simulated restart");
    assert_eq!(
        runtime
            .open_balance_for_owner(account, asset, PlaintextBackend::authorization_for_tests(),)
            .expect("persistent balance"),
        100
    );
    let withdrawal = runtime
        .debit_withdrawal(WithdrawalCommand {
            nullifier,
            account,
            asset,
            gross_amount: 40,
            expected_old_state_root: deposit_root,
        })
        .expect("persistent withdrawal");
    assert_eq!(withdrawal.version, 2);

    let replay = runtime.debit_withdrawal(WithdrawalCommand {
        nullifier,
        account,
        asset,
        gross_amount: 1,
        expected_old_state_root: withdrawal.new_state_root,
    });
    assert!(matches!(replay, Err(RuntimeError::NullifierAlreadySpent)));
}
