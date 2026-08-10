use ppsc_runtime::{
    AssetId, BalanceRuntime, BalanceRuntimeApi, DepositCommand, PlaintextBackend, PrivateAccountId,
    WithdrawalCommand,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = BalanceRuntime::new(PlaintextBackend);
    let account = PrivateAccountId::from_bytes([7_u8; 32]);
    let asset = AssetId::from_bytes([9_u8; 20]);
    let initial_root = runtime.state_root()?;
    let deposit = runtime.credit_deposit(DepositCommand {
        deposit_id: [1_u8; 32],
        account,
        asset,
        amount: 100,
        expected_old_state_root: initial_root,
    })?;
    let withdrawal = runtime.debit_withdrawal(WithdrawalCommand {
        nullifier: [2_u8; 32],
        account,
        asset,
        gross_amount: 40,
        expected_old_state_root: deposit.new_state_root,
    })?;
    let balance = runtime.open_balance_for_owner(
        account,
        asset,
        PlaintextBackend::authorization_for_tests(),
    )?;

    println!(
        "development runtime completed version {}",
        withdrawal.version
    );
    println!("development plaintext balance: {balance}");
    Ok(())
}
