use postgres::NoTls;
use ppsc_core::Commitment;
use ppsc_runtime::{
    postgres::PostgresBalanceRuntime, AssetId, BalanceRuntimeApi, DepositCommand, PlaintextBackend,
    PrivateAccountId, WithdrawalCommand,
};
use std::{env, error::Error, process::Command};

const MEMBER_KEY_1: &str = "0x0000000000000000000000000000000000000000000000000000000000000b0b";
const MEMBER_KEY_2: &str = "0x000000000000000000000000000000000000000000000000000000000000d00d";

struct Config {
    database_url: String,
    rpc_url: String,
    swap: String,
    token: String,
    relayer_key: String,
}

impl Config {
    fn load() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            rpc_url: required("RPC_URL")?,
            swap: required("SWAP")?,
            token: required("TOKEN")?,
            relayer_key: required("RELAYER_KEY")?,
        })
    }
}

fn required(name: &str) -> Result<String, Box<dyn Error>> {
    env::var(name).map_err(|_| format!("missing environment variable {name}").into())
}

fn run_cast(args: &[String]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("cast").args(args).output()?;
    if !output.status.success() {
        return Err(format!("cast failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn call(config: &Config, signature: &str, args: &[String]) -> Result<String, Box<dyn Error>> {
    let mut command = vec!["call".into(), config.swap.clone(), signature.into()];
    command.extend_from_slice(args);
    command.extend([
        "--rpc-url".into(),
        config.rpc_url.clone(),
        "--no-proxy".into(),
    ]);
    run_cast(&command)
}

fn send(config: &Config, signature: &str, args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut command = vec!["send".into(), config.swap.clone(), signature.into()];
    command.extend_from_slice(args);
    command.extend([
        "--private-key".into(),
        config.relayer_key.clone(),
        "--rpc-url".into(),
        config.rpc_url.clone(),
        "--no-proxy".into(),
        "--quiet".into(),
    ]);
    run_cast(&command)?;
    Ok(())
}

fn bytes32(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    decode_fixed::<32>(value)
}

fn address20(value: &str) -> Result<[u8; 20], Box<dyn Error>> {
    decode_fixed::<20>(value)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], Box<dyn Error>> {
    let raw = value.strip_prefix("0x").ok_or("hex must start with 0x")?;
    if raw.len() != N * 2 {
        return Err(format!("expected {}-byte hex value", N).into());
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16)?;
    }
    Ok(output)
}

fn hex(value: &[u8]) -> String {
    let mut output = String::from("0x");
    for byte in value {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn sign(digest: &str, key: &str) -> Result<String, Box<dyn Error>> {
    run_cast(&[
        "wallet".into(),
        "sign".into(),
        "--no-hash".into(),
        "--private-key".into(),
        key.into(),
        digest.into(),
    ])
}

fn signatures(digest: &str) -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "[{},{}]",
        sign(digest, MEMBER_KEY_1)?,
        sign(digest, MEMBER_KEY_2)?
    ))
}

fn runtime(config: &Config) -> Result<PostgresBalanceRuntime<PlaintextBackend>, Box<dyn Error>> {
    Ok(PostgresBalanceRuntime::connect(
        &config.database_url,
        PlaintextBackend,
    )?)
}

fn state_root(config: &Config) -> Result<Commitment, Box<dyn Error>> {
    Ok(Commitment::from_bytes(bytes32(&call(
        config,
        "privateStateRoots(address)(bytes32)",
        std::slice::from_ref(&config.token),
    )?)?))
}

fn account(value: &str) -> Result<PrivateAccountId, Box<dyn Error>> {
    Ok(PrivateAccountId::from_bytes(bytes32(value)?))
}

fn asset(config: &Config) -> Result<AssetId, Box<dyn Error>> {
    Ok(AssetId::from_bytes(address20(&config.token)?))
}

fn deposit(
    config: &Config,
    deposit_id: &str,
    amount: &str,
    account_commitment: &str,
) -> Result<(), Box<dyn Error>> {
    let amount = amount.parse::<u128>()?;
    let old_root = state_root(config)?;
    let transition = runtime(config)?.credit_deposit(DepositCommand {
        deposit_id: bytes32(deposit_id)?,
        account: account(account_commitment)?,
        asset: asset(config)?,
        amount,
        expected_old_state_root: old_root,
    })?;
    let settlement = format!(
        "({},{},{},{})",
        hex(old_root.as_bytes()),
        hex(transition.new_state_root.as_bytes()),
        hex(transition.encrypted_balance_data_id.as_bytes()),
        hex(transition.transcript_root.as_bytes())
    );
    let digest = call(
        config,
        "depositDigest(bytes32,(bytes32,bytes32,bytes32,bytes32))(bytes32)",
        &[deposit_id.into(), settlement.clone()],
    )?;
    send(
        config,
        "finalizeDeposit(bytes32,(bytes32,bytes32,bytes32,bytes32),bytes[])",
        &[deposit_id.into(), settlement, signatures(&digest)?],
    )?;
    println!(
        "deposit finalized: amount={amount} encryptedBalanceDataId={} version={}",
        hex(transition.encrypted_balance_data_id.as_bytes()),
        transition.version
    );
    Ok(())
}

fn query(config: &Config, account_commitment: &str) -> Result<(), Box<dyn Error>> {
    let balance = runtime(config)?.open_balance_for_owner(
        account(account_commitment)?,
        asset(config)?,
        PlaintextBackend::authorization_for_tests(),
    )?;
    let view = runtime(config)?.encrypted_balance(account(account_commitment)?, asset(config)?)?;
    println!(
        "authorized confidential balance: amount={balance} dataId={} version={}",
        hex(view.data_id.as_bytes()),
        view.version
    );
    Ok(())
}

fn withdraw(
    config: &Config,
    withdrawal_id: &str,
    amount: &str,
    account_commitment: &str,
) -> Result<(), Box<dyn Error>> {
    let amount = amount.parse::<u128>()?;
    let old_root = state_root(config)?;
    let nullifier = bytes32(&run_cast(&[
        "keccak".into(),
        format!("swap-withdrawal-nullifier:{withdrawal_id}"),
    ])?)?;
    let transition = runtime(config)?.debit_withdrawal(WithdrawalCommand {
        nullifier,
        account: account(account_commitment)?,
        asset: asset(config)?,
        gross_amount: amount,
        expected_old_state_root: old_root,
    })?;
    let settlement = format!(
        "({},{},{},{},{})",
        hex(&nullifier),
        hex(old_root.as_bytes()),
        hex(transition.new_state_root.as_bytes()),
        hex(transition.encrypted_balance_data_id.as_bytes()),
        hex(transition.transcript_root.as_bytes())
    );
    let digest = call(
        config,
        "withdrawalSettlementDigest(bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32))(bytes32)",
        &[withdrawal_id.into(), settlement.clone()],
    )?;
    send(
        config,
        "finalizeWithdrawal(bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32),bytes[])",
        &[withdrawal_id.into(), settlement, signatures(&digest)?],
    )?;
    println!(
        "withdrawal finalized: grossAmount={amount} encryptedBalanceDataId={} version={}",
        hex(transition.encrypted_balance_data_id.as_bytes()),
        transition.version
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::load()?;
    // Fail early with a clearer database connection error and ensure migrations exist.
    postgres::Client::connect(&config.database_url, NoTls)?;
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("deposit") => deposit(
            &config,
            args.get(2).ok_or("deposit requires depositId")?,
            args.get(3).ok_or("deposit requires amount in token base units")?,
            args.get(4).ok_or("deposit requires privateAccountCommitment")?,
        ),
        Some("query") => query(
            &config,
            args.get(2).ok_or("query requires privateAccountCommitment")?,
        ),
        Some("withdraw") => withdraw(
            &config,
            args.get(2).ok_or("withdraw requires withdrawalId")?,
            args.get(3).ok_or("withdraw requires amount in token base units")?,
            args.get(4).ok_or("withdraw requires privateAccountCommitment")?,
        ),
        _ => Err("usage: confidential_swap_worker <deposit depositId amount accountCommitment|query accountCommitment|withdraw withdrawalId amount accountCommitment>".into()),
    }
}
