use postgres::NoTls;
use ppsc_core::Commitment;
use ppsc_runtime::{
    postgres::PostgresBalanceRuntime, AssetId, BalanceRuntimeApi, DepositCommand, PlaintextBackend,
    PrivateAccountId, TransferCommand, WithdrawalCommand,
};
use std::{
    env,
    error::Error,
    process::Command,
    thread,
    time::{Duration, Instant},
};

const MEMBER_KEY_1: &str = "0x0000000000000000000000000000000000000000000000000000000000000b0b";
const MEMBER_KEY_2: &str = "0x000000000000000000000000000000000000000000000000000000000000d00d";

struct Config {
    database_url: String,
    rpc_url: String,
    swap: String,
    token: String,
    node_tx_key: String,
}

impl Config {
    fn load() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            rpc_url: required("RPC_URL")?,
            swap: required("SWAP")?,
            token: required("TOKEN")?,
            node_tx_key: required("NODE_TX_KEY")?,
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
        config.node_tx_key.clone(),
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
    let runtime = runtime(config)?;
    let database_root = runtime.state_root()?;
    let chain_root = state_root(config)?;
    if database_root != chain_root {
        return Err(format!(
            "database/chain state-root mismatch: database={} chain={}; use the database created for this Swap deployment",
            hex(database_root.as_bytes()),
            hex(chain_root.as_bytes())
        )
        .into());
    }
    let balance = runtime.open_balance_for_owner(
        account(account_commitment)?,
        asset(config)?,
        PlaintextBackend::authorization_for_tests(),
    )?;
    let view = runtime.encrypted_balance(account(account_commitment)?, asset(config)?)?;
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

fn transfer(
    config: &Config,
    transfer_id: &str,
    amount: &str,
    sender_commitment: &str,
    receiver_commitment: &str,
) -> Result<(), Box<dyn Error>> {
    let amount = amount.parse::<u128>()?;
    let old_root = state_root(config)?;
    let transition = runtime(config)?.transfer(TransferCommand {
        transfer_id: bytes32(transfer_id)?,
        sender: account(sender_commitment)?,
        receiver: account(receiver_commitment)?,
        asset: asset(config)?,
        amount,
        expected_old_state_root: old_root,
    })?;
    let settlement = format!(
        "({},{},{},{},{})",
        hex(old_root.as_bytes()),
        hex(transition.new_state_root.as_bytes()),
        hex(transition.sender_data_id.as_bytes()),
        hex(transition.receiver_data_id.as_bytes()),
        hex(transition.transcript_root.as_bytes())
    );
    let digest = call(
        config,
        "confidentialTransferDigest(bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32))(bytes32)",
        &[transfer_id.into(), settlement.clone()],
    )?;
    send(
        config,
        "finalizeConfidentialTransfer(bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32),bytes[])",
        &[transfer_id.into(), settlement, signatures(&digest)?],
    )?;
    println!(
        "confidential transfer finalized: amount={amount} senderDataId={} receiverDataId={}",
        hex(transition.sender_data_id.as_bytes()),
        hex(transition.receiver_data_id.as_bytes())
    );
    Ok(())
}

fn fields(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(|value| value.trim_matches(['[', ']', ',']).to_owned())
        .collect()
}

fn cursor(client: &mut postgres::Client, kind: &str) -> Result<i64, Box<dyn Error>> {
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS ppsc_swap_listener_cursors (
           task_kind TEXT PRIMARY KEY, next_index BIGINT NOT NULL CHECK(next_index >= 0));",
    )?;
    client.execute(
        "INSERT INTO ppsc_swap_listener_cursors(task_kind,next_index) VALUES($1,0)
         ON CONFLICT(task_kind) DO NOTHING",
        &[&kind],
    )?;
    Ok(client
        .query_one(
            "SELECT next_index FROM ppsc_swap_listener_cursors WHERE task_kind=$1",
            &[&kind],
        )?
        .get(0))
}

fn advance_cursor(
    client: &mut postgres::Client,
    kind: &str,
    next: i64,
) -> Result<(), Box<dyn Error>> {
    client.execute(
        "UPDATE ppsc_swap_listener_cursors SET next_index=$2 WHERE task_kind=$1",
        &[&kind, &next],
    )?;
    Ok(())
}

fn process_pending(
    config: &Config,
    client: &mut postgres::Client,
) -> Result<usize, Box<dyn Error>> {
    let counts = fields(&call(
        config,
        "taskCounts()(uint256,uint256,uint256,uint256)",
        &[],
    )?);
    if counts.len() != 4 {
        return Err("unexpected taskCounts response".into());
    }
    let mut handled = 0;
    for (kind, count, id_getter, record_getter) in [
        (
            "deposit",
            counts[0].parse::<i64>()?,
            "depositTaskIds(uint256)(bytes32)",
            "deposits(bytes32)(address,address,uint256,bytes32,uint64,uint8)",
        ),
        (
            "transfer",
            counts[1].parse::<i64>()?,
            "transferTaskIds(uint256)(bytes32)",
            "confidentialTransferRequests(bytes32)(address,address,bytes32,bytes32,uint256,uint64,uint8)",
        ),
        (
            "withdrawal",
            counts[2].parse::<i64>()?,
            "withdrawalTaskIds(uint256)(bytes32)",
            "withdrawalRequests(bytes32)(address,address,address,uint256,bytes32,uint64,uint8)",
        ),
        (
            "opening",
            counts[3].parse::<i64>()?,
            "openingTaskIds(uint256)(bytes32)",
            "balanceOpeningRequests(bytes32)(address,address,bytes32,bytes32,uint64,uint8)",
        ),
    ] {
        let mut index = cursor(client, kind)?;
        while index < count {
            let id = call(config, id_getter, &[index.to_string()])?;
            let record = fields(&call(config, record_getter, std::slice::from_ref(&id))?);
            match kind {
                "deposit" if record.len() == 6 && record[5] == "1" => {
                    deposit(config, &id, &record[2], &record[3])?;
                }
                "transfer" if record.len() == 7 && record[6] == "1" => {
                    transfer(config, &id, &record[4], &record[2], &record[3])?;
                }
                "withdrawal" if record.len() == 7 && record[6] == "1" => {
                    withdraw(config, &id, &record[3], &record[4])?;
                }
                "opening" if record.len() == 6 && record[5] == "1" => {
                    fulfill_opening(config, &id, &record[2])?;
                }
                _ => {}
            }
            index += 1;
            advance_cursor(client, kind, index)?;
            handled += 1;
        }
    }
    Ok(handled)
}

fn fulfill_opening(
    config: &Config,
    request_id: &str,
    account_commitment: &str,
) -> Result<(), Box<dyn Error>> {
    let balance = runtime(config)?.open_balance_for_owner(
        account(account_commitment)?,
        asset(config)?,
        PlaintextBackend::authorization_for_tests(),
    )?;
    // Development encoding only. A production backend encrypts to recipientEncryptionKey.
    let encrypted_result = format!("0x{balance:064x}");
    let digest = call(
        config,
        "balanceOpeningDigest(bytes32,bytes)(bytes32)",
        &[request_id.into(), encrypted_result.clone()],
    )?;
    send(
        config,
        "fulfillBalanceOpening(bytes32,bytes,bytes[])",
        &[request_id.into(), encrypted_result, signatures(&digest)?],
    )?;
    println!("balance opening fulfilled: request={request_id}");
    Ok(())
}

fn watch(config: &Config) -> Result<(), Box<dyn Error>> {
    let interval = env::var("POLL_INTERVAL_SECONDS")
        .unwrap_or_else(|_| "2".into())
        .parse::<u64>()?;
    let mut client = postgres::Client::connect(&config.database_url, NoTls)?;
    let rotation_after = env::var("COMMITTEE_ROTATION_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok());
    let started = Instant::now();
    let mut rotated = false;
    println!(
        "committee daemon started: swap={} poll={}s",
        config.swap, interval
    );
    loop {
        match process_pending(config, &mut client) {
            Ok(handled) if handled > 0 => println!("processed {handled} on-chain task(s)"),
            Ok(_) => {}
            Err(error) => eprintln!("poll failed; will retry: {error}"),
        }
        if !rotated
            && rotation_after
                .is_some_and(|seconds| started.elapsed() >= Duration::from_secs(seconds))
        {
            handoff(
                config,
                &required("NEXT_COMMITTEE_ID")?,
                &required("NEXT_COMMITTEE_NODES")?,
            )?;
            rotated = true;
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

fn handoff(config: &Config, next_committee: &str, nodes_csv: &str) -> Result<(), Box<dyn Error>> {
    let mut client = postgres::Client::connect(&config.database_url, NoTls)?;
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS ppsc_balance_handoff_fragments(
      account_id BYTEA NOT NULL,asset_id BYTEA NOT NULL,node_address TEXT NOT NULL,
      ciphertext BYTEA NOT NULL,version BIGINT NOT NULL,committee_id BYTEA NOT NULL,
      PRIMARY KEY(account_id,asset_id,node_address));",
    )?;
    let root = runtime(config)?.state_root()?;
    let target_urls = required("NEXT_NODE_DATABASE_URLS")?;
    let target_urls: Vec<&str> = target_urls
        .split(';')
        .filter(|url| !url.is_empty())
        .collect();
    let nodes: Vec<&str> = nodes_csv
        .split(',')
        .filter(|node| !node.is_empty())
        .collect();
    if target_urls.len() != nodes.len() || nodes.is_empty() {
        return Err(
            "NEXT_NODE_DATABASE_URLS must contain one semicolon-separated DSN per node".into(),
        );
    }
    let records = client.query(
        "SELECT account_id,asset_id,data_id,version,ciphertext FROM ppsc_balance_records",
        &[],
    )?;
    for (node, target_url) in nodes.iter().zip(target_urls) {
        // Each node owns a distinct PostgreSQL database. Connecting the runtime first applies
        // the same schema before the handoff snapshot is installed.
        let _ = PostgresBalanceRuntime::connect(target_url, PlaintextBackend)?;
        let mut target = postgres::Client::connect(target_url, NoTls)?;
        let mut transaction = target.transaction()?;
        for record in &records {
            let account_id: Vec<u8> = record.get(0);
            let asset_id: Vec<u8> = record.get(1);
            let data_id: Vec<u8> = record.get(2);
            let version: i64 = record.get(3);
            let ciphertext: Vec<u8> = record.get(4);
            transaction.execute(
                "INSERT INTO ppsc_balance_records(account_id,asset_id,data_id,version,ciphertext)
                 VALUES($1,$2,$3,$4,$5) ON CONFLICT(account_id,asset_id) DO UPDATE SET
                 data_id=EXCLUDED.data_id,version=EXCLUDED.version,
                 ciphertext=EXCLUDED.ciphertext,updated_at=now()",
                &[&account_id, &asset_id, &data_id, &version, &ciphertext],
            )?;
        }
        transaction.execute(
            "UPDATE ppsc_runtime_meta SET state_root=$1,updated_at=now() WHERE singleton=TRUE",
            &[&root.as_bytes().as_slice()],
        )?;
        transaction.commit()?;
        println!("handoff snapshot installed: node={node}");
    }
    let handoff_root = run_cast(&[
        "keccak".into(),
        format!(
            "PPSC_HANDOFF:{}:{next_committee}:{nodes_csv}",
            hex(root.as_bytes())
        ),
    ])?;
    for node in nodes_csv.split(',').filter(|node| !node.is_empty()) {
        client.execute(
            "INSERT INTO ppsc_balance_handoff_fragments
             (account_id,asset_id,node_address,ciphertext,version,committee_id)
             SELECT account_id,asset_id,$1,ciphertext,version,$2 FROM ppsc_balance_records
             ON CONFLICT(account_id,asset_id,node_address) DO UPDATE SET
             ciphertext=EXCLUDED.ciphertext,version=EXCLUDED.version,committee_id=EXCLUDED.committee_id",
            &[&node, &bytes32(next_committee)?.as_slice()],
        )?;
    }
    send(
        config,
        "beginCommitteeHandoff(bytes32,bytes32)",
        &[next_committee.into(), handoff_root.clone()],
    )?;
    let digest = call(config, "committeeHandoffDigest()(bytes32)", &[])?;
    let next_key_1 = required("NEXT_MEMBER_KEY_1")?;
    let next_key_2 = required("NEXT_MEMBER_KEY_2")?;
    let old_signatures = signatures(&digest)?;
    let new_signatures = format!(
        "[{},{}]",
        sign(&digest, &next_key_1)?,
        sign(&digest, &next_key_2)?
    );
    send(
        config,
        "finalizeCommitteeHandoff(bytes[],bytes[])",
        &[old_signatures, new_signatures],
    )?;
    println!("committee handoff finalized: next={next_committee} root={handoff_root}");
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
        Some("transfer") => transfer(
            &config,
            args.get(2).ok_or("transfer requires transferId")?,
            args.get(3).ok_or("transfer requires amount")?,
            args.get(4).ok_or("transfer requires sender commitment")?,
            args.get(5).ok_or("transfer requires receiver commitment")?,
        ),
        Some("watch") | None => watch(&config),
        Some("handoff") => handoff(
            &config,
            args.get(2).ok_or("handoff requires nextCommitteeId")?,
            args.get(3).ok_or("handoff requires comma-separated nodes")?,
        ),
        _ => Err("usage: confidential_swap_worker [watch|deposit depositId amount accountCommitment|query accountCommitment|transfer transferId amount senderCommitment receiverCommitment|withdraw withdrawalId amount accountCommitment|handoff nextCommitteeId commaSeparatedNodes]".into()),
    }
}
