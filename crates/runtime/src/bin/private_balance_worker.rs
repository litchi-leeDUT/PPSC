use postgres::{Client, NoTls};
use ppsc_core::{Commitment, DataId, ExecutionId, PublicBytes};
use ppsc_runtime::{
    private_transfer::{PrivateTransferProgram, PrivateTransferRequest},
    AssetId, FheAmount, FheBackend, PlaintextBackend, PrivateAccountId,
};
use std::{env, error::Error, process::Command};

const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const PK_ROOT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const MEMBER_KEY_1: &str = "0x0000000000000000000000000000000000000000000000000000000000000b0b";
const MEMBER_KEY_2: &str = "0x000000000000000000000000000000000000000000000000000000000000d00d";

struct Config {
    database_url: String,
    rpc_url: String,
    control: String,
    app: String,
    runtime_key: String,
    committee_id: String,
    user: String,
    receiver: String,
    nodes: Vec<String>,
}

impl Config {
    fn load() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            rpc_url: required("RPC_URL")?,
            control: required("CONTROL")?,
            app: required("APP")?,
            runtime_key: required("RUNTIME_KEY")?,
            committee_id: required("COMMITTEE_ID")?,
            user: required("DEMO_USER")?,
            receiver: required("RECEIVER")?,
            nodes: vec![
                required("NODE_1")?,
                required("NODE_2")?,
                required("NODE_3")?,
            ],
        })
    }
}

fn required(name: &str) -> Result<String, Box<dyn Error>> {
    env::var(name).map_err(|_| format!("missing environment variable {name}").into())
}

fn cast(config: &Config, args: &[String]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("cast")
        .args(args)
        .args(["--rpc-url", &config.rpc_url, "--no-proxy"])
        .output()?;
    if !output.status.success() {
        return Err(format!("cast failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn call(
    config: &Config,
    target: &str,
    signature: &str,
    args: &[String],
) -> Result<String, Box<dyn Error>> {
    let mut command = vec!["call".into(), target.into(), signature.into()];
    command.extend_from_slice(args);
    cast(config, &command)
}

fn send(
    config: &Config,
    target: &str,
    signature: &str,
    args: &[String],
) -> Result<(), Box<dyn Error>> {
    let mut command = vec!["send".into(), target.into(), signature.into()];
    command.extend_from_slice(args);
    command.extend([
        "--private-key".into(),
        config.runtime_key.clone(),
        "--quiet".into(),
    ]);
    cast(config, &command)?;
    Ok(())
}

fn local_cast(args: &[String]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("cast").args(args).output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn migrate(client: &mut Client) -> Result<(), Box<dyn Error>> {
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS ppsc_demo_ciphertext_slots (
            data_id BYTEA NOT NULL, slot INTEGER NOT NULL, ciphertext BYTEA NOT NULL,
            PRIMARY KEY(data_id, slot));
         CREATE TABLE IF NOT EXISTS ppsc_demo_variable_bindings (
            variable_address BYTEA PRIMARY KEY, data_id BYTEA NOT NULL, slot INTEGER NOT NULL,
            account_id BYTEA NOT NULL, role TEXT NOT NULL);",
    )?;
    Ok(())
}

fn bytes32(hex: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let raw = hex
        .strip_prefix("0x")
        .ok_or("hex value must start with 0x")?;
    if raw.len() != 64 {
        return Err("expected bytes32".into());
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16)?;
    }
    Ok(output)
}

fn account_id(address: &str) -> Result<PrivateAccountId, Box<dyn Error>> {
    let raw = address
        .strip_prefix("0x")
        .ok_or("address must start with 0x")?;
    if raw.len() != 40 {
        return Err("invalid address length".into());
    }
    let mut output = [0_u8; 32];
    for index in 0..20 {
        output[12 + index] = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16)?;
    }
    Ok(PrivateAccountId::from_bytes(output))
}

fn hex(value: &[u8]) -> String {
    let mut output = String::from("0x");
    for byte in value {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn variable(config: &Config, signature: &str, args: &[String]) -> Result<String, Box<dyn Error>> {
    call(config, &config.app, signature, args)
}

fn storage_root(config: &Config) -> Result<String, Box<dyn Error>> {
    let nodes = format!("[{}]", config.nodes.join(","));
    let encoded = local_cast(&["abi-encode".into(), "f(address[])".into(), nodes])?;
    local_cast(&["keccak".into(), encoded])
}

fn bootstrap(config: &Config, client: &mut Client) -> Result<(), Box<dyn Error>> {
    client.batch_execute("TRUNCATE ppsc_demo_ciphertext_slots, ppsc_demo_variable_bindings")?;
    let contract_id = call(
        config,
        &config.app,
        "confidentialContractId()(bytes32)",
        &[],
    )?;
    let sender_var = variable(
        config,
        "balanceVariable(address)(bytes32)",
        std::slice::from_ref(&config.user),
    )?;
    let receiver_var = variable(
        config,
        "balanceVariable(address)(bytes32)",
        std::slice::from_ref(&config.receiver),
    )?;
    let minimum_var = variable(config, "minimumBalanceVariable()(bytes32)", &[])?;
    let amount_var = variable(config, "transferAmountVariable()(bytes32)", &[])?;
    let root = storage_root(config)?;
    let nodes = format!("[{}]", config.nodes.join(","));
    let asset = AssetId::from_bytes([12; 20]);
    let entries = [
        (
            sender_var,
            [0xa1; 32],
            100,
            account_id(&config.user)?,
            "sender",
            config.user.clone(),
        ),
        (
            receiver_var,
            [0xa2; 32],
            20,
            account_id(&config.receiver)?,
            "receiver",
            config.receiver.clone(),
        ),
        (
            minimum_var,
            [0xa3; 32],
            50,
            account_id(&config.user)?,
            "minimum",
            config.user.clone(),
        ),
        (
            amount_var,
            [0xa4; 32],
            30,
            account_id(&config.user)?,
            "amount",
            config.user.clone(),
        ),
    ];
    for (variable, data, value, account, role, owner) in entries {
        let ciphertext = PlaintextBackend.encrypt_amount(value, account, asset)?;
        client.execute(
            "INSERT INTO ppsc_demo_ciphertext_slots(data_id,slot,ciphertext) VALUES($1,0,$2)",
            &[&data.as_slice(), &ciphertext.as_bytes()],
        )?;
        client.execute(
            "INSERT INTO ppsc_demo_variable_bindings(variable_address,data_id,slot,account_id,role)
             VALUES($1,$2,0,$3,$4)",
            &[
                &bytes32(&variable)?.as_slice(),
                &data.as_slice(),
                &account.as_bytes().as_slice(),
                &role,
            ],
        )?;
        let data_hex = hex(&data);
        send(config, &config.control,
            "registerDataFor(address,bytes32,bytes32,bytes32,bytes32,bytes32,uint8,uint16,uint64,uint64)",
            &[owner, data_hex.clone(), data_hex.clone(), PK_ROOT.into(), root.clone(), ZERO32.into(), "0".into(), "2".into(), "1".into(), "1".into()])?;
        send(
            config,
            &config.control,
            "registerDataLocations(bytes32,address[])",
            &[data_hex.clone(), nodes.clone()],
        )?;
        send(
            config,
            &config.control,
            "declareStateVariable(bytes32,bytes32,bytes32,uint32)",
            &[contract_id.clone(), variable, data_hex, "0".into()],
        )?;
    }
    println!("Runtime bootstrap completed: encrypted balances and policy variables persisted");
    Ok(())
}

fn binding(
    client: &mut Client,
    variable: &[u8; 32],
) -> Result<(DataId, i32, PrivateAccountId), Box<dyn Error>> {
    let row = client.query_one(
        "SELECT data_id,slot,account_id FROM ppsc_demo_variable_bindings WHERE variable_address=$1",
        &[&variable.as_slice()],
    )?;
    Ok((
        DataId::from_bytes(
            row.get::<_, Vec<u8>>(0)
                .try_into()
                .map_err(|_| "bad data id")?,
        ),
        row.get(1),
        PrivateAccountId::from_bytes(
            row.get::<_, Vec<u8>>(2)
                .try_into()
                .map_err(|_| "bad account id")?,
        ),
    ))
}

fn load(client: &mut Client, data: DataId, slot: i32) -> Result<PublicBytes, Box<dyn Error>> {
    let row = client.query_one(
        "SELECT ciphertext FROM ppsc_demo_ciphertext_slots WHERE data_id=$1 AND slot=$2",
        &[&data.as_bytes().as_slice(), &slot],
    )?;
    Ok(PublicBytes::new(row.get(0)))
}

fn query(config: &Config, client: &mut Client, who: &str) -> Result<(), Box<dyn Error>> {
    let address = if who == "sender" {
        &config.user
    } else {
        &config.receiver
    };
    let variable_hex = variable(
        config,
        "balanceVariable(address)(bytes32)",
        std::slice::from_ref(address),
    )?;
    let variable_bytes = bytes32(&variable_hex)?;
    let (data, slot, account) = binding(client, &variable_bytes)?;
    let chain_ref = call(
        config,
        &config.control,
        "stateVariableReference(bytes32)((bytes32,bytes32,uint8,uint32,uint64,bool))",
        &[variable_hex],
    )?;
    if !chain_ref
        .to_ascii_lowercase()
        .contains(&hex(data.as_bytes())[2..])
    {
        return Err("database binding differs from ControlPlane".into());
    }
    let value = PlaintextBackend.decrypt_for_owner(
        &FheAmount::from_bytes(load(client, data, slot)?.into_vec()),
        account,
        PlaintextBackend::authorization_for_tests(),
    )?;
    println!(
        "authorized balance opening: account={address} balance={value} dataId={} slot={slot}",
        hex(data.as_bytes())
    );
    Ok(())
}

fn sign(digest: &str, key: &str) -> Result<String, Box<dyn Error>> {
    local_cast(&[
        "wallet".into(),
        "sign".into(),
        "--no-hash".into(),
        "--private-key".into(),
        key.into(),
        digest.into(),
    ])
}

fn process(config: &Config, client: &mut Client, execution: &str) -> Result<(), Box<dyn Error>> {
    let sender_var = bytes32(&variable(
        config,
        "balanceVariable(address)(bytes32)",
        std::slice::from_ref(&config.user),
    )?)?;
    let receiver_var = bytes32(&variable(
        config,
        "balanceVariable(address)(bytes32)",
        std::slice::from_ref(&config.receiver),
    )?)?;
    let minimum_var = bytes32(&variable(config, "minimumBalanceVariable()(bytes32)", &[])?)?;
    let amount_var = bytes32(&variable(config, "transferAmountVariable()(bytes32)", &[])?)?;
    let (sender_data, sender_slot, sender_account) = binding(client, &sender_var)?;
    let (receiver_data, receiver_slot, receiver_account) = binding(client, &receiver_var)?;
    let (minimum_data, minimum_slot, _) = binding(client, &minimum_var)?;
    let (amount_data, amount_slot, _) = binding(client, &amount_var)?;
    send(
        config,
        &config.control,
        "assignCommittee(bytes32,bytes32)",
        &[execution.into(), config.committee_id.clone()],
    )?;
    send(
        config,
        &config.control,
        "markRunning(bytes32)",
        &[execution.into()],
    )?;
    let old_root = bytes32(&call(
        config,
        &config.app,
        "privateStateRoot()(bytes32)",
        &[],
    )?)?;
    let output = PrivateTransferProgram::new(PlaintextBackend).evaluate(
        &PrivateTransferRequest {
            execution_id: ExecutionId::from_bytes(bytes32(execution)?),
            old_state_root: Commitment::from_bytes(old_root),
            sender_variable_address: sender_var,
            receiver_variable_address: receiver_var,
            sender_account,
            receiver_account,
            asset: AssetId::from_bytes([12; 20]),
            sender_balance_data_id: sender_data,
            receiver_balance_data_id: receiver_data,
            minimum_balance_data_id: minimum_data,
            amount_data_id: amount_data,
        },
        load(client, sender_data, sender_slot)?,
        load(client, receiver_data, receiver_slot)?,
        load(client, minimum_data, minimum_slot)?,
        load(client, amount_data, amount_slot)?,
    )?;
    let root = storage_root(config)?;
    let result = format!(
        "({},{},{},{},{},0,2,2,{},{})",
        hex(output.output_data_id.as_bytes()),
        hex(output.output_commitment.as_bytes()),
        PK_ROOT,
        root,
        ZERO32,
        hex(output.new_state_root.as_bytes()),
        hex(output.transcript_root.as_bytes())
    );
    let digest = call(config,&config.control,"resultDigest(bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32,uint8,uint16,uint64,bytes32,bytes32))(bytes32)",&[execution.into(),result.clone()])?;
    let signatures = format!(
        "[{},{}]",
        sign(&digest, MEMBER_KEY_1)?,
        sign(&digest, MEMBER_KEY_2)?
    );
    send(config,&config.control,"submitResult(bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32,uint8,uint16,uint64,bytes32,bytes32),bytes[])",&[execution.into(),result,signatures])?;
    let nodes = format!("[{}]", config.nodes.join(","));
    send(
        config,
        &config.control,
        "registerDataLocations(bytes32,address[])",
        &[hex(output.output_data_id.as_bytes()), nodes],
    )?;
    let updates = format!("[({},0),({},1)]", hex(&sender_var), hex(&receiver_var));
    let update_digest = call(
        config,
        &config.control,
        "variableUpdateDigest(bytes32,(bytes32,uint32)[])(bytes32)",
        &[execution.into(), updates.clone()],
    )?;
    let update_signatures = format!(
        "[{},{}]",
        sign(&update_digest, MEMBER_KEY_1)?,
        sign(&update_digest, MEMBER_KEY_2)?
    );
    send(
        config,
        &config.control,
        "updateStateVariablesAfterResult(bytes32,(bytes32,uint32)[],bytes[])",
        &[execution.into(), updates, update_signatures],
    )?;
    let mut tx = client.transaction()?;
    tx.execute(
        "INSERT INTO ppsc_demo_ciphertext_slots(data_id,slot,ciphertext) VALUES($1,0,$2),($1,1,$3)",
        &[
            &output.output_data_id.as_bytes().as_slice(),
            &output.sender_ciphertext.as_slice(),
            &output.receiver_ciphertext.as_slice(),
        ],
    )?;
    tx.execute(
        "UPDATE ppsc_demo_variable_bindings SET data_id=$1,slot=0 WHERE variable_address=$2",
        &[
            &output.output_data_id.as_bytes().as_slice(),
            &sender_var.as_slice(),
        ],
    )?;
    tx.execute(
        "UPDATE ppsc_demo_variable_bindings SET data_id=$1,slot=1 WHERE variable_address=$2",
        &[
            &output.output_data_id.as_bytes().as_slice(),
            &receiver_var.as_slice(),
        ],
    )?;
    tx.commit()?;
    println!("execution processed and committed: {execution}");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::load()?;
    let mut client = Client::connect(&config.database_url, NoTls)?;
    migrate(&mut client)?;
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("bootstrap") => bootstrap(&config, &mut client),
        Some("query") => query(&config, &mut client, args.get(2).map(String::as_str).unwrap_or("sender")),
        Some("process") => process(&config, &mut client, args.get(2).ok_or("process requires executionId")?),
        _ => Err("usage: private_balance_worker <bootstrap|query sender|query receiver|process executionId>".into()),
    }
}
