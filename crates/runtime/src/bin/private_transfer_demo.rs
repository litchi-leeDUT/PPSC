use ppsc_core::{Commitment, DataId, ExecutionId, PublicBytes};
use ppsc_runtime::{
    private_transfer::{PrivateTransferProgram, PrivateTransferRequest},
    AssetId, FheAmount, FheBackend, PlaintextBackend, PrivateAccountId, RuntimeError,
};
use std::collections::BTreeMap;

struct Binding {
    data_id: DataId,
    slot: usize,
}

#[derive(Default)]
struct RuntimeNodeStorage {
    bindings: BTreeMap<[u8; 32], Binding>,
    objects: BTreeMap<DataId, Vec<Vec<u8>>>,
}

impl RuntimeNodeStorage {
    fn declare(&mut self, variable: [u8; 32], data_id: DataId, ciphertext: Vec<u8>) {
        self.objects.insert(data_id, vec![ciphertext]);
        self.bindings.insert(variable, Binding { data_id, slot: 0 });
    }

    fn load(&self, variable: &[u8; 32]) -> Result<PublicBytes, RuntimeError> {
        let binding = self
            .bindings
            .get(variable)
            .ok_or(RuntimeError::BalanceNotFound)?;
        let ciphertext = self
            .objects
            .get(&binding.data_id)
            .and_then(|slots| slots.get(binding.slot))
            .ok_or(RuntimeError::CorruptPersistence)?;
        Ok(PublicBytes::new(ciphertext.clone()))
    }

    fn advance_balances(
        &mut self,
        sender_variable: [u8; 32],
        receiver_variable: [u8; 32],
        output_id: DataId,
        sender_ciphertext: Vec<u8>,
        receiver_ciphertext: Vec<u8>,
    ) {
        self.objects
            .insert(output_id, vec![sender_ciphertext, receiver_ciphertext]);
        self.bindings.insert(
            sender_variable,
            Binding {
                data_id: output_id,
                slot: 0,
            },
        );
        self.bindings.insert(
            receiver_variable,
            Binding {
                data_id: output_id,
                slot: 1,
            },
        );
    }
}

fn authorized_open(
    storage: &RuntimeNodeStorage,
    variable: &[u8; 32],
    account: PrivateAccountId,
) -> Result<u128, Box<dyn std::error::Error>> {
    let ciphertext = storage.load(variable)?;
    Ok(PlaintextBackend.decrypt_for_owner(
        &FheAmount::from_bytes(ciphertext.into_vec()),
        account,
        PlaintextBackend::authorization_for_tests(),
    )?)
}

fn encrypt(
    value: u128,
    account: PrivateAccountId,
    asset: AssetId,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(PlaintextBackend
        .encrypt_amount(value, account, asset)?
        .as_bytes()
        .to_vec())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("write to string");
    }
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sender = PrivateAccountId::from_bytes([10; 32]);
    let receiver = PrivateAccountId::from_bytes([11; 32]);
    let asset = AssetId::from_bytes([12; 20]);
    let sender_variable = [7; 32];
    let receiver_variable = [8; 32];
    let minimum_variable = [9; 32];
    let amount_variable = [13; 32];
    let sender_id = DataId::from_bytes([1; 32]);
    let receiver_id = DataId::from_bytes([2; 32]);
    let minimum_id = DataId::from_bytes([3; 32]);
    let amount_id = DataId::from_bytes([4; 32]);

    // Runtime bootstrap: users do not define bindings or put plaintext on chain.
    let mut storage = RuntimeNodeStorage::default();
    storage.declare(sender_variable, sender_id, encrypt(100, sender, asset)?);
    storage.declare(
        receiver_variable,
        receiver_id,
        encrypt(20, receiver, asset)?,
    );
    storage.declare(minimum_variable, minimum_id, encrypt(50, sender, asset)?);
    storage.declare(amount_variable, amount_id, encrypt(30, sender, asset)?);

    let sender_before = authorized_open(&storage, &sender_variable, sender)?;
    let receiver_before = authorized_open(&storage, &receiver_variable, receiver)?;
    println!(
        "balance query before (authorized opening): sender={sender_before}, receiver={receiver_before}"
    );

    let request = PrivateTransferRequest {
        execution_id: ExecutionId::from_bytes([6; 32]),
        old_state_root: Commitment::from_bytes([5; 32]),
        sender_variable_address: sender_variable,
        receiver_variable_address: receiver_variable,
        sender_account: sender,
        receiver_account: receiver,
        asset,
        sender_balance_data_id: sender_id,
        receiver_balance_data_id: receiver_id,
        minimum_balance_data_id: minimum_id,
        amount_data_id: amount_id,
    };
    println!("invoke condition: sender > minimum, then transfer encrypted amount");
    let output = PrivateTransferProgram::new(PlaintextBackend).evaluate(
        &request,
        storage.load(&sender_variable)?,
        storage.load(&receiver_variable)?,
        storage.load(&minimum_variable)?,
        storage.load(&amount_variable)?,
    )?;

    // Mirrors committee-signed ControlPlane.updateStateVariablesAfterResult.
    storage.advance_balances(
        sender_variable,
        receiver_variable,
        output.output_data_id,
        output.sender_ciphertext.as_slice().to_vec(),
        output.receiver_ciphertext.as_slice().to_vec(),
    );
    let sender_after = authorized_open(&storage, &sender_variable, sender)?;
    let receiver_after = authorized_open(&storage, &receiver_variable, receiver)?;
    println!("program: C2S -> MPC(gt,conditional_sub_add) -> S2C");
    println!(
        "balance query after (authorized opening): sender={sender_after}, receiver={receiver_after}"
    );
    println!("output_data_id={}", hex(output.output_data_id.as_bytes()));
    println!(
        "output_commitment={}",
        hex(output.output_commitment.as_bytes())
    );
    println!("new_state_root={}", hex(output.new_state_root.as_bytes()));
    println!("transcript_root={}", hex(output.transcript_root.as_bytes()));
    Ok(())
}
