//! Real confidential transfer executor: chains BFV + Multiparty + `Fr` Shamir + MPC comparison
//! into one loop "encrypted balance → H2S → conditional transfer → S2H → encrypted balance".
//!
//! Simulates multiple parties in one process (3 Multiparty keys, Shamir committee t=2/n=5); the
//! secret never leaves the process and is never serialized. A production deployment must split the
//! roles onto separate nodes and coordinate them through the protocol engine / network.

use ark_bn254::Fr;
use ppsc_crypto::mpc::{
    conditional_transfer_strictly_greater, generate_bit_extract_pair, Committee, F2,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::bfv_shamir::{bfv_share_plaintext, bfv_shares_to_ciphertext};
use crate::{Ciphertext, CkksContext, KeyPair};

pub struct RealTransferExecutor {
    ctx: CkksContext,
    party_keys: Vec<KeyPair>,
    committee_f: Committee<Fr>,
    committee_b: Committee<F2>,
    rng: StdRng,
}

impl Default for RealTransferExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl RealTransferExecutor {
    pub fn new() -> Self {
        let ctx = CkksContext::bfv_new(2, 8).expect("bfv context");
        let mut party_keys = vec![ctx.multiparty_keygen_first().expect("kp1")];
        for _ in 1..3 {
            let kp = ctx
                .multiparty_keygen_next_kp(party_keys.last().expect("last kp"))
                .expect("next kp");
            party_keys.push(kp);
        }
        let committee_f = Committee::<Fr>::new(2, 5).expect("committee f");
        let committee_b = Committee::<F2>::new(2, 5).expect("committee b");
        let rng = StdRng::seed_from_u64(0xDEAD_BEEF);
        Self {
            ctx,
            party_keys,
            committee_f,
            committee_b,
            rng,
        }
    }

    /// The aggregate public key (the last party of Multiparty key generation).
    fn agg_key(&self) -> &KeyPair {
        self.party_keys.last().expect("aggregate key")
    }

    /// Encrypt a balance vector (padded to BFV batch=8).
    pub fn encrypt_balance(&self, amounts: &[u128]) -> Ciphertext {
        let mut data: Vec<i64> = amounts.iter().map(|&a| a as i64).collect();
        data.resize(8, 0);
        self.ctx
            .bfv_encrypt_int(self.agg_key(), &data)
            .expect("encrypt balance")
    }

    /// Multiparty-decrypt a balance vector (returns batch=8 plaintext).
    pub fn decrypt_balance(&self, ct: &Ciphertext) -> Vec<u128> {
        self.ctx
            .bfv_multiparty_decrypt(ct, &self.party_keys, 8)
            .expect("decrypt balance")
            .iter()
            .map(|&x| x as u128)
            .collect()
    }

    /// Multiparty-decrypt a single slot (batch=1 ciphertext).
    pub fn decrypt_single(&self, ct: &Ciphertext) -> u128 {
        self.ctx
            .bfv_multiparty_decrypt(ct, &self.party_keys, 1)
            .expect("decrypt single")[0] as u128
    }

    /// Conditional transfer: the first 4 slots of `packed` are sender / receiver / minimum / amount.
    /// Returns `(sender', receiver')`, two batch=1 ciphertexts (updated balances).
    pub fn transfer(&mut self, packed: &Ciphertext) -> (Ciphertext, Ciphertext) {
        // H2S: Multiparty decryption + Fr Shamir sharing.
        let shares = bfv_share_plaintext(
            &self.ctx,
            packed,
            &self.party_keys,
            &self.committee_f,
            8,
            &mut self.rng,
        )
        .expect("h2s");

        // MPC secret comparison + conditional transfer.
        let pair = generate_bit_extract_pair(&self.committee_f, &self.committee_b, &mut self.rng)
            .expect("pair");
        let (sender_new, receiver_new) = conditional_transfer_strictly_greater(
            &shares[0],
            &shares[1],
            &shares[2],
            &shares[3],
            &pair,
            &self.committee_f,
            &self.committee_b,
            &mut self.rng,
        )
        .expect("transfer");

        // S2H: Fr sharing → BFV.
        let sender_ct =
            bfv_shares_to_ciphertext(&self.ctx, self.agg_key(), &[sender_new], &self.committee_f)
                .expect("s2h sender");
        let receiver_ct = bfv_shares_to_ciphertext(
            &self.ctx,
            self.agg_key(),
            &[receiver_new],
            &self.committee_f,
        )
        .expect("s2h receiver");
        (sender_ct, receiver_ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_confidential_transfer_loop() {
        let mut executor = RealTransferExecutor::new();

        // deposit: sender=100, receiver=20; transfer parameters minimum=50, amount=30.
        let packed = executor.encrypt_balance(&[100, 20, 50, 30]);

        // transfer: sender(100) > minimum(50), move amount(30).
        let (sender_ct, receiver_ct) = executor.transfer(&packed);

        assert_eq!(executor.decrypt_single(&sender_ct), 70);
        assert_eq!(executor.decrypt_single(&receiver_ct), 50);
    }

    #[test]
    fn demo_no_transfer_when_below_minimum() {
        let mut executor = RealTransferExecutor::new();

        // sender=40 <= minimum=50, no transfer should happen.
        let packed = executor.encrypt_balance(&[40, 20, 50, 30]);
        let (sender_ct, receiver_ct) = executor.transfer(&packed);

        assert_eq!(executor.decrypt_single(&sender_ct), 40);
        assert_eq!(executor.decrypt_single(&receiver_ct), 20);
    }
}
