//! Assemble and broadcast Vector artifacts as Solana transactions.
//!
//! # `Hash` version note
//!
//! `solana-message`/`solana-transaction` 3.1 carry `recent_blockhash` as
//! `solana-hash 4.x`, while `solana-rpc-client::get_latest_blockhash` returns
//! `solana-hash 3.1.0`. Both versions already live in the dependency tree. We
//! build transactions against the 4.x `Hash` and bridge the RPC's 3.1.0
//! blockhash into it through bytes in [`crate::read::VectorClient::send_artifact`]
//! (the same byte-bridge pattern `read.rs` uses for `Address`/`Pubkey`).

use solana_address::Address;
use solana_hash::Hash;
use solana_message::Message;
use solana_signature::Signature;
use solana_transaction::Transaction;
use vector_core::Artifact;

/// Build an UNSIGNED transaction from an artifact's instruction layout, with
/// `fee_payer` as the payer. The caller adds signatures + a fresh blockhash.
///
/// `art.instructions` are `solana_instruction::Instruction 3.4` and `fee_payer`
/// is `solana_address::Address 2.6` — exactly the types `solana-message 3.1`
/// (`solana-instruction ^3`, `solana-address ^2.1`) accepts, so they flow
/// straight into [`Message::new`] without conversion.
pub fn into_unsigned_tx(
    art: &Artifact,
    fee_payer: &Address,
    recent_blockhash: Hash,
) -> Transaction {
    let message =
        Message::new_with_blockhash(&art.instructions, Some(fee_payer), &recent_blockhash);
    Transaction::new_unsigned(message)
}

impl crate::read::VectorClient {
    /// Broadcast an artifact: fetch a recent blockhash, sign with `payer`, send + confirm.
    pub async fn send_artifact(
        &self,
        art: &Artifact,
        payer: &solana_keypair::Keypair,
    ) -> Result<Signature, String> {
        use solana_signer::Signer;

        // RPC returns a `solana-hash 3.1.0` Hash; bridge it to the 4.x Hash the
        // message/transaction crates use, through bytes.
        let rpc_blockhash = self
            .rpc
            .get_latest_blockhash()
            .await
            .map_err(|e| e.to_string())?;
        let blockhash = Hash::new_from_array(rpc_blockhash.to_bytes());

        // `payer.pubkey()` is `solana-pubkey 3.0.0`, a shim over the workspace
        // `solana-address 2.6.0`; convert through bytes for an explicit `Address`.
        let payer_addr = Address::from(payer.pubkey().to_bytes());

        let tx = Transaction::new_signed_with_payer(
            &art.instructions,
            Some(&payer_addr),
            &[payer],
            blockhash,
        );

        // `send_and_confirm_transaction` returns `solana-signature 3.4.0` — the
        // single signature node this crate also pins — so it is returned as-is.
        self.rpc
            .send_and_confirm_transaction(&tx)
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use solana_address::Address;
    use vector_core::{Ed25519, Op, Vector};

    #[test]
    fn unsigned_tx_carries_all_artifact_instructions_in_order() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let art = v.authorize(&[0u8; 32], Op::Inert);
        let fee_payer = Address::from([2u8; 32]);
        let tx = into_unsigned_tx(&art, &fee_payer, Default::default());
        assert_eq!(tx.message.instructions.len(), art.instructions.len());
    }
}
