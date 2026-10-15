//! Falcon-512. The identity is the 897-byte wire public key. Signing is left
//! to the caller, with `pqcrypto-falcon` or another Falcon signer.

use solana_address::Address;
use solana_instruction::Instruction;

use crate::instructions::create_initialize_instruction;
use crate::scheme::Scheme;

/// Falcon-512. The identity is the 897-byte wire public key; the account
/// stores its 1024-byte prepared form.
pub const FALCON512: Scheme = Scheme::of::<vector::schemes::falcon512::Falcon512>();

/// Initialize a Falcon-512 vector account. `wire_pubkey` is the standard
/// 897-byte Falcon public key; the on-chain program prepares it.
pub fn create_initialize_falcon512(
    payer: &Address,
    wire_pubkey: &[u8; FALCON512.identity_len],
) -> Instruction {
    create_initialize_instruction(payer, &FALCON512, wire_pubkey)
}
