//! Falcon-512. The identity is the 897-byte wire public key. Signing is left
//! to the caller, with `pqcrypto-falcon` or another Falcon signer.

use solana_address::Address;
use solana_falcon512::{FALCON_512_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN};
use solana_instruction::Instruction;

use crate::instructions::create_initialize_instruction;
use crate::scheme::Scheme;

pub const FALCON512_WIRE_PUBKEY_LEN: usize = FALCON_512_PUBKEY_LEN;
pub const FALCON512_SIGNATURE_LEN: usize = FALCON_512_SIGNATURE_LEN;

/// Falcon-512. The identity is the 897-byte wire public key; the account
/// stores its 1024-byte prepared form.
pub const FALCON512: Scheme = Scheme {
    id: 4,
    signature_len: FALCON512_SIGNATURE_LEN,
    identity_len: FALCON512_WIRE_PUBKEY_LEN,
    stored_identity_len: size_of::<vector::schemes::falcon512::Falcon512>(),
    next_key_len: 0,
    next_key_optional: false,
};

/// Initialize a Falcon-512 vector account. `wire_pubkey` is the standard
/// 897-byte Falcon public key; the on-chain program prepares it.
pub fn create_initialize_falcon512(
    payer: &Address,
    wire_pubkey: &[u8; FALCON512_WIRE_PUBKEY_LEN],
) -> Instruction {
    create_initialize_instruction(payer, &FALCON512, wire_pubkey)
}
