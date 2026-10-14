//! ML-DSA-44 with an empty FIPS 204 context. Sign with an external signer.
//! Registration is three `initialize` instructions in one transaction.

use solana_address::Address;
use solana_instruction::Instruction;
use solana_ml_dsa::ml_dsa_44::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

use crate::instructions::create_initialize_instructions;
use crate::scheme::Scheme;

pub const MLDSA44_PUBKEY_LEN: usize = PUBLIC_KEY_LEN;
pub const MLDSA44_SIGNATURE_LEN: usize = SIGNATURE_LEN;

/// The public key is the client identity; the account also holds its prepared form.
pub const MLDSA44: Scheme = Scheme {
    id: 5,
    signature_len: MLDSA44_SIGNATURE_LEN,
    identity_len: MLDSA44_PUBKEY_LEN,
    stored_identity_len: size_of::<vector::schemes::mldsa44::MlDsa44>(),
    next_key_len: 0,
};

/// Create an ML-DSA-44 account: three `initialize` instructions, for one
/// transaction.
pub fn create_initialize_mldsa44(
    payer: &Address,
    public_key: &[u8; MLDSA44_PUBKEY_LEN],
) -> Vec<Instruction> {
    create_initialize_instructions(payer, &MLDSA44, public_key)
}
