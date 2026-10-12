//! ML-DSA-44 with an empty FIPS 204 context. Sign with an external signer.
//! Registration is Initialize followed by two Expand instructions.

use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_ml_dsa::ml_dsa_44::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

use crate::instructions::create_initialize_instruction;
use crate::scheme::{find_vector_pda, Scheme, PROGRAM_ID};

pub const MLDSA44_PUBKEY_LEN: usize = PUBLIC_KEY_LEN;
pub const MLDSA44_SIGNATURE_LEN: usize = SIGNATURE_LEN;
/// `expand` instructions after `initialize` to reach the full account.
pub const MLDSA44_EXPAND_STEPS: usize = 2;
pub const MLDSA44_EXPAND_DISCRIMINATOR: u8 = *vector::Expand::DISCRIMINATOR;

/// The public key is the client identity; the account also holds its prepared form.
pub const MLDSA44: Scheme = Scheme {
    id: 5,
    signature_len: MLDSA44_SIGNATURE_LEN,
    identity_len: MLDSA44_PUBKEY_LEN,
    stored_identity_len: size_of::<vector::schemes::mldsa44::MlDsa44>(),
    next_key_len: 0,
    next_key_optional: false,
};

/// Create an ML-DSA-44 account. It is created short: follow with
/// [`MLDSA44_EXPAND_STEPS`] [`create_expand_mldsa44`] instructions, in the
/// same transaction or later.
pub fn create_initialize_mldsa44(
    payer: &Address,
    public_key: &[u8; MLDSA44_PUBKEY_LEN],
) -> Instruction {
    create_initialize_instruction(payer, &MLDSA44, public_key)
}

/// Grow the account by one step. Anyone can send it; it fails once the
/// account is complete.
pub fn create_expand_mldsa44(public_key: &[u8; MLDSA44_PUBKEY_LEN]) -> Instruction {
    let (vector, _bump) = find_vector_pda(&MLDSA44, public_key);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new(vector, false)],
        data: vec![MLDSA44_EXPAND_DISCRIMINATOR],
    }
}
