//! ML-DSA-44 with an empty FIPS 204 context. Sign with an external signer.
//! Registration is Initialize followed by two Expand instructions.

use solana_address::{address, Address};
use solana_instruction::{AccountMeta, Instruction};
use solana_ml_dsa::ml_dsa_44::{PreparedVerifyingKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};

use crate::instructions::create_initialize_instruction;
use crate::scheme::{find_vector_pda, Scheme};

pub const MLDSA44_PUBKEY_LEN: usize = PUBLIC_KEY_LEN;
pub const MLDSA44_SIGNATURE_LEN: usize = SIGNATURE_LEN;
/// `pk[1312] || pad[3] || PreparedKey[20,544]`.
pub const MLDSA44_STORED_IDENTITY_LEN: usize =
    MLDSA44_PUBKEY_LEN + 3 + PreparedVerifyingKey::<false>::BYTE_LEN;
/// `expand` instructions after `initialize` to reach the full account.
pub const MLDSA44_EXPAND_STEPS: usize = 2;
pub const MLDSA44_EXPAND_DISCRIMINATOR: u8 = 6;

/// The public key is the client identity; the account also holds its prepared form.
pub const MLDSA44: Scheme = Scheme {
    program_id: address!("5qR1iCC5hinGAR9iE8dp5xJyh3Wq1Cwsxa4BuBuJieMr"),
    signature_len: MLDSA44_SIGNATURE_LEN,
    identity_len: MLDSA44_PUBKEY_LEN,
    stored_identity_len: MLDSA44_STORED_IDENTITY_LEN,
};

/// Initialize an ML-DSA-44 vector account with the standard public key.
/// Creates the first 10,240 bytes; follow with [`MLDSA44_EXPAND_STEPS`]
/// [`create_expand_mldsa44`] instructions, in the same transaction or later.
pub fn create_initialize_mldsa44(
    payer: &Address,
    public_key: &[u8; MLDSA44_PUBKEY_LEN],
) -> Instruction {
    create_initialize_instruction(payer, &MLDSA44, public_key, public_key)
}

/// Grow the vector account by one 10,240-byte step and expand the rows that
/// fit. Permissionless and deterministic; fails once the account is complete.
///
/// Accounts: `[vector_pda(writable)]`. Data: `[MLDSA44_EXPAND_DISCRIMINATOR]`.
pub fn create_expand_mldsa44(public_key: &[u8; MLDSA44_PUBKEY_LEN]) -> Instruction {
    let (vector, _bump) = find_vector_pda(&MLDSA44, public_key);
    Instruction {
        program_id: MLDSA44.program_id,
        accounts: vec![AccountMeta::new(vector, false)],
        data: vec![MLDSA44_EXPAND_DISCRIMINATOR],
    }
}
