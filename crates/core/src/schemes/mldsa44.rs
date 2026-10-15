//! ML-DSA-44 with an empty FIPS 204 context. Sign with an external signer.
//! Registration is three `initialize` instructions in one transaction.

use solana_address::Address;
use solana_instruction::Instruction;

use crate::instructions::create_initialize_instructions;
use crate::scheme::Scheme;

/// The public key is the client identity; the account also holds its prepared form.
pub const MLDSA44: Scheme = Scheme::of::<vector::schemes::mldsa44::MlDsa44>();

/// Create an ML-DSA-44 account: three `initialize` instructions, for one
/// transaction.
pub fn create_initialize_mldsa44(
    payer: &Address,
    public_key: &[u8; MLDSA44.identity_len],
) -> Vec<Instruction> {
    create_initialize_instructions(payer, &MLDSA44, public_key)
}
