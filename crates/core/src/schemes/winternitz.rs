//! DKKW25 one-time Winternitz. Sign through `solana_winternitz::winternitz::SigningKey`:
//! each key permits one signing attempt, including failed salt sampling.

use solana_address::Address;
use solana_instruction::Instruction;
use solana_winternitz::{winternitz, PUBLIC_KEY_LEN};

use crate::{instructions::create_initialize_instruction, scheme::Scheme};

pub const WINTERNITZ_PUBKEY_LEN: usize = PUBLIC_KEY_LEN;
pub const WINTERNITZ_SIGNATURE_LEN: usize = winternitz::SIGNATURE_LEN;

/// The first key is the permanent identity. The account stores the key that
/// signs next, which changes as it rotates.
pub const WINTERNITZ: Scheme = Scheme {
    id: 6,
    signature_len: WINTERNITZ_SIGNATURE_LEN,
    identity_len: WINTERNITZ_PUBKEY_LEN,
    stored_identity_len: size_of::<vector::schemes::winternitz::Winternitz>(),
    next_key_len: WINTERNITZ_PUBKEY_LEN,
    next_key_optional: false,
};

/// Initialize a stable account with its first signing key.
pub fn create_initialize_winternitz(
    payer: &Address,
    public_key: &[u8; WINTERNITZ_PUBKEY_LEN],
) -> Instruction {
    create_initialize_instruction(payer, &WINTERNITZ, public_key, public_key)
}
