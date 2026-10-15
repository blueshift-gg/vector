//! DKKW25 one-time Winternitz. Sign through `solana_winternitz::winternitz::SigningKey`:
//! each key permits one signing attempt, including failed salt sampling.

use solana_address::Address;
use solana_instruction::Instruction;

use crate::{instructions::create_initialize_instruction, scheme::Scheme};

/// The first key is the permanent identity. The account stores the key that
/// signs next, which changes as it rotates.
pub const WINTERNITZ: Scheme = Scheme::of::<vector::schemes::winternitz::Winternitz>();

/// Initialize a stable account with its first signing key.
pub fn create_initialize_winternitz(
    payer: &Address,
    public_key: &[u8; WINTERNITZ.identity_len],
) -> Instruction {
    create_initialize_instruction(payer, &WINTERNITZ, public_key)
}
