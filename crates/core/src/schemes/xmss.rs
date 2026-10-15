//! DKKW25 generalized XMSS. Sign through `solana_winternitz::xmss::SigningKey`:
//! each key permits 256 signing attempts, including failed salt sampling.

use solana_address::Address;
use solana_instruction::Instruction;

use crate::{instructions::create_initialize_instruction, scheme::Scheme};

/// The first key is the permanent identity. The account stores the key that
/// signs next, which changes as it rotates.
pub const XMSS: Scheme = Scheme::of::<vector::schemes::xmss::Xmss>();

/// Initialize a stable account with its first signing key.
pub fn create_initialize_xmss(
    payer: &Address,
    public_key: &[u8; XMSS.identity_len],
) -> Instruction {
    create_initialize_instruction(payer, &XMSS, public_key)
}
