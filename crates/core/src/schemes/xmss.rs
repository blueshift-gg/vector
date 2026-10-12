//! DKKW25 generalized XMSS. Sign through `solana_winternitz::xmss::SigningKey`:
//! each key permits 256 signing attempts, including failed salt sampling.

use solana_address::Address;
use solana_instruction::Instruction;
use solana_winternitz::{xmss, PUBLIC_KEY_LEN};

use crate::{instructions::create_initialize_instruction, scheme::Scheme};

pub const XMSS_PUBKEY_LEN: usize = PUBLIC_KEY_LEN;
pub const XMSS_SIGNATURE_LEN: usize = xmss::SIGNATURE_LEN;

/// The first key is the permanent identity. The account stores the key that
/// signs next, which changes as it rotates.
pub const XMSS: Scheme = Scheme {
    id: 7,
    signature_len: XMSS_SIGNATURE_LEN,
    identity_len: XMSS_PUBKEY_LEN,
    stored_identity_len: XMSS_PUBKEY_LEN,
    next_key_len: XMSS_PUBKEY_LEN,
    next_key_optional: true,
};

/// Initialize a stable account with its first signing key.
pub fn create_initialize_xmss(payer: &Address, public_key: &[u8; XMSS_PUBKEY_LEN]) -> Instruction {
    create_initialize_instruction(payer, &XMSS, public_key, public_key)
}
