//! DKKW25 generalized XMSS. Sign through `solana_winternitz::Signer`:
//! each key permits 256 signing attempts, including failed salt sampling.

use solana_address::{address, Address};
use solana_instruction::Instruction;
use solana_winternitz::{xmss, PUBLIC_KEY_LENGTH};

use crate::{instructions::create_initialize_instruction, scheme::Scheme};

pub const XMSS_PUBKEY_LEN: usize = PUBLIC_KEY_LENGTH;
pub const XMSS_SIGNATURE_LEN: usize = xmss::SIGNATURE_LENGTH;

/// The public key is stored verbatim; the PDA seed is its SHA-256 hash.
pub const XMSS: Scheme = Scheme {
    program_id: address!("7qCyy3NJQDMctSDiM4DxNjNR6TyasouyyRTBREhcXdsE"),
    signature_len: XMSS_SIGNATURE_LEN,
    identity_len: XMSS_PUBKEY_LEN,
    stored_identity_len: XMSS_PUBKEY_LEN,
};

/// Initialize an account with an immutable XMSS public key.
pub fn create_initialize_xmss(payer: &Address, public_key: &[u8; XMSS_PUBKEY_LEN]) -> Instruction {
    create_initialize_instruction(payer, &XMSS, public_key, public_key)
}
