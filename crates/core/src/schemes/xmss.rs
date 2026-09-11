//! DKKW25 generalized XMSS. Sign through `solana_winternitz::Signer`:
//! each key permits 256 signing attempts, including failed salt sampling.

use sha2::{Digest, Sha256};
use solana_address::{address, Address};
use solana_instruction::Instruction;
use solana_winternitz::{xmss, PUBLIC_KEY_LENGTH};

use crate::{instructions::create_initialize_instruction, scheme::Scheme};

pub const XMSS_PUBKEY_LEN: usize = PUBLIC_KEY_LENGTH;
pub const XMSS_SIGNATURE_LEN: usize = xmss::SIGNATURE_LENGTH;

/// The initial key hash is the permanent identity; the current key follows it.
pub const XMSS: Scheme = Scheme {
    program_id: address!("7qCyy3NJQDMctSDiM4DxNjNR6TyasouyyRTBREhcXdsE"),
    signature_len: XMSS_SIGNATURE_LEN,
    identity_len: 32,
    stored_identity_len: 32 + XMSS_PUBKEY_LEN,
};

/// Derive the permanent account identity. Do not recompute it on rotation.
pub fn xmss_identity(initial_public_key: &[u8; XMSS_PUBKEY_LEN]) -> [u8; 32] {
    Sha256::digest(initial_public_key).into()
}

/// Initialize a stable account with its first signing key.
pub fn create_initialize_xmss(payer: &Address, public_key: &[u8; XMSS_PUBKEY_LEN]) -> Instruction {
    create_initialize_instruction(payer, &XMSS, &xmss_identity(public_key), public_key)
}
