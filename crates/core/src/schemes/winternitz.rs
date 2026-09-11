//! DKKW25 one-time Winternitz. Sign through `solana_winternitz::Signer`:
//! each key permits one signing attempt, including failed salt sampling.

use sha2::{Digest, Sha256};
use solana_address::{address, Address};
use solana_instruction::Instruction;
use solana_winternitz::{winternitz, PUBLIC_KEY_LENGTH};

use crate::{instructions::create_initialize_instruction, scheme::Scheme};

pub const WINTERNITZ_PUBKEY_LEN: usize = PUBLIC_KEY_LENGTH;
pub const WINTERNITZ_SIGNATURE_LEN: usize = winternitz::SIGNATURE_LENGTH;

/// The initial key hash is the permanent identity; the current key follows it.
pub const WINTERNITZ: Scheme = Scheme {
    program_id: address!("GvCGfvMTr8YZJZkV9KxaGF1Y2EzxUksur8iDwjVwJwGf"),
    signature_len: WINTERNITZ_SIGNATURE_LEN,
    identity_len: 32,
    stored_identity_len: 32 + WINTERNITZ_PUBKEY_LEN,
};

/// Derive the permanent account identity. Do not recompute it on rotation.
pub fn winternitz_identity(initial_public_key: &[u8; WINTERNITZ_PUBKEY_LEN]) -> [u8; 32] {
    Sha256::digest(initial_public_key).into()
}

/// Initialize a stable account with its first signing key.
pub fn create_initialize_winternitz(
    payer: &Address,
    public_key: &[u8; WINTERNITZ_PUBKEY_LEN],
) -> Instruction {
    create_initialize_instruction(
        payer,
        &WINTERNITZ,
        &winternitz_identity(public_key),
        public_key,
    )
}
