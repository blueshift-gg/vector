//! DKKW25 one-time Winternitz. Sign through `solana_winternitz::Signer`:
//! each key permits one signing attempt, including failed salt sampling.

use solana_address::{address, Address};
use solana_instruction::Instruction;
use solana_winternitz::{winternitz, PUBLIC_KEY_LENGTH};

use crate::{instructions::create_initialize_instruction, scheme::Scheme};

pub const WINTERNITZ_PUBKEY_LEN: usize = PUBLIC_KEY_LENGTH;
pub const WINTERNITZ_SIGNATURE_LEN: usize = winternitz::SIGNATURE_LENGTH;

/// The public key is stored verbatim; the PDA seed is its SHA-256 hash.
pub const WINTERNITZ: Scheme = Scheme {
    program_id: address!("GvCGfvMTr8YZJZkV9KxaGF1Y2EzxUksur8iDwjVwJwGf"),
    signature_len: WINTERNITZ_SIGNATURE_LEN,
    identity_len: WINTERNITZ_PUBKEY_LEN,
    stored_identity_len: WINTERNITZ_PUBKEY_LEN,
};

/// Initialize an account with an immutable Winternitz public key.
pub fn create_initialize_winternitz(
    payer: &Address,
    public_key: &[u8; WINTERNITZ_PUBKEY_LEN],
) -> Instruction {
    create_initialize_instruction(payer, &WINTERNITZ, public_key, public_key)
}
