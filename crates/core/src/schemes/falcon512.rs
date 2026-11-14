//! Falcon-512. The identity is the 897-byte wire public key. Signing is left
//! to the caller, with `pqcrypto-falcon` or another Falcon signer.

use core::mem::offset_of;

use pinocchio::error::ProgramError;
use solana_falcon512::{
    Falcon512PreparedPubkey, Falcon512Pubkey, Falcon512Signature, FALCON_512_PREPARED_PUBKEY_LEN,
};

use crate::{
    scheme::{write, Scheme, SigningScheme, SIGNED_LEN},
    state::VectorAccount,
};

/// Falcon-512. The key is given in its 897-byte wire form; a signature is
/// the compressed form, zero-padded to 666 bytes.
#[repr(C)]
pub struct Falcon512 {
    /// The key with its NTT done, so that verifying does not redo it.
    prepared: [u8; FALCON_512_PREPARED_PUBKEY_LEN],
}

/// The prepared key is read in place, as 16-bit coefficients, so it must sit
/// at an even offset in the account. Account data is 8-byte aligned.
const _: () =
    assert!((VectorAccount::HEADER_LEN + offset_of!(Falcon512, prepared)).is_multiple_of(2));

unsafe impl SigningScheme for Falcon512 {
    const ID: u8 = 4;
    type Key = Falcon512Pubkey;
    type Signature = Falcon512Signature;
    type NextKey = [u8; 0];

    #[inline]
    fn initialize(key: &Falcon512Pubkey, identity: &mut [u8]) -> Result<(), ProgramError> {
        let prepared = key
            .try_prepare_pubkey()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        write(identity, prepared.as_bytes())
    }

    fn advance(
        &mut self,
        signed: &[u8; SIGNED_LEN],
        signature: &Falcon512Signature,
        _next_key: &[u8; 0],
    ) -> Result<(), ProgramError> {
        let prepared = Falcon512PreparedPubkey::<false>::try_from_slice(&self.prepared)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        if signature.verify_with_prepared(signed, prepared) {
            Ok(())
        } else {
            Err(ProgramError::MissingRequiredSignature)
        }
    }
}

/// Falcon-512. The identity is the 897-byte wire public key; the account
/// stores its 1024-byte prepared form.
pub const FALCON512: Scheme = Scheme::of::<Falcon512>();

#[cfg(feature = "client")]
pub use client::*;

#[cfg(feature = "client")]
mod client {
    #[allow(unused_imports)]
    use super::*;

    use solana_address::Address;
    use solana_instruction::Instruction;

    use crate::instructions::create_initialize_instruction;

    /// Initialize a Falcon-512 vector account. `wire_pubkey` is the standard
    /// 897-byte Falcon public key; the on-chain program prepares it.
    pub fn create_initialize_falcon512(
        payer: &Address,
        wire_pubkey: &[u8; FALCON512.identity_len],
    ) -> Instruction {
        create_initialize_instruction(payer, &FALCON512, wire_pubkey)
    }
}
