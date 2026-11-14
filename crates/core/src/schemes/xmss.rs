//! DKKW25 generalized XMSS. Sign through `solana_xmss::SigningKey`:
//! each key permits 256 signing attempts, including failed salt sampling.

use pinocchio::error::ProgramError;
use solana_xmss::{Signature, VerifyingKey, LEAVES};

use solana_nostd_sha256::hash;

use crate::{
    error::VectorError,
    scheme::{write, Scheme, SigningScheme, SIGNED_LEN},
};

/// DKKW25 XMSS. A key signs once per leaf of its tree, so `Advance` may
/// keep it, and must replace it after the last leaf.
#[repr(C)]
pub struct Xmss {
    public_key: VerifyingKey,
    /// The lowest leaf that may sign next (u32 LE). A signature moves it
    /// past its own leaf, so no leaf signs twice.
    next_leaf: [u8; 4],
}

unsafe impl SigningScheme for Xmss {
    const ID: u8 = 7;
    type Key = VerifyingKey;
    type Signature = Signature;
    type NextKey = VerifyingKey;

    #[inline]
    fn initialize(key: &VerifyingKey, identity: &mut [u8]) -> Result<(), ProgramError> {
        // A new account is zeroed, so its next leaf is 0.
        write(identity, key.as_bytes())
    }

    /// The same key as `next_key` keeps it, and its used leaves stay used.
    #[inline]
    fn advance(
        &mut self,
        signed: &[u8; SIGNED_LEN],
        signature: &Signature,
        next_key: &VerifyingKey,
    ) -> Result<(), ProgramError> {
        if signature.leaf() < u32::from_le_bytes(self.next_leaf) {
            return Err(VectorError::LeafUsed.into());
        }
        self.public_key
            .verify(&hash(signed), signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)?;

        if *next_key != self.public_key {
            self.public_key = *next_key;
            self.next_leaf = [0; 4];
        } else {
            let next = signature
                .leaf()
                .checked_add(1)
                .filter(|next| *next < LEAVES)
                .ok_or(VectorError::TreeExhausted)?;
            self.next_leaf = next.to_le_bytes();
        }
        Ok(())
    }
}

/// The first key is the permanent identity. The account stores the key that
/// signs next, which changes as it rotates.
pub const XMSS: Scheme = Scheme::of::<Xmss>();

#[cfg(feature = "client")]
pub use client::*;

#[cfg(feature = "client")]
mod client {
    #[allow(unused_imports)]
    use super::*;

    use solana_address::Address;
    use solana_instruction::Instruction;

    use crate::instructions::create_initialize_instruction;

    /// Initialize a stable account with its first signing key.
    pub fn create_initialize_xmss(
        payer: &Address,
        public_key: &[u8; XMSS.identity_len],
    ) -> Instruction {
        create_initialize_instruction(payer, &XMSS, public_key)
    }
}
