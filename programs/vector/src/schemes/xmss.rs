use pinocchio::error::ProgramError;
use solana_winternitz::{
    xmss::{Signature, LEAVES},
    VerifyingKey,
};

use crate::{
    error::VectorError,
    scheme::{write, SigningScheme},
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

    fn initialize(key: &VerifyingKey, identity: &mut [u8]) -> Result<(), ProgramError> {
        // A new account is zeroed, so its next leaf is 0.
        write(identity, key.as_bytes())
    }

    /// The same key as `next_key` keeps it, and its used leaves stay used.
    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &Signature,
        next_key: &VerifyingKey,
    ) -> Result<(), ProgramError> {
        if signature.leaf() < u32::from_le_bytes(self.next_leaf) {
            return Err(VectorError::LeafUsed.into());
        }
        self.public_key
            .verify(digest, signature)
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
