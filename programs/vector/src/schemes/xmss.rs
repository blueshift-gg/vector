use pinocchio::error::ProgramError;
use solana_winternitz::{
    xmss::{Signature, LEAVES},
    VerifyingKey,
};

use crate::scheme::SigningScheme;

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
        let (public_key, next_leaf) = identity.split_at_mut(VerifyingKey::BYTE_LEN);
        public_key.copy_from_slice(key.as_bytes());
        next_leaf.fill(0);
        Ok(())
    }

    /// The same key as `next_key` keeps it, and its used leaves stay used.
    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &Signature,
        next_key: &VerifyingKey,
    ) -> Result<(), ProgramError> {
        if signature.leaf() < u32::from_le_bytes(self.next_leaf) {
            return Err(ProgramError::MissingRequiredSignature);
        }
        self.public_key
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)?;

        if *next_key != self.public_key {
            self.public_key = *next_key;
            self.next_leaf = [0; 4];
        } else if signature.leaf() + 1 < LEAVES {
            // Verified, so the leaf is one of the tree's and this cannot overflow.
            self.next_leaf = (signature.leaf() + 1).to_le_bytes();
        } else {
            // The tree is used up.
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }
}
