use pinocchio::error::ProgramError;
use solana_winternitz::{xmss, VerifyingKey, PUBLIC_KEY_LEN};

use crate::scheme::SigningScheme;

/// DKKW25 XMSS. A key signs once per leaf of its tree, so `Advance` may
/// keep it, and must replace it after the last leaf.
#[repr(C)]
pub struct Xmss {
    public_key: [u8; PUBLIC_KEY_LEN],
    /// The lowest leaf that may sign next (u32 LE). A signature moves it
    /// past its own leaf, so no leaf signs twice.
    next_leaf: [u8; 4],
}

unsafe impl SigningScheme for Xmss {
    const SIGNATURE_LEN: usize = xmss::SIGNATURE_LEN;
    const NEXT_KEY_LEN: usize = PUBLIC_KEY_LEN;

    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        let public_key: &[u8; PUBLIC_KEY_LEN] = key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        identity[..PUBLIC_KEY_LEN].copy_from_slice(public_key);
        identity[PUBLIC_KEY_LEN..].fill(0);
        Ok(())
    }

    /// The same key as `next_key` keeps it, and its used leaves stay used.
    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &[u8],
        next_key: &[u8],
    ) -> Result<(), ProgramError> {
        let next_key: [u8; PUBLIC_KEY_LEN] = next_key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let signature = xmss::Signature::ref_from_bytes(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if signature.leaf() < u32::from_le_bytes(self.next_leaf) {
            return Err(ProgramError::MissingRequiredSignature);
        }
        VerifyingKey::ref_from_bytes(&self.public_key)
            .map_err(|_| ProgramError::InvalidAccountData)?
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)?;

        if next_key != self.public_key {
            self.public_key = next_key;
            self.next_leaf = [0; 4];
        } else if signature.leaf() + 1 < xmss::LEAVES {
            // Verified, so the leaf is one of the tree's and this cannot overflow.
            self.next_leaf = (signature.leaf() + 1).to_le_bytes();
        } else {
            // The tree is used up.
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }
}
