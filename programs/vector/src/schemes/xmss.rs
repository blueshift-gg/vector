use pinocchio::error::ProgramError;
use solana_winternitz::{xmss, VerifyingKey, PUBLIC_KEY_LEN};

use crate::scheme::SigningScheme;

/// DKKW25 XMSS. A key signs once per leaf of its tree, so a `Passthrough`
/// may keep it or replace it, and must replace it after the last leaf.
#[repr(C)]
pub struct Xmss {
    public_key: [u8; PUBLIC_KEY_LEN],
    /// The lowest leaf that may sign next (u32 LE). A signature moves it
    /// past its own leaf, so no leaf signs twice.
    next_leaf: [u8; 4],
}

unsafe impl SigningScheme for Xmss {
    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        let public_key: &[u8; PUBLIC_KEY_LEN] = key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        identity[..PUBLIC_KEY_LEN].copy_from_slice(public_key);
        identity[PUBLIC_KEY_LEN..].fill(0);
        Ok(())
    }

    fn signature_len(&self) -> usize {
        xmss::SIGNATURE_LEN
    }

    fn advance(&mut self, digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        let signature = xmss::Signature::ref_from_bytes(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if signature.leaf() < u32::from_le_bytes(self.next_leaf) {
            return Err(ProgramError::MissingRequiredSignature);
        }
        VerifyingKey::ref_from_bytes(&self.public_key)
            .map_err(|_| ProgramError::InvalidAccountData)?
            .verify(digest, signature)
            .map_err(|_| ProgramError::MissingRequiredSignature)?;
        // Verified, so the leaf is one of the tree's and this cannot overflow.
        self.next_leaf = (signature.leaf() + 1).to_le_bytes();
        Ok(())
    }

    fn spent(&self) -> bool {
        u32::from_le_bytes(self.next_leaf) >= xmss::LEAVES
    }

    /// The data starts with `0` to keep the key, or `1` and the key that
    /// signs next. The owner signed the whole transaction, the key included.
    fn passthrough<'a>(&mut self, data: &'a [u8]) -> Result<&'a [u8], ProgramError> {
        match data.split_first() {
            Some((0, instructions)) if !self.spent() => Ok(instructions),
            Some((1, data)) => {
                let (public_key, instructions) = data
                    .split_first_chunk()
                    .ok_or(ProgramError::InvalidInstructionData)?;
                // The same key again keeps its used leaves used.
                if self.public_key != *public_key {
                    self.public_key = *public_key;
                    self.next_leaf = [0; 4];
                }
                Ok(instructions)
            }
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
