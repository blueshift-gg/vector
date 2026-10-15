//! The program's own errors, returned as `ProgramError::Custom(code)`.
//! Every other failure is a `ProgramError` in its standard meaning: a bad
//! signature, for one, is `MissingRequiredSignature`.

use pinocchio::error::ProgramError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum VectorError {
    /// `Advance` or `Passthrough` ran inside another instruction. They read
    /// the transaction's top-level instructions, so they run only there.
    NotTopLevel,
    /// `Passthrough`: no `Advance` comes earlier, or the first one does not
    /// list a signer.
    NotAdvanced,
    /// Winternitz: the next key is the key that just signed.
    KeyReused,
    /// XMSS: the signature's leaf has signed before.
    LeafUsed,
    /// XMSS: the tree's last leaf signed, and the key was not replaced.
    TreeExhausted,
}

impl From<VectorError> for ProgramError {
    fn from(error: VectorError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
