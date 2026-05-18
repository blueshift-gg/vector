use brine_ed25519::{hasher::FastSha512, verify};
use pinocchio::error::ProgramError;
use solana_address::{bytes_are_curve_point, Address};
use vector_common::SigningScheme;

/// Ed25519. Identity is the 32-byte public key; signatures are 64-byte
/// `(R, s)` verified directly over the 32-byte advance digest.
pub struct Ed25519;

impl SigningScheme for Ed25519 {
    const SIGNATURE_LEN: usize = 64;
    const IDENTITY_LEN: usize = 32;
    const INIT_PAYLOAD_LEN: usize = 32;

    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        let pubkey: &[u8; 32] = payload
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if !bytes_are_curve_point(pubkey) {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity_out.copy_from_slice(pubkey);
        Ok(())
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        let sig: &[u8; 64] = signature
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let pubkey_bytes: &[u8; 32] = identity
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        // `solana_address::Address` is `#[repr(transparent)]` over `[u8; 32]`.
        let pubkey: &Address = unsafe { &*(pubkey_bytes.as_ptr() as *const Address) };
        verify::<FastSha512>(pubkey, sig, &[digest])
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}
