use pinocchio::error::ProgramError;
use solana_nostd_keccak::{hash, hashv};

use crate::scheme::SigningScheme;

/// secp256k1 ECDSA in an EIP-191 "Ethereum Signed Message" envelope, so any
/// Ethereum wallet's `personal_sign` produces a signature. A signature is
/// the 65-byte `(r, s, v)`; `v` is the recovery id, 0 or 1.
#[repr(C)]
pub struct Eip191 {
    /// The Ethereum address: the last 20 bytes of the public key's keccak.
    address: [u8; 20],
}

unsafe impl SigningScheme for Eip191 {
    const SIGNATURE_LEN: usize = 65;

    fn initialize(key: &[u8], identity: &mut [u8]) -> Result<(), ProgramError> {
        let address: &[u8; 20] = key
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if address == &[0; 20] {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity.copy_from_slice(address);
        Ok(())
    }

    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &[u8],
        _next_key: &[u8],
    ) -> Result<(), ProgramError> {
        let (rs, v) = signature
            .split_first_chunk::<64>()
            .filter(|(_, v)| v.len() == 1)
            .ok_or(ProgramError::InvalidInstructionData)?;

        let signed = hashv(&[b"\x19Ethereum Signed Message:\n32", digest]);
        let public_key = secp256k1_recover(&signed, v[0] as u64, rs)?;
        if hash(&public_key)[12..] == self.address {
            Ok(())
        } else {
            Err(ProgramError::MissingRequiredSignature)
        }
    }
}

/// Recover the 64-byte uncompressed secp256k1 public key (`x || y`) from a
/// 32-byte message hash, 64-byte signature, and recovery id (0 or 1) via the
/// `sol_secp256k1_recover` syscall (re-exported by pinocchio).
fn secp256k1_recover(
    hash: &[u8; 32],
    recovery_id: u64,
    signature: &[u8; 64],
) -> Result<[u8; 64], ProgramError> {
    #[allow(unused_mut)]
    let mut result = core::mem::MaybeUninit::<[u8; 64]>::uninit();

    #[cfg(target_os = "solana")]
    {
        let rc = unsafe {
            pinocchio::syscalls::sol_secp256k1_recover(
                hash.as_ptr(),
                recovery_id,
                signature.as_ptr(),
                result.as_mut_ptr() as *mut u8,
            )
        };
        if rc != 0 {
            return Err(ProgramError::InvalidArgument);
        }
        // SAFETY: the syscall wrote all 64 bytes on success (rc == 0).
        Ok(unsafe { result.assume_init() })
    }

    #[cfg(not(target_os = "solana"))]
    {
        let _ = (hash, recovery_id, signature, &result);
        Err(ProgramError::InvalidArgument)
    }
}
