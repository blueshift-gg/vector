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
    const ID: u8 = 2;
    type Key = [u8; 20];
    type Signature = [u8; 65];
    type NextKey = [u8; 0];

    fn initialize(key: &[u8; 20], identity: &mut [u8]) -> Result<(), ProgramError> {
        if key == &[0; 20] {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity.copy_from_slice(key);
        Ok(())
    }

    fn advance(
        &mut self,
        digest: &[u8; 32],
        signature: &[u8; 65],
        _next_key: &[u8; 0],
    ) -> Result<(), ProgramError> {
        let [rs @ .., v] = signature;
        let signed = hashv(&[b"\x19Ethereum Signed Message:\n32", digest]);
        let public_key =
            secp256k1_recover(&signed, *v, rs).ok_or(ProgramError::MissingRequiredSignature)?;
        if hash(&public_key)[12..] == self.address {
            Ok(())
        } else {
            Err(ProgramError::MissingRequiredSignature)
        }
    }
}

/// `sol_secp256k1_recover`: the 64-byte public key (`x || y`) that made
/// `signature` over `hash`. Off chain, what the runtime runs for it, which
/// accepts a high-S signature.
fn secp256k1_recover(hash: &[u8; 32], recovery_id: u8, signature: &[u8; 64]) -> Option<[u8; 64]> {
    #[cfg(target_os = "solana")]
    {
        let mut public_key = core::mem::MaybeUninit::<[u8; 64]>::uninit();
        // SAFETY: the syscall reads 32 and 64 bytes and writes 64.
        let rc = unsafe {
            pinocchio::syscalls::sol_secp256k1_recover(
                hash.as_ptr(),
                recovery_id.into(),
                signature.as_ptr(),
                public_key.as_mut_ptr().cast(),
            )
        };
        // SAFETY: on success the syscall wrote all 64 bytes.
        (rc == 0).then(|| unsafe { public_key.assume_init() })
    }

    #[cfg(not(target_os = "solana"))]
    {
        let recovery_id = libsecp256k1::RecoveryId::parse(recovery_id).ok()?;
        let signature = libsecp256k1::Signature::parse_standard(signature).ok()?;
        let public_key = libsecp256k1::recover(
            &libsecp256k1::Message::parse(hash),
            &signature,
            &recovery_id,
        )
        .ok()?;
        public_key.serialize()[1..].try_into().ok()
    }
}
