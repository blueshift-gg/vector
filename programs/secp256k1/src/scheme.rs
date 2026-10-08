use pinocchio::error::ProgramError;
use vector_common::{secp256k1_recover, SigningScheme};

const COMPRESSED_PUBKEY_LEN: usize = 33;

/// Plain secp256k1 ECDSA. Identity is the 33-byte sec1-compressed pubkey;
/// signatures are 64 bytes `(r, s)`.
///
/// Verified by public-key recovery: `(r, s)` is valid for `digest` under
/// `Q` exactly when `Q` is one of the keys `sol_secp256k1_recover` returns
/// for it, so recovering and comparing is standard ECDSA verification. The
/// wire carries no recovery id; id `0` is tried first, then `1`. Negating
/// `s` flips the id, so a signer that picks the `s` with id `0` pays for
/// one recovery.
pub struct Secp256k1Ecdsa;

impl SigningScheme for Secp256k1Ecdsa {
    const SIGNATURE_LEN: usize = 64;
    const IDENTITY_LEN: usize = COMPRESSED_PUBKEY_LEN;
    const INIT_PAYLOAD_LEN: usize = COMPRESSED_PUBKEY_LEN;

    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        if payload.len() != COMPRESSED_PUBKEY_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        // sec1 compressed pubkey: `0x02` (even y) or `0x03` (odd y) || x[32].
        if payload[0] != 0x02 && payload[0] != 0x03 {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity_out.copy_from_slice(payload);
        Ok(())
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        let sig: &[u8; 64] = signature
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if identity.len() != COMPRESSED_PUBKEY_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        // Ids 2 and 3 (`r` reduced past the group order) are skipped: such a
        // signature occurs with probability about 2^-128.
        for recovery_id in 0..2 {
            // A recovery error means no key exists for this id, not that
            // the other id has none.
            if let Ok(point) = secp256k1_recover(digest, recovery_id, sig) {
                // sec1 compression of `x || y`: `0x02 | (y & 1)`, then `x`.
                if identity[0] == 0x02 | (point[63] & 1) && identity[1..] == point[..32] {
                    return Ok(());
                }
            }
        }
        Err(ProgramError::MissingRequiredSignature)
    }
}
