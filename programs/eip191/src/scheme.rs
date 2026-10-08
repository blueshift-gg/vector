use pinocchio::error::ProgramError;
use solana_nostd_keccak::{hash, hashv};
use vector_common::{secp256k1_recover, SigningScheme};

const ETH_ADDRESS_LEN: usize = 20;

/// secp256k1 ECDSA + EIP-191 ("Ethereum Signed Message") envelope. Identity
/// is the 20-byte Ethereum address; signatures are 65 bytes `(r, s, v)`. The
/// recovery id `v` rides in the signature carve-out so it is excluded from
/// the digest the client signs.
pub struct Secp256k1Eip191;

impl SigningScheme for Secp256k1Eip191 {
    const SIGNATURE_LEN: usize = 65;
    const IDENTITY_LEN: usize = ETH_ADDRESS_LEN;
    const INIT_PAYLOAD_LEN: usize = ETH_ADDRESS_LEN;

    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        let eth_addr: &[u8; ETH_ADDRESS_LEN] = payload
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if eth_addr == &[0u8; ETH_ADDRESS_LEN] {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity_out.copy_from_slice(eth_addr);
        Ok(())
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        if signature.len() != Self::SIGNATURE_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        if identity.len() != ETH_ADDRESS_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let rs: &[u8; 64] = signature[..64]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let v = signature[64];
        // EIP-191 personal message: keccak256("\x19Ethereum Signed
        // Message:\n32" || digest).
        let eth_digest = hashv(&[b"\x19Ethereum Signed Message:\n32", digest]);
        let recovered = secp256k1_recover(&eth_digest, v as u64, rs)?;
        let h = hash(&recovered);
        if h[12..32] == *identity {
            Ok(())
        } else {
            Err(ProgramError::MissingRequiredSignature)
        }
    }
}
