//! Plain secp256k1 ECDSA scheme: identity is the 33-byte sec1-compressed
//! pubkey, verified via standard ECDSA (no envelope, no recovery byte).

use pinocchio::error::ProgramError;
use solana_secp256k1::{CompressedPoint, Secp256k1Point, UncompressedPoint};
use solana_secp256k1_ecdsa::{hash::sha256::Sha256, Secp256k1EcdsaSignature};

use crate::scheme::{write, Scheme, SigningScheme, SIGNED_LEN};

/// Plain secp256k1 ECDSA, with no recovery, over the SHA-256 of `"vector:" ||
/// digest`. A signature is the 64-byte `(r, s)`.
#[repr(C)]
pub struct Secp256k1 {
    /// sec1-compressed: `0x02` or `0x03`, then the x coordinate.
    public_key: [u8; CompressedPoint::SIZE],
}

unsafe impl SigningScheme for Secp256k1 {
    const ID: u8 = 3;
    type Key = [u8; CompressedPoint::SIZE];
    type Signature = [u8; 64];
    type NextKey = [u8; 0];

    fn initialize(key: &Self::Key, identity: &mut [u8]) -> Result<(), ProgramError> {
        // The prefix, then that the x coordinate is on the curve: a key that
        // is not could never sign, and would hold the account for good.
        let point = CompressedPoint::try_from_sec1_bytes(key)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        UncompressedPoint::try_from(point).map_err(|_| ProgramError::InvalidInstructionData)?;
        write(identity, key)
    }

    fn advance(
        &mut self,
        signed: &[u8; SIGNED_LEN],
        signature: &[u8; 64],
        _next_key: &[u8; 0],
    ) -> Result<(), ProgramError> {
        Secp256k1EcdsaSignature(*signature)
            .verify::<Sha256, CompressedPoint>(signed, CompressedPoint(self.public_key))
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}

/// Plain secp256k1 ECDSA — identity is the 33-byte compressed pubkey.
pub const SECP256K1: Scheme = Scheme::of::<Secp256k1>();

#[cfg(feature = "client")]
pub use client::*;

#[cfg(feature = "client")]
mod client {
    #[allow(unused_imports)]
    use super::*;

    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as Secp256k1SigningKey};
    use sha2::{Digest, Sha256};
    use solana_address::Address;
    use solana_instruction::Instruction;

    use crate::digest::advance_vector_digest;
    use crate::instructions::{create_advance_instruction, create_initialize_instruction};
    use crate::scheme::signed;

    /// 33-byte sec1-compressed secp256k1 public key (the identity).
    pub fn secp256k1_compressed_pubkey(
        signing_key: &Secp256k1SigningKey,
    ) -> [u8; SECP256K1.identity_len] {
        let encoded = signing_key.verifying_key().to_encoded_point(true);
        encoded.as_bytes().try_into().expect("a compressed point")
    }

    /// Initialize a plain-secp256k1 (compressed-pubkey) ECDSA vector account.
    pub fn create_initialize_secp256k1_ecdsa(
        payer: &Address,
        compressed_pubkey: &[u8; SECP256K1.identity_len],
    ) -> Instruction {
        create_initialize_instruction(payer, &SECP256K1, compressed_pubkey)
    }

    /// Sign an advance with a plain secp256k1 key. Put any passthrough among
    /// `pre_instructions` or `post_instructions`, so the signature covers it.
    /// Pass `fee_payer` when it is also an account of one of those instructions.
    pub fn sign_advance_instruction_secp256k1_ecdsa(
        signing_key: &Secp256k1SigningKey,
        nonce: &[u8; 32],
        pre_instructions: &[Instruction],
        post_instructions: &[Instruction],
        fee_payer: Option<&Address>,
    ) -> Instruction {
        let identity = secp256k1_compressed_pubkey(signing_key);
        let digest = advance_vector_digest(
            &SECP256K1,
            nonce,
            &identity,
            pre_instructions,
            post_instructions,
            fee_payer,
        );
        let (sig, _recid) = signing_key
            .sign_prehash(&Sha256::digest(signed(&digest)))
            .expect("secp256k1 signing failed");
        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        create_advance_instruction(&SECP256K1, &identity, &sig_bytes)
    }

    /// Sign an advance with nothing around it. Landing it only moves the nonce,
    /// which cancels everything signed against the old one. It must be the only
    /// instruction of its transaction.
    pub fn sign_revocation_instruction_secp256k1_ecdsa(
        signing_key: &Secp256k1SigningKey,
        nonce: &[u8; 32],
    ) -> Instruction {
        sign_advance_instruction_secp256k1_ecdsa(signing_key, nonce, &[], &[], None)
    }
}
