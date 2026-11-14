//! Ed25519 scheme: identity is the 32-byte public key, verified directly
//! over `"vector:" || digest`.

use brine_ed25519::{hasher::FastSha512, verify};
use pinocchio::error::ProgramError;
use solana_address::{bytes_are_curve_point, Address};

use crate::scheme::{write, Scheme, SigningScheme, SIGNED_LEN};

/// The eight points of order dividing 8, in their canonical encodings. A key
/// that is one of them cannot sign (its signatures never verify, or, for the
/// non-canonical encodings of them, anyone can forge one), so it would hold
/// the account for good or for anyone.
const SMALL_ORDER: [[u8; 32]; 8] = [
    // Order 1: (0, 1).
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // Order 2: (0, -1).
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // Order 4: (+-sqrt(-1), 0).
    [0; 32],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0x80,
    ],
    // Order 8.
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0xfa,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x85,
    ],
];

/// Whether the encoding's y coordinate (the low 255 bits) is at least
/// p = 2^255 - 19: a second encoding of a point with a small y.
fn y_not_reduced(key: &[u8; 32]) -> bool {
    key[31] & 0x7f == 0x7f && key[1..31].iter().all(|&b| b == 0xff) && key[0] >= 0xed
}

/// Ed25519. A signature is the 64-byte `(R, s)`, over `"vector:" || digest`.
#[repr(C)]
pub struct Ed25519 {
    public_key: Address,
}

unsafe impl SigningScheme for Ed25519 {
    const ID: u8 = 1;
    type Key = Address;
    type Signature = [u8; 64];
    type NextKey = [u8; 0];

    #[inline]
    fn initialize(key: &Address, identity: &mut [u8]) -> Result<(), ProgramError> {
        // A point, in its one canonical encoding, of large order.
        if !bytes_are_curve_point(key)
            || y_not_reduced(key.as_array())
            || SMALL_ORDER.contains(key.as_array())
        {
            return Err(ProgramError::InvalidInstructionData);
        }
        write(identity, key.as_array())
    }

    #[inline]
    fn advance(
        &mut self,
        signed: &[u8; SIGNED_LEN],
        signature: &[u8; 64],
        _next_key: &[u8; 0],
    ) -> Result<(), ProgramError> {
        verify::<FastSha512>(&self.public_key, signature, &[signed])
            .map_err(|_| ProgramError::MissingRequiredSignature)
    }
}

/// Ed25519 — identity is the 32-byte public key.
pub const ED25519: Scheme = Scheme::of::<Ed25519>();

#[cfg(feature = "client")]
pub use client::*;

#[cfg(feature = "client")]
mod client {
    #[allow(unused_imports)]
    use super::*;

    use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
    use solana_address::Address;
    use solana_instruction::Instruction;

    use crate::digest::advance_vector_digest;
    use crate::instructions::{create_advance_instruction, create_initialize_instruction};
    use crate::scheme::signed;

    /// 32-byte Ed25519 public key (the identity) for a signing key.
    pub fn ed25519_pubkey(signing_key: &SigningKey) -> [u8; ED25519.identity_len] {
        signing_key.verifying_key().to_bytes()
    }

    /// Initialize an Ed25519 vector account. `pubkey` is the 32-byte public key.
    pub fn create_initialize_ed25519(
        payer: &Address,
        pubkey: &[u8; ED25519.identity_len],
    ) -> Instruction {
        create_initialize_instruction(payer, &ED25519, pubkey)
    }

    /// Sign an advance with an Ed25519 key. Put any passthrough among
    /// `pre_instructions` or `post_instructions`, so the signature covers it.
    /// Pass `fee_payer` when it is also an account of one of those instructions.
    pub fn sign_advance_instruction_ed25519(
        signing_key: &SigningKey,
        nonce: &[u8; 32],
        pre_instructions: &[Instruction],
        post_instructions: &[Instruction],
        fee_payer: Option<&Address>,
    ) -> Instruction {
        let identity = ed25519_pubkey(signing_key);
        let digest = advance_vector_digest(
            &ED25519,
            nonce,
            &identity,
            pre_instructions,
            post_instructions,
            fee_payer,
        );
        let signature: [u8; 64] = signing_key.sign(&signed(&digest)).to_bytes();
        create_advance_instruction(&ED25519, &identity, &signature)
    }

    /// Sign an advance with nothing around it. Landing it only moves the nonce,
    /// which cancels everything signed against the old one. It must be the only
    /// instruction of its transaction.
    pub fn sign_revocation_instruction_ed25519(
        signing_key: &SigningKey,
        nonce: &[u8; 32],
    ) -> Instruction {
        sign_advance_instruction_ed25519(signing_key, nonce, &[], &[], None)
    }
}
