//! secp256k1 + EIP-191. The identity is the 20-byte Ethereum address, and
//! what is signed is the digest in a personal-sign envelope.

use pinocchio::error::ProgramError;
use solana_nostd_keccak::{hash, hashv};

use crate::scheme::{write, Scheme, SigningScheme, SIGNED_LEN};

/// secp256k1 ECDSA in an EIP-191 "Ethereum Signed Message" envelope, so any
/// Ethereum wallet's `personal_sign` produces a signature. What it signs is
/// `"vector:" || digest`, 39 bytes. A signature is the 65-byte `(r, s, v)`;
/// `v` is the recovery id, 0 or 1, or as wallets return it, 27 or 28.
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

    #[inline]
    fn initialize(key: &[u8; 20], identity: &mut [u8]) -> Result<(), ProgramError> {
        if key == &[0; 20] {
            return Err(ProgramError::InvalidInstructionData);
        }
        write(identity, key)
    }

    #[inline]
    fn advance(
        &mut self,
        signed: &[u8; SIGNED_LEN],
        signature: &[u8; 65],
        _next_key: &[u8; 0],
    ) -> Result<(), ProgramError> {
        let [rs @ .., v] = signature;
        let envelope = hashv(&[b"\x19Ethereum Signed Message:\n39", signed]);
        // Wallets return `v` as 27 or 28; the recovery id is 0 or 1.
        let public_key = secp256k1_recover(&envelope, *v % 27, rs)
            .ok_or(ProgramError::MissingRequiredSignature)?;
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

/// secp256k1 ECDSA + EIP-191 envelope — identity is the 20-byte ETH address.
pub const EIP191: Scheme = Scheme::of::<Eip191>();

#[cfg(feature = "client")]
pub use client::*;

#[cfg(feature = "client")]
mod client {
    #[allow(unused_imports)]
    use super::*;

    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as Secp256k1SigningKey};
    use sha3::{Digest as Sha3Digest, Keccak256};
    use solana_address::Address;
    use solana_instruction::Instruction;

    use crate::digest::advance_vector_digest;
    use crate::instructions::{create_advance_instruction, create_initialize_instruction};
    use crate::scheme::signed;

    /// Derive the 20-byte Ethereum address from an uncompressed secp256k1 public
    /// key. Accepts the 65-byte `0x04 || x || y` form or the raw 64-byte point.
    pub fn eth_address_from_pubkey(uncompressed: &[u8]) -> [u8; EIP191.identity_len] {
        let point = match uncompressed.len() {
            65 => &uncompressed[1..],
            64 => uncompressed,
            _ => panic!("invalid uncompressed public key length"),
        };
        let hash: [u8; 32] = Keccak256::digest(point).into();
        let mut addr = [0u8; EIP191.identity_len];
        addr.copy_from_slice(&hash[12..32]);
        addr
    }

    /// 20-byte Ethereum address (the identity) for an EIP-191 secp256k1 key.
    pub fn secp256k1_eip191_eth_address(
        signing_key: &Secp256k1SigningKey,
    ) -> [u8; EIP191.identity_len] {
        let verifying_key = signing_key.verifying_key();
        let uncompressed = verifying_key.to_encoded_point(false);
        eth_address_from_pubkey(uncompressed.as_bytes())
    }

    /// Initialize an EIP-191 vector account. `eth_address` is the 20-byte ETH
    /// address (no padding).
    pub fn create_initialize_secp256k1_eip191(
        payer: &Address,
        eth_address: &[u8; EIP191.identity_len],
    ) -> Instruction {
        create_initialize_instruction(payer, &EIP191, eth_address)
    }

    /// `keccak256("\x19Ethereum Signed Message:\n39" || "vector:" || digest)`: what
    /// an EIP-191 signer actually signs, for a wallet's `personal_sign` of the 39
    /// bytes `"vector:" || digest`. Public for signers that take a prehash.
    pub fn eip191_envelope_hash(digest: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"\x19Ethereum Signed Message:\n39");
        hasher.update(signed(digest));
        hasher.finalize().into()
    }

    /// Sign an advance with an EIP-191 secp256k1 key. Put any passthrough among
    /// `pre_instructions` or `post_instructions`, so the signature covers it.
    /// Pass `fee_payer` when it is also an account of one of those instructions.
    pub fn sign_advance_instruction_secp256k1_eip191(
        signing_key: &Secp256k1SigningKey,
        nonce: &[u8; 32],
        pre_instructions: &[Instruction],
        post_instructions: &[Instruction],
        fee_payer: Option<&Address>,
    ) -> Instruction {
        let identity = secp256k1_eip191_eth_address(signing_key);
        let digest = advance_vector_digest(
            &EIP191,
            nonce,
            &identity,
            pre_instructions,
            post_instructions,
            fee_payer,
        );
        let eth_digest = eip191_envelope_hash(&digest);
        let (sig, recid) = signing_key
            .sign_prehash(&eth_digest)
            .expect("secp256k1 signing failed");
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig.to_bytes());
        sig_bytes[64] = recid.to_byte();
        create_advance_instruction(&EIP191, &identity, &sig_bytes)
    }

    /// Sign an advance with nothing around it. Landing it only moves the nonce,
    /// which cancels everything signed against the old one. It must be the only
    /// instruction of its transaction.
    pub fn sign_revocation_instruction_secp256k1_eip191(
        signing_key: &Secp256k1SigningKey,
        nonce: &[u8; 32],
    ) -> Instruction {
        sign_advance_instruction_secp256k1_eip191(signing_key, nonce, &[], &[], None)
    }
}
