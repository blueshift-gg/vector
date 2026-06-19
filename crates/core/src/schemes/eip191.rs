//! secp256k1 + EIP-191 program: identity is the 20-byte Ethereum address;
//! the digest is wrapped in the EIP-191 personal-sign envelope before
//! signing/recovery.

use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as Secp256k1SigningKey};
use sha3::{Digest as Sha3Digest, Keccak256};
use solana_address::{address, Address};
use solana_instruction::Instruction;

use crate::instructions::{create_advance_instruction, create_initialize_instruction};
use crate::protocol::advance_vector_digest;
use crate::scheme::Scheme;

pub const EIP191_ETH_ADDRESS_LEN: usize = 20;

/// secp256k1 ECDSA + EIP-191 envelope — identity is the 20-byte ETH address.
pub const EIP191: Scheme = Scheme {
    program_id: address!("G6okL1MvXx7k5eytY7wRXNupXyYG1QVZW37ygAjMiTTu"),
    signature_len: 65,
    identity_len: EIP191_ETH_ADDRESS_LEN,
    stored_identity_len: EIP191_ETH_ADDRESS_LEN,
};

/// Derive the 20-byte Ethereum address from an uncompressed secp256k1 public
/// key. Accepts the 65-byte `0x04 || x || y` form or the raw 64-byte point.
pub fn eth_address_from_pubkey(uncompressed: &[u8]) -> [u8; EIP191_ETH_ADDRESS_LEN] {
    let point = match uncompressed.len() {
        65 => &uncompressed[1..],
        64 => uncompressed,
        _ => panic!("invalid uncompressed public key length"),
    };
    let hash: [u8; 32] = Keccak256::digest(point).into();
    let mut addr = [0u8; EIP191_ETH_ADDRESS_LEN];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

/// 20-byte Ethereum address (the identity) for an EIP-191 secp256k1 key.
pub fn secp256k1_eip191_eth_address(
    signing_key: &Secp256k1SigningKey,
) -> [u8; EIP191_ETH_ADDRESS_LEN] {
    let verifying_key = signing_key.verifying_key();
    let uncompressed = verifying_key.to_encoded_point(false);
    eth_address_from_pubkey(uncompressed.as_bytes())
}

/// Initialize an EIP-191 vector account. `eth_address` is the 20-byte ETH
/// address (no padding).
pub fn create_initialize_secp256k1_eip191(
    payer: &Address,
    eth_address: &[u8; EIP191_ETH_ADDRESS_LEN],
) -> Instruction {
    create_initialize_instruction(payer, &EIP191, eth_address, eth_address)
}

/// `keccak256("\x19Ethereum Signed Message:\n32" || digest)` — the EIP-191
/// personal-sign envelope the on-chain program reproduces before
/// `secp256k1_recover`.
fn eip191_envelope_hash(digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n32");
    hasher.update(digest);
    hasher.finalize().into()
}

/// Sign the advance digest with an EIP-191 secp256k1 key, returning the
/// advance ix alone. Any CPI passthrough must be built separately via
/// [`crate::instructions::create_passthrough_instruction`] and included
/// among `pre_instructions` or `post_instructions` so the digest commits
/// to its bytes.
pub fn sign_advance_instruction_secp256k1_eip191(
    signing_key: &Secp256k1SigningKey,
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> Instruction {
    let identity = secp256k1_eip191_eth_address(signing_key);
    let digest = advance_vector_digest(
        &EIP191,
        nonce,
        &identity,
        pre_instructions,
        post_instructions,
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

// ---------------------------------------------------------------------------
// Eip191 struct — implements SchemeMeta + Signer + Verifier
// ---------------------------------------------------------------------------

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

use crate::scheme::{SchemeMeta, Signer, Verifier};

/// EIP-191 secp256k1 signer/verifier. Identity is the 20-byte Ethereum address.
#[derive(Clone)]
pub struct Eip191 {
    key: SigningKey,
}

impl Eip191 {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_slice(seed).expect("valid secp256k1 scalar"),
        }
    }
}

impl SchemeMeta for Eip191 {
    const PROGRAM_ID: solana_address::Address = EIP191.program_id;
    const SIGNATURE_LEN: usize = 65;
    const IDENTITY_LEN: usize = 20;
    const STORED_IDENTITY_LEN: usize = 20;
}

impl Signer for Eip191 {
    fn identity(&self) -> Vec<u8> {
        let unc = self.key.verifying_key().to_encoded_point(false);
        eth_address_from_pubkey(unc.as_bytes()).to_vec()
    }

    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        let eth = eip191_envelope_hash(digest);
        let (sig, rid): (Signature, RecoveryId) = self.key.sign_prehash(&eth).expect("sign");
        let mut out = vec![0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = rid.to_byte();
        out
    }
}

impl crate::scheme::Registration for Eip191 {}
impl crate::scheme::SingleTxRegister for Eip191 {}

use crate::branching::derive_lane_seed;
impl crate::scheme::Derivable for Eip191 {
    fn derive(&self, index: u32) -> Self {
        let master: [u8; 32] = self.key.to_bytes().into();
        Self::from_seed(&derive_lane_seed(&master, "eip191", index))
    }
}

impl Verifier for Eip191 {
    fn verify(identity: &[u8], _pk: Option<&[u8]>, digest: &[u8; 32], signature: &[u8]) -> bool {
        if signature.len() != 65 {
            return false;
        }
        let eth = eip191_envelope_hash(digest);
        let Ok(sig) = Signature::from_slice(&signature[..64]) else {
            return false;
        };
        let Some(rid) = RecoveryId::from_byte(signature[64]) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::recover_from_prehash(&eth, &sig, rid) else {
            return false;
        };
        let unc = vk.to_encoded_point(false);
        eth_address_from_pubkey(unc.as_bytes()).as_slice() == identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::{Signer, Verifier};

    #[test]
    fn sign_then_verify_roundtrip() {
        let k = Eip191::from_seed(&[8u8; 32]);
        let digest = [4u8; 32];
        let sig = k.sign(&digest);
        assert_eq!(sig.len(), 65);
        assert_eq!(k.identity().len(), 20);
        assert!(Eip191::verify(&k.identity(), None, &digest, &sig));
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!Eip191::verify(&k.identity(), None, &digest, &bad));
    }
}
