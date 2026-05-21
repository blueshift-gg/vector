//! secp256k1 + EIP-191 program: identity is the 20-byte Ethereum address;
//! the digest is wrapped in the EIP-191 personal-sign envelope before
//! signing/recovery.

use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as Secp256k1SigningKey};
use sha3::{Digest as Sha3Digest, Keccak256};
use solana_address::{address, Address};
use solana_instruction::Instruction;

use crate::digest::advance_vector_digest;
use crate::instructions::{create_advance_instruction, create_initialize_instruction};
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
