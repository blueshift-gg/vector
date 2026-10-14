//! secp256k1 + EIP-191. The identity is the 20-byte Ethereum address, and
//! what is signed is the digest in a personal-sign envelope.

use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as Secp256k1SigningKey};
use sha3::{Digest as Sha3Digest, Keccak256};
use solana_address::Address;
use solana_instruction::Instruction;

use crate::digest::advance_vector_digest;
use crate::instructions::{create_advance_instruction, create_initialize_instruction};
use crate::scheme::Scheme;

pub const EIP191_ETH_ADDRESS_LEN: usize = 20;

/// secp256k1 ECDSA + EIP-191 envelope — identity is the 20-byte ETH address.
pub const EIP191: Scheme = Scheme {
    id: 2,
    signature_len: 65,
    identity_len: EIP191_ETH_ADDRESS_LEN,
    stored_identity_len: size_of::<vector::schemes::eip191::Eip191>(),
    next_key_len: 0,
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
    create_initialize_instruction(payer, &EIP191, eth_address)
}

/// `keccak256("\x19Ethereum Signed Message:\n32" || digest)`: what an EIP-191
/// signer actually signs. Public for signers that take a prehash.
pub fn eip191_envelope_hash(digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n32");
    hasher.update(digest);
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
