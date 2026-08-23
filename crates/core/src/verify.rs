//! Offline verification of `advance` signatures. Each function recomputes
//! the canonical digest via
//! [`advance_vector_digest_with_fee_payer`](crate::digest::advance_vector_digest_with_fee_payer)
//! and checks the signature the way the on-chain program will, so a PASS
//! here means the transaction will verify on-chain against the same nonce.
//! On success each function returns the digest — which **is** the account's
//! next nonce, so chains of dependent transactions can be pre-signed by
//! feeding each digest into the next signing call.
//!
//! One caveat: ed25519 is checked with `ed25519-dalek` offline while the
//! on-chain program uses `brine-ed25519`, so adversarially malformed
//! signatures (non-canonical scalars, small-order points) may be judged
//! differently by the two implementations. Honestly-generated signatures
//! verify identically.
//!
//! `fee_payer` participates in **message-level flag promotion only**: the
//! live sysvar the on-chain program hashes carries message-level account
//! flags, and the fee payer is always a writable signer at the message
//! level. The digest is therefore independent of the fee payer **unless**
//! its key appears among the committed instructions' accounts, in which
//! case promotion folds it in and the signature is bound to that fee payer.

use ed25519_dalek::Verifier as _;
use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use k256::ecdsa::{
    RecoveryId, Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey,
};
use sha3::{Digest as Sha3Digest, Keccak256};
use solana_address::Address;
use solana_falcon512::{Falcon512Pubkey, Falcon512Signature};
use solana_instruction::Instruction;

use crate::digest::advance_vector_digest_with_fee_payer;
use crate::schemes::eip191::{eip191_envelope_hash, EIP191, EIP191_ETH_ADDRESS_LEN};
use crate::schemes::falcon512::{falcon512_identity, FALCON512, FALCON512_WIRE_PUBKEY_LEN};
use crate::schemes::{
    ed25519::{ED25519, ED25519_PUBKEY_LEN},
    secp256k1::{SECP256K1, SECP256K1_COMPRESSED_PUBKEY_LEN},
};

/// Why an offline `advance` verification failed. The crate otherwise
/// carries no error types, so this stays deliberately small; the two
/// parse-stage variants carry a static reason so the `Display` output is
/// self-explaining at call sites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature bytes are unusable before any curve math runs (wrong
    /// length, out-of-range scalar, invalid recovery byte).
    MalformedSignature(&'static str),
    /// The key material and the identity disagree (invalid public key
    /// bytes, or an EIP-191 recovery yielding a different address).
    IdentityMismatch(&'static str),
    /// The signature does not verify over the recomputed digest.
    SignatureInvalid,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::MalformedSignature(why) | VerifyError::IdentityMismatch(why) => {
                f.write_str(why)
            }
            VerifyError::SignatureInvalid => f.write_str(
                "signature does not verify over the recomputed advance digest — the signed \
                 payload differs from this instruction layout, nonce, or identity",
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify an Ed25519 `advance` signature offline. `pubkey` is the 32-byte
/// identity, `signature` the 64-byte wire signature (the advance ix data
/// after the 1-byte discriminator). Returns the recomputed digest — the
/// account's next nonce — on success.
///
/// Offline verification uses `ed25519-dalek` while the on-chain program
/// uses `brine-ed25519`; see the module docs for the (adversarial-only)
/// gap between the two.
pub fn verify_advance_signature_ed25519(
    pubkey: &[u8; ED25519_PUBKEY_LEN],
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
    signature: &[u8],
) -> Result<[u8; 32], VerifyError> {
    let sig_bytes: &[u8; 64] = signature
        .try_into()
        .map_err(|_| VerifyError::MalformedSignature("ed25519 signature must be 64 bytes"))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(pubkey)
        .map_err(|_| VerifyError::IdentityMismatch("identity is not a valid ed25519 public key"))?;

    let digest = advance_vector_digest_with_fee_payer(
        &ED25519,
        nonce,
        pubkey,
        pre_instructions,
        post_instructions,
        fee_payer,
    );

    verifying_key
        .verify(&digest, &ed25519_dalek::Signature::from_bytes(sig_bytes))
        .map_err(|_| VerifyError::SignatureInvalid)?;
    Ok(digest)
}

/// Verify a plain-secp256k1 ECDSA `advance` signature offline.
/// `compressed_pubkey` is the 33-byte sec1 identity, `signature` the
/// 64-byte `r || s` wire form. Returns the recomputed digest on success.
///
/// High-S signatures are normalized before checking: the on-chain
/// `solana-secp256k1-ecdsa` verifier accepts both `s` normalizations, so
/// the offline check must too or PASS/FAIL would diverge.
pub fn verify_advance_signature_secp256k1_ecdsa(
    compressed_pubkey: &[u8; SECP256K1_COMPRESSED_PUBKEY_LEN],
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
    signature: &[u8],
) -> Result<[u8; 32], VerifyError> {
    let verifying_key =
        Secp256k1VerifyingKey::from_sec1_bytes(compressed_pubkey).map_err(|_| {
            VerifyError::IdentityMismatch(
                "identity is not a valid sec1-compressed secp256k1 pubkey",
            )
        })?;
    let sig = Secp256k1Signature::from_slice(signature).map_err(|_| {
        VerifyError::MalformedSignature("secp256k1 signature must be 64 bytes of valid r || s")
    })?;
    let sig = sig.normalize_s().unwrap_or(sig);

    let digest = advance_vector_digest_with_fee_payer(
        &SECP256K1,
        nonce,
        compressed_pubkey,
        pre_instructions,
        post_instructions,
        fee_payer,
    );

    verifying_key
        .verify_prehash(&digest, &sig)
        .map_err(|_| VerifyError::SignatureInvalid)?;
    Ok(digest)
}

/// Verify an EIP-191 `advance` signature offline. `eth_address` is the
/// 20-byte identity, `signature` the 65-byte `r || s || v` wire form with
/// `v` the raw recovery id (`0..=3`). Returns the recomputed digest on
/// success.
///
/// The key is recovered from the EIP-191 envelope of the digest
/// ([`eip191_envelope_hash`]) and its derived Ethereum address compared to
/// the identity. The Ethereum legacy `v = 27/28` form is **rejected**: the
/// on-chain program passes `v` straight to `sol_secp256k1_recover`, which
/// errors on recovery ids above 3, so a legacy-form signature would pass
/// offline yet fail on-chain — subtract 27 at assembly time. High-S
/// signatures are normalized (with the recovery id's parity flipped to
/// keep recovering the same key), since `sol_secp256k1_recover` accepts
/// them.
pub fn verify_advance_signature_secp256k1_eip191(
    eth_address: &[u8; EIP191_ETH_ADDRESS_LEN],
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
    signature: &[u8],
) -> Result<[u8; 32], VerifyError> {
    let sig_bytes: &[u8; 65] = signature.try_into().map_err(|_| {
        VerifyError::MalformedSignature("eip191 signature must be 65 bytes (r || s || v)")
    })?;
    let v = sig_bytes[64];
    if v == 27 || v == 28 {
        return Err(VerifyError::MalformedSignature(
            "eip191 recovery byte is in the Ethereum legacy 27/28 form; the on-chain program \
             requires the raw 0/1 form — subtract 27 when assembling the advance instruction",
        ));
    }
    let mut recovery_id = RecoveryId::from_byte(v).ok_or(VerifyError::MalformedSignature(
        "eip191 recovery byte must be 0..=3",
    ))?;
    let mut sig = Secp256k1Signature::from_slice(&sig_bytes[..64]).map_err(|_| {
        VerifyError::MalformedSignature("eip191 signature r || s bytes are not a valid signature")
    })?;
    // Normalizing s negates the signature point, so the recovery id's
    // Y-parity bit flips to keep recovering the same public key.
    if let Some(normalized) = sig.normalize_s() {
        sig = normalized;
        recovery_id = RecoveryId::from_byte(recovery_id.to_byte() ^ 1)
            .expect("flipping the parity bit keeps the id in 0..=3");
    }

    let digest = advance_vector_digest_with_fee_payer(
        &EIP191,
        nonce,
        eth_address,
        pre_instructions,
        post_instructions,
        fee_payer,
    );
    let envelope = eip191_envelope_hash(&digest);

    let recovered = Secp256k1VerifyingKey::recover_from_prehash(&envelope, &sig, recovery_id)
        .map_err(|_| VerifyError::SignatureInvalid)?;
    let uncompressed = recovered.to_encoded_point(false);
    let hash: [u8; 32] = Keccak256::digest(&uncompressed.as_bytes()[1..]).into();
    if hash[12..32] != *eth_address {
        return Err(VerifyError::IdentityMismatch(
            "recovered Ethereum address does not match the identity",
        ));
    }
    Ok(digest)
}

/// Verify a Falcon-512 `advance` signature offline, given the 897-byte wire
/// pubkey (the identity, `sha256(wire_pubkey)`, is derived from it).
/// `signature` is the 666-byte zero-padded wire form. Verification runs
/// `solana-falcon512`'s host-callable verifier over the raw digest — the
/// same code path the on-chain program executes. Returns the recomputed
/// digest on success.
pub fn verify_advance_signature_falcon512(
    wire_pubkey: &[u8; FALCON512_WIRE_PUBKEY_LEN],
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
    signature: &[u8],
) -> Result<[u8; 32], VerifyError> {
    let sig_bytes: &[u8; crate::FALCON512_SIGNATURE_LEN] = signature.try_into().map_err(|_| {
        VerifyError::MalformedSignature("falcon512 signature must be 666 bytes (zero-padded wire)")
    })?;
    let identity = falcon512_identity(wire_pubkey);

    let digest = advance_vector_digest_with_fee_payer(
        &FALCON512,
        nonce,
        &identity,
        pre_instructions,
        post_instructions,
        fee_payer,
    );

    if Falcon512Signature::from_ref(sig_bytes)
        .verify(&digest, Falcon512Pubkey::from_ref(wire_pubkey))
    {
        Ok(digest)
    } else {
        Err(VerifyError::SignatureInvalid)
    }
}

