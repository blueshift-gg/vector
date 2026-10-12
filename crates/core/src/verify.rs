//! Check an `advance` signature offline, the way the program will.
//!
//! Ed25519 is checked with `ed25519-dalek` here and `brine-ed25519` on chain.
//! The two can only disagree on deliberately malformed signatures.

use ed25519_dalek::Verifier as _;
use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use k256::ecdsa::{
    RecoveryId, Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey,
};
use sha3::{Digest as Sha3Digest, Keccak256};
use solana_address::Address;
use solana_falcon512::{Falcon512Pubkey, Falcon512Signature};
use solana_instruction::Instruction;

use crate::digest::advance_vector_digest;
use crate::scheme::Scheme;
use crate::schemes::{
    ed25519::ED25519,
    eip191::{eip191_envelope_hash, EIP191},
    falcon512::FALCON512,
    mldsa44::MLDSA44,
    secp256k1::SECP256K1,
};

/// Why an offline check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature bytes are unusable: wrong length, or out of range.
    MalformedSignature(&'static str),
    /// The identity is not a valid key, or not the key that signed.
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

/// Verify an advance signature: recompute the digest and check `signature`
/// over it with the scheme's verifier. Returns the digest, which is the
/// account's next nonce.
///
/// `fee_payer` is as in [`advance_vector_digest`]. Winternitz and XMSS have
/// no offline verifier.
pub fn verify_advance_signature(
    scheme: &Scheme,
    identity: &[u8],
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
    signature: &[u8],
) -> Result<[u8; 32], VerifyError> {
    if identity.len() != scheme.identity_len {
        return Err(VerifyError::IdentityMismatch(
            "identity has the wrong length for its scheme",
        ));
    }
    if signature.len() != scheme.signature_len {
        return Err(VerifyError::MalformedSignature(
            "signature has the wrong length for its scheme",
        ));
    }

    let digest = advance_vector_digest(
        scheme,
        nonce,
        identity,
        pre_instructions,
        post_instructions,
        fee_payer,
    );
    match scheme.id {
        id if id == ED25519.id => ed25519(identity, &digest, signature),
        id if id == EIP191.id => eip191(identity, &digest, signature),
        id if id == SECP256K1.id => secp256k1(identity, &digest, signature),
        id if id == FALCON512.id => falcon512(identity, &digest, signature),
        id if id == MLDSA44.id => mldsa44(identity, &digest, signature),
        _ => Err(VerifyError::IdentityMismatch(
            "this scheme has no offline verifier",
        )),
    }?;
    Ok(digest)
}

// One check per scheme. `verify_advance_signature` has already checked the
// lengths of `identity` and `signature`.

fn ed25519(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), VerifyError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(identity.try_into().unwrap())
        .map_err(|_| VerifyError::IdentityMismatch("identity is not a valid ed25519 public key"))?;
    let signature = ed25519_dalek::Signature::from_bytes(signature.try_into().unwrap());
    key.verify(digest, &signature)
        .map_err(|_| VerifyError::SignatureInvalid)
}

/// A high-S signature is accepted, as it is on chain.
fn secp256k1(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), VerifyError> {
    let key = Secp256k1VerifyingKey::from_sec1_bytes(identity).map_err(|_| {
        VerifyError::IdentityMismatch("identity is not a valid sec1-compressed secp256k1 pubkey")
    })?;
    let signature = Secp256k1Signature::from_slice(signature).map_err(|_| {
        VerifyError::MalformedSignature("secp256k1 signature is not a valid r || s")
    })?;
    let signature = signature.normalize_s().unwrap_or(signature);
    key.verify_prehash(digest, &signature)
        .map_err(|_| VerifyError::SignatureInvalid)
}

/// A high-S signature is accepted, as it is on chain. `v` is the raw
/// recovery id, 0 or 1: the program rejects Ethereum's 27/28 form, so this
/// does too.
fn eip191(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), VerifyError> {
    let v = signature[64];
    if v == 27 || v == 28 {
        return Err(VerifyError::MalformedSignature(
            "eip191 recovery byte is in the Ethereum legacy 27/28 form; the on-chain program \
             requires the raw 0/1 form — subtract 27 when assembling the advance instruction",
        ));
    }
    let mut recovery_id = RecoveryId::from_byte(v).ok_or(VerifyError::MalformedSignature(
        "eip191 recovery byte must be 0..=3",
    ))?;
    let mut sig = Secp256k1Signature::from_slice(&signature[..64]).map_err(|_| {
        VerifyError::MalformedSignature("eip191 signature r || s bytes are not a valid signature")
    })?;
    // Normalizing s negates the signature point, so the recovery id's
    // Y-parity bit flips to keep recovering the same public key.
    if let Some(normalized) = sig.normalize_s() {
        sig = normalized;
        recovery_id = RecoveryId::from_byte(recovery_id.to_byte() ^ 1)
            .expect("flipping the parity bit keeps the id in 0..=3");
    }

    let envelope = eip191_envelope_hash(digest);
    let recovered = Secp256k1VerifyingKey::recover_from_prehash(&envelope, &sig, recovery_id)
        .map_err(|_| VerifyError::SignatureInvalid)?;
    let uncompressed = recovered.to_encoded_point(false);
    let hash: [u8; 32] = Keccak256::digest(&uncompressed.as_bytes()[1..]).into();
    if hash[12..32] != *identity {
        return Err(VerifyError::IdentityMismatch(
            "recovered Ethereum address does not match the identity",
        ));
    }
    Ok(())
}

/// The verifier the program uses. `signature` is the 666-byte zero-padded
/// form.
fn falcon512(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), VerifyError> {
    let signature = Falcon512Signature::from_ref(signature.try_into().unwrap());
    if signature.verify(
        digest,
        Falcon512Pubkey::from_ref(identity.try_into().unwrap()),
    ) {
        Ok(())
    } else {
        Err(VerifyError::SignatureInvalid)
    }
}

/// The verifier the program uses, with an empty context.
fn mldsa44(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), VerifyError> {
    use solana_ml_dsa::ml_dsa_44::{Signature, VerifyingKey};
    let key = VerifyingKey::<false>::from_bytes(identity.try_into().unwrap());
    key.verify(digest, Signature::ref_from_bytes(signature).unwrap())
        .map_err(|_| VerifyError::SignatureInvalid)
}
