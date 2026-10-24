//! Check an `advance` signature offline with the program's own code: the
//! account is initialized and advanced as on chain, so the check cannot
//! disagree with the program.

use solana_address::Address;
use solana_instruction::Instruction;

use crate::digest::advance_message;
use crate::instructions::AdvanceSigner;
use crate::scheme::{find_vector_pda, VectorAccount};

/// Why an offline check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The identity is not a key of its scheme: `initialize` refuses it.
    InvalidIdentity,
    /// The signature is not one the scheme can read.
    MalformedSignature,
    /// The signature does not verify over the recomputed digest.
    SignatureInvalid,
    /// Winternitz and XMSS: the signature covers a next key, which this does
    /// not take.
    RotatingKey,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            VerifyError::InvalidIdentity => "the identity is not a key of its scheme",
            VerifyError::MalformedSignature => "the signature is not one its scheme can read",
            VerifyError::SignatureInvalid => {
                "the signature does not verify over the recomputed advance digest: the signed \
                 payload differs from this instruction layout, nonce, or identity"
            }
            VerifyError::RotatingKey => "Winternitz and XMSS signatures are not checked offline",
        })
    }
}

impl std::error::Error for VerifyError {}

/// Verify an advance signature: recompute the digest and check `signature`
/// over it, as the program would for a new account. Returns the digest,
/// which is the next nonce of the signer's nonce account, or of its own.
///
/// `nonce` is the one the signer signed over, [`signed_nonce`](crate::signed_nonce)
/// for a nonce account; `fee_payer` is as in
/// [`advance_vector_digest`](crate::advance_vector_digest).
pub fn verify_advance_signature(
    signer: AdvanceSigner,
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
    signature: &[u8],
) -> Result<[u8; 32], VerifyError> {
    let AdvanceSigner {
        scheme, identity, ..
    } = signer;
    if scheme.next_key_len != 0 {
        return Err(VerifyError::RotatingKey);
    }
    if identity.len() != scheme.identity_len {
        return Err(VerifyError::InvalidIdentity);
    }
    if signature.len() != scheme.signature_len {
        return Err(VerifyError::MalformedSignature);
    }

    // The account as on chain: 8-byte aligned, the identity after the
    // header. Falcon-512 and ML-DSA-44 read their prepared key in place.
    let mut account = vec![0u64; scheme.account_len.div_ceil(8)];
    // SAFETY: any `u64` buffer is a valid byte buffer of 8 times its length.
    let account = unsafe {
        core::slice::from_raw_parts_mut(account.as_mut_ptr().cast::<u8>(), scheme.account_len)
    };
    let stored = &mut account[VectorAccount::HEADER_LEN..];
    (scheme.initialize)(identity, stored).map_err(|_| VerifyError::InvalidIdentity)?;

    let message = advance_message(&[signer], pre_instructions, post_instructions, fee_payer);
    let (vector, _) = find_vector_pda(scheme, identity);
    let mut nonce = *nonce;
    (scheme.advance)(
        stored,
        &mut nonce,
        &message,
        vector.as_array(),
        &mut &signature[..],
    )
    .map_err(|error| match error {
        pinocchio::error::ProgramError::MissingRequiredSignature => VerifyError::SignatureInvalid,
        _ => VerifyError::MalformedSignature,
    })?;
    Ok(nonce)
}
