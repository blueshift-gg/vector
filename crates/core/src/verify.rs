//! Check `advance` signatures offline with the program's own code: each
//! account is initialized and advanced as on chain, so the check cannot
//! disagree with the program.

use solana_address::Address;
use solana_instruction::Instruction;

use crate::digest::advance_message;
use crate::instructions::AdvanceSigner;
use crate::scheme::{find_vector_pda, signed_nonce, VectorAccount, NEVER_EXPIRES};

/// Why an offline check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The identity is not a key of its scheme: `initialize` refuses it.
    InvalidIdentity,
    /// The signature is not one the scheme can read.
    MalformedSignature,
    /// The signature does not verify over the recomputed digest.
    SignatureInvalid,
    /// The advance's `valid_until` is before the slot checked against.
    Expired,
    /// The signer lists a nonce account but is given a vector's own nonce, or
    /// the other way around.
    NonceMismatch,
    /// The program refused the signature for its scheme's own reason, as
    /// this `VectorError` code (a Winternitz key reused, an XMSS leaf used).
    Rejected(u32),
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::InvalidIdentity => f.write_str("the identity is not a key of its scheme"),
            VerifyError::MalformedSignature => {
                f.write_str("the signature is not one its scheme can read")
            }
            VerifyError::SignatureInvalid => f.write_str(
                "the signature does not verify over the recomputed advance digest: the signed \
                 payload differs from this instruction layout, nonce, or identity",
            ),
            VerifyError::Expired => f.write_str("the transaction's valid_until slot has passed"),
            VerifyError::NonceMismatch => f.write_str(
                "the signer lists a nonce account but is given none, or the other way around",
            ),
            VerifyError::Rejected(code) => write!(f, "the program refuses it: custom error {code}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// The nonce a signature is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerNonce {
    /// The vector's own nonce.
    Vector([u8; 32]),
    /// A nonce account's nonce, and the vector's own that the signature takes
    /// in too: [`signed_nonce`] of the two.
    Account { account: [u8; 32], vector: [u8; 32] },
    /// What the signature is over already: [`signed_nonce`] of a nonce
    /// account's nonce, or a vector's own.
    Signed([u8; 32]),
}

impl SignerNonce {
    fn signed(&self) -> [u8; 32] {
        match self {
            SignerNonce::Vector(nonce) | SignerNonce::Signed(nonce) => *nonce,
            SignerNonce::Account { account, vector } => signed_nonce(account, vector),
        }
    }
}

/// One signer of an advance to check: who it is, the nonce it signed over,
/// and its signature.
#[derive(Clone, Copy, Debug)]
pub struct AdvanceEntry<'a> {
    /// The signer, as it is listed in the advance. If its
    /// [`nonce_account`](AdvanceSigner::nonce_account) is set, `nonce` must be
    /// [`SignerNonce::Account`] or [`SignerNonce::Signed`].
    pub signer: AdvanceSigner<'a>,
    /// What it signed over.
    pub nonce: SignerNonce,
    /// Its signature, as it is in the advance's data.
    pub signature: &'a [u8],
    /// Winternitz and XMSS: the key the account holds now, if it has rotated
    /// since it was created. `None` is the identity.
    pub current_key: Option<&'a [u8]>,
}

impl<'a> AdvanceEntry<'a> {
    /// A signer of its own nonce, whose key is the one it was created with.
    pub fn new(signer: AdvanceSigner<'a>, nonce: SignerNonce, signature: &'a [u8]) -> Self {
        Self {
            signer,
            nonce,
            signature,
            current_key: None,
        }
    }
}

/// Verify every signature of an advance: recompute the one message all
/// signers approve (it covers `valid_until`), and for each entry its digest, then check its signature
/// as the program would. Returns each entry's digest, which is the next nonce
/// of its nonce account, or of its own account. Entries are in the advance's
/// order, and one account listed twice signs the second time over the nonce
/// the first returned.
///
/// `slot` is the slot the transaction would land in. With it, a
/// `valid_until` before it is [`VerifyError::Expired`]; with `None`, expiry
/// is not checked.
///
/// Not checked, because it takes the chain: that a nonce account is past its
/// creation slot, that it belongs to the vector, that a vector holds the
/// nonce given, and an XMSS leaf not used before.
///
/// `fee_payer` is as in [`advance_vector_digest`](crate::advance_vector_digest).
pub fn verify_advance(
    valid_until: u64,
    entries: &[AdvanceEntry],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
    slot: Option<u64>,
) -> Result<Vec<[u8; 32]>, VerifyError> {
    if slot.is_some_and(|slot| slot > valid_until) {
        return Err(VerifyError::Expired);
    }
    let signers: Vec<AdvanceSigner> = entries.iter().map(|entry| entry.signer).collect();
    let message = advance_message(
        valid_until,
        &signers,
        pre_instructions,
        post_instructions,
        fee_payer,
    );

    entries
        .iter()
        .map(|entry| verify_entry(entry, &message))
        .collect()
}

/// [`verify_advance`] for one signer. `nonce` is what the signature is over:
/// the vector's own, or for a signer with a nonce account,
/// [`signed_nonce`] of it (use [`verify_advance`] and [`SignerNonce`] to have
/// that done for you). Returns the digest.
pub fn verify_advance_signature(
    signer: AdvanceSigner,
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
    signature: &[u8],
) -> Result<[u8; 32], VerifyError> {
    let entry = AdvanceEntry::new(signer, SignerNonce::Signed(*nonce), signature);
    let digests = verify_advance(
        NEVER_EXPIRES,
        &[entry],
        pre_instructions,
        post_instructions,
        fee_payer,
        None,
    )?;
    Ok(digests[0])
}

fn verify_entry(entry: &AdvanceEntry, message: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
    let AdvanceEntry {
        signer,
        nonce,
        signature,
        current_key,
    } = *entry;
    let scheme = signer.scheme;

    let listed = signer.nonce_account.is_some();
    match nonce {
        SignerNonce::Vector(_) if listed => return Err(VerifyError::NonceMismatch),
        SignerNonce::Account { .. } if !listed => return Err(VerifyError::NonceMismatch),
        _ => {}
    }
    if signer.identity.len() != scheme.identity_len {
        return Err(VerifyError::InvalidIdentity);
    }
    if signature.len() != scheme.signature_len || signer.next_key.len() != scheme.next_key_len {
        return Err(VerifyError::MalformedSignature);
    }
    let key = current_key.unwrap_or(signer.identity);
    if key.len() != scheme.identity_len {
        return Err(VerifyError::InvalidIdentity);
    }

    // The account as on chain: 8-byte aligned, the identity after the
    // header. Falcon-512 and ML-DSA-44 read their prepared key in place.
    let mut account = vec![0u64; scheme.account_len.div_ceil(8)];
    // SAFETY: any `u64` buffer is a valid byte buffer of 8 times its length.
    let account = unsafe {
        core::slice::from_raw_parts_mut(account.as_mut_ptr().cast::<u8>(), scheme.account_len)
    };
    let stored = &mut account[VectorAccount::HEADER_LEN..];
    (scheme.initialize)(key, stored).map_err(|_| VerifyError::InvalidIdentity)?;

    // The bytes the program reads for this signer.
    let mut data = Vec::with_capacity(signer.next_key.len() + signature.len());
    data.extend_from_slice(signer.next_key);
    data.extend_from_slice(signature);

    let (vector, _) = find_vector_pda(scheme, signer.identity);
    let mut digest = nonce.signed();
    (scheme.advance)(
        stored,
        &mut digest,
        message,
        vector.as_array(),
        &mut &data[..],
    )
    .map_err(|error| match error {
        pinocchio::error::ProgramError::MissingRequiredSignature => VerifyError::SignatureInvalid,
        pinocchio::error::ProgramError::Custom(code) => VerifyError::Rejected(code),
        _ => VerifyError::MalformedSignature,
    })?;
    Ok(digest)
}
