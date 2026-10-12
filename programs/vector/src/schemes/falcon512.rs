use crate::{
    scheme::{IdentitySeed, SigningScheme},
    state::VectorAccount,
};
use pinocchio::error::ProgramError;
use solana_falcon512::{
    Falcon512PreparedPubkey, Falcon512Pubkey, Falcon512Signature, FALCON_512_PREPARED_PUBKEY_LEN,
    FALCON_512_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN,
};
use solana_nostd_sha256::hash;

/// Falcon's on-chain identity layout: `sha256(wire_pubkey)[32] ||
/// prepared_pubkey[1024]`.
///
/// * The first 32 bytes are the PDA seed and digest input — derivable
///   off-chain from the standard wire pubkey via plain SHA-256.
/// * The 1024-byte prepared pubkey lets `verify` skip the per-call
///   NTT/preparation; it must be read zero-copy (a 1024-byte stack copy
///   overflows the BPF frame) so it has to sit at a 2-byte-aligned account
///   offset. After the 34-byte account header and the hash it does. The
///   `PREPARED_ALIGNED` assertion below pins this invariant.
const HASH_LEN: usize = 32;
const PREPARED_OFFSET: usize = HASH_LEN;
const FALCON_IDENTITY_LEN: usize = PREPARED_OFFSET + FALCON_512_PREPARED_PUBKEY_LEN;

/// `prepared` must start at a 2-byte-aligned account offset for the zero-copy
/// `Falcon512PreparedPubkey::try_from_slice`. Account data is 8-byte aligned
/// per the Solana ABI, so the requirement reduces to an even offset.
const PREPARED_ALIGNED: () =
    assert!((VectorAccount::HEADER_LEN + PREPARED_OFFSET).is_multiple_of(2));

/// Falcon-512. Identity is the 897-byte wire pubkey (hashed + prepared on
/// init); signatures are 666-byte zero-padded compressed Falcon.
pub struct Falcon512;

impl Falcon512 {
    pub const ID: u8 = 4;
}

impl SigningScheme for Falcon512 {
    fn id(&self) -> u8 {
        Self::ID
    }

    fn signature_len(&self) -> usize {
        FALCON_512_SIGNATURE_LEN
    }
    fn identity_len(&self) -> usize {
        FALCON_IDENTITY_LEN
    }
    fn key_len(&self) -> usize {
        FALCON_512_PUBKEY_LEN
    }

    fn initialize(&self, key: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        let () = PREPARED_ALIGNED;
        let pubkey = Falcon512Pubkey::try_from_slice(key)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let prepared = pubkey
            .try_prepare_pubkey()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        // Layout: hash[..32] || prepared[32..].
        let wire_hash = hash(key);
        identity_out[..HASH_LEN].copy_from_slice(&wire_hash);
        identity_out[PREPARED_OFFSET..].copy_from_slice(prepared.as_bytes());
        Ok(())
    }

    /// Falcon stores `sha256(wire_pubkey)` as the first 32 bytes of identity
    /// — exactly the PDA seed off-chain clients compute from a wire pubkey,
    /// so we just slice it out.
    fn seed_from_identity(&self, identity: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&identity[..HASH_LEN])
    }

    /// At init time we have the wire pubkey, not the populated
    /// identity. The PDA seed is `sha256(wire_pubkey)` — the same hash
    /// `populate_identity` writes to the front of the identity buffer.
    fn seed_from_key(&self, key: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&hash(key))
    }

    fn advance(
        &self,
        identity: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProgramError> {
        // Zero-copy borrow of the prepared pubkey straight out of the
        // account (a 1024-byte stack copy would overflow the BPF frame);
        // `PREPARED_ALIGNED` guarantees a 2-byte-aligned offset.
        let prepared = Falcon512PreparedPubkey::try_from_slice(&identity[PREPARED_OFFSET..])
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let sig = Falcon512Signature::try_from_slice(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if sig.verify_with_prepared(digest, prepared) {
            Ok(())
        } else {
            Err(ProgramError::MissingRequiredSignature)
        }
    }
}
