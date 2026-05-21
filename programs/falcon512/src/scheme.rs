use pinocchio::error::ProgramError;
use solana_falcon512::{
    Falcon512PreparedPubkey, Falcon512Pubkey, Falcon512Signature, FALCON_512_PREPARED_PUBKEY_LEN,
    FALCON_512_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN,
};
use solana_nostd_sha256::hash;
use vector_common::{IdentitySeed, SigningScheme, VectorAccount};

/// Falcon's on-chain identity layout: `sha256(wire_pubkey)[32] || pad[1] ||
/// prepared_pubkey[1024]`.
///
/// * The first 32 bytes are the PDA seed and digest input — derivable
///   off-chain from the standard wire pubkey via plain SHA-256.
/// * The 1024-byte prepared pubkey lets `verify` skip the per-call
///   NTT/preparation; it must be read zero-copy (a 1024-byte stack copy
///   overflows the BPF frame) so it has to sit at a 2-byte-aligned account
///   offset. The 33-byte account header makes offset `33 + 32` odd, so a
///   one-byte pad realigns `prepared` to an even offset. The
///   `PREPARED_ALIGNED` assertion below pins this invariant.
const HASH_LEN: usize = 32;
const PAD_LEN: usize = 1;
const PREPARED_OFFSET: usize = HASH_LEN + PAD_LEN;
const FALCON_IDENTITY_LEN: usize = PREPARED_OFFSET + FALCON_512_PREPARED_PUBKEY_LEN;

/// `prepared` must start at a 2-byte-aligned account offset for the zero-copy
/// `Falcon512PreparedPubkey::try_from_slice`. Account data is 8-byte aligned
/// per the Solana ABI, so the requirement reduces to an even offset.
const PREPARED_ALIGNED: () =
    assert!((VectorAccount::HEADER_LEN + PREPARED_OFFSET).is_multiple_of(2));

/// Falcon-512. Identity is the 897-byte wire pubkey (hashed + prepared on
/// init); signatures are 666-byte zero-padded compressed Falcon.
pub struct Falcon512;

impl SigningScheme for Falcon512 {
    const SIGNATURE_LEN: usize = FALCON_512_SIGNATURE_LEN;
    const IDENTITY_LEN: usize = FALCON_IDENTITY_LEN;
    const INIT_PAYLOAD_LEN: usize = FALCON_512_PUBKEY_LEN;

    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        let () = PREPARED_ALIGNED;
        let pubkey = Falcon512Pubkey::try_from_slice(payload)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let prepared = pubkey
            .try_prepare_pubkey()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        // Layout: hash[..32] || pad[1] (zero) || prepared[33..].
        let wire_hash = hash(payload);
        identity_out[..HASH_LEN].copy_from_slice(&wire_hash);
        identity_out[HASH_LEN..PREPARED_OFFSET].fill(0);
        identity_out[PREPARED_OFFSET..].copy_from_slice(prepared.as_bytes());
        Ok(())
    }

    /// Falcon stores `sha256(wire_pubkey)` as the first 32 bytes of identity
    /// — exactly the PDA seed off-chain clients compute from a wire pubkey,
    /// so we just slice it out.
    fn pda_seed_from_identity(identity: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&identity[..HASH_LEN])
    }

    /// At init time we have the wire pubkey (payload), not the populated
    /// identity. The PDA seed is `sha256(wire_pubkey)` — the same hash
    /// `populate_identity` writes to the front of the identity buffer.
    fn pda_seed_from_payload(payload: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&hash(payload))
    }

    /// The 897-byte wire pubkey can't be cheaply rebuilt on-chain, and the
    /// 1024-byte prepared form can't be reproduced off-chain — so the digest
    /// folds in `sha256(wire_pubkey)`, which `populate_identity` stored as
    /// the first 32 bytes and the client computes from its wire pubkey.
    fn digest_identity(identity: &[u8]) -> &[u8] {
        &identity[..HASH_LEN]
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        // Zero-copy borrow of the prepared pubkey straight out of the
        // account (a 1024-byte stack copy would overflow the BPF frame); the
        // 1-byte pad guarantees a 2-byte-aligned offset.
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
