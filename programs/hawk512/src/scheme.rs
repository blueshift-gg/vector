use pinocchio::error::ProgramError;
use solana_hawk512::{
    Hawk512PreparedPubkey, Hawk512Pubkey, Hawk512Signature, HAWK_512_PREPARED_PUBKEY_LEN,
    HAWK_512_PUBKEY_LEN, HAWK_512_SIGNATURE_LEN,
};
use solana_nostd_sha256::hash;
use vector_common::{IdentitySeed, SigningScheme, VectorAccount};

/// Hawk-512 on-chain identity layout:
/// `sha256(wire_pubkey)[32] || pad[7] || prepared_pubkey[18464]`.
///
/// * The first 32 bytes are the PDA seed and digest input — `sha256` of the
///   1024-byte wire pubkey, which a client computes trivially.
/// * The 18 464-byte prepared pubkey is borrowed zero-copy by both
///   `prepare_into` (write, in `expand`) and `verify_with_prepared` (read,
///   in `advance`); Hawk's API requires it **8-byte aligned**. The account
///   header is 33 bytes, so a 7-byte pad lands `prepared` on an offset that
///   is a multiple of 8. `PREPARED_ALIGNED` pins the invariant.
const HASH_LEN: usize = 32;
const PAD_LEN: usize = 7;
const PREPARED_OFFSET: usize = HASH_LEN + PAD_LEN; // 39
const HAWK_IDENTITY_LEN: usize = PREPARED_OFFSET + HAWK_512_PREPARED_PUBKEY_LEN;

/// `prepared` must start at an 8-byte-aligned account offset. Account data is
/// 8-byte aligned per the Solana ABI, so the requirement reduces to
/// `(HEADER_LEN + PREPARED_OFFSET) % 8 == 0` (33 + 39 = 72).
const PREPARED_ALIGNED: () =
    assert!((VectorAccount::HEADER_LEN + PREPARED_OFFSET) % 8 == 0);

/// `initialize` allocates `min(full, 10240)` and `expand` grows to `full` in
/// a single resize, capped at `MAX_PERMITTED_DATA_INCREASE` (10240). That
/// requires `full - 10240 <= 10240`, i.e. the whole account ≤ 20480 bytes.
const _SINGLE_EXPAND_FITS: () =
    assert!(VectorAccount::HEADER_LEN + HAWK_IDENTITY_LEN <= 2 * 10240);

/// Hawk-512. Identity is `sha256(wire_pubkey)` (32 bytes); the 18 KB
/// prepared pubkey is written by a second, permissionless `initialize` call
/// (`prepare`). Signatures are 555 bytes.
pub struct Hawk512;

impl SigningScheme for Hawk512 {
    const SIGNATURE_LEN: usize = HAWK_512_SIGNATURE_LEN;
    const IDENTITY_LEN: usize = HAWK_IDENTITY_LEN;
    /// `initialize` payload is the 1024-byte wire pubkey.
    const INIT_PAYLOAD_LEN: usize = HAWK_512_PUBKEY_LEN;

    /// First `initialize` call: write only `sha256(wire)`. The pad and the
    /// 18 KB prepared region stay zero (the runtime zero-fills new account
    /// data); the second `initialize` call (`prepare`) fills it.
    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        let () = PREPARED_ALIGNED;
        if payload.len() != HAWK_512_PUBKEY_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity_out[..HASH_LEN].copy_from_slice(&hash(payload));
        Ok(())
    }

    /// PDA seed is `sha256(wire_pubkey)`, stored as the first 32 bytes.
    fn pda_seed_from_identity(identity: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&identity[..HASH_LEN])
    }

    /// At init time the payload is the wire pubkey; its seed is `sha256`.
    fn pda_seed_from_payload(payload: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&hash(payload))
    }

    /// The client can't reproduce the 18 KB prepared form and the program
    /// can't cheaply rebuild the wire pubkey, so the digest folds in
    /// `sha256(wire_pubkey)` — the stored 32-byte prefix.
    fn digest_identity(identity: &[u8]) -> &[u8] {
        &identity[..HASH_LEN]
    }

    /// Second `initialize` call: re-supply the wire pubkey, bind it to the
    /// committed `sha256`, then write the ~18 KB prepared blob in place.
    /// Permissionless — the hash binding is the only authorisation needed.
    fn prepare(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        if payload.len() != HAWK_512_PUBKEY_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        // Bind expand to what initialize committed — without this, anyone
        // could write a *different* key's prepared blob into the account.
        if hash(payload)[..] != identity_out[..HASH_LEN] {
            return Err(ProgramError::InvalidAccountData);
        }
        let pubkey = Hawk512Pubkey::try_from_slice(payload)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let prepared_out: &mut [u8; HAWK_512_PREPARED_PUBKEY_LEN] = (&mut identity_out
            [PREPARED_OFFSET..])
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        // `prepare_into` is frame-split (≤4 KiB SBF frames) and writes the
        // 18 KB result straight into the account; it also re-checks 8-byte
        // alignment and errors rather than risking UB.
        pubkey
            .prepare_into(prepared_out)
            .map_err(|_| ProgramError::InvalidInstructionData)
    }

    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError> {
        // SAFETY: `identity` is borrowed from account data (8-byte aligned
        // per the Solana ABI) and `PREPARED_ALIGNED` guarantees the
        // `PREPARED_OFFSET` slice is also 8-byte aligned, as
        // `Hawk512PreparedPubkey::try_from_slice` requires. The slice length
        // is exactly `HAWK_512_PREPARED_PUBKEY_LEN`.
        let prepared = unsafe {
            Hawk512PreparedPubkey::try_from_slice(&identity[PREPARED_OFFSET..])
                .map_err(|_| ProgramError::InvalidAccountData)?
        };
        let sig = Hawk512Signature::try_from_slice(signature)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        if sig.verify_with_prepared(digest, prepared) {
            Ok(())
        } else {
            Err(ProgramError::MissingRequiredSignature)
        }
    }
}
