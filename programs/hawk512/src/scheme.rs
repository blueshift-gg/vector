use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult, Resize};
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
///   `prepare_into` (write, in `finalize`) and `verify_with_prepared` (read,
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
    assert!((VectorAccount::HEADER_LEN + PREPARED_OFFSET).is_multiple_of(8));

/// `initialize` allocates `min(full, 10240)` and `finalize` grows to `full`
/// in a single resize, capped at `MAX_PERMITTED_DATA_INCREASE` (10240). That
/// requires `full - 10240 <= 10240`, i.e. the whole account ≤ 20480 bytes.
const _SINGLE_EXPAND_FITS: () = assert!(VectorAccount::HEADER_LEN + HAWK_IDENTITY_LEN <= 2 * 10240);

/// Hawk-512. Identity is `sha256(wire_pubkey)` (32 bytes); the 18 KB
/// prepared pubkey is written by two follow-up permissionless ixs
/// (`store_wire`, `finalize`). Signatures are 555 bytes.
pub struct Hawk512;

/// Registration entry point — all three steps share discriminator `0` and
/// route here. Selection is by ix shape + vector account state:
///
/// | metas | data         | vector size | → step                       |
/// |-------|--------------|-------------|------------------------------|
/// | 3     | 32 B hash    | n/a         | step 1 (`vector_common::initialize`) |
/// | 1     | 1024 B wire  | < full_len  | step 2 ([`store_wire`])      |
/// | 1     | empty        | < full_len  | step 3 ([`finalize`])        |
/// | 1     | any          | == full_len | `AccountAlreadyInitialized`  |
///
/// Each handler still owner- and content-validates internally; the
/// dispatch is just routing. Keeping the branching here lets [`lib`]'s
/// match arm stay a single line per discriminator, mirroring every other
/// Vector scheme's structure.
///
/// A fully-prepared account returns `AccountAlreadyInitialized` rather
/// than silently no-op'ing so callers notice their state is wrong — they
/// almost certainly meant `advance` (disc 1), not a re-register.
pub fn initialize(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    match accounts {
        [_, _, _] => vector_common::initialize::<Hawk512>(program_id, accounts, instruction_data),
        [vector] => {
            if vector.data_len() < VectorAccount::account_len::<Hawk512>() {
                if instruction_data.is_empty() {
                    finalize(program_id, accounts)
                } else {
                    store_wire(program_id, accounts, instruction_data)
                }
            } else {
                Err(ProgramError::AccountAlreadyInitialized)
            }
        }
        _ => Err(ProgramError::NotEnoughAccountKeys),
    }
}

/// Registration step 2 — verify `sha256(payload) == committed hash` from
/// step 1, then stash the 1024-byte wire pubkey in the account's
/// prepared region so [`finalize`] can consume it. The hash verify is the
/// grief-prevention anchor — only callers who possess the actual wire
/// bytes can complete this step, so an attacker who squatted on step 1
/// can neither block this nor corrupt the stashed wire.
///
/// Accounts: `[vector_pda(writable)]`. Data: 1024 bytes (the wire pubkey).
fn store_wire(program_id: &Address, accounts: &mut [AccountView], payload: &[u8]) -> ProgramResult {
    let [vector] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !vector.owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if payload.len() != HAWK_512_PUBKEY_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut data = vector.try_borrow_mut()?;
    let (_, identity_out) = data.split_at_mut(VectorAccount::HEADER_LEN);
    if hash(payload) != identity_out[..HASH_LEN] {
        return Err(ProgramError::InvalidInstructionData);
    }
    identity_out[PREPARED_OFFSET..PREPARED_OFFSET + HAWK_512_PUBKEY_LEN].copy_from_slice(payload);
    Ok(())
}

/// Registration step 3 — resize the account from the base 10 240 B to
/// the full 18 536 B, then expand the wire pubkey stashed by
/// [`store_wire`] into its 18 KB prepared form in place. Idempotent —
/// re-running on an already-prepared account is a no-op.
///
/// Accounts: `[vector_pda(writable)]`. Data: empty.
fn finalize(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let () = PREPARED_ALIGNED;
    let [vector] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !vector.owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let full_len = VectorAccount::account_len::<Hawk512>();
    if vector.data_len() >= full_len {
        // Already fully prepared — idempotent no-op.
        return Ok(());
    }
    // Copy the wire pubkey out *before* resizing — `prepare_into` writes
    // its 18 KB output into the same region (the prepared offset), and we
    // need the input intact at call time. 1024 B is well under the SBF
    // 4 KiB stack frame.
    let wire: [u8; HAWK_512_PUBKEY_LEN] = {
        let data = vector.try_borrow()?;
        data[VectorAccount::HEADER_LEN + PREPARED_OFFSET
            ..VectorAccount::HEADER_LEN + PREPARED_OFFSET + HAWK_512_PUBKEY_LEN]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?
    };
    vector.resize(full_len)?;
    let mut data = vector.try_borrow_mut()?;
    let (_, identity_out) = data.split_at_mut(VectorAccount::HEADER_LEN);
    // Re-verify the stashed wire still matches the commit. Cheap (1 sha256
    // of 1024 B) and means even a same-tx attacker can't sneak invalid wire
    // bytes in between `store_wire` and `finalize`.
    if hash(&wire) != identity_out[..HASH_LEN] {
        return Err(ProgramError::InvalidInstructionData);
    }
    let prepared_out: &mut [u8; HAWK_512_PREPARED_PUBKEY_LEN] = (&mut identity_out
        [PREPARED_OFFSET..])
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let pubkey =
        Hawk512Pubkey::try_from_slice(&wire).map_err(|_| ProgramError::InvalidAccountData)?;
    pubkey
        .prepare_into(prepared_out)
        .map_err(|_| ProgramError::InvalidAccountData)
}

impl SigningScheme for Hawk512 {
    const SIGNATURE_LEN: usize = HAWK_512_SIGNATURE_LEN;
    const IDENTITY_LEN: usize = HAWK_IDENTITY_LEN;
    /// `initialize` payload is the 32-byte `sha256(wire_pubkey)` commit.
    /// The wire pubkey itself ships via `store_wire` (disc 0 + 1024-byte
    /// payload + 1 meta), and the 18 KB prepared expansion runs via
    /// `finalize` (disc 0 + empty payload + 1 meta). Splitting registration
    /// into three ixs is what keeps each tx under the 1232-byte network
    /// limit: the 1024-byte wire payload can't coexist with the
    /// `system_program` meta needed for `CreateAccount`.
    const INIT_PAYLOAD_LEN: usize = HASH_LEN;

    /// First call (3-meta init): commit `sha256(wire_pubkey)` to the
    /// account header. The wire pubkey itself is not yet known to the
    /// program — it arrives via `store_wire`, which verifies it against
    /// this commit before stashing.
    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError> {
        let () = PREPARED_ALIGNED;
        if payload.len() != HASH_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        identity_out[..HASH_LEN].copy_from_slice(payload);
        Ok(())
    }

    /// PDA seed is `sha256(wire_pubkey)`, stored as the first 32 bytes.
    fn pda_seed_from_identity(identity: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&identity[..HASH_LEN])
    }

    /// At init time the payload **is** the hash — no further hashing.
    fn pda_seed_from_payload(payload: &[u8]) -> IdentitySeed {
        IdentitySeed::copy_from(&payload[..HASH_LEN])
    }

    /// The client can't reproduce the 18 KB prepared form and the program
    /// can't cheaply rebuild the wire pubkey, so the digest folds in
    /// `sha256(wire_pubkey)` — the stored 32-byte prefix.
    fn digest_identity(identity: &[u8]) -> &[u8] {
        &identity[..HASH_LEN]
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
