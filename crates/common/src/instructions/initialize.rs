use core::mem::MaybeUninit;

use pinocchio::{
    account::MAX_PERMITTED_DATA_INCREASE,
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, slot_hashes, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use solana_nostd_sha256::hashv;

use crate::scheme::SigningScheme;
use crate::state::VectorAccount;

/// Create the vector account at the canonical PDA for the identity derived
/// from the init payload, derive the initial nonce on-chain, and write the
/// header + the scheme's identity prefix.
///
/// This is strictly *create*: it makes no owner/state checks and never
/// resizes. Re-invoking it on an existing account fails naturally — the
/// system-program `CreateAccount` CPI errors on an account it no longer
/// owns. Single-step schemes (Ed25519/EIP-191/Falcon-512/Secp256k1) register
/// in this one call. Hawk-512's program routes its *first* call here and a
/// later call to [`prepare`](super::prepare::process) (it allocates only the
/// `min(full, MAX_PERMITTED_DATA_INCREASE)` base chunk here, since its full
/// account exceeds the single-CPI allocation cap — rent is funded for the
/// final size so the later resize stays rent-exempt).
///
/// Instruction data (after the discriminator): `init_payload` — the wire
/// pubkey/address, length `S::INIT_PAYLOAD_LEN`. No scheme byte (the program
/// ID identifies the scheme).
///
/// Accounts:
/// 0. `[signer, writable]` payer
/// 1. `[writable]`         vector PDA
/// 2. `[]`                 system program
pub fn process<S: SigningScheme>(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let [payer, vector, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let init_payload = instruction_data;
    if init_payload.len() != S::INIT_PAYLOAD_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    // PDA seed is derived directly from the payload (avoiding computing the
    // identity twice). For schemes where payload == identity this matches the
    // default rule; Falcon/Hawk override so the seed is `sha256(wire_pubkey)`.
    let identity_seed = S::pda_seed_from_payload(init_payload);

    let (expected_pda, bump) =
        Address::find_program_address(&[b"vector", identity_seed.as_slice()], program_id);
    if vector.address() != &expected_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    // Derive the initial nonce from the canonical PDA seed + latest slot
    // entry via the get_sysvar syscall. Read one entry (40 bytes) at offset 8
    // (past the entry count header). Entry layout:
    // [u64 slot_height, [u8; 32] slot_hash].
    let mut entry: [MaybeUninit<u8>; 40] = [MaybeUninit::uninit(); 40];
    let entry = unsafe {
        slot_hashes::fetch_into_unchecked(&mut *(entry.as_mut_ptr() as *mut [u8; 40]), 8)?;
        &*(entry.as_ptr() as *const [u8; 40])
    };
    let nonce = hashv(&[identity_seed.as_slice(), entry]);

    let bump_arr = [bump];
    let seeds = [
        Seed::from(b"vector"),
        Seed::from(identity_seed.as_slice()),
        Seed::from(&bump_arr),
    ];
    let signers = [Signer::from(&seeds)];

    // A CPI `CreateAccount` can only allocate up to
    // `MAX_PERMITTED_DATA_INCREASE` bytes; schemes whose identity exceeds
    // that (Hawk-512) get a base chunk now and grow in `prepare`. Rent is
    // funded for the *final* size so the account stays rent-exempt across a
    // later resize.
    let full_len = VectorAccount::account_len::<S>();
    let alloc_len = full_len.min(MAX_PERMITTED_DATA_INCREASE);
    let lamports = Rent::get()?.try_minimum_balance(full_len)?;

    CreateAccount {
        from: payer,
        to: vector,
        lamports,
        space: alloc_len as u64,
        owner: program_id,
    }
    .invoke_signed(&signers)?;

    // Single mutable borrow: write the 33-byte header, then have the scheme
    // populate the identity bytes that fit in the initial allocation.
    // Single-step schemes get exactly `IDENTITY_LEN`; Hawk-512 gets the base
    // chunk and writes only its cheap `sha256(wire)` prefix here.
    {
        let mut data = vector.try_borrow_mut()?;
        data[..32].copy_from_slice(&nonce);
        data[32] = bump;
        let (_, identity_out) = data.split_at_mut(VectorAccount::HEADER_LEN);
        S::populate_identity(init_payload, identity_out)?;
    }

    Ok(())
}
