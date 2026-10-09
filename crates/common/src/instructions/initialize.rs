use core::mem::MaybeUninit;

use pinocchio::{
    account::MAX_PERMITTED_DATA_INCREASE,
    cpi::Signer,
    error::ProgramError,
    sysvars::{rent::Rent, slot_hashes, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::{
    create_program_account_with_minimum_balance_signed, instructions::Transfer,
};
use solana_nostd_sha256::hashv;

use crate::scheme::SigningScheme;
use crate::state::{signer_seeds, VectorAccount};

/// Create the vector account at the canonical PDA for the identity derived
/// from the init payload, derive the initial nonce on-chain, and write the
/// header + the scheme's identity prefix.
///
/// This is strictly *create*. An address that already holds lamports but no
/// data is created all the same, so nobody can block a registration by
/// funding the PDA first. Re-invoking it on an existing account fails with
/// `AccountAlreadyInitialized`. Schemes with larger identities finish
/// preparation in later instructions.
///
/// Instruction data (after the discriminator): `init_payload` — the wire
/// pubkey/address, length `S::INIT_PAYLOAD_LEN`. No scheme byte (the program
/// ID identifies the scheme).
///
/// Accounts:
/// 0. `[signer, writable]` payer
/// 1. `[writable]`         vector PDA
/// 2. `[]`                 system_program (required for the System Program
///    CPIs — pinocchio's `invoke_signed` resolves the System program out of
///    the parent's `account_infos`, so the runtime needs it loaded via this
///    ix's metas; built-in programs are NOT auto-loaded for CPI dispatch).
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
    // default rule; Falcon overrides so the seed is `sha256(wire_pubkey)`.
    let identity_seed = S::pda_seed_from_payload(init_payload);

    let (expected_pda, bump) =
        Address::find_program_address(&[b"vector", &[S::ID], identity_seed.as_slice()], program_id);
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

    let (scheme, bump_arr) = ([S::ID], [bump]);
    let seeds = signer_seeds(&scheme, &identity_seed, &bump_arr);
    let signers = [Signer::from(&seeds)];

    // One instruction can only grow an account by
    // `MAX_PERMITTED_DATA_INCREASE` bytes. ML-DSA grows its prepared key
    // in later instructions.
    let full_len = VectorAccount::account_len::<S>();
    let alloc_len = full_len.min(MAX_PERMITTED_DATA_INCREASE);

    // Anyone can send lamports to the PDA before it exists, and a plain
    // `CreateAccount` refuses an address that holds any. The helper funds
    // only the shortfall in that case, and fails on an account that already
    // has data.
    create_program_account_with_minimum_balance_signed(
        vector, alloc_len, program_id, payer, None, &signers,
    )?;

    // Rent is always funded for the *final* size, which keeps the account
    // rent-exempt across any later resize.
    let shortfall = Rent::get()?
        .try_minimum_balance(full_len)?
        .saturating_sub(vector.lamports());
    if shortfall > 0 {
        Transfer {
            from: payer,
            to: vector,
            lamports: shortfall,
        }
        .invoke()?;
    }

    // Single mutable borrow: write the 34-byte header, then have the scheme
    // populate the identity bytes that fit in the initial allocation.
    {
        let mut data = vector.try_borrow_mut()?;
        data[..32].copy_from_slice(&nonce);
        data[32] = S::ID;
        data[33] = bump;
        let (_, identity_out) = data.split_at_mut(VectorAccount::HEADER_LEN);
        S::populate_identity(init_payload, identity_out)?;
    }

    Ok(())
}
