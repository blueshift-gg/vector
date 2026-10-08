use core::mem::MaybeUninit;

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::slot_hashes,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::create_program_account_with_minimum_balance_signed;
use solana_nostd_sha256::hashv;

use crate::scheme::SigningScheme;
use crate::state::VectorAccount;

/// Create the vector account at the canonical PDA for the identity derived
/// from the init payload, derive the initial nonce on-chain, and write the
/// header + the scheme's identity prefix.
///
/// This is strictly *create*. An address that already holds lamports but no
/// data is created all the same, so nobody can block a registration by
/// funding the PDA first. Re-invoking it on an existing account fails with
/// `AccountAlreadyInitialized`. Every current scheme
/// (Ed25519/EIP-191/Falcon-512/Secp256k1) registers in this one call.
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

    // Anyone can send lamports to the PDA before it exists, and a plain
    // `CreateAccount` refuses an address that holds any. The helper funds
    // only the shortfall in that case, and fails on an account that already
    // has data.
    create_program_account_with_minimum_balance_signed(
        vector,
        VectorAccount::account_len::<S>(),
        program_id,
        payer,
        None,
        &signers,
    )?;

    // Single mutable borrow: write the 33-byte header, then have the scheme
    // populate the identity bytes that fit in the initial allocation —
    // exactly `IDENTITY_LEN` for every current scheme.
    {
        let mut data = vector.try_borrow_mut()?;
        data[..32].copy_from_slice(&nonce);
        data[32] = bump;
        let (_, identity_out) = data.split_at_mut(VectorAccount::HEADER_LEN);
        S::populate_identity(init_payload, identity_out)?;
    }

    Ok(())
}
