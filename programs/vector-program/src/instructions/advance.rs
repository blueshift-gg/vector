use core::mem::MaybeUninit;

use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};

use crate::helpers::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};
use crate::state::{VectorAccount, VectorBuffer};

const SIGNATURE_LEN: usize = 64;

/// Upper bound on account metas per CPI'd instruction. Sizes the stack-
/// allocated meta buffer and the `invoke_signed_with_bounds` const generic.
const MAX_CPI_INSTRUCTION_ACCOUNTS: usize = 32;

/// Verify the `advance_vector_signature` over the canonical
/// `advance_vector_digest`, install the digest as the next seed, and replay
/// the supplied compiled CPI payload under the vector PDA's signer seeds.
///
/// Instruction data (after the discriminator stripped by `lib.rs`):
///
/// ```text
/// [0..64]  advance_vector_signature
/// [64]     num_instructions: u8
/// for each instruction:
///   u8  num_accounts
///   u16 data_len (little endian)
///   [u8; data_len] instruction_data
/// ```
///
/// Trailing accounts are consumed in order: each compiled instruction takes
/// the next `1 + num_accounts` views as `program_id + metas`. Signer/writable
/// flags are inherited from the outer transaction. Every CPI is signed with
/// `["vector", vector.pubkey, [bump]]`.
///
/// Accounts:
/// 0. `[writable]` vector PDA
/// 1. `[]`         instructions sysvar
/// 2. `[..]`       CPI payload accounts, in order
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    // `VectorBuffer` carves the signature hole at `current_instruction_index`,
    // which is only meaningful at the top level. Refuse nested CPI.
    if get_stack_height() != TRANSACTION_LEVEL_STACK_HEIGHT {
        return Err(ProgramError::InvalidInstructionData);
    }

    let [vector, instructions_sysvar, remaining @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let (advance_vector_signature, mut payload) = split_signature(instruction_data)?;
    let (pubkey, bump, next_seed) =
        verify_and_extract_signer(vector, instructions_sysvar, advance_vector_signature)?;

    // Scope the borrow so it's dropped before the CPI loop; otherwise any
    // sub-instruction referencing the same PDA would hit `AccountBorrowFailed`.
    {
        let mut data = vector.try_borrow_mut()?;
        data[..32].copy_from_slice(&next_seed);
    }

    let bump = [bump];
    let seeds = [
        Seed::from(b"vector"),
        Seed::from(&pubkey),
        Seed::from(&bump),
    ];
    let signers = [Signer::from(&seeds)];

    let num_instructions = read_u8(&mut payload)? as usize;
    let mut cursor = 0usize;
    for _ in 0..num_instructions {
        invoke_next(&mut payload, remaining, &mut cursor, &signers)?;
    }

    if !payload.is_empty() || cursor != remaining.len() {
        return Err(ProgramError::InvalidInstructionData);
    }

    Ok(())
}

#[inline(always)]
fn split_signature(data: &[u8]) -> Result<(&[u8; SIGNATURE_LEN], &[u8]), ProgramError> {
    data.split_first_chunk::<SIGNATURE_LEN>()
        .ok_or(ProgramError::InvalidInstructionData)
}

/// Verify the signature and return `(pubkey, bump, next_seed)`. Reads the
/// vector account by value so no borrow lingers across the CPI loop.
#[inline(always)]
fn verify_and_extract_signer(
    vector: &AccountView,
    instructions_sysvar: &AccountView,
    advance_vector_signature: &[u8; SIGNATURE_LEN],
) -> Result<([u8; 32], u8, [u8; 32]), ProgramError> {
    let vector_account: VectorAccount = vector.try_into()?;
    let advance_vector_buffer: VectorBuffer = instructions_sysvar.try_into()?;
    let advance_vector_digest =
        vector_account.verify(&advance_vector_buffer, advance_vector_signature)?;
    Ok((
        vector_account.address,
        vector_account.bump,
        advance_vector_digest,
    ))
}

/// Decode the next compiled instruction from `payload`, consume its accounts
/// from `remaining` via `cursor`, and CPI-invoke it under `signers`.
#[inline(always)]
fn invoke_next(
    payload: &mut &[u8],
    remaining: &[AccountView],
    cursor: &mut usize,
    signers: &[Signer],
) -> ProgramResult {
    let num_accounts = read_u8(payload)? as usize;
    let data_len = read_u16(payload)? as usize;

    if num_accounts > MAX_CPI_INSTRUCTION_ACCOUNTS || payload.len() < data_len {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (data, rest) = payload.split_at(data_len);
    *payload = rest;

    let end = cursor
        .checked_add(1 + num_accounts)
        .ok_or(ProgramError::InvalidInstructionData)?;
    if end > remaining.len() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let program_view = &remaining[*cursor];
    let account_views = &remaining[*cursor + 1..end];
    *cursor = end;

    let mut metas: [MaybeUninit<InstructionAccount>; MAX_CPI_INSTRUCTION_ACCOUNTS] =
        [const { MaybeUninit::uninit() }; MAX_CPI_INSTRUCTION_ACCOUNTS];
    for (slot, view) in metas.iter_mut().zip(account_views) {
        slot.write(InstructionAccount::from(view));
    }
    // SAFETY: the loop initialised exactly `num_accounts` entries, and
    // `MaybeUninit<InstructionAccount>` shares layout with `InstructionAccount`.
    let metas_slice: &[InstructionAccount] =
        unsafe { core::slice::from_raw_parts(metas.as_ptr().cast(), num_accounts) };

    let instruction = InstructionView {
        program_id: program_view.address(),
        accounts: metas_slice,
        data,
    };

    invoke_signed_with_bounds::<MAX_CPI_INSTRUCTION_ACCOUNTS, AccountView>(
        &instruction,
        account_views,
        signers,
    )
}

#[inline(always)]
fn read_u8(payload: &mut &[u8]) -> Result<u8, ProgramError> {
    let (first, rest) = payload
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    *payload = rest;
    Ok(*first)
}

#[inline(always)]
fn read_u16(payload: &mut &[u8]) -> Result<u16, ProgramError> {
    let (chunk, rest) = payload
        .split_first_chunk::<2>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    *payload = rest;
    Ok(u16::from_le_bytes(*chunk))
}
