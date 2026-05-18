use alloc::vec::Vec;

use pinocchio::{
    cpi::{invoke_signed_with_slice, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};

use crate::{
    helpers::{read_u16, read_u8},
    scheme::SigningScheme,
    state::{signer_seeds, VectorAccount},
};

/// Vector's auth model relies on instructions-sysvar introspection, which is
/// only reliable in a top-level instruction. Reject any CPI invocation of
/// `advance` so a parent program cannot rewrite the sysvar layout the
/// signature was bound to.
#[inline(always)]
fn cpi_guard() -> Result<(), ProgramError> {
    #[cfg(target_os = "solana")]
    {
        /// Stack height of a top-level (non-CPI) instruction.
        const TRANSACTION_LEVEL_STACK_HEIGHT: u64 = 1;

        if unsafe { pinocchio::syscalls::sol_get_stack_height() }
            == TRANSACTION_LEVEL_STACK_HEIGHT
        {
            Ok(())
        } else {
            Err(ProgramError::IncorrectAuthority)
        }
    }
    #[cfg(not(target_os = "solana"))]
    {
        // Off-chain (host) builds can't trip this gate; treat as pass.
        Ok(())
    }
}

/// Verify the `advance_vector_signature` over the canonical
/// `advance_vector_digest`, install the digest as the next nonce, and replay
/// the supplied compiled CPI payload under the vector PDA's signer seeds.
///
/// Instruction data (after the discriminator stripped by [`crate::process`]):
///
/// ```text
/// [0..sig_len]  advance_vector_signature  (scheme-defined: 64 / 65 / 666)
/// [sig_len]     num_instructions: u8
/// for each instruction:
///   u8  num_accounts
///   u16 data_len (little endian)
///   [u8; data_len] instruction_data
/// ```
///
/// Accounts:
/// 0. `[writable]` vector PDA
/// 1. `[]`         instructions sysvar
/// 2. `[..]`       CPI payload accounts, in order
pub fn process<S: SigningScheme>(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    cpi_guard()?;

    let [vector, instructions_sysvar, remaining @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let (pda_address, state, identity_seed, payload) =
        VectorAccount::advance_nonce::<S>(vector, &*instructions_sysvar, program_id, data)?;

    let bump = [state.bump];
    let seeds = signer_seeds(&identity_seed, &bump);
    passthrough_cpi(payload, remaining, &[Signer::from(&seeds)], &pda_address)
}

/// Decode and invoke each compiled instruction from `payload`, consuming
/// accounts from `remaining` in order. Errors if any bytes or accounts are
/// left unconsumed.
fn passthrough_cpi(
    payload: &[u8],
    remaining: &[AccountView],
    signers: &[Signer],
    vector_address: &[u8; 32],
) -> ProgramResult {
    let mut payload = payload;
    let num_instructions = read_u8(&mut payload)? as usize;
    let mut cursor = 0usize;

    for _ in 0..num_instructions {
        let num_accounts = read_u8(&mut payload)? as usize;
        let data_len = read_u16(&mut payload)? as usize;

        if payload.len() < data_len {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (data, rest) = payload.split_at(data_len);
        payload = rest;

        let end = cursor
            .checked_add(1 + num_accounts)
            .ok_or(ProgramError::InvalidInstructionData)?;
        if end > remaining.len() {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let program_view = &remaining[cursor];
        let account_views = &remaining[cursor + 1..end];
        cursor = end;

        // Build the instruction-account metas on the heap (pinocchio's bump
        // allocator), promoting any account whose address matches the vector
        // PDA to `is_signer` so re-entry into `close`/`withdraw` passes the
        // `vector.is_signer()` gate.
        let mut metas: Vec<InstructionAccount> = Vec::with_capacity(num_accounts);
        for view in account_views {
            let mut meta = InstructionAccount::from(view);
            if view.address().as_ref() == vector_address {
                meta.is_signer = true;
            }
            metas.push(meta);
        }

        invoke_signed_with_slice(
            &InstructionView {
                program_id: program_view.address(),
                accounts: &metas,
                data,
            },
            account_views,
            signers,
        )?;
    }

    if !payload.is_empty() || cursor != remaining.len() {
        return Err(ProgramError::InvalidInstructionData);
    }

    Ok(())
}
