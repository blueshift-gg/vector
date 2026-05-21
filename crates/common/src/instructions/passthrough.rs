use alloc::vec::Vec;

use pinocchio::{
    cpi::{invoke_signed_with_slice, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::instructions::INSTRUCTIONS_ID,
    AccountView, Address, ProgramResult,
};

use crate::{
    helpers::{read_u16, read_u16_at, read_u8},
    instructions::advance::cpi_guard,
    scheme::SigningScheme,
    state::{signer_seeds, VectorAccount},
};

/// Discriminator the sysvar scan looks for. Kept in sync with
/// [`VectorInstruction::Advance`](super::VectorInstruction).
const ADVANCE_DISCRIMINATOR: u8 = 1;

/// Authorize a batch of CPIs against the vector PDA's signer seeds, gated
/// by a sibling `advance` ix earlier in the same transaction.
///
/// The authorization model: `advance`'s signature commits (via the digest)
/// to the *entire* instructions sysvar buffer minus its own sig bytes —
/// which transitively commits to this `passthrough` ix's data and account
/// layout. So if `advance` ran successfully earlier in the tx (atomicity
/// ensures it did, or the tx aborted), the caller signed off on this
/// specific passthrough payload. The on-chain scan below just confirms
/// such an `advance` exists for *our* vector PDA — it doesn't need to
/// re-verify the sig.
///
/// CPI is rejected via [`cpi_guard`]: the sysvar scan is only meaningful
/// at top-level, where the sysvar reflects the actual tx layout.
///
/// Instruction data (after the discriminator stripped by [`crate::dispatch`]):
///
/// ```text
/// [0]  num_instructions: u8
/// for each instruction:
///   u8  num_accounts
///   u16 data_len (little endian)
///   [u8; data_len] instruction_data
/// ```
///
/// Accounts:
/// 0. `[writable]` vector PDA
/// 1. `[]`         instructions sysvar
/// 2. `[..]`       CPI payload accounts, in order (program_id then accounts
///    for each sub-instruction)
pub fn process<S: SigningScheme>(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    cpi_guard()?;

    let [vector, instructions_sysvar, remaining @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !vector.owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if instructions_sysvar.address() != &INSTRUCTIONS_ID {
        return Err(ProgramError::UnsupportedSysvar);
    }

    let pda_address = vector.address().to_bytes();

    let (identity_seed, bump) = {
        let header_and_identity = vector.try_borrow()?;
        if header_and_identity.len() < VectorAccount::HEADER_LEN + S::IDENTITY_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        let bump = header_and_identity[32];
        let identity = &header_and_identity
            [VectorAccount::HEADER_LEN..VectorAccount::HEADER_LEN + S::IDENTITY_LEN];
        (S::pda_seed_from_identity(identity), bump)
    };

    // Confirm a sibling `advance` earlier in this tx authorises the
    // passthrough. Earlier-only enforcement: solana atomicity already
    // protects us against ordering games (a later advance failing would
    // revert this), but scanning strictly before the current ix makes the
    // intent explicit and matches the user-facing flow ("sign + then
    // execute").
    verify_prior_advance(instructions_sysvar, program_id, &pda_address)?;

    let bump_arr = [bump];
    let seeds = signer_seeds(&identity_seed, &bump_arr);
    let signers = [Signer::from(&seeds)];

    passthrough_cpi(data, remaining, &signers, &pda_address)
}

/// Walk the instructions sysvar and confirm there is at least one prior
/// (index `< current_instruction_index`) instruction whose:
/// * program_id matches `program_id` (i.e. it is one of *this* program's
///   ixs, so its sig was checked against this program's verify code), and
/// * discriminator byte is [`ADVANCE_DISCRIMINATOR`], and
/// * first meta address equals `vector_address` (binding it to the same
///   vector PDA we are signing for here).
///
/// Returns `Ok(())` on hit, `ProgramError::MissingRequiredSignature` if no
/// matching prior advance is found.
fn verify_prior_advance(
    sysvar: &AccountView,
    program_id: &Address,
    vector_address: &[u8; 32],
) -> Result<(), ProgramError> {
    if sysvar.address() != &INSTRUCTIONS_ID {
        return Err(ProgramError::UnsupportedSysvar);
    }
    // The sysvar borrow is leaked (mirroring `VectorBuffer`) so the slice
    // can outlive the inner block; the data is read-only.
    core::mem::forget(sysvar.try_borrow()?);
    let data: &[u8] = unsafe { core::slice::from_raw_parts(sysvar.data_ptr(), sysvar.data_len()) };

    if data.len() < 6 {
        return Err(ProgramError::InvalidAccountData);
    }

    let num_ixs = read_u16_at(data, 0)? as usize;
    let current = read_u16_at(data, data.len() - 2)? as usize;
    if current >= num_ixs {
        return Err(ProgramError::InvalidAccountData);
    }

    // Only scan earlier ixs — passthrough must come strictly after its
    // sibling advance.
    for i in 0..current {
        let off_pos = 2usize
            .checked_add(2 * i)
            .ok_or(ProgramError::InvalidAccountData)?;
        let off = read_u16_at(data, off_pos)? as usize;

        let num_accts = read_u16_at(data, off)? as usize;
        let metas_len = num_accts
            .checked_mul(33)
            .ok_or(ProgramError::InvalidAccountData)?;
        let prog_pos = off
            .checked_add(2)
            .and_then(|n| n.checked_add(metas_len))
            .ok_or(ProgramError::InvalidAccountData)?;
        let data_len_pos = prog_pos
            .checked_add(32)
            .ok_or(ProgramError::InvalidAccountData)?;
        let disc_pos = data_len_pos
            .checked_add(2)
            .ok_or(ProgramError::InvalidAccountData)?;
        // Tolerate a malformed sysvar entry by treating it as a miss.
        if disc_pos >= data.len() || prog_pos + 32 > data.len() {
            continue;
        }
        if &data[prog_pos..prog_pos + 32] != program_id.as_ref() {
            continue;
        }
        if data[disc_pos] != ADVANCE_DISCRIMINATOR {
            continue;
        }
        if num_accts < 1 {
            continue;
        }
        // First meta = vector_pda. Each meta is `flag(1) || addr(32)`.
        let first_addr_pos = off
            .checked_add(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(ProgramError::InvalidAccountData)?;
        if first_addr_pos + 32 > data.len() {
            continue;
        }
        if &data[first_addr_pos..first_addr_pos + 32] == vector_address {
            return Ok(());
        }
    }

    Err(ProgramError::MissingRequiredSignature)
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
