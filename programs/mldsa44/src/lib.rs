//! ML-DSA-44 authorization. Initialize stores the public key and first prepared
//! row; two permissionless expansions complete the verification cache.
#![no_std]

use pinocchio::{
    account::MAX_PERMITTED_DATA_INCREASE, entrypoint, error::ProgramError, nostd_panic_handler,
    AccountView, Address, ProgramResult, Resize,
};
use solana_address::declare_id;
use vector_common::{dispatch, VectorAccount};

mod scheme;
use scheme::MlDsa44;

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("5qR1iCC5hinGAR9iE8dp5xJyh3Wq1Cwsxa4BuBuJieMr");

/// `6`, after the shared `0..=4` and the rotating programs' `5`.
const EXPAND_DISCRIMINATOR: u8 = 6;

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data {
        [EXPAND_DISCRIMINATOR] => expand(program_id, accounts),
        _ => dispatch::<MlDsa44>(program_id, accounts, instruction_data),
    }
}

/// Grow the account by one runtime step and fill the prepared rows that now
/// fit. Permissionless: the content is a function of the stored key. Fails
/// once the account is complete.
///
/// Accounts:
/// 0. `[writable]` vector PDA
fn expand(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [vector] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !vector.owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let full = VectorAccount::account_len::<MlDsa44>();
    let old = vector.data_len();
    if old < VectorAccount::HEADER_LEN + MlDsa44::PREFIX_LEN || old >= full {
        return Err(ProgramError::InvalidAccountData);
    }
    vector.resize(full.min(old + MAX_PERMITTED_DATA_INCREASE))?;
    let mut data = vector.try_borrow_mut()?;
    let (_, identity) = data.split_at_mut(VectorAccount::HEADER_LEN);
    MlDsa44::fill(identity, old - VectorAccount::HEADER_LEN)
}
