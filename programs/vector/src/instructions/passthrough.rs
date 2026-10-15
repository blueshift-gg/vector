use alloc::vec::Vec;
use core::slice::from_ref;

use pinocchio::{
    cpi::{invoke_signed_with_slice, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::instructions::Instructions,
    AccountView, Address, ProgramResult,
};

use crate::{
    instructions::{top_level_only, Advance},
    state::{VectorAccount, VECTOR_SEED},
};

/// # Passthrough
///
/// Run instructions as one or more accounts: each is invoked with them as
/// signers. This is how an account moves funds, uses another program, or
/// calls `Withdraw` and `Close` on itself.
///
/// Each signer is a vector account, and signs either as itself or as its
/// system PDA, `[vector address, system_bump]` under the program and owned by
/// the System program. The system PDA is for what only a system account can
/// do, such as `Transfer`, `Allocate` or `Assign`.
///
/// It checks no signature. It requires the transaction's first `Advance` to
/// come earlier and list every signer. `Advance` verifies a signature for
/// every account it lists, and that signature is over the whole transaction,
/// this instruction included. Only one `Advance` can succeed in a
/// transaction: each one's message covers the other's signatures.
///
/// > Find the first `Advance`, and check it lists each signer
/// > Invoke each instruction, signing as whichever signers it names
///
/// Accounts:
///
/// 1. instructions_sysvar
/// 2. signers: one vector account each
/// 3. then, for each instruction: its program and its accounts
///
/// Parameters:
///
/// - num_signers: u8
/// - for each signer: 0 to sign as the account, 1 as its system PDA
/// - num_instructions: u8
/// - for each instruction: num_accounts: u8, data_len: u16, data
///
/// Account Checks:
/// - InstructionsSysvar: the instructions sysvar
/// - Signer: owned by the program, listed in the first `Advance`
pub struct Passthrough<'a> {
    instructions_sysvar: &'a AccountView,
    signers: &'a mut [AccountView],
    system: &'a [u8],
    remaining: &'a [AccountView],
    instructions: &'a [u8],
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Passthrough<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        top_level_only()?;

        let [instructions_sysvar, accounts @ ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        let [num_signers, data @ ..] = data else {
            return Err(ProgramError::InvalidInstructionData);
        };
        let (system, instructions) = data
            .split_at_checked((*num_signers).into())
            .ok_or(ProgramError::InvalidInstructionData)?;
        let (signers, remaining) = accounts
            .split_at_mut_checked(system.len())
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        if signers.is_empty() {
            return Err(ProgramError::NotEnoughAccountKeys);
        }

        Ok(Self {
            instructions_sysvar,
            signers,
            system,
            remaining,
            instructions,
        })
    }
}

impl<'a> Passthrough<'a> {
    pub const DISCRIMINATOR: &'a u8 = &1;

    pub fn process(&mut self) -> ProgramResult {
        let authorities = self.authorities()?;
        let seeds: Vec<Vec<Seed>> = authorities.iter().map(Authority::seeds).collect();

        let mut data = self.instructions;
        let mut accounts = self.remaining;

        for _ in 0..read::<1>(&mut data)?[0] {
            let num_accounts = read::<1>(&mut data)?[0] as usize;
            let data_len = u16::from_le_bytes(*read::<2>(&mut data)?) as usize;
            let (instruction_data, rest) = data
                .split_at_checked(data_len)
                .ok_or(ProgramError::InvalidInstructionData)?;
            data = rest;

            let ([program, instruction_accounts @ ..], rest) = accounts
                .split_at_checked(1 + num_accounts)
                .ok_or(ProgramError::NotEnoughAccountKeys)?
            else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            accounts = rest;

            // An authority signs wherever it appears, and only there.
            let names = |authority: &Authority| {
                instruction_accounts
                    .iter()
                    .any(|account| account.address() == &authority.address)
            };
            let metas: Vec<InstructionAccount> = instruction_accounts
                .iter()
                .map(|account| {
                    let mut meta = InstructionAccount::from(account);
                    meta.is_signer |= authorities
                        .iter()
                        .any(|authority| account.address() == &authority.address);
                    meta
                })
                .collect();
            let signers: Vec<Signer> = authorities
                .iter()
                .zip(&seeds)
                .filter(|(authority, _)| names(authority))
                .map(|(_, seeds)| Signer::from(seeds.as_slice()))
                .collect();

            invoke_signed_with_slice(
                &InstructionView {
                    program_id: program.address(),
                    accounts: &metas,
                    data: instruction_data,
                },
                instruction_accounts,
                &signers,
            )?;
        }

        if !data.is_empty() || !accounts.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }

    /// Who this passthrough signs as: each signer, checked against the
    /// first `Advance`, with the address and seeds it signs with.
    fn authorities(&mut self) -> Result<Vec<Authority>, ProgramError> {
        let instructions = Instructions::try_from(self.instructions_sysvar)?;
        let advance = (0..instructions.load_current_index())
            .filter_map(|index| instructions.load_instruction_at(index.into()).ok())
            .find(|instruction| {
                instruction.get_program_id() == &crate::ID
                    && instruction.get_instruction_data().first() == Some(Advance::DISCRIMINATOR)
            })
            .ok_or(ProgramError::MissingRequiredSignature)?;

        self.signers
            .iter_mut()
            .zip(self.system)
            .map(|(signer, system)| {
                let vector = *signer.address();
                // The seeds come from the account itself, so a signature can
                // only ever be the account's own.
                let header = {
                    let mut data = VectorAccount::borrow(signer)?;
                    *VectorAccount::split(&mut data)?.0
                };
                let listed = (0..advance.num_account_metas()).any(|index| {
                    advance
                        .get_instruction_account_at(index)
                        .is_ok_and(|meta| meta.key == vector)
                });
                if !listed {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                let address = match system {
                    0 => vector,
                    1 => Address::create_program_address(
                        &[vector.as_ref(), &[header.system_bump]],
                        &crate::ID,
                    )?,
                    _ => return Err(ProgramError::InvalidInstructionData),
                };
                Ok(Authority {
                    vector,
                    header,
                    address,
                })
            })
            .collect()
    }
}

/// An address the passthrough signs as: a vector account, or its system
/// PDA.
struct Authority {
    vector: Address,
    header: VectorAccount,
    address: Address,
}

impl Authority {
    fn seeds(&self) -> Vec<Seed<'_>> {
        if self.address == self.vector {
            [
                VECTOR_SEED,
                from_ref(&self.header.scheme),
                &self.header.seed,
                from_ref(&self.header.bump),
            ]
            .map(Seed::from)
            .to_vec()
        } else {
            [self.vector.as_ref(), from_ref(&self.header.system_bump)]
                .map(Seed::from)
                .to_vec()
        }
    }
}

/// Take the next `N` bytes off the front of `data`.
fn read<'a, const N: usize>(data: &mut &'a [u8]) -> Result<&'a [u8; N], ProgramError> {
    let (bytes, rest) = data
        .split_first_chunk()
        .ok_or(ProgramError::InvalidInstructionData)?;
    *data = rest;
    Ok(bytes)
}
