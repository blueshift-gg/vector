use alloc::vec::Vec;

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
/// Run instructions as the account: each is invoked with the account as a
/// signer. This is how the account moves funds, uses another program, or
/// calls `Withdraw` and `Close` on itself.
///
/// It checks no signature. It requires an earlier `Advance` in the same
/// transaction that lists the account, and the data says where: the
/// `Advance`'s index in the transaction, and the account's index in it.
/// `Advance` verifies a signature for every account it lists, and that
/// signature is over the whole transaction, this instruction included.
///
/// > Check the `Advance` at `advance_index` lists the account at
/// >   `account_index`
/// > Invoke each instruction, signing as the account
///
/// Accounts:
///
/// 1. vector:              [mut]
/// 2. instructions_sysvar
/// 3. then, for each instruction: its program and its accounts
///
/// Parameters:
///
/// - advance_index: u8, usually 0
/// - account_index: u8
/// - num_instructions: u8
/// - for each instruction: num_accounts: u8, data_len: u16, data
///
/// Account Checks:
/// - Vector: owned by the program, listed in an earlier `Advance`
/// - InstructionsSysvar: the instructions sysvar
pub struct Passthrough<'a> {
    vector: &'a mut AccountView,
    instructions_sysvar: &'a AccountView,
    /// `SystemPassthrough`: the account's system PDA, which signs instead.
    system: Option<&'a AccountView>,
    remaining: &'a [AccountView],
    advance_index: usize,
    account_index: usize,
    instructions: &'a [u8],
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Passthrough<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let [vector, instructions_sysvar, remaining @ ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Self::new(data, vector, instructions_sysvar, None, remaining)
    }
}

/// # SystemPassthrough
///
/// `Passthrough`, signing as the account's system PDA instead of the
/// account: `[vector address, system_bump]`, owned by the System program.
/// It is for what only a system account can do, such as `Transfer`,
/// `Allocate` or `Assign`. The account itself does not sign.
///
/// Accounts:
///
/// 1. vector
/// 2. instructions_sysvar
/// 3. system: the account's system PDA
/// 4. then, for each instruction: its program and its accounts
///
/// Parameters: as `Passthrough`
///
/// Account Checks:
/// - Vector: owned by the program, listed in an earlier `Advance`
/// - InstructionsSysvar: the instructions sysvar
/// - System: the PDA of `[vector address, system_bump]`
pub struct SystemPassthrough<'a>(Passthrough<'a>);

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for SystemPassthrough<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let [vector, instructions_sysvar, system, remaining @ ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Passthrough::new(data, vector, instructions_sysvar, Some(system), remaining).map(Self)
    }
}

impl<'a> SystemPassthrough<'a> {
    pub const DISCRIMINATOR: &'a u8 = &5;

    pub fn process(&mut self) -> ProgramResult {
        self.0.process()
    }
}

impl<'a> Passthrough<'a> {
    pub const DISCRIMINATOR: &'a u8 = &1;

    fn new(
        data: &'a [u8],
        vector: &'a mut AccountView,
        instructions_sysvar: &'a AccountView,
        system: Option<&'a AccountView>,
        remaining: &'a [AccountView],
    ) -> Result<Self, ProgramError> {
        top_level_only()?;

        let [advance_index, account_index, instructions @ ..] = data else {
            return Err(ProgramError::InvalidInstructionData);
        };

        Ok(Self {
            vector,
            instructions_sysvar,
            system,
            remaining,
            advance_index: (*advance_index).into(),
            account_index: (*account_index).into(),
            instructions,
        })
    }

    pub fn process(&mut self) -> ProgramResult {
        let address = self.vector.address().to_bytes();
        // The seeds come from the account itself, so the signature below can
        // only ever be the account's own.
        let account = {
            let mut data = VectorAccount::borrow(self.vector)?;
            *VectorAccount::split(&mut data)?.0
        };
        check_advanced(
            self.instructions_sysvar,
            &address,
            self.advance_index,
            self.account_index,
        )?;

        match self.system {
            None => {
                let (scheme, bump) = ([account.scheme], [account.bump]);
                let seeds = [
                    Seed::from(VECTOR_SEED),
                    Seed::from(&scheme),
                    Seed::from(&account.seed),
                    Seed::from(&bump),
                ];
                self.invoke(self.vector.address(), &[Signer::from(&seeds)])
            }
            Some(system) => {
                let bump = [account.system_bump];
                let pda = Address::create_program_address(&[&address, &bump], &crate::ID)?;
                if system.address() != &pda {
                    return Err(ProgramError::InvalidSeeds);
                }
                let seeds = [Seed::from(&address), Seed::from(&bump)];
                self.invoke(system.address(), &[Signer::from(&seeds)])
            }
        }
    }

    /// Invoke each instruction in the data, taking its program and accounts
    /// from the remaining accounts in order, with `signer` signing. All of
    /// both must be used.
    fn invoke(&self, signer: &Address, signers: &[Signer]) -> ProgramResult {
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

            // The signer signs wherever it appears.
            let metas: Vec<InstructionAccount> = instruction_accounts
                .iter()
                .map(|account| {
                    let mut meta = InstructionAccount::from(account);
                    meta.is_signer |= account.address() == signer;
                    meta
                })
                .collect();

            invoke_signed_with_slice(
                &InstructionView {
                    program_id: program.address(),
                    accounts: &metas,
                    data: instruction_data,
                },
                instruction_accounts,
                signers,
            )?;
        }

        if !data.is_empty() || !accounts.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }
}

/// The instruction at `advance_index` is an earlier `Advance` whose account
/// at `account_index` is `vector`. It ran, so the account's signature was
/// verified.
fn check_advanced(
    instructions_sysvar: &AccountView,
    vector: &[u8; 32],
    advance_index: usize,
    account_index: usize,
) -> ProgramResult {
    let instructions = Instructions::try_from(instructions_sysvar)?;
    if advance_index >= instructions.load_current_index().into() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let advance = instructions.load_instruction_at(advance_index)?;
    let listed = advance.get_program_id() == &crate::ID
        && advance.get_instruction_data().first() == Some(Advance::DISCRIMINATOR)
        && advance
            .get_instruction_account_at(account_index)
            .is_ok_and(|meta| meta.key.as_array() == vector);
    if !listed {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

/// Take the next `N` bytes off the front of `data`.
fn read<'a, const N: usize>(data: &mut &'a [u8]) -> Result<&'a [u8; N], ProgramError> {
    let (bytes, rest) = data
        .split_first_chunk()
        .ok_or(ProgramError::InvalidInstructionData)?;
    *data = rest;
    Ok(bytes)
}
