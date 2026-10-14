use alloc::vec::Vec;

use pinocchio::{
    cpi::{invoke_signed_with_slice, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::instructions::Instructions,
    AccountView, ProgramResult,
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
/// transaction that lists the account. `Advance` verifies a signature for
/// every account it lists, and that signature is over the whole transaction,
/// this instruction included.
///
/// > Find an earlier `Advance` that lists the account
/// > Let the scheme take its part: a rotating scheme sets its next key
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
/// - what the scheme takes first: for Winternitz, the key that signs next;
///   for XMSS, `0`, or `1` and the key that signs next
/// - num_instructions: u8
/// - for each instruction: num_accounts: u8, data_len: u16, data
///
/// Account Checks:
/// - Vector: owned by the program, complete, listed in an earlier `Advance`
/// - InstructionsSysvar: the instructions sysvar
pub struct Passthrough<'a> {
    vector: &'a mut AccountView,
    instructions_sysvar: &'a AccountView,
    remaining: &'a [AccountView],
    /// What the scheme takes, if anything, then the instructions.
    instructions: &'a [u8],
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Passthrough<'a> {
    type Error = ProgramError;

    fn try_from(
        (instructions, accounts): (&'a [u8], &'a mut [AccountView]),
    ) -> Result<Self, Self::Error> {
        top_level_only()?;

        let [vector, instructions_sysvar, remaining @ ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        Ok(Self {
            vector,
            instructions_sysvar,
            remaining,
            instructions,
        })
    }
}

impl<'a> Passthrough<'a> {
    pub const DISCRIMINATOR: &'a u8 = &1;

    pub fn process(&mut self) -> ProgramResult {
        let address = self.vector.address().to_bytes();

        // The seeds come from the account itself, so the signature below can
        // only ever be the account's own. A scheme whose key rotates takes
        // its next key off the front of the data.
        let (seed, scheme, bump, instructions) = {
            let mut data = VectorAccount::borrow(self.vector)?;
            let (account, identity) = VectorAccount::load(&mut data)?;
            check_advanced(self.instructions_sysvar, &address)?;
            (
                account.seed,
                [account.scheme],
                [account.bump],
                identity.passthrough(self.instructions)?,
            )
        };

        let seeds = [
            Seed::from(VECTOR_SEED),
            Seed::from(&scheme),
            Seed::from(&seed),
            Seed::from(&bump),
        ];
        self.invoke(instructions, &[Signer::from(&seeds)])
    }

    /// Invoke each instruction in the data, taking its program and accounts
    /// from the remaining accounts in order. All of both must be used.
    fn invoke(&self, mut data: &[u8], signers: &[Signer]) -> ProgramResult {
        let vector = self.vector.address();
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

            // The account signs wherever it appears.
            let metas: Vec<InstructionAccount> = instruction_accounts
                .iter()
                .map(|account| {
                    let mut meta = InstructionAccount::from(account);
                    meta.is_signer |= account.address() == vector;
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

/// An earlier instruction of this transaction is an `Advance` that lists
/// `vector`. It ran, so the account's signature was verified.
fn check_advanced(instructions_sysvar: &AccountView, vector: &[u8; 32]) -> ProgramResult {
    let instructions = Instructions::try_from(instructions_sysvar)?;

    for index in 0..instructions.load_current_index().into() {
        let instruction = instructions.load_instruction_at(index)?;
        if instruction.get_program_id() == &crate::ID
            && instruction.get_instruction_data().first() == Some(Advance::DISCRIMINATOR)
            && (0..instruction.num_account_metas()).any(|i| {
                instruction
                    .get_instruction_account_at(i)
                    .is_ok_and(|meta| meta.key.as_array() == vector)
            })
        {
            return Ok(());
        }
    }
    Err(ProgramError::MissingRequiredSignature)
}

/// Take the next `N` bytes off the front of `data`.
fn read<'a, const N: usize>(data: &mut &'a [u8]) -> Result<&'a [u8; N], ProgramError> {
    let (bytes, rest) = data
        .split_first_chunk()
        .ok_or(ProgramError::InvalidInstructionData)?;
    *data = rest;
    Ok(bytes)
}
