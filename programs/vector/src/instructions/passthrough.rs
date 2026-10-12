use alloc::vec::Vec;

use pinocchio::{
    cpi::{invoke_signed_with_slice, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};

use crate::{
    instructions::Advance,
    state::{signer_seeds, VectorAccount},
    transaction::{check_instructions_sysvar, top_level_only, Transaction},
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
/// - for Winternitz, the key that signs next; for XMSS, `0`, or `1` and
///   the key that signs next
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

        // Account Checks
        if !vector.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        check_instructions_sysvar(instructions_sysvar)?;

        Ok(Self {
            vector,
            instructions_sysvar,
            remaining,
            instructions,
        })
    }
}

impl<'a> Passthrough<'a> {
    pub const DISCRIMINATOR: &'a u8 = &4;

    pub fn process(&mut self) -> ProgramResult {
        let scheme = VectorAccount::scheme(self.vector)?;
        self.check_advanced()?;

        let mut data = self.vector.try_borrow_mut()?;
        let (account, identity) = VectorAccount::split(&mut data)?;
        let identity = identity
            .get_mut(..scheme.identity_len())
            .ok_or(ProgramError::AccountDataTooSmall)?;

        // The seeds come from the account itself, so the signature below can
        // only ever be the account's own.
        let (scheme_id, bump) = ([scheme.id()], [account.bump]);
        let identity_seed = scheme.seed_from_identity(identity);
        let seeds = signer_seeds(&scheme_id, &identity_seed, &bump);

        // A rotating scheme takes its next key off the front of the data.
        let instructions = scheme.passthrough(identity, self.instructions)?;
        drop(data);

        self.invoke(instructions, &[Signer::from(&seeds)])
    }

    /// An earlier instruction of this transaction is an `Advance` that lists
    /// the account. It ran, so the account's signature was verified.
    fn check_advanced(&self) -> ProgramResult {
        let data = self.instructions_sysvar.try_borrow()?;
        let transaction = Transaction::new(&data);
        let vector = self.vector.address().as_ref();

        for index in 0..transaction.current_index()? {
            let instruction = transaction.instruction(index)?;
            if instruction.program_id == crate::ID.as_ref()
                && instruction.data.first() == Some(Advance::DISCRIMINATOR)
                && instruction.accounts.iter().any(|meta| &meta[1..] == vector)
            {
                return Ok(());
            }
        }
        Err(ProgramError::MissingRequiredSignature)
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

/// Take the next `N` bytes off the front of `data`.
fn read<'a, const N: usize>(data: &mut &'a [u8]) -> Result<&'a [u8; N], ProgramError> {
    let (bytes, rest) = data
        .split_first_chunk()
        .ok_or(ProgramError::InvalidInstructionData)?;
    *data = rest;
    Ok(bytes)
}
