use core::{mem::MaybeUninit, slice::from_ref};

use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer, MAX_STATIC_CPI_ACCOUNTS},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::instructions::Instructions,
    AccountView, Address, ProgramResult,
};

use crate::{
    error::VectorError,
    instructions::{top_level_only, Advance},
    state::{VectorAccount, VECTOR_SEED},
};

/// Most signers one `Passthrough` takes: the runtime's limit on signers of
/// one call (`MAX_SIGNERS` in Agave's `cpi.rs`).
const MAX_SIGNERS: usize = 16;

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
/// - for each signer, what it signs as: 0 the account, 1 its system PDA
/// - num_instructions: u8
/// - for each instruction: num_accounts: u8, data_len: u16, data
///
/// Account Checks:
/// - InstructionsSysvar: the instructions sysvar
/// - Signer: owned by the program, listed in the first `Advance`
pub struct Passthrough<'a> {
    instructions_sysvar: &'a AccountView,
    signers: &'a [AccountView],
    signs: &'a [Signs],
    remaining: &'a [AccountView],
    instructions: &'a [u8],
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Passthrough<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        top_level_only()?;

        let [instructions_sysvar, accounts @ ..] = &*accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        let [num_signers, data @ ..] = data else {
            return Err(ProgramError::InvalidInstructionData);
        };
        let (signs, instructions) = data
            .split_at_checked((*num_signers).into())
            .ok_or(ProgramError::InvalidInstructionData)?;
        let signs = Signs::parse(signs)?;
        let (signers, remaining) = accounts
            .split_at_checked(signs.len())
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        if signers.is_empty() {
            return Err(ProgramError::NotEnoughAccountKeys);
        }

        Ok(Self {
            instructions_sysvar,
            signers,
            signs,
            remaining,
            instructions,
        })
    }
}

impl<'a> Passthrough<'a> {
    pub const DISCRIMINATOR: &'a u8 = &1;

    pub fn process(&self) -> ProgramResult {
        let mut authorities = [const { MaybeUninit::uninit() }; MAX_SIGNERS];
        let authorities = self.authorities(&mut authorities)?;

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

            invoke(program, instruction_accounts, instruction_data, authorities)?;
        }

        if !data.is_empty() || !accounts.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }

    /// Who this passthrough signs as: each signer, checked against the
    /// first `Advance`, with the address and seeds it signs with.
    fn authorities<'b>(
        &self,
        buffer: &'b mut [MaybeUninit<Authority<'a>>],
    ) -> Result<&'b [Authority<'a>], ProgramError> {
        let instructions = Instructions::try_from(self.instructions_sysvar)?;
        let advance = (0..instructions.load_current_index())
            .filter_map(|index| instructions.load_instruction_at(index.into()).ok())
            .find(|instruction| {
                instruction.get_program_id() == &crate::ID
                    && instruction.get_instruction_data().first() == Some(Advance::DISCRIMINATOR)
            })
            .ok_or(VectorError::NotAdvanced)?;

        fill(
            buffer,
            self.signers.iter().zip(self.signs).map(|(signer, signs)| {
                if !signer.owned_by(&crate::ID) {
                    return Err(ProgramError::InvalidAccountOwner);
                }
                let vector = signer.address();
                let listed = (0..advance.num_account_metas()).any(|index| {
                    advance
                        .get_instruction_account_at(index)
                        .is_ok_and(|meta| &meta.key == vector)
                });
                if !listed {
                    return Err(VectorError::NotAdvanced.into());
                }
                // SAFETY: nothing writes a header the `Advance` lists while this
                // runs. Only `Advance` and `Initialize` write one: `Advance` runs
                // only at the top level, and `Initialize` refuses a complete
                // account, which every listed one is.
                let header = VectorAccount::header(unsafe { signer.borrow_unchecked() })?;
                Ok(match signs {
                    Signs::Vector => Authority::Vector {
                        address: vector,
                        seeds: [
                            Seed::from(VECTOR_SEED),
                            Seed::from(from_ref(&header.scheme)),
                            Seed::from(&header.seed),
                            Seed::from(from_ref(&header.bump)),
                        ],
                    },
                    Signs::System => {
                        let bump = from_ref(&header.system_bump);
                        Authority::System {
                            address: Address::create_program_address(
                                &[vector.as_ref(), bump],
                                &crate::ID,
                            )?,
                            seeds: [Seed::from(vector.as_ref()), Seed::from(bump)],
                        }
                    }
                })
            }),
        )
    }
}

/// What one signer of a `Passthrough` signs as: a byte of its data.
#[repr(u8)]
#[derive(Clone, Copy)]
enum Signs {
    /// The vector account.
    Vector = 0,
    /// The account's system PDA.
    System = 1,
}

impl Signs {
    const ALL: [Signs; 2] = [Signs::Vector, Signs::System];

    /// The bytes as `Signs`, in place, if each is one.
    fn parse(bytes: &[u8]) -> Result<&[Signs], ProgramError> {
        let valid = |byte: &u8| Self::ALL.iter().any(|signs| *signs as u8 == *byte);
        if !bytes.iter().all(valid) {
            return Err(ProgramError::InvalidInstructionData);
        }
        // SAFETY: `Signs` is one byte, and every byte is one of its values.
        Ok(unsafe { core::slice::from_raw_parts(bytes.as_ptr().cast(), bytes.len()) })
    }
}

/// An address the passthrough signs as, with its seeds, which point into the
/// account.
enum Authority<'a> {
    /// The vector account: `["vector", [scheme], seed, [bump]]`.
    Vector {
        address: &'a Address,
        seeds: [Seed<'a>; 4],
    },
    /// Its system PDA, which the program derives: `[vector address,
    /// system_bump]`.
    System {
        address: Address,
        seeds: [Seed<'a>; 2],
    },
}

impl Authority<'_> {
    fn address(&self) -> &Address {
        match self {
            Self::Vector { address, .. } => address,
            Self::System { address, .. } => address,
        }
    }

    fn signer(&self) -> Signer<'_, '_> {
        match self {
            Self::Vector { seeds, .. } => Signer::from(seeds),
            Self::System { seeds, .. } => Signer::from(seeds),
        }
    }
}

/// Invoke one instruction, each authority signing wherever it appears: at
/// most `MAX_STATIC_CPI_ACCOUNTS` (64) accounts, all on the stack.
#[inline(never)]
fn invoke(
    program: &AccountView,
    accounts: &[AccountView],
    data: &[u8],
    authorities: &[Authority],
) -> ProgramResult {
    let signs =
        |authority: &Authority, account: &AccountView| account.address() == authority.address();

    let mut metas = [const { MaybeUninit::uninit() }; MAX_STATIC_CPI_ACCOUNTS];
    let metas = fill(
        &mut metas,
        accounts.iter().map(|account| {
            let mut meta = InstructionAccount::from(account);
            meta.is_signer |= authorities
                .iter()
                .any(|authority| signs(authority, account));
            Ok(meta)
        }),
    )?;
    // Only the authorities the instruction names sign it: each costs the
    // runtime a derivation.
    let mut signers = [const { MaybeUninit::uninit() }; MAX_SIGNERS];
    let signers = fill(
        &mut signers,
        authorities
            .iter()
            .filter(|authority| accounts.iter().any(|account| signs(authority, account)))
            .map(|authority| Ok(authority.signer())),
    )?;

    call(
        &InstructionView {
            program_id: program.address(),
            accounts: metas,
            data,
        },
        accounts,
        signers,
    )
}

/// The call itself. pinocchio lays its accounts out on the stack, so this
/// frame holds them and `invoke`'s holds the rest: SBF allows 4 KB a frame.
#[inline(never)]
fn call(
    instruction: &InstructionView,
    accounts: &[AccountView],
    signers: &[Signer],
) -> ProgramResult {
    invoke_signed_with_bounds::<MAX_STATIC_CPI_ACCOUNTS, _>(instruction, accounts, signers)
}

/// Write `items` to the front of `buffer` and return them, or the first
/// error. More items than `buffer` holds is `InvalidArgument`.
fn fill<T>(
    buffer: &mut [MaybeUninit<T>],
    items: impl Iterator<Item = Result<T, ProgramError>>,
) -> Result<&[T], ProgramError> {
    let mut len = 0;
    for item in items {
        buffer
            .get_mut(len)
            .ok_or(ProgramError::InvalidArgument)?
            .write(item?);
        len += 1;
    }
    // SAFETY: the first `len` slots were written.
    Ok(unsafe { core::slice::from_raw_parts(buffer.as_ptr().cast(), len) })
}

/// Take the next `N` bytes off the front of `data`.
fn read<'a, const N: usize>(data: &mut &'a [u8]) -> Result<&'a [u8; N], ProgramError> {
    let (bytes, rest) = data
        .split_first_chunk()
        .ok_or(ProgramError::InvalidInstructionData)?;
    *data = rest;
    Ok(bytes)
}
