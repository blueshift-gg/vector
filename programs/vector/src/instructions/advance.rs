use alloc::vec::Vec;

use pinocchio::{
    account::RefMut, error::ProgramError, sysvars::instructions::Instructions, AccountView,
    ProgramResult,
};
use solana_nostd_sha256::hashv;

use crate::{instructions::top_level_only, state::VectorAccount};

/// # Advance
///
/// Verify that every listed account signed this transaction, and move each
/// account to its next nonce. It runs no CPI: pair it with `Passthrough`.
///
/// Every signer signs the same message, the whole transaction with the
/// signatures left out. The signatures are the tail of this instruction's
/// data, so they are the only bytes of the transaction that nobody signs.
///
/// > Borrow every account, which refuses one listed twice
/// > Hash the transaction without the signatures into the message
/// > For each account, verify its signature over
/// >   `SHA256(message || nonce || address)`
/// > Store that digest as the account's next nonce, and its next key
///
/// Accounts:
///
/// 1..n. vector:             [mut]   one per signer
/// n+1.  instructions_sysvar
///
/// Parameters:
///
/// - next_keys: one per account, in order, each as long as its account's
///   scheme says (none for a scheme whose key never changes)
/// - signatures: one per account, in order, each as long as its account's
///   scheme says
///
/// Account Checks:
/// - Vector: at least one, each owned by the program, complete, of a known
///   scheme, and listed once
/// - InstructionsSysvar: the instructions sysvar
pub struct Advance<'a> {
    vectors: &'a mut [AccountView],
    instructions_sysvar: &'a AccountView,
    data: &'a [u8],
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Advance<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        top_level_only()?;

        let [vectors @ .., instructions_sysvar] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Account Checks: `Instructions` checks the sysvar's address.
        if vectors.is_empty() {
            return Err(ProgramError::NotEnoughAccountKeys);
        }

        Ok(Self {
            vectors,
            instructions_sysvar,
            data,
        })
    }
}

impl<'a> Advance<'a> {
    pub const DISCRIMINATOR: &'a u8 = &0;

    pub fn process(&mut self) -> ProgramResult {
        // Every borrow is held to the end, so an account listed twice fails.
        let mut accounts = self
            .vectors
            .iter_mut()
            .map(|vector| Ok((vector.address().to_bytes(), VectorAccount::borrow(vector)?)))
            .collect::<Result<Vec<([u8; 32], RefMut<'_, [u8]>)>, ProgramError>>()?;

        let mut next_keys_len = 0;
        for (_, data) in &accounts {
            next_keys_len += VectorAccount::scheme(data)?.next_key_len();
        }
        let (mut next_keys, mut signatures) = self
            .data
            .split_at_checked(next_keys_len)
            .ok_or(ProgramError::InvalidInstructionData)?;
        let message = message(self.instructions_sysvar, signatures.len())?;

        for (address, data) in &mut accounts {
            let scheme = VectorAccount::scheme(data)?;
            let (account, identity) = VectorAccount::split(data)?;
            let next_key = take(&mut next_keys, scheme.next_key_len())?;
            let signature = take(&mut signatures, scheme.signature_len())?;

            // The message is the same for every signer. The nonce and the
            // address make the digest this account's own.
            let digest = hashv(&[&message, &account.nonce, address]);
            scheme.advance(identity, &digest, signature, next_key)?;
            account.nonce = digest;
        }

        // The data was next keys and signatures and nothing else.
        if !signatures.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }
}

/// The SHA-256 of the transaction with the executing `Advance`'s last
/// `signatures_len` bytes, its signatures, cut out.
fn message(
    instructions_sysvar: &AccountView,
    signatures_len: usize,
) -> Result<[u8; 32], ProgramError> {
    let instructions = Instructions::try_from(instructions_sysvar)?;
    let data = instructions_sysvar.try_borrow()?;
    let advance = instructions.load_instruction_at(instructions.load_current_index().into())?;

    let advance_data = advance.get_instruction_data();
    let end = advance_data.as_ptr() as usize - data.as_ptr() as usize + advance_data.len();
    Ok(hashv(&[&data[..end - signatures_len], &data[end..]]))
}

/// Take the next `len` bytes off the front of `data`.
fn take<'a>(data: &mut &'a [u8], len: usize) -> Result<&'a [u8], ProgramError> {
    let (bytes, rest) = data
        .split_at_checked(len)
        .ok_or(ProgramError::InvalidInstructionData)?;
    *data = rest;
    Ok(bytes)
}
