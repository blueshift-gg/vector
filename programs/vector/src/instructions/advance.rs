use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, instructions::Instructions, Sysvar},
    AccountView, ProgramResult,
};
use solana_nostd_sha256::hashv;

use crate::{
    error::VectorError,
    instructions::top_level_only,
    scheme::VALID_UNTIL_LEN,
    state::{NonceAccount, VectorAccount},
};

/// # Advance
///
/// Verify that every listed account signed this transaction, and move each
/// account to its next nonce. It runs no CPI: pair it with `Passthrough`.
///
/// Every signer signs the same message, the whole transaction with this
/// instruction's next keys and signatures left out: its `valid_until` stays
/// in, so every signature covers the one expiry. Each signer's digest then
/// covers its own next key, so the signatures are the only bytes nobody
/// signs.
///
/// > Check the slot is not past `valid_until`
/// > Hash the transaction without the next keys and signatures into the message
/// > For each account, verify its signature over `"vector:" || digest`, where
/// >   `digest = SHA256(message || nonce || address || next_key)`
/// > Store that digest as the account's next nonce, and its next key
///
/// A signer signs over its account's own nonce, or over a nonce account of
/// its vector listed right after it: `SHA256(nonce account's nonce ||
/// vector's nonce)` stands in for the nonce, and the digest moves the nonce
/// account only. Each nonce account is a chain of its own, so transactions
/// signed over different ones land in any order; moving the vector's own
/// nonce cancels them all.
///
/// An account listed twice is advanced twice, and needs a signature for
/// each: the second is over the nonce the first stored.
///
/// Accounts:
///
/// 1..n. vector:             [mut]   one per signer, each optionally
///                                   followed by its nonce account [mut]
/// n+1.  instructions_sysvar
///
/// Parameters:
///
/// - valid_until: u64 LE, the last slot the transaction may land in, for
///   every signer; `u64::MAX` for none. The message covers it
///
/// then, for each account in order:
///
/// - next_key: as long as its scheme says (none for a scheme whose key never
///   changes)
/// - signature: as long as its scheme says
///
/// Account Checks:
/// - Vector: at least one, each owned by the program, complete, of a known
///   scheme
/// - Nonce: one of the vector before it, past the slot it was created in
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
        let (valid_until, mut data) = self
            .data
            .split_first_chunk::<VALID_UNTIL_LEN>()
            .ok_or(ProgramError::InvalidInstructionData)?;
        // The slot is checked before anything is hashed: an expired one is
        // cheap.
        let slot = Clock::get()?.slot;
        if slot > u64::from_le_bytes(*valid_until) {
            return Err(VectorError::Expired.into());
        }
        let message = message(self.instructions_sysvar, data.len())?;
        let mut accounts = &mut *self.vectors;

        while let [vector, rest @ ..] = core::mem::take(&mut accounts) {
            // A nonce account right after the vector holds the nonce it signs.
            let listed = rest.first().is_some_and(NonceAccount::is);
            let (nonce, rest) = rest.split_at_mut(listed as usize);
            accounts = rest;

            let address = vector.address().to_bytes();
            let mut external = nonce
                .first_mut()
                .map(|nonce| NonceAccount::borrow(nonce, &address, slot))
                .transpose()?;
            let mut account = VectorAccount::borrow(vector)?;
            let scheme = VectorAccount::scheme(&account)?;
            let (header, identity) = VectorAccount::split(&mut account)?;
            match &mut external {
                Some(external) => {
                    let mut nonce = external.signed(&header.nonce);
                    (scheme.advance)(identity, &mut nonce, &message, &address, &mut data)?;
                    external.nonce = nonce;
                }
                None => {
                    (scheme.advance)(identity, &mut header.nonce, &message, &address, &mut data)?
                }
            }
        }

        // The data was next keys and signatures and nothing else.
        if !data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }
}

/// The SHA-256 of the transaction with the executing `Advance`'s last
/// `cut` bytes (its next keys and signatures) cut out.
fn message(instructions_sysvar: &AccountView, cut: usize) -> Result<[u8; 32], ProgramError> {
    let instructions = Instructions::try_from(instructions_sysvar)?;
    let data = instructions_sysvar.try_borrow()?;
    let advance = instructions.load_instruction_at(instructions.load_current_index().into())?;

    // Where this instruction's data ends in the sysvar, and the signed
    // bytes before it.
    let advance_data = advance.get_instruction_data();
    let end = (advance_data.as_ptr() as usize)
        .wrapping_sub(data.as_ptr() as usize)
        .wrapping_add(advance_data.len());
    let (before, after) = data
        .split_at_checked(end)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let signed = before
        .len()
        .checked_sub(cut)
        .and_then(|len| before.get(..len))
        .ok_or(ProgramError::InvalidInstructionData)?;
    Ok(hashv(&[signed, after]))
}
