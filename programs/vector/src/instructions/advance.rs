use pinocchio::{
    error::ProgramError, sysvars::instructions::Instructions, AccountView, ProgramResult,
};
use solana_nostd_sha256::hashv;

use crate::{instructions::top_level_only, state::VectorAccount};

/// # Advance
///
/// Verify that every listed account signed this transaction, and move each
/// account to its next nonce. It runs no CPI: pair it with `Passthrough`.
///
/// Every signer signs the same message, the whole transaction with this
/// instruction's data left out. Each signer's digest then covers its own
/// next key, so the signatures are the only bytes nobody signs.
///
/// > Hash the transaction without this instruction's data into the message
/// > For each account, verify its signature over
/// >   `SHA256(message || nonce || address || next_key)`
/// > Store that digest as the account's next nonce, and its next key
///
/// An account listed twice is advanced twice, and needs a signature for
/// each: the second is over the nonce the first stored.
///
/// Accounts:
///
/// 1..n. vector:             [mut]   one per signer
/// n+1.  instructions_sysvar
///
/// Parameters, for each account in order:
///
/// - next_key: as long as its scheme says (none for a scheme whose key never
///   changes)
/// - signature: as long as its scheme says
///
/// Account Checks:
/// - Vector: at least one, each owned by the program, complete, of a known
///   scheme
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
        let message = message(self.instructions_sysvar, self.data.len())?;
        let mut data = self.data;

        for vector in self.vectors.iter_mut() {
            let address = vector.address().to_bytes();
            let mut account = VectorAccount::borrow(vector)?;
            let scheme = VectorAccount::scheme(&account)?;
            let (header, identity) = VectorAccount::split(&mut account)?;
            (scheme.advance)(identity, &mut header.nonce, &message, &address, &mut data)?;
        }

        // The data was next keys and signatures and nothing else.
        if !data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }
}

/// The SHA-256 of the transaction with the executing `Advance`'s last
/// `cut` bytes cut out.
fn message(instructions_sysvar: &AccountView, cut: usize) -> Result<[u8; 32], ProgramError> {
    let instructions = Instructions::try_from(instructions_sysvar)?;
    let data = instructions_sysvar.try_borrow()?;
    let advance = instructions.load_instruction_at(instructions.load_current_index().into())?;

    let advance_data = advance.get_instruction_data();
    let end = advance_data.as_ptr() as usize - data.as_ptr() as usize + advance_data.len();
    Ok(hashv(&[&data[..end - cut], &data[end..]]))
}
