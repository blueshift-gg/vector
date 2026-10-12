use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use solana_nostd_sha256::hashv;

use crate::{
    state::VectorAccount,
    transaction::{check_instructions_sysvar, top_level_only, Transaction},
};

/// # Advance
///
/// Verify that every listed account signed this transaction, and move each
/// account to its next nonce. It runs no CPI: pair it with `Passthrough`.
///
/// Every signer signs the same message, the whole transaction with the
/// signatures left out. The signatures are this instruction's data, so they
/// are the only bytes of the transaction that nobody signs.
///
/// > Hash the transaction without the signatures into the message
/// > For each account, verify its signature over
/// >   `SHA256(message || nonce || address)`
/// > Store that digest as the account's next nonce
///
/// Accounts:
///
/// 1..n. vector:             [mut]   one per signer
/// n+1.  instructions_sysvar
///
/// Parameters:
///
/// - signatures: one per account, in order, each as long as its account's
///   scheme says
///
/// Account Checks:
/// - Vector: at least one, each owned by the program and of a known scheme
/// - InstructionsSysvar: the instructions sysvar
pub struct Advance<'a> {
    vectors: &'a mut [AccountView],
    instructions_sysvar: &'a AccountView,
    signatures: &'a [u8],
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Advance<'a> {
    type Error = ProgramError;

    fn try_from(
        (signatures, accounts): (&'a [u8], &'a mut [AccountView]),
    ) -> Result<Self, Self::Error> {
        top_level_only()?;

        let [vectors @ .., instructions_sysvar] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Account Checks
        if vectors.is_empty() {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        check_instructions_sysvar(instructions_sysvar)?;

        Ok(Self {
            vectors,
            instructions_sysvar,
            signatures,
        })
    }
}

impl<'a> Advance<'a> {
    pub const DISCRIMINATOR: &'a u8 = &1;

    pub fn process(&mut self) -> ProgramResult {
        let message = self.message()?;

        let mut signatures = self.signatures;
        for vector in self.vectors.iter_mut() {
            let scheme = VectorAccount::scheme(vector)?;
            let (signature, rest) = signatures
                .split_at_checked(scheme.signature_len())
                .ok_or(ProgramError::InvalidInstructionData)?;
            signatures = rest;

            let address = vector.address().to_bytes();
            let mut data = vector.try_borrow_mut()?;
            let (account, identity) = VectorAccount::split(&mut data)?;
            let identity = identity
                .get(..scheme.identity_len())
                .ok_or(ProgramError::AccountDataTooSmall)?;

            // The message is the same for every signer. The nonce and the
            // address make the digest this account's own.
            let digest = hashv(&[&message, &account.nonce, &address]);
            scheme.verify(identity, &digest, signature)?;
            account.nonce = digest;
        }

        // The data was signatures and nothing else.
        if !signatures.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }

    /// The SHA-256 of the transaction with this instruction's signatures
    /// cut out: everything after its discriminator.
    fn message(&self) -> Result<[u8; 32], ProgramError> {
        let data = self.instructions_sysvar.try_borrow()?;
        let transaction = Transaction::new(&data);
        let advance = transaction.instruction(transaction.current_index()?)?;

        let signatures_start = advance.data_offset + 1;
        let signatures_end = advance.data_offset + advance.data.len();
        if signatures_start > signatures_end {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(hashv(&[&data[..signatures_start], &data[signatures_end..]]))
    }
}
