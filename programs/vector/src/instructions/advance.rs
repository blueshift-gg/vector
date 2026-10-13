use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use solana_nostd_sha256::hashv;

use crate::{
    instructions::Passthrough,
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
/// > If the signature used the key up, require a later `Passthrough` for
/// >   the account: that is where its next key comes from
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
    pub const DISCRIMINATOR: &'a u8 = &0;

    pub fn process(&mut self) -> ProgramResult {
        let message = self.message()?;

        let mut signatures = self.signatures;
        for vector in self.vectors.iter_mut() {
            let address = vector.address().to_bytes();
            let mut data = VectorAccount::borrow(vector)?;
            let (account, identity) = VectorAccount::load(&mut data)?;

            let (signature, rest) = signatures
                .split_at_checked(identity.signature_len())
                .ok_or(ProgramError::InvalidInstructionData)?;
            signatures = rest;

            // The message is the same for every signer. The nonce and the
            // address make the digest this account's own.
            let digest = hashv(&[&message, &account.nonce, &address]);
            identity.advance(&digest, signature)?;
            account.nonce = digest;
            if identity.spent() {
                check_passthrough_follows(self.instructions_sysvar, &address)?;
            }
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

/// A later instruction of this transaction is a `Passthrough` for `vector`.
/// The transaction lands whole or not at all, so the account's next key is
/// stored if this signature is used.
fn check_passthrough_follows(
    instructions_sysvar: &AccountView,
    vector: &[u8; 32],
) -> ProgramResult {
    let data = instructions_sysvar.try_borrow()?;
    let transaction = Transaction::new(&data);

    for index in transaction.current_index()? + 1..transaction.num_instructions()? {
        let instruction = transaction.instruction(index)?;
        if instruction.program_id == crate::ID.as_ref()
            && instruction.data.first() == Some(Passthrough::DISCRIMINATOR)
            && instruction.accounts.first().map(|meta| &meta[1..]) == Some(vector)
        {
            return Ok(());
        }
    }
    Err(ProgramError::InvalidInstructionData)
}
