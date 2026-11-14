use pinocchio::{error::ProgramError, AccountView, ProgramResult};

use crate::{
    error::VectorError,
    state::{VectorAccount, VectorAccountExt as _},
};

/// # Withdraw
///
/// Send lamports from the account to the receiver. The runtime refuses to
/// leave it with less than rent-exemption but more than nothing, and a
/// Winternitz or XMSS account refuses nothing: it would close, which `Close`
/// refuses it.
///
/// It only runs inside a `Passthrough`, which is what makes the account a
/// signer. The owner's signature on the `Advance` covers it.
///
/// Accounts:
///
/// 1. vector:      [signer, mut]
/// 2. receiver:    [mut]
///
/// Parameters:
///
/// - lamports: u64
///
/// Account Checks:
/// - Vector: signer, and a complete vector account of the program
pub struct Withdraw<'a> {
    vector: &'a mut AccountView,
    receiver: &'a mut AccountView,
    lamports: u64,
    /// The scheme's key changes, so the account must not close.
    rotates: bool,
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Withdraw<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let [vector, receiver] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Account Checks: the runtime refuses to debit an account the
        // program does not own, or to change the lamports an instruction
        // holds in total, so a receiver that is the vector fails.
        if !vector.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Only a vector account is the vector's to spend. A nonce account is
        // the program's too, and its keypair can sign: it is not a vector.
        let (scheme, _) = VectorAccount::load(vector)?;

        let lamports = u64::from_le_bytes(
            data.try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        );

        Ok(Self {
            vector,
            receiver,
            lamports,
            rotates: scheme.next_key_len != 0,
        })
    }
}

impl<'a> Withdraw<'a> {
    pub const DISCRIMINATOR: &'a u8 = &vector_signer::WITHDRAW_DISCRIMINATOR;

    pub fn process(&mut self) -> ProgramResult {
        let remaining = self
            .vector
            .lamports()
            .checked_sub(self.lamports)
            .ok_or(ProgramError::InsufficientFunds)?;
        if self.rotates && remaining == 0 {
            return Err(VectorError::KeyRotates.into());
        }
        let received = self
            .receiver
            .lamports()
            .checked_add(self.lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.vector.set_lamports(remaining);
        self.receiver.set_lamports(received);

        Ok(())
    }
}
