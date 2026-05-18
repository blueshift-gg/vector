use pinocchio::error::ProgramError;

pub mod advance;
pub mod close;
pub mod initialize;
pub mod prepare;
pub mod withdraw;

/// Discriminator-tagged instructions handled by every Vector program. The set
/// is identical across schemes.
///
/// `Close` and `Withdraw` are reachable as top-level instructions but their
/// handlers gate on `vector.is_signer()`, which only holds when re-entered as
/// a CPI from `Advance` (whose signer-promotion turns the PDA into a signer).
/// Authorisation for both therefore comes from the offchain signature on the
/// wrapping `Advance`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorInstruction {
    /// Phase-aware and permissionless: the first call (account
    /// system-owned) creates it and stores the cheap identity prefix; a
    /// second call with the same accounts/args (account program-owned, not
    /// yet full) runs the scheme's `prepare` to fill any heavy region
    /// (Hawk-512); once full it is an idempotent no-op. Single-step schemes
    /// complete in the first call.
    InitializeVector = 0,
    AdvanceVector = 1,
    CloseVector = 2,
    WithdrawVector = 3,
}

impl TryFrom<&u8> for VectorInstruction {
    type Error = ProgramError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::InitializeVector),
            1 => Ok(Self::AdvanceVector),
            2 => Ok(Self::CloseVector),
            3 => Ok(Self::WithdrawVector),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
