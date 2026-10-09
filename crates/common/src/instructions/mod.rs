use pinocchio::error::ProgramError;

pub mod advance;
pub mod close;
pub mod initialize;
pub mod passthrough;
pub mod withdraw;

/// Discriminator-tagged instructions that act on one account of one scheme.
/// `Advance` (`1`) is not here: it takes several accounts of several schemes,
/// so the program routes it itself.
///
/// `Close` and `Withdraw` are reachable as top-level instructions but their
/// handlers gate on `vector.is_signer()`, which only holds when re-entered as
/// a CPI from `Passthrough` (which promotes the vector PDA to a signer when
/// invoking sub-instructions). Authorisation for both comes from the
/// offchain signature on the sibling `Advance` in the same transaction
/// (Advance's digest commits to the whole sysvar buffer, which includes the
/// Passthrough ix).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorInstruction {
    /// Create the vector account at the canonical PDA, derive the initial
    /// nonce on-chain, and write the header + the scheme's identity prefix.
    /// Every scheme completes registration in this one call.
    Initialize = 0,
    Close = 2,
    Withdraw = 3,
    /// Replay a batch of CPIs under the vector PDA's signer seeds. Must
    /// be preceded in the same tx by an `Advance` for the same vector;
    /// the on-chain handler scans the instructions sysvar to enforce
    /// this.
    Passthrough = 4,
}

impl TryFrom<&u8> for VectorInstruction {
    type Error = ProgramError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Initialize),
            2 => Ok(Self::Close),
            3 => Ok(Self::Withdraw),
            4 => Ok(Self::Passthrough),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
