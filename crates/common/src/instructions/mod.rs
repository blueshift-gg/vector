use pinocchio::error::ProgramError;

pub mod advance;
pub mod close;
pub mod initialize;
pub mod passthrough;
pub mod withdraw;

/// Discriminator-tagged instructions handled by every Vector program. The set
/// is identical across schemes.
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
    /// Single-step schemes complete in this one call; Hawk-512 routes the
    /// same discriminator to its own multi-step handler (see
    /// `programs/hawk512/src/scheme.rs`).
    Initialize = 0,
    /// Verify the advance signature and install the digest as the next
    /// nonce. Does NOT execute any CPI — pair with `Passthrough` in the
    /// same tx for that. A standalone `Advance` is valid (just bumps the
    /// nonce).
    Advance = 1,
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
            1 => Ok(Self::Advance),
            2 => Ok(Self::Close),
            3 => Ok(Self::Withdraw),
            4 => Ok(Self::Passthrough),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
