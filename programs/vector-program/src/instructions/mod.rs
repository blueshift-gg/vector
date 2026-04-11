use pinocchio::error::ProgramError;

pub mod advance;
pub mod close;
pub mod initialize;

/// Discriminator-tagged instructions handled by the vector program.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorInstruction {
    InitializeVector = 0,
    AdvanceVector = 1,
    CloseVector = 2,
}

impl TryFrom<&u8> for VectorInstruction {
    type Error = ProgramError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::InitializeVector),
            1 => Ok(Self::AdvanceVector),
            2 => Ok(Self::CloseVector),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
