use pinocchio::error::ProgramError;

pub mod advance;
pub use advance::Advance;

pub mod passthrough;
pub use passthrough::Passthrough;

pub mod initialize;
pub use initialize::Initialize;

pub mod withdraw;
pub use withdraw::Withdraw;

pub mod close;
pub use close::Close;

pub mod initialize_nonce;
pub use initialize_nonce::InitializeNonce;

/// `Advance` and `Passthrough` read the instructions sysvar, which describes
/// the transaction's top-level instructions. Called from inside another
/// instruction, they would be reading their caller's place in the list.
#[inline(always)]
fn top_level_only() -> Result<(), ProgramError> {
    #[cfg(target_os = "solana")]
    {
        /// Stack height of a top-level (non-CPI) instruction.
        const TRANSACTION_LEVEL_STACK_HEIGHT: u64 = 1;

        if unsafe { pinocchio::syscalls::sol_get_stack_height() } != TRANSACTION_LEVEL_STACK_HEIGHT
        {
            return Err(crate::error::VectorError::NotTopLevel.into());
        }
    }
    Ok(())
}
