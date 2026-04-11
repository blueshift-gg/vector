/// Stack height of a top-level (non-CPI) instruction.
pub const TRANSACTION_LEVEL_STACK_HEIGHT: u64 = 1;

/// Current CPI stack depth. Falls back to top-level on host builds where the
/// syscall is unavailable.
#[inline(always)]
pub fn get_stack_height() -> u64 {
    #[cfg(target_os = "solana")]
    // SAFETY: parameterless syscall with no side effects.
    unsafe {
        solana_define_syscall::definitions::sol_get_stack_height()
    }
    #[cfg(not(target_os = "solana"))]
    TRANSACTION_LEVEL_STACK_HEIGHT
}
