use pinocchio::error::ProgramError;

#[inline(always)]
pub fn read_u8(payload: &mut &[u8]) -> Result<u8, ProgramError> {
    let (first, rest) = payload
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    *payload = rest;
    Ok(*first)
}

#[inline(always)]
pub fn read_u16(payload: &mut &[u8]) -> Result<u16, ProgramError> {
    let (chunk, rest) = payload
        .split_first_chunk::<2>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    *payload = rest;
    Ok(u16::from_le_bytes(*chunk))
}

#[inline(always)]
pub fn read_u16_at(data: &[u8], offset: usize) -> Result<u16, ProgramError> {
    let bytes: &[u8; 2] = data
        .get(offset..offset.wrapping_add(2))
        .and_then(|s| s.try_into().ok())
        .ok_or(ProgramError::InvalidAccountData)?;
    Ok(u16::from_le_bytes(*bytes))
}

/// Recover the 64-byte uncompressed secp256k1 public key (`x || y`) from a
/// 32-byte message hash, 64-byte signature, and recovery id (0 or 1) via the
/// `sol_secp256k1_recover` syscall (re-exported by pinocchio).
pub fn secp256k1_recover(
    hash: &[u8; 32],
    recovery_id: u64,
    signature: &[u8; 64],
) -> Result<[u8; 64], ProgramError> {
    #[allow(unused_mut)]
    let mut result = core::mem::MaybeUninit::<[u8; 64]>::uninit();

    #[cfg(target_os = "solana")]
    {
        let rc = unsafe {
            pinocchio::syscalls::sol_secp256k1_recover(
                hash.as_ptr(),
                recovery_id,
                signature.as_ptr(),
                result.as_mut_ptr() as *mut u8,
            )
        };
        if rc != 0 {
            return Err(ProgramError::InvalidArgument);
        }
        // SAFETY: the syscall wrote all 64 bytes on success (rc == 0).
        Ok(unsafe { result.assume_init() })
    }

    #[cfg(not(target_os = "solana"))]
    {
        let _ = (hash, recovery_id, signature, &result);
        Err(ProgramError::InvalidArgument)
    }
}
