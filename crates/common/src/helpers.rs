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
