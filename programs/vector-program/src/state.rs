use brine_ed25519::{hasher::Sha512, verify};
use pinocchio::{error::ProgramError, sysvars::instructions::INSTRUCTIONS_ID, AccountView};
use solana_sha256_hasher::hashv;

const SIGNATURE_LEN: usize = 64;
const DISCRIMINATOR_LEN: usize = 1;
pub const DIGEST_LEN: usize = 32;

/// On-chain vector state.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorAccount {
    pub seed: [u8; 32],
    pub address: [u8; 32],
    pub bump: u8,
}

impl VectorAccount {
    pub const LEN: usize = 65;

    /// Verify the Ed25519 signature over
    /// `SHA256(buffer.pre || seed || address || buffer.post)` and return the
    /// digest. The digest doubles as the next seed.
    pub fn verify(
        &self,
        buffer: &VectorBuffer,
        advance_vector_signature: &[u8; SIGNATURE_LEN],
    ) -> Result<[u8; DIGEST_LEN], ProgramError> {
        let advance_vector_digest =
            hashv(&[buffer.pre, &self.seed, &self.address, buffer.post]).to_bytes();
        verify::<Sha512>(
            &self.address,
            advance_vector_signature,
            &[&advance_vector_digest],
        )
        .map_err(|_| ProgramError::MissingRequiredSignature)?;
        Ok(advance_vector_digest)
    }
}

impl<'a> TryFrom<&'a mut AccountView> for &'a mut VectorAccount {
    type Error = ProgramError;

    /// Zero-copy mutable view. Leaks the borrow guard so the runtime lock is
    /// held for the lifetime of the returned reference, blocking aliasing
    /// `&mut VectorAccount`s through duplicate `AccountView`s.
    fn try_from(account: &'a mut AccountView) -> Result<Self, Self::Error> {
        if !account.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }

        if account.data_len() < VectorAccount::LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }

        core::mem::forget(account.try_borrow_mut()?);

        // SAFETY: `VectorAccount` is `#[repr(C)]` with only `u8` fields, so
        // it is 1-byte aligned and the cast is sound.
        Ok(unsafe { &mut *(account.data_mut_ptr() as *mut VectorAccount) })
    }
}

impl TryFrom<&AccountView> for VectorAccount {
    type Error = ProgramError;

    /// Read-only snapshot copied by value. Releases the runtime borrow before
    /// returning so the same PDA can appear as a CPI signer downstream.
    fn try_from(account: &AccountView) -> Result<Self, Self::Error> {
        if !account.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        if account.data_len() < VectorAccount::LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }

        let data = account.try_borrow()?;
        let mut uninit = core::mem::MaybeUninit::<VectorAccount>::uninit();
        // SAFETY: `VectorAccount` is `#[repr(C)]`, 65 bytes, no padding.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                uninit.as_mut_ptr() as *mut u8,
                VectorAccount::LEN,
            );
        }
        // SAFETY: every byte was written by the copy above.
        Ok(unsafe { uninit.assume_init() })
    }
}

/// The pre/post slices of the instructions sysvar bracketing the executing
/// instruction's 64-byte signature region. `pre || sig || post` reconstructs
/// the entire sysvar; carving out `sig` is what lets the signature embed
/// itself in the buffer it signs.
pub struct VectorBuffer<'a> {
    pub pre: &'a [u8],
    pub post: &'a [u8],
}

impl<'a> TryFrom<&'a AccountView> for VectorBuffer<'a> {
    type Error = ProgramError;

    fn try_from(account: &'a AccountView) -> Result<Self, Self::Error> {
        if account.address() != &INSTRUCTIONS_ID {
            return Err(ProgramError::UnsupportedSysvar);
        }

        // Leak the borrow so the slice can live for `'a`. The sysvar is
        // read-only.
        core::mem::forget(account.try_borrow()?);

        // SAFETY: the leaked borrow keeps the data immutable for `'a`.
        let data: &'a [u8] =
            unsafe { core::slice::from_raw_parts(account.data_ptr(), account.data_len()) };

        // Sysvar layout:
        //   [0..2]                          num_instructions (u16 LE)
        //   [2..2 + 2 * num_instructions]   u16 LE offset per instruction
        //   ...instruction regions...
        //   [len - 2..len]                  current instruction index (u16 LE)
        if data.len() < 6 {
            return Err(ProgramError::InvalidAccountData);
        }

        let num_instructions = u16::from_le_bytes(
            data[0..2]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        ) as usize;
        let current_index = u16::from_le_bytes(
            data[data.len() - 2..]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        ) as usize;
        if current_index >= num_instructions {
            return Err(ProgramError::InvalidAccountData);
        }

        let ix_offset_pos = current_index
            .checked_mul(2)
            .and_then(|n| n.checked_add(2))
            .ok_or(ProgramError::InvalidAccountData)?;
        let ix_offset_bytes = data
            .get(ix_offset_pos..ix_offset_pos.saturating_add(2))
            .ok_or(ProgramError::InvalidAccountData)?;
        let ix_offset = u16::from_le_bytes(
            ix_offset_bytes
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        ) as usize;

        // Instruction region layout:
        //   [0..2]                       num_accounts (u16 LE)
        //   [2..2 + 33 * num_accounts]   metas (1 flag byte + 32 addr each)
        //   [+ 32]                       program id
        //   [+ 2]                        data_len (u16 LE)
        //   [...]                        instruction data (disc byte first)
        let num_accounts_bytes = data
            .get(ix_offset..ix_offset.saturating_add(2))
            .ok_or(ProgramError::InvalidAccountData)?;
        let num_accounts = u16::from_le_bytes(
            num_accounts_bytes
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        ) as usize;

        let metas_len = num_accounts
            .checked_mul(33)
            .ok_or(ProgramError::InvalidAccountData)?;
        let disc_pos = ix_offset
            .checked_add(2)
            .and_then(|n| n.checked_add(metas_len))
            .and_then(|n| n.checked_add(32))
            .and_then(|n| n.checked_add(2))
            .ok_or(ProgramError::InvalidAccountData)?;

        let sig_start = disc_pos
            .checked_add(DISCRIMINATOR_LEN)
            .ok_or(ProgramError::InvalidAccountData)?;
        let sig_end = sig_start
            .checked_add(SIGNATURE_LEN)
            .ok_or(ProgramError::InvalidAccountData)?;

        // Bounds-check the signature region and the trailing index footer.
        if sig_end
            .checked_add(2)
            .ok_or(ProgramError::InvalidAccountData)?
            > data.len()
        {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(VectorBuffer {
            pre: &data[..sig_start],
            post: &data[sig_end..],
        })
    }
}
