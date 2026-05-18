use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address};
use solana_nostd_sha256::hashv;

use crate::buffer::VectorBuffer;
use crate::scheme::{IdentitySeed, SigningScheme};

pub const DIGEST_LEN: usize = 32;

/// On-chain vector state — fixed-size header.
///
/// Layout (33 bytes, `#[repr(C)]`):
/// ```text
/// nonce: [u8; 32]  // offset  0 — current state nonce
/// bump:  u8        // offset 32 — PDA bump seed
/// ```
///
/// The scheme's identity bytes follow at offset
/// [`HEADER_LEN`](Self::HEADER_LEN); length is `S::IDENTITY_LEN`. Because
/// each scheme is its own program, there is no on-chain scheme discriminator
/// — the program ID *is* the discriminator.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorAccount {
    pub nonce: [u8; 32],
    pub bump: u8,
}

impl VectorAccount {
    /// Length of the fixed-size header preceding the identity bytes.
    pub const HEADER_LEN: usize = 33;

    /// Total account length for scheme `S`: `HEADER_LEN + S::IDENTITY_LEN`.
    #[inline]
    pub fn account_len<S: SigningScheme>() -> usize {
        Self::HEADER_LEN + S::IDENTITY_LEN
    }

    /// Read-only header snapshot. Validates ownership and minimum size, then
    /// releases the runtime borrow before returning so the same PDA can
    /// appear as a CPI signer downstream.
    fn load(account: &AccountView, program_id: &Address) -> Result<Self, ProgramError> {
        if !account.owned_by(program_id) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        if account.data_len() < Self::HEADER_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        let data = account.try_borrow()?;
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[..32]);
        Ok(Self {
            nonce,
            bump: data[32],
        })
    }

    /// Verify the signature over `SHA256(buffer.pre || nonce || identity ||
    /// buffer.post)` and return the digest. The digest doubles as the next
    /// nonce.
    fn verify<S: SigningScheme>(
        &self,
        identity: &[u8],
        buffer: &VectorBuffer,
        signature: &[u8],
    ) -> Result<[u8; DIGEST_LEN], ProgramError> {
        let digest = hashv(&[
            buffer.pre,
            &self.nonce,
            S::digest_identity(identity),
            buffer.post,
        ]);
        S::verify(identity, &digest, signature)?;
        Ok(digest)
    }

    /// Parse the signature off `instruction_data`, verify it against the
    /// instructions-sysvar buffer, write the digest as the next nonce, and
    /// return `(pda_address, state, identity_seed, payload)`. All borrows are
    /// released before returning so the PDA can appear in downstream CPI.
    pub fn advance_nonce<'a, S: SigningScheme>(
        account: &mut AccountView,
        instructions_sysvar: &AccountView,
        program_id: &Address,
        instruction_data: &'a [u8],
    ) -> Result<([u8; 32], Self, IdentitySeed, &'a [u8]), ProgramError> {
        let pda_address = account.address().to_bytes();
        let mut state = Self::load(account, program_id)?;

        let (signature, payload) = instruction_data
            .split_at_checked(S::SIGNATURE_LEN)
            .ok_or(ProgramError::InvalidInstructionData)?;

        let buffer = VectorBuffer::from_instructions_sysvar(instructions_sysvar, signature.len())?;

        let (new_nonce, identity_seed) = {
            let data = account.try_borrow()?;
            if data.len() < Self::HEADER_LEN + S::IDENTITY_LEN {
                return Err(ProgramError::AccountDataTooSmall);
            }
            let identity = &data[Self::HEADER_LEN..Self::HEADER_LEN + S::IDENTITY_LEN];
            let digest = state.verify::<S>(identity, &buffer, signature)?;
            (digest, S::pda_seed_from_identity(identity))
        };

        state.nonce = new_nonce;
        account.try_borrow_mut()?[..32].copy_from_slice(&state.nonce);
        Ok((pda_address, state, identity_seed, payload))
    }
}

/// Build the three PDA signer seeds for a vector account:
/// `["vector", identity-or-hash, &[bump]]`.
pub fn signer_seeds<'a>(
    identity_seed: &'a IdentitySeed,
    bump: &'a [u8; 1],
) -> [Seed<'a>; 3] {
    [
        Seed::from(b"vector"),
        Seed::from(identity_seed.as_slice()),
        Seed::from(&bump[..]),
    ]
}
