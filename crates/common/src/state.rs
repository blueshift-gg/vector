use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address};
use solana_nostd_sha256::hashv;

use crate::scheme::{IdentitySeed, SigningScheme};

/// On-chain vector state — fixed-size header.
///
/// Layout (34 bytes, `#[repr(C)]`):
/// ```text
/// nonce:  [u8; 32]  // offset  0 — current state nonce
/// scheme: u8        // offset 32 — `SigningScheme::ID`
/// bump:   u8        // offset 33 — PDA bump seed
/// ```
///
/// The scheme's identity bytes follow at offset
/// [`HEADER_LEN`](Self::HEADER_LEN); length is `S::IDENTITY_LEN`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorAccount {
    pub nonce: [u8; 32],
    pub scheme: u8,
    pub bump: u8,
}

impl VectorAccount {
    /// Length of the fixed-size header preceding the identity bytes.
    pub const HEADER_LEN: usize = 34;

    /// Total account length for scheme `S`: `HEADER_LEN + S::IDENTITY_LEN`.
    #[inline]
    pub fn account_len<S: SigningScheme>() -> usize {
        Self::HEADER_LEN + S::IDENTITY_LEN
    }

    /// The account is one scheme `S` created. Every handler that reads the
    /// identity through `S` calls this first: the bytes after the header
    /// mean something else under any other scheme.
    pub fn check_scheme<S: SigningScheme>(data: &[u8]) -> Result<(), ProgramError> {
        match data.get(32) {
            Some(&scheme) if scheme == S::ID => Ok(()),
            Some(_) => Err(ProgramError::InvalidAccountData),
            None => Err(ProgramError::AccountDataTooSmall),
        }
    }

    /// Read-only header snapshot. Validates ownership, minimum size and
    /// scheme, then releases the runtime borrow before returning so the same
    /// PDA can appear as a CPI signer downstream.
    fn load<S: SigningScheme>(
        account: &AccountView,
        program_id: &Address,
    ) -> Result<Self, ProgramError> {
        if !account.owned_by(program_id) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        if account.data_len() < Self::HEADER_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        let data = account.try_borrow()?;
        Self::check_scheme::<S>(&data)?;
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[..32]);
        Ok(Self {
            nonce,
            scheme: data[32],
            bump: data[33],
        })
    }

    /// Verify `signature` over `SHA256(message || nonce || identity)` and
    /// install that digest as the next nonce. `message` is what all signers
    /// of the transaction share ([`crate::buffer::message`]); the nonce and
    /// identity make the digest this account's alone.
    pub fn advance_nonce<S: SigningScheme>(
        account: &mut AccountView,
        program_id: &Address,
        message: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProgramError> {
        let state = Self::load::<S>(account, program_id)?;
        let mut data = account.try_borrow_mut()?;
        let identity = data
            .get(Self::HEADER_LEN..Self::HEADER_LEN + S::IDENTITY_LEN)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        let digest = hashv(&[message, &state.nonce, S::digest_identity(identity)]);
        S::verify(identity, &digest, signature)?;
        data[..32].copy_from_slice(&digest);
        Ok(())
    }
}

/// Build the four PDA signer seeds for a vector account:
/// `["vector", &[scheme], identity-or-hash, &[bump]]`.
pub fn signer_seeds<'a>(
    scheme: &'a [u8; 1],
    identity_seed: &'a IdentitySeed,
    bump: &'a [u8; 1],
) -> [Seed<'a>; 4] {
    [
        Seed::from(b"vector"),
        Seed::from(&scheme[..]),
        Seed::from(identity_seed.as_slice()),
        Seed::from(&bump[..]),
    ]
}
