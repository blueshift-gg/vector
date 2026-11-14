//! The vector account and the nonce account, as live accounts: their
//! layouts are `vector-signer`'s, and reading them from an `AccountView`,
//! and what only runs on chain, is here.

use core::mem::MaybeUninit;

use pinocchio::{
    account::RefMut,
    error::ProgramError,
    sysvars::{clock::Clock, slot_hashes, Sysvar},
    AccountView,
};
use solana_nostd_sha256::hashv;

pub use vector_signer::state::{NonceAccount, VectorAccount, NONCE_TAG, VECTOR_SEED};

use crate::{
    error::VectorError,
    scheme::{cast_mut, Scheme},
};

/// A vector account, read from the account that holds it.
pub trait VectorAccountExt {
    /// Borrow the data of an account the program owns.
    fn borrow(account: &mut AccountView) -> Result<RefMut<'_, [u8]>, ProgramError>;

    /// Check that `account` is a complete vector account the program owns,
    /// and return its scheme and a copy of its header. Every instruction
    /// that acts for a vector account loads it this way.
    fn load(account: &AccountView) -> Result<(&'static Scheme, VectorAccount), ProgramError>;
}

impl VectorAccountExt for VectorAccount {
    fn borrow(account: &mut AccountView) -> Result<RefMut<'_, [u8]>, ProgramError> {
        if !account.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        account.try_borrow_mut()
    }

    fn load(account: &AccountView) -> Result<(&'static Scheme, VectorAccount), ProgramError> {
        if !account.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        let data = account.try_borrow()?;
        Ok((Self::scheme(&data)?, *Self::header(&data)?))
    }
}

/// The newest entry of the slot hashes sysvar: a slot (u64) and its hash.
/// It is the same for every instruction in a slot and different in the next.
pub fn latest_slot_hash() -> Result<[u8; 40], ProgramError> {
    let mut entry = MaybeUninit::<[u8; 40]>::uninit();
    // SAFETY: the syscall writes all 40 bytes or fails. The entries start
    // after the sysvar's 8-byte length.
    unsafe {
        slot_hashes::fetch_into_unchecked(&mut *entry.as_mut_ptr(), 8)?;
        Ok(entry.assume_init())
    }
}

/// A nonce account, created and read on chain.
pub trait NonceAccountExt: Sized {
    /// A nonce account at `address` of the vector at `vector`, created now.
    fn create(address: &[u8; 32], vector: [u8; 32]) -> Result<Self, ProgramError>;

    /// Whether `account` is a nonce account: the program's, and
    /// [`NonceAccount::LEN`] bytes.
    fn is(account: &AccountView) -> bool;

    /// Borrow `account`, which [`is`](Self::is) a nonce account.
    fn load(account: &mut AccountView) -> Result<RefMut<'_, Self>, ProgramError>;

    /// [`load`](Self::load) `account` as a nonce account of the vector at
    /// `vector`, past the slot it was created in.
    fn borrow<'a>(
        account: &'a mut AccountView,
        vector: &[u8; 32],
        slot: u64,
    ) -> Result<RefMut<'a, Self>, ProgramError>;
}

impl NonceAccountExt for NonceAccount {
    fn create(address: &[u8; 32], vector: [u8; 32]) -> Result<Self, ProgramError> {
        Ok(Self::new(
            hashv(&[NONCE_TAG, address, &latest_slot_hash()?]),
            vector,
            Clock::get()?.slot,
        ))
    }

    fn is(account: &AccountView) -> bool {
        account.owned_by(&crate::ID) && account.data_len() == Self::LEN
    }

    fn load(account: &mut AccountView) -> Result<RefMut<'_, Self>, ProgramError> {
        RefMut::try_map(account.try_borrow_mut()?, |data| {
            // SAFETY: the account is plain bytes.
            unsafe { cast_mut::<Self>(data) }.ok_or(ProgramError::InvalidAccountData)
        })
        .map_err(|(_, error)| error)
    }

    fn borrow<'a>(
        account: &'a mut AccountView,
        vector: &[u8; 32],
        slot: u64,
    ) -> Result<RefMut<'a, Self>, ProgramError> {
        let nonce = Self::load(account)?;
        if &nonce.vector != vector {
            return Err(VectorError::ForeignNonce.into());
        }
        if nonce.created() >= slot {
            return Err(VectorError::FreshNonce.into());
        }
        Ok(nonce)
    }
}
