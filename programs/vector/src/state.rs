//! The vector account: a fixed header, then the scheme's identity.

use core::mem::{size_of, MaybeUninit};

use pinocchio::{
    account::RefMut,
    error::ProgramError,
    sysvars::{clock::Clock, slot_hashes, Sysvar},
    AccountView,
};
use solana_nostd_sha256::hashv;

use crate::{
    error::VectorError,
    scheme::{cast, cast_mut, Scheme},
    schemes,
};

/// First seed of every vector account's address:
/// `["vector", [scheme], seed, [bump]]`.
pub const VECTOR_SEED: &[u8] = b"vector";

/// The header every vector account starts with. It is plain bytes: `repr(C)`
/// with alignment 1, no padding and no invalid bit patterns.
///
/// ```text
/// nonce:  [u8; 32]  // offset  0 — what the next signature must be made over
/// seed:   [u8; 32]  // offset 32 — sha256 of the key it was created with
/// scheme:  u8       // offset 64 — the scheme of the identity that follows
/// bump:    u8       // offset 65 — PDA bump seed
/// system_bump: u8   // offset 66 — bump of the account's system PDA
/// _pad:    u8       // offset 67
/// ```
///
/// The system PDA, `[vector address, system_bump]`, belongs to the System
/// program: `Passthrough` can sign as it, for what only a system account can
/// do.
///
/// The pad keeps the identity at a multiple of 4 in the account: Falcon-512
/// and ML-DSA-44 read their prepared key in place.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorAccount {
    pub nonce: [u8; 32],
    pub seed: [u8; 32],
    pub scheme: u8,
    pub bump: u8,
    pub system_bump: u8,
    _pad: u8,
}

impl VectorAccount {
    /// Length of the header. The identity follows it.
    pub const HEADER_LEN: usize = size_of::<Self>();

    /// Borrow the data of an account the program owns.
    pub fn borrow(account: &mut AccountView) -> Result<RefMut<'_, [u8]>, ProgramError> {
        if !account.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        account.try_borrow_mut()
    }

    /// The scheme of an account, from its header. The program takes the
    /// scheme from here and never from the caller, so the identity is always
    /// read as the scheme that wrote it.
    pub fn scheme(data: &[u8]) -> Result<&'static Scheme, ProgramError> {
        schemes::scheme(Self::header(data)?.scheme).map_err(|_| ProgramError::InvalidAccountData)
    }

    /// The header at the start of account data.
    pub fn header(data: &[u8]) -> Result<&Self, ProgramError> {
        let header = data
            .get(..Self::HEADER_LEN)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        // SAFETY: the header is plain bytes.
        unsafe { cast(header) }.ok_or(ProgramError::AccountDataTooSmall)
    }

    /// Split account data into the header and the identity bytes after it.
    pub fn split(data: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ProgramError> {
        let (header, identity) = data
            .split_at_mut_checked(Self::HEADER_LEN)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        // SAFETY: the header is plain bytes.
        let header = unsafe { cast_mut(header) }.ok_or(ProgramError::AccountDataTooSmall)?;
        Ok((header, identity))
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

/// What a nonce account's first nonce hashes first:
/// `SHA256("nonce" || address || latest slot hash)`.
pub const NONCE_TAG: &[u8] = b"nonce";

/// A nonce kept apart from its vector account. A vector can have any number,
/// each its own hash chain, so its transactions need not wait for one
/// another; the vector account still signs. Its address is any the caller
/// creates, as for System nonce accounts; `Close` closes it.
///
/// A signature over it is over [`signed`](Self::signed), which takes in the
/// vector's own nonce too: moving that nonce cancels every signature
/// outstanding over every one of the vector's nonce accounts.
///
/// Its first nonce takes in the slot hash of the slot it is created in, and
/// it neither signs nor closes in that slot. So an account closed and created
/// again never holds a nonce it held before.
///
/// ```text
/// nonce:   [u8; 32]  // offset  0 — the chain's current link
/// vector:  [u8; 32]  // offset 32 — the vector account whose key signs
/// created: u64       // offset 64 — the slot it was created in
/// ```
///
/// No vector account is as long, so the length tells the two apart:
/// `schemes` asserts it for every scheme at compile time.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceAccount {
    pub nonce: [u8; 32],
    pub vector: [u8; 32],
    created: [u8; 8],
}

impl NonceAccount {
    pub const LEN: usize = size_of::<Self>();

    /// A nonce account at `address` of the vector at `vector`, created now.
    pub fn new(address: &[u8; 32], vector: [u8; 32]) -> Result<Self, ProgramError> {
        Ok(Self {
            nonce: hashv(&[NONCE_TAG, address, &latest_slot_hash()?]),
            vector,
            created: Clock::get()?.slot.to_le_bytes(),
        })
    }

    /// Whether `account` is a nonce account: the program's, and [`LEN`](Self::LEN) bytes.
    pub fn is(account: &AccountView) -> bool {
        account.owned_by(&crate::ID) && account.data_len() == Self::LEN
    }

    /// Borrow `account`, which [`is`](Self::is) a nonce account.
    pub fn load(account: &mut AccountView) -> Result<RefMut<'_, Self>, ProgramError> {
        RefMut::try_map(account.try_borrow_mut()?, |data| {
            // SAFETY: the account is plain bytes.
            unsafe { cast_mut::<Self>(data) }.ok_or(ProgramError::InvalidAccountData)
        })
        .map_err(|(_, error)| error)
    }

    /// [`load`](Self::load) `account` as a nonce account of the vector at
    /// `vector`, past the slot it was created in.
    pub fn borrow<'a>(
        account: &'a mut AccountView,
        vector: &[u8; 32],
    ) -> Result<RefMut<'a, Self>, ProgramError> {
        let nonce = Self::load(account)?;
        if &nonce.vector != vector {
            return Err(VectorError::ForeignNonce.into());
        }
        if u64::from_le_bytes(nonce.created) >= Clock::get()?.slot {
            return Err(VectorError::FreshNonce.into());
        }
        Ok(nonce)
    }

    /// What the vector's key signs over: `SHA256(nonce || vector's nonce)`.
    pub fn signed(&self, vector_nonce: &[u8; 32]) -> [u8; 32] {
        hashv(&[&self.nonce, vector_nonce])
    }
}
