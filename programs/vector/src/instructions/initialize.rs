use core::{mem::MaybeUninit, slice::from_ref};

use pinocchio::{
    account::MAX_PERMITTED_DATA_INCREASE,
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, slot_hashes, Sysvar},
    AccountView, Address, ProgramResult, Resize,
};
use pinocchio_system::{
    create_program_account_with_minimum_balance_signed, instructions::Transfer,
};
use solana_nostd_sha256::{hash, hashv};

use crate::{
    scheme::Scheme,
    schemes,
    state::{VectorAccount, VECTOR_SEED},
};

/// # Initialize
///
/// Create the vector account for a key. Anyone can, for any key: only the
/// key's owner can use the account afterwards.
///
/// The address is derived from the scheme and the SHA-256 of the key. The
/// first nonce is derived from that hash and the latest slot hash, so an
/// account that is closed and created again in a later slot starts somewhere
/// new.
///
/// An instruction can allocate 10,240 bytes, so a bigger account (ML-DSA-44)
/// takes more than one call. The first creates it and writes what fits;
/// each later call grows it and fills in the rest from the stored key, until
/// it is complete. The account tells the two apart: the first finds it not
/// yet the program's.
///
/// > First call: create the account at the address for this scheme and key,
/// >   fund it for its full size, write the header and what fits of the
/// >   identity
/// > Later calls: grow the account, fill in the new bytes
///
/// Accounts:
///
/// 1. payer:           [signer, mut]
/// 2. vector:          [mut]
/// 3. system_program:  [executable]
///
/// Parameters:
///
/// - first call: scheme: u8, then the key, as the scheme takes it
/// - later calls: none
///
/// Account Checks:
/// - Vector: first call, at the address derived from the scheme and the
///   key; later calls, owned by the program and not complete
/// - Key: the scheme validates it as it writes the identity
/// - Payer, SystemProgram: no need to check since the create CPI fails
pub enum Initialize<'a> {
    Create(Create<'a>),
    Grow(&'a mut AccountView),
}

pub struct Create<'a> {
    payer: &'a AccountView,
    vector: &'a mut AccountView,
    scheme: &'static Scheme,
    key: &'a [u8],
    seed: [u8; 32],
    bump: u8,
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Initialize<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let [payer, vector, _system_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        if vector.owned_by(&crate::ID) {
            if !data.is_empty() {
                return Err(ProgramError::AccountAlreadyInitialized);
            }
            return Ok(Self::Grow(vector));
        }

        let [scheme, key @ ..] = data else {
            return Err(ProgramError::InvalidInstructionData);
        };
        let scheme = schemes::scheme(*scheme)?;

        // Account Checks
        let seed = hash(key);
        let (address, bump) =
            Address::find_program_address(&[VECTOR_SEED, &[scheme.id], &seed], &crate::ID);
        if vector.address() != &address {
            return Err(ProgramError::InvalidSeeds);
        }

        Ok(Self::Create(Create {
            payer,
            vector,
            scheme,
            key,
            seed,
            bump,
        }))
    }
}

impl<'a> Initialize<'a> {
    pub const DISCRIMINATOR: &'a u8 = &2;

    pub fn process(&mut self) -> ProgramResult {
        match self {
            Self::Create(create) => create.process(),
            Self::Grow(vector) => grow(vector),
        }
    }
}

impl Create<'_> {
    fn process(&mut self) -> ProgramResult {
        let (payer, vector, scheme) = (self.payer, &mut *self.vector, self.scheme);

        // Create the account. Anyone can send lamports to the address before
        // it exists, and a plain `CreateAccount` refuses an address that
        // holds any; this funds only the shortfall, and still fails on an
        // account that has data.
        let full_len = scheme.account_len();
        let seeds = [
            Seed::from(VECTOR_SEED),
            Seed::from(from_ref(&scheme.id)),
            Seed::from(&self.seed),
            Seed::from(from_ref(&self.bump)),
        ];
        create_program_account_with_minimum_balance_signed(
            vector,
            full_len.min(MAX_PERMITTED_DATA_INCREASE),
            &crate::ID,
            payer,
            None,
            &[Signer::from(&seeds)],
        )?;

        // An account created short is funded for its full size, so it stays
        // rent-exempt as it grows.
        if full_len > MAX_PERMITTED_DATA_INCREASE {
            let shortfall = Rent::get()?
                .try_minimum_balance(full_len)?
                .saturating_sub(vector.lamports());
            Transfer {
                from: payer,
                to: vector,
                lamports: shortfall,
            }
            .invoke()?;
        }

        let (_, system_bump) =
            Address::find_program_address(&[vector.address().as_ref()], &crate::ID);

        // Write the header, then as much of the identity as fits.
        let mut data = vector.try_borrow_mut()?;
        let (account, identity) = VectorAccount::split(&mut data)?;
        account.nonce = hashv(&[&self.seed, &latest_slot_hash()?]);
        account.seed = self.seed;
        account.scheme = scheme.id;
        account.bump = self.bump;
        account.system_bump = system_bump;
        (scheme.initialize)(self.key, identity)
    }
}

/// Grow the account by what one instruction can allocate, up to its full
/// length, and let the scheme fill in the new bytes. What is written depends
/// only on the key already stored.
fn grow(vector: &mut AccountView) -> ProgramResult {
    let scheme = VectorAccount::scheme(&vector.try_borrow()?)?;

    let old_len = vector.data_len();
    let full_len = scheme.account_len();
    if old_len >= full_len {
        return Err(ProgramError::InvalidAccountData);
    }
    vector.resize(full_len.min(old_len + MAX_PERMITTED_DATA_INCREASE))?;

    let mut data = vector.try_borrow_mut()?;
    let (_, identity) = VectorAccount::split(&mut data)?;
    (scheme.grow)(identity, old_len.saturating_sub(VectorAccount::HEADER_LEN))
}

/// The newest entry of the slot hashes sysvar: a slot (u64) and its hash.
/// It is the same for every instruction in a slot and different in the next.
fn latest_slot_hash() -> Result<[u8; 40], ProgramError> {
    let mut entry = MaybeUninit::<[u8; 40]>::uninit();
    // SAFETY: the syscall writes all 40 bytes or fails. The entries start
    // after the sysvar's 8-byte length.
    unsafe {
        slot_hashes::fetch_into_unchecked(&mut *entry.as_mut_ptr(), 8)?;
        Ok(entry.assume_init())
    }
}
