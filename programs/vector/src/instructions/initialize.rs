use core::mem::MaybeUninit;

use pinocchio::{
    account::MAX_PERMITTED_DATA_INCREASE,
    cpi::Signer,
    error::ProgramError,
    sysvars::{rent::Rent, slot_hashes, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::{
    create_program_account_with_minimum_balance_signed, instructions::Transfer,
};
use solana_nostd_sha256::hashv;

use crate::{
    constants::VECTOR_SEED,
    scheme::{IdentitySeed, SigningScheme},
    schemes,
    state::{signer_seeds, VectorAccount},
};

/// # Initialize
///
/// Create the vector account for a key. Anyone can, for any key: only the
/// key's owner can use the account afterwards.
///
/// The address is derived from the scheme and the key. The first nonce is
/// derived from the key and the latest slot hash, so an account that is
/// closed and created again in a later slot starts somewhere new.
///
/// > Create the account at the address for this scheme and key
/// > Fund it for its full size
/// > Write the header and the scheme's identity bytes
///
/// An instruction can allocate 10,240 bytes. A scheme with a bigger account
/// (ML-DSA-44) is created at that size and finished with `Expand`.
///
/// Accounts:
///
/// 1. payer:           [signer, mut]
/// 2. vector:          [mut]
/// 3. system_program:  [executable]
///
/// Parameters:
///
/// - scheme: u8
/// - key: the public key or address, in the scheme's wire form
///
/// Account Checks:
/// - Vector: at the address derived from the scheme and the key
/// - Payer, SystemProgram: no need to check since the create CPI fails
pub struct Initialize<'a> {
    payer: &'a AccountView,
    vector: &'a mut AccountView,
    scheme: &'static dyn SigningScheme,
    key: &'a [u8],
    identity_seed: IdentitySeed,
    bump: u8,
}

impl<'a> TryFrom<(&'a [u8], &'a mut [AccountView])> for Initialize<'a> {
    type Error = ProgramError;

    fn try_from((data, accounts): (&'a [u8], &'a mut [AccountView])) -> Result<Self, Self::Error> {
        let [payer, vector, _system_program] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        let [scheme, key @ ..] = data else {
            return Err(ProgramError::InvalidInstructionData);
        };
        let scheme = schemes::scheme(*scheme)?;
        if key.len() != scheme.key_len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Account Checks
        let identity_seed = scheme.seed_from_key(key);
        let (address, bump) = Address::find_program_address(
            &[VECTOR_SEED, &[scheme.id()], identity_seed.as_slice()],
            &crate::ID,
        );
        if vector.address() != &address {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(Self {
            payer,
            vector,
            scheme,
            key,
            identity_seed,
            bump,
        })
    }
}

impl<'a> Initialize<'a> {
    pub const DISCRIMINATOR: &'a u8 = &0;

    pub fn process(&mut self) -> ProgramResult {
        let (payer, vector, scheme) = (self.payer, &mut *self.vector, self.scheme);
        let nonce = hashv(&[self.identity_seed.as_slice(), &latest_slot_hash()?]);

        // Create the account. Anyone can send lamports to the address before
        // it exists, and a plain `CreateAccount` refuses an address that
        // holds any; this funds only the shortfall, and still fails on an
        // account that has data.
        let full_len = VectorAccount::len(scheme);
        let (scheme_seed, bump_seed) = ([scheme.id()], [self.bump]);
        let seeds = signer_seeds(&scheme_seed, &self.identity_seed, &bump_seed);
        create_program_account_with_minimum_balance_signed(
            vector,
            full_len.min(MAX_PERMITTED_DATA_INCREASE),
            &crate::ID,
            payer,
            None,
            &[Signer::from(&seeds)],
        )?;

        // Fund it for its full size, so it stays rent-exempt as it grows.
        let shortfall = Rent::get()?
            .try_minimum_balance(full_len)?
            .saturating_sub(vector.lamports());
        if shortfall > 0 {
            Transfer {
                from: payer,
                to: vector,
                lamports: shortfall,
            }
            .invoke()?;
        }

        // Write the header, then as much of the identity as fits.
        let mut data = vector.try_borrow_mut()?;
        let (account, identity) = VectorAccount::split(&mut data)?;
        account.nonce = nonce;
        account.scheme = scheme.id();
        account.bump = self.bump;
        scheme.initialize(self.key, identity)
    }
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
