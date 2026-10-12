//! The scheme/program/account primitives shared by every scheme: the
//! [`Scheme`] descriptor, the program's [`VectorAccount`] header, and
//! canonical PDA derivation. Per-scheme details (identity derivation,
//! signing, init builders) live in [`crate::schemes`].

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::{address, Address};

/// The account header, as the program defines it.
pub use vector::state::VectorAccount;
/// The Vector program: one program for every signing scheme.
pub use vector::ID as PROGRAM_ID;
pub const SYSTEM_PROGRAM_ID: Address = address!("11111111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR_ID: Address = address!("Sysvar1nstructions1111111111111111111111111");

pub const INITIALIZE_DISCRIMINATOR: u8 = *vector::Initialize::DISCRIMINATOR;
pub const ADVANCE_DISCRIMINATOR: u8 = *vector::Advance::DISCRIMINATOR;
pub const CLOSE_DISCRIMINATOR: u8 = *vector::Close::DISCRIMINATOR;
pub const WITHDRAW_DISCRIMINATOR: u8 = *vector::Withdraw::DISCRIMINATOR;
pub const PASSTHROUGH_DISCRIMINATOR: u8 = *vector::Passthrough::DISCRIMINATOR;

pub use vector::state::VECTOR_SEED as VECTOR_PDA_SEED;

/// Everything a client needs to use one signing scheme: its scheme byte and
/// how big its signature and identity are. The concrete instances live in
/// [`crate::schemes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scheme {
    /// The scheme byte: a header field of every account, a PDA seed, and
    /// what `initialize` takes after its discriminator.
    pub id: u8,
    /// Wire signature length carried in `advance` instruction data.
    pub signature_len: usize,
    /// Length of the identity: the key the account is created with, as
    /// `initialize` takes it. It names the account for good, also after a
    /// Winternitz or XMSS key rotates.
    pub identity_len: usize,
    /// Bytes the on-chain account stores after its header: the size of the
    /// scheme's identity struct in the program.
    pub stored_identity_len: usize,
    /// Length of the key a `passthrough` carries for a scheme whose key
    /// rotates (Winternitz, XMSS): the key that signs next. Zero otherwise.
    pub next_key_len: usize,
    /// The next key may be left out, keeping the current one (XMSS).
    pub next_key_optional: bool,
}

impl Scheme {
    /// Total on-chain account length: `VectorAccount::HEADER_LEN +
    /// stored_identity_len`.
    pub const fn account_len(&self) -> usize {
        VectorAccount::HEADER_LEN + self.stored_identity_len
    }
}

/// The PDA seed for an identity: its SHA-256, for every scheme.
pub fn vector_seed(identity: &[u8]) -> [u8; 32] {
    Sha256::digest(identity).into()
}

/// Derive the canonical `(vector_pda, bump)` for a scheme + identity.
/// Seeds: `["vector", [scheme], sha256(identity)]`.
pub fn find_vector_pda(scheme: &Scheme, identity: &[u8]) -> (Address, u8) {
    assert_eq!(
        identity.len(),
        scheme.identity_len,
        "identity length mismatch"
    );
    Address::find_program_address(
        &[VECTOR_PDA_SEED, &[scheme.id], &vector_seed(identity)],
        &PROGRAM_ID,
    )
}
