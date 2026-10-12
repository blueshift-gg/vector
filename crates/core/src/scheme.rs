//! The scheme/program/account primitives shared by every scheme: the
//! [`Scheme`] descriptor, the host-side [`VectorAccount`] header mirror, and
//! canonical PDA derivation. Per-scheme details (identity derivation,
//! signing, init builders) live in [`crate::schemes`].

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::{address, Address};

/// The Vector program: one program for every signing scheme.
pub const PROGRAM_ID: Address = address!("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV");
pub const SYSTEM_PROGRAM_ID: Address = address!("11111111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR_ID: Address = address!("Sysvar1nstructions1111111111111111111111111");

pub const INITIALIZE_DISCRIMINATOR: u8 = 0;
pub const ADVANCE_DISCRIMINATOR: u8 = 1;
pub const CLOSE_DISCRIMINATOR: u8 = 2;
pub const WITHDRAW_DISCRIMINATOR: u8 = 3;
pub const PASSTHROUGH_DISCRIMINATOR: u8 = 4;

pub const VECTOR_PDA_SEED: &[u8] = b"vector";

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
    /// Bytes the on-chain account stores after its header: the key in the
    /// form the scheme verifies against. Equals `identity_len` for schemes
    /// that store the key as given; Falcon-512 and ML-DSA-44 prepare it.
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

/// Host-side mirror of the on-chain account header:
/// `nonce (32) || seed (32) || scheme (1) || bump (1)`. The scheme's
/// identity bytes follow at offset [`HEADER_LEN`](Self::HEADER_LEN).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorAccount {
    pub nonce: [u8; 32],
    /// [`vector_seed`] of the identity.
    pub seed: [u8; 32],
    pub scheme: u8,
    pub bump: u8,
}

impl VectorAccount {
    pub const HEADER_LEN: usize = 66;

    /// Total on-chain account length for an identity of `identity_len` bytes.
    pub const fn account_len(identity_len: usize) -> usize {
        Self::HEADER_LEN + identity_len
    }

    pub fn header_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut bytes = [0u8; Self::HEADER_LEN];
        bytes[..32].copy_from_slice(&self.nonce);
        bytes[32..64].copy_from_slice(&self.seed);
        bytes[64] = self.scheme;
        bytes[65] = self.bump;
        bytes
    }

    pub fn from_header_bytes(bytes: &[u8; Self::HEADER_LEN]) -> Self {
        VectorAccount {
            nonce: bytes[..32].try_into().unwrap(),
            seed: bytes[32..64].try_into().unwrap(),
            scheme: bytes[64],
            bump: bytes[65],
        }
    }
}

/// The PDA seed for an identity: its SHA-256, for every scheme.
pub fn vector_seed(identity: &[u8]) -> [u8; 32] {
    Sha256::digest(identity).into()
}

/// Derive the canonical `(vector_pda, bump)` for a scheme + identity.
/// Seeds: `["vector", [scheme], sha256(identity)]`.
pub fn find_vector_pda(scheme: &Scheme, identity: &[u8]) -> (Address, u8) {
    assert_eq!(identity.len(), scheme.identity_len, "identity length mismatch");
    Address::find_program_address(
        &[VECTOR_PDA_SEED, &[scheme.id], &vector_seed(identity)],
        &PROGRAM_ID,
    )
}
