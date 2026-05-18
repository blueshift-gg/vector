//! The scheme/program/account primitives shared by every scheme: the
//! [`Scheme`] descriptor, the host-side [`VectorAccount`] header mirror, and
//! canonical PDA derivation. Per-scheme details (identity derivation,
//! signing, init builders) live in [`crate::schemes`].

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::{address, Address};

pub const SYSTEM_PROGRAM_ID: Address = address!("11111111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR_ID: Address =
    address!("Sysvar1nstructions1111111111111111111111111");

pub const INITIALIZE_DISCRIMINATOR: u8 = 0;
pub const ADVANCE_DISCRIMINATOR: u8 = 1;
pub const CLOSE_DISCRIMINATOR: u8 = 2;
pub const WITHDRAW_DISCRIMINATOR: u8 = 3;

pub const VECTOR_PDA_SEED: &[u8] = b"vector";

/// Everything a client needs to address one Vector program. Each on-chain
/// scheme is a separate program; this is the off-chain mirror of "which
/// program + how big its signature/identity are". The five concrete
/// instances live in [`crate::schemes`] (`ED25519`, `EIP191`, `FALCON512`,
/// `SECP256K1`, `HAWK512`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scheme {
    /// On-chain program ID. Must match the program's `declare_id!`.
    pub program_id: Address,
    /// Wire signature length carried in `advance` instruction data.
    pub signature_len: usize,
    /// Length of the client-side identity — the value hashed into the
    /// advance digest and used to derive the PDA. For most schemes this is
    /// the pubkey/address itself; for Falcon/Hawk it's `sha256(wire)` (32).
    pub identity_len: usize,
    /// Bytes the on-chain account stores after the 33-byte header. Equals
    /// `identity_len` for schemes that store the pubkey verbatim; larger for
    /// schemes that store an expanded form (Falcon: 32 + 1 + 1024).
    pub stored_identity_len: usize,
}

impl Scheme {
    /// Total on-chain account length: `VectorAccount::HEADER_LEN +
    /// stored_identity_len`.
    pub const fn account_len(&self) -> usize {
        VectorAccount::HEADER_LEN + self.stored_identity_len
    }
}

/// Host-side mirror of the on-chain `VectorAccount` *header*:
/// `nonce (32) || bump (1)` — 33 bytes. The scheme's identity bytes follow
/// at offset [`HEADER_LEN`](Self::HEADER_LEN).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorAccount {
    pub nonce: [u8; 32],
    pub bump: u8,
}

impl VectorAccount {
    pub const HEADER_LEN: usize = 33;

    /// Total on-chain account length for an identity of `identity_len` bytes.
    pub const fn account_len(identity_len: usize) -> usize {
        Self::HEADER_LEN + identity_len
    }

    pub fn header_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut bytes = [0u8; Self::HEADER_LEN];
        bytes[..32].copy_from_slice(&self.nonce);
        bytes[32] = self.bump;
        bytes
    }

    pub fn from_header_bytes(bytes: &[u8; Self::HEADER_LEN]) -> Self {
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&bytes[..32]);
        VectorAccount {
            nonce,
            bump: bytes[32],
        }
    }
}

/// 32-byte PDA-seed input derived from a scheme's identity: identity bytes
/// themselves when `identity.len() <= 32`, `sha256(identity)` otherwise.
/// Off-chain mirror of `IdentitySeed::default_from` in `vector-common`.
pub fn pda_seed_from_identity(identity: &[u8]) -> [u8; 32] {
    if identity.len() <= 32 {
        let mut out = [0u8; 32];
        out[..identity.len()].copy_from_slice(identity);
        out
    } else {
        Sha256::digest(identity).into()
    }
}

/// Derive the canonical `(vector_pda, bump)` for a scheme + identity.
/// Seeds: `["vector", identity_seed]` (no scheme byte — the program ID is
/// the discriminator).
pub fn find_vector_pda(scheme: &Scheme, identity: &[u8]) -> (Address, u8) {
    debug_assert_eq!(identity.len(), scheme.identity_len);
    let seed_bytes = pda_seed_from_identity(identity);
    let seed_len = identity.len().min(32);
    Address::find_program_address(
        &[VECTOR_PDA_SEED, &seed_bytes[..seed_len]],
        &scheme.program_id,
    )
}
