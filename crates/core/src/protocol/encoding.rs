//! Protocol-level constants and the [`VectorAccount`] header mirror, and
//! (in a later task) the passthrough wire codec.
//!
//! These are the shared primitives that every scheme and instruction builder
//! depends on: discriminators, well-known Solana program IDs, the PDA seed,
//! and the 33-byte on-chain account header struct.

use solana_address::{address, Address};

/// Solana native System Program address.
pub const SYSTEM_PROGRAM_ID: Address = address!("11111111111111111111111111111111");
/// Solana Instructions sysvar address (read by the on-chain advance handler).
pub const INSTRUCTIONS_SYSVAR_ID: Address = address!("Sysvar1nstructions1111111111111111111111111");

/// Instruction discriminator for the `initialize` handler (= 0).
pub const INITIALIZE_DISCRIMINATOR: u8 = 0;
/// Instruction discriminator for the `advance` handler (= 1).
pub const ADVANCE_DISCRIMINATOR: u8 = 1;
/// Instruction discriminator for the `close` sub-instruction handler (= 2).
pub const CLOSE_DISCRIMINATOR: u8 = 2;
/// Instruction discriminator for the `withdraw` sub-instruction handler (= 3).
pub const WITHDRAW_DISCRIMINATOR: u8 = 3;
/// Instruction discriminator for the `passthrough` handler (= 4).
pub const PASSTHROUGH_DISCRIMINATOR: u8 = 4;

/// First PDA seed used across every Vector scheme: `b"vector"`.
pub const VECTOR_PDA_SEED: &[u8] = b"vector";

/// Host-side mirror of the on-chain `VectorAccount` *header*:
/// `nonce (32) || bump (1)` — 33 bytes. The scheme's identity bytes follow
/// at offset [`HEADER_LEN`](Self::HEADER_LEN).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorAccount {
    /// Current nonce: the next advance must sign over this value.
    pub nonce: [u8; 32],
    /// PDA canonical bump seed, stored so callers can reconstruct the signer seeds.
    pub bump: u8,
}

impl VectorAccount {
    /// Size of the fixed header in bytes (`nonce[32] + bump[1]`).
    pub const HEADER_LEN: usize = 33;

    /// Total on-chain account length for an identity of `identity_len` bytes.
    pub const fn account_len(identity_len: usize) -> usize {
        Self::HEADER_LEN + identity_len
    }

    /// Serialize the header to its 33-byte wire representation.
    pub fn header_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut bytes = [0u8; Self::HEADER_LEN];
        bytes[..32].copy_from_slice(&self.nonce);
        bytes[32] = self.bump;
        bytes
    }

    /// Deserialize the header from its 33-byte wire representation.
    pub fn from_header_bytes(bytes: &[u8; Self::HEADER_LEN]) -> Self {
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&bytes[..32]);
        VectorAccount {
            nonce,
            bump: bytes[32],
        }
    }
}
