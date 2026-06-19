//! The scheme/program/account primitives shared by every scheme: the
//! [`Scheme`] descriptor. Per-scheme details (identity derivation,
//! signing, init builders) live in [`crate::schemes`]. Protocol-level
//! constants, [`VectorAccount`], and PDA derivation live in
//! [`crate::protocol`].

use crate::instructions::create_initialize_instruction;
use crate::protocol::VectorAccount;
use solana_address::Address;
use solana_instruction::Instruction;

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

/// Const dimensions + program id for one Vector program.
pub trait SchemeMeta {
    /// On-chain program ID for this scheme.
    const PROGRAM_ID: Address;
    /// Wire signature length in bytes carried in the `advance` instruction data.
    const SIGNATURE_LEN: usize;
    /// Client-side identity length: the value hashed into the digest and used for PDA derivation.
    const IDENTITY_LEN: usize;
    /// On-chain stored identity length: may differ from `IDENTITY_LEN` for PQ schemes.
    const STORED_IDENTITY_LEN: usize;
    /// Runtime descriptor for value-taking APIs (the digest builder).
    fn descriptor() -> Scheme {
        Scheme {
            program_id: Self::PROGRAM_ID,
            signature_len: Self::SIGNATURE_LEN,
            identity_len: Self::IDENTITY_LEN,
            stored_identity_len: Self::STORED_IDENTITY_LEN,
        }
    }
}

/// Holds a secret; produces the wire signature over the advance digest.
pub trait Signer: SchemeMeta {
    /// Client identity (`IDENTITY_LEN` bytes): pubkey/address, or
    /// `sha256(wire)` for PQ schemes.
    fn identity(&self) -> Vec<u8>;
    /// Wire pubkey carried in the artifact for PQ schemes; `None` for the
    /// curve schemes.
    fn public_key(&self) -> Option<Vec<u8>> {
        None
    }
    /// Wire signature over `digest`, `SIGNATURE_LEN` bytes.
    fn sign(&self, digest: &[u8; 32]) -> Vec<u8>;
}

/// Transaction-layout for account lifecycle (NOT key custody): the
/// registration transaction(s) and any pre-instructions the advance digest
/// must commit to (e.g. a compute-budget bump for an expensive verify).
pub trait Registration: Signer {
    /// Top-level instructions that must precede the advance and be committed
    /// by the digest. Default: none.
    fn advance_pre_instructions(&self) -> Vec<Instruction> {
        Vec::new()
    }
    /// Account-registration transactions, one group per transaction. Default:
    /// a single `initialize` (init payload = wire pubkey for PQ schemes, else identity).
    fn registration_groups(&self, payer: &Address) -> Vec<Vec<Instruction>> {
        let id = self.identity();
        let init_payload = self.public_key().unwrap_or_else(|| id.clone());
        vec![vec![create_initialize_instruction(
            payer,
            &Self::descriptor(),
            &id,
            &init_payload,
        )]]
    }
}

/// Marker for schemes whose registration is a single transaction, so
/// `Vector::initialize` (a one-tx convenience) is available. Multi-tx schemes
/// (Hawk-512) implement only `Registration` and must use `register()`.
pub trait SingleTxRegister: Registration {}

/// Pure, offline signature check. No secret, no RPC.
pub trait Verifier: SchemeMeta {
    /// `identity` is the client identity; `public_key` is the PQ wire pubkey
    /// when present.
    fn verify(
        identity: &[u8],
        public_key: Option<&[u8]>,
        digest: &[u8; 32],
        signature: &[u8],
    ) -> bool;
}

/// SDK-only sub-key lanes; only 32-byte-key schemes implement it.
pub trait Derivable: Signer + Sized {
    /// Derive child key at `index` using HKDF-SHA256 over the scheme's master secret.
    fn derive(&self, index: u32) -> Self;
}
