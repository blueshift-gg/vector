//! The single contract a Vector program must satisfy.
//!
//! A scheme decides three things: how big its wire signature is, what bytes
//! it stores on-chain as the signer's "identity" (a pubkey or address), and
//! how to verify a signature over a 32-byte digest. Everything else —
//! account creation, nonce advancement, CPI passthrough, close/withdraw — is
//! scheme-independent and lives in [`crate`].

use pinocchio::error::ProgramError;
use solana_nostd_sha256::hash;

/// Contract every signing scheme satisfies. One `impl` per program.
pub trait SigningScheme {
    /// Wire signature length carried in the `advance` instruction data.
    const SIGNATURE_LEN: usize;

    /// Bytes the scheme stores on-chain — its full identity (the verifier's
    /// pubkey or address). Account length is
    /// [`VectorAccount::HEADER_LEN`](crate::VectorAccount::HEADER_LEN) plus
    /// this.
    const IDENTITY_LEN: usize;

    /// `initialize` payload length (after the instruction discriminator).
    /// Usually equals `IDENTITY_LEN` (the pubkey is stored verbatim), but
    /// may differ for schemes that expand or compress on-chain: Falcon-512
    /// takes a 897-byte wire pubkey and expands it into the 1057-byte
    /// stored identity; Hawk-512 takes a 32-byte hash commit (the full
    /// 18.5 KB identity is filled by follow-up `store_wire` + `finalize`
    /// ixs).
    const INIT_PAYLOAD_LEN: usize;

    /// Validate the init payload and write the on-chain identity bytes into
    /// `identity_out` (exactly `IDENTITY_LEN` wide).
    fn populate_identity(payload: &[u8], identity_out: &mut [u8]) -> Result<(), ProgramError>;

    /// The slice of the stored identity folded into the advance digest.
    ///
    /// Must be reproducible off-chain by the signer. Default: the whole
    /// identity — correct for schemes that store exactly the signer's pubkey
    /// (Ed25519, EIP-191, secp256k1-ECDSA). Schemes that store an
    /// expanded/prepared form the client can't cheaply recompute (Falcon,
    /// Hawk) override to return the stable client-derivable prefix, e.g.
    /// `sha256(wire_pubkey)`.
    fn digest_identity(identity: &[u8]) -> &[u8] {
        identity
    }

    /// PDA seed derived from the stored identity — used at advance time.
    /// Default: the identity itself when `<= 32` bytes, else `sha256`.
    /// Schemes whose stored form differs from the seed (Falcon) override.
    fn pda_seed_from_identity(identity: &[u8]) -> IdentitySeed {
        IdentitySeed::default_from(identity)
    }

    /// PDA seed derived from the init payload — used at init time, before the
    /// account exists. Must produce the same bytes
    /// [`pda_seed_from_identity`](Self::pda_seed_from_identity) would after
    /// init runs.
    fn pda_seed_from_payload(payload: &[u8]) -> IdentitySeed {
        IdentitySeed::default_from(payload)
    }

    /// Verify `signature` over `digest` against the stored `identity`.
    fn verify(identity: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<(), ProgramError>;
}

/// PDA-seed buffer — variable length up to 32 bytes (Solana's per-seed cap).
///
/// Holds the bytes and the real length so callers can pass
/// `&self.bytes[..self.len]` to `Seed::from`.
pub struct IdentitySeed {
    bytes: [u8; 32],
    len: usize,
}

impl IdentitySeed {
    /// Copy up to 32 bytes verbatim.
    pub fn copy_from(src: &[u8]) -> Self {
        let len = src.len().min(32);
        let mut bytes = [0u8; 32];
        bytes[..len].copy_from_slice(&src[..len]);
        Self { bytes, len }
    }

    /// `sha256(input)` — the seed for identities longer than 32 bytes.
    pub fn from_hash(input: &[u8]) -> Self {
        Self {
            bytes: hash(input),
            len: 32,
        }
    }

    /// Default rule: identity bytes themselves when `<= 32`, else `sha256`.
    pub fn default_from(input: &[u8]) -> Self {
        if input.len() <= 32 {
            Self::copy_from(input)
        } else {
            Self::from_hash(input)
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
