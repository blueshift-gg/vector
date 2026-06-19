//! Falcon-512 (post-quantum) program. Verify-side library only; signing is
//! left to the caller (pair with `pqcrypto-falcon` or another Falcon
//! signer). The client identity is `sha256(wire_pubkey)`.

use pqcrypto_falcon::falcon512 as pqf;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _};
use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::{address, Address};
use solana_falcon512::{FALCON_512_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN};
use solana_instruction::Instruction;

use crate::instructions::create_initialize_instruction;
use crate::scheme::{Scheme, SchemeMeta, Signer, Verifier};

pub const FALCON512_WIRE_PUBKEY_LEN: usize = FALCON_512_PUBKEY_LEN;
pub const FALCON512_SIGNATURE_LEN: usize = FALCON_512_SIGNATURE_LEN;
/// Falcon-512 prepared pubkey (`N * 2`, `N = 512`).
pub const FALCON512_PREPARED_PUBKEY_LEN: usize = 1024;
/// Falcon's on-chain stored identity: `sha256(wire_pubkey)[32] || pad[1] ||
/// prepared_pubkey[1024]`. The 1-byte pad lands `prepared` on a 2-byte
/// account offset for the on-chain zero-copy borrow.
pub const FALCON512_STORED_IDENTITY_LEN: usize = 32 + 1 + FALCON512_PREPARED_PUBKEY_LEN;

/// Falcon-512 — the client identity is `sha256(wire_pubkey)` (32 bytes); the
/// account stores that hash plus the 1024-byte prepared pubkey.
pub const FALCON512: Scheme = Scheme {
    program_id: address!("HdkE3dPYgCRZJgLv64mbFmojyCprUim8VRXzK2wR6Qgm"),
    signature_len: FALCON512_SIGNATURE_LEN,
    identity_len: 32,
    stored_identity_len: FALCON512_STORED_IDENTITY_LEN,
};

/// `sha256(wire_pubkey)` — Falcon's client-side identity (PDA seed + the
/// bytes folded into the advance digest). Mirrors the first 32 bytes the
/// on-chain program stores.
pub fn falcon512_identity(wire_pubkey: &[u8; FALCON512_WIRE_PUBKEY_LEN]) -> [u8; 32] {
    Sha256::digest(wire_pubkey).into()
}

/// Initialize a Falcon-512 vector account. `wire_pubkey` is the standard
/// 897-byte Falcon public key; the on-chain program hashes and prepares it.
pub fn create_initialize_falcon512(
    payer: &Address,
    wire_pubkey: &[u8; FALCON512_WIRE_PUBKEY_LEN],
) -> Instruction {
    let identity = falcon512_identity(wire_pubkey);
    create_initialize_instruction(payer, &FALCON512, &identity, wire_pubkey)
}

// ---------------------------------------------------------------------------
// Falcon512 struct — implements SchemeMeta + Signer + Verifier
// ---------------------------------------------------------------------------

/// Falcon-512 signer + offline verifier. Identity is sha256(wire pubkey).
#[derive(Clone)]
pub struct Falcon512 {
    pk: pqf::PublicKey,
    sk: pqf::SecretKey,
}

impl Falcon512 {
    pub fn generate() -> Self {
        let (pk, sk) = pqf::keypair();
        Self { pk, sk }
    }

    pub fn from_keypair(pk: pqf::PublicKey, sk: pqf::SecretKey) -> Self {
        Self { pk, sk }
    }

    fn wire_pk(&self) -> [u8; FALCON512_WIRE_PUBKEY_LEN] {
        let mut out = [0u8; FALCON512_WIRE_PUBKEY_LEN];
        out.copy_from_slice(self.pk.as_bytes());
        out
    }
}

impl SchemeMeta for Falcon512 {
    const PROGRAM_ID: Address = FALCON512.program_id;
    const SIGNATURE_LEN: usize = FALCON512_SIGNATURE_LEN;
    const IDENTITY_LEN: usize = 32;
    const STORED_IDENTITY_LEN: usize = FALCON512_STORED_IDENTITY_LEN;
}

impl Signer for Falcon512 {
    fn identity(&self) -> Vec<u8> {
        falcon512_identity(&self.wire_pk()).to_vec()
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.wire_pk().to_vec())
    }

    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        let sig = pqf::detached_sign(digest, &self.sk);
        let raw = sig.as_bytes();
        let mut out = vec![0u8; FALCON512_SIGNATURE_LEN];
        out[..raw.len()].copy_from_slice(raw);
        out
    }
}

impl crate::scheme::Registration for Falcon512 {}
impl crate::scheme::SingleTxRegister for Falcon512 {}

impl Verifier for Falcon512 {
    fn verify(
        identity: &[u8],
        public_key: Option<&[u8]>,
        digest: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        let Some(wire) = public_key else {
            return false;
        };
        let Ok(wire_arr) = <[u8; FALCON512_WIRE_PUBKEY_LEN]>::try_from(wire) else {
            return false;
        };
        if falcon512_identity(&wire_arr).as_slice() != identity {
            return false;
        }
        let Ok(pk) = pqf::PublicKey::from_bytes(wire) else {
            return false;
        };
        // Strip trailing zero-pad back to the variable-length detached sig.
        // Falcon detached sigs always end in a non-zero content byte.
        let end = signature
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        let Ok(sig) = pqf::DetachedSignature::from_bytes(&signature[..end]) else {
            return false;
        };
        pqf::verify_detached_signature(&sig, digest, &pk).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::{Signer, Verifier};
    #[test]
    fn sign_then_verify_roundtrip() {
        let k = Falcon512::generate();
        let digest = [1u8; 32];
        let sig = k.sign(&digest);
        assert_eq!(sig.len(), FALCON512_SIGNATURE_LEN);
        let pk = k.public_key().unwrap();
        assert!(Falcon512::verify(&k.identity(), Some(&pk), &digest, &sig));
        let mut bad = digest;
        bad[0] ^= 1;
        assert!(!Falcon512::verify(&k.identity(), Some(&pk), &bad, &sig));
    }
}
