//! Hawk-512 (post-quantum) program. Verify-only library; signing is left to
//! the caller. The client identity is `sha256(wire_pubkey)`. Registration is
//! three permissionless ixs (see [`create_initialize_hawk512`],
//! [`create_hawk512_store_wire`], [`create_hawk512_finalize`]).

use hawk512::{self as hawk, xof::RngContext as HawkRngContext, Rng};
use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::{address, Address};
use solana_instruction::{AccountMeta, Instruction};

use crate::instructions::create_initialize_instruction;
use crate::protocol::{find_vector_pda, INITIALIZE_DISCRIMINATOR};
use crate::scheme::{Scheme, SchemeMeta, Signer, Verifier};

/// Hawk-512 wire pubkey length.
pub const HAWK512_WIRE_PUBKEY_LEN: usize = 1024;
pub const HAWK512_SIGNATURE_LEN: usize = 555;
/// Hawk-512 prepared pubkey blob.
pub const HAWK512_PREPARED_PUBKEY_LEN: usize = 18464;
/// Hawk's on-chain stored identity: `sha256(wire)[32] || pad[7] ||
/// prepared[18464]`. The 7-byte pad lands `prepared` on an 8-byte account
/// offset (Hawk's zero-copy borrow requires 8-byte alignment).
pub const HAWK512_STORED_IDENTITY_LEN: usize = 32 + 7 + HAWK512_PREPARED_PUBKEY_LEN;

/// Hawk-512 (post-quantum) — client identity is `sha256(wire_pubkey)` (32
/// bytes). Three-call registration: the 18 KB prepared pubkey is too large
/// to allocate or compute in a single instruction, and the 1024-byte wire
/// pubkey can't coexist with the `system_program` meta needed for
/// `CreateAccount`. See [`create_initialize_hawk512`] for the flow.
pub const HAWK512: Scheme = Scheme {
    program_id: address!("Ecm48RMiE4qvyw6m4M5DeutpRAN1AF4tis6ijc6Zq3H9"),
    signature_len: HAWK512_SIGNATURE_LEN,
    identity_len: 32,
    stored_identity_len: HAWK512_STORED_IDENTITY_LEN,
};

/// `sha256(wire_pubkey)` — Hawk's client-side identity (PDA seed + digest
/// input). Mirrors the first 32 bytes the on-chain program stores.
pub fn hawk512_identity(wire_pubkey: &[u8; HAWK512_WIRE_PUBKEY_LEN]) -> [u8; 32] {
    Sha256::digest(wire_pubkey).into()
}

/// Hawk-512 registration is three permissionless ixs, all on discriminator
/// `0` — the on-chain dispatcher selects each handler by ix shape + vector
/// account state (see `programs/hawk512/src/scheme.rs`).
///
/// 1. [`create_initialize_hawk512`] commits the 32-byte `sha256(wire)` and
///    allocates the ~10 KB base account. Carries the `system_program` meta
///    for `CreateAccount`.
/// 2. [`create_hawk512_store_wire`] carries the 1024-byte wire pubkey; the
///    program verifies its hash against the commit and stashes the wire in
///    the account.
/// 3. [`create_hawk512_finalize`] carries no payload; pair it with a
///    `ComputeBudgetProgram::set_compute_unit_limit(600_000)` ix because
///    `prepare_into` draws ~410 k CU (the 200 k per-tx default isn't
///    enough). The on-chain handler resizes the account to ~18.5 KB and
///    runs `prepare_into`. Idempotent.
///
/// The split is forced by the 1232-byte tx ceiling: the wire pubkey can't
/// fit with `system_program`, and `finalize`'s ~410 k-CU `prepare_into`
/// can't fit alongside the wire either.
pub fn create_initialize_hawk512(
    payer: &Address,
    wire_pubkey: &[u8; HAWK512_WIRE_PUBKEY_LEN],
) -> Instruction {
    let identity = hawk512_identity(wire_pubkey);
    create_initialize_instruction(payer, &HAWK512, &identity, &identity)
}

/// Hawk-512 registration step 2 — ship the 1024-byte wire pubkey. The
/// on-chain handler verifies `sha256(payload) == stored hash` (the commit
/// from step 1) before stashing, so an attacker who squatted on init can
/// neither block this nor corrupt the stashed wire.
///
/// Accounts: `[vector_pda]` — no payer, no system_program. The tx-level
/// fee payer signer is enough; trimming the metas is what gets the
/// 1024-byte payload under the 1232-byte ceiling.
pub fn create_hawk512_store_wire(wire_pubkey: &[u8; HAWK512_WIRE_PUBKEY_LEN]) -> Instruction {
    let identity = hawk512_identity(wire_pubkey);
    let (vector, _bump) = find_vector_pda(&HAWK512, &identity);
    let mut data = Vec::with_capacity(1 + HAWK512_WIRE_PUBKEY_LEN);
    data.push(INITIALIZE_DISCRIMINATOR);
    data.extend_from_slice(wire_pubkey);
    Instruction {
        program_id: HAWK512.program_id,
        accounts: vec![AccountMeta::new(vector, false)],
        data,
    }
}

/// Hawk-512 registration step 3 — resize the account to ~18.5 KB and
/// `prepare_into` the stashed wire. Idempotent: re-running on a fully
/// prepared account is a no-op.
///
/// Accounts: `[vector_pda]`. Data: `[0]` (just the discriminator).
/// The finalize tx must include a
/// `ComputeBudgetProgram::set_compute_unit_limit(600_000)` ix because
/// `prepare_into` draws ~410 k CU on the live validator (the per-tx
/// default of 200 k otherwise leaves it short).
pub fn create_hawk512_finalize(wire_pubkey: &[u8; HAWK512_WIRE_PUBKEY_LEN]) -> Instruction {
    let identity = hawk512_identity(wire_pubkey);
    let (vector, _bump) = find_vector_pda(&HAWK512, &identity);
    Instruction {
        program_id: HAWK512.program_id,
        accounts: vec![AccountMeta::new(vector, false)],
        data: vec![INITIALIZE_DISCRIMINATOR],
    }
}

// ---------------------------------------------------------------------------
// Hawk512 struct — implements SchemeMeta + Signer + Verifier
// ---------------------------------------------------------------------------

/// `hawk512::Rng` adapter over a continuous `SHAKE256(seed)` squeeze — the
/// same deterministic stream Hawk's reference (and the TS port) use, so a
/// given seed reproduces the same keypair / signature byte-for-byte.
struct SeededRng(HawkRngContext);

impl SeededRng {
    fn new(seed: &[u8]) -> Self {
        Self(HawkRngContext::new(seed))
    }
}

impl Rng for SeededRng {
    fn fill(&mut self, out: &mut [u8]) {
        let v = self.0.random(out.len());
        out.copy_from_slice(&v);
    }
}

/// Hawk-512 signer + offline verifier. Identity is `sha256(wire pubkey)`.
///
/// Signing randomness is derived per-message from a secret entropy seed
/// (`sha256(entropy || digest)`) so it is fresh per distinct message yet
/// reproducible. Reusing one randomness stream across different messages can
/// leak the secret in lattice signatures, so we never reuse a fixed seed.
pub struct Hawk512 {
    wire: [u8; HAWK512_WIRE_PUBKEY_LEN],
    sk: hawk::SecretKey,
    entropy: [u8; 32],
}

impl Hawk512 {
    /// Derive a Hawk-512 keypair deterministically from `seed`. The same seed
    /// reproduces the same keypair (and thus the same identity / PDA). The
    /// per-message signing entropy is a secret value bound to `seed`.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut rng = SeededRng::new(seed);
        let (pk, sk) = hawk::keygen(&mut rng).expect("hawk keygen");
        let mut wire = [0u8; HAWK512_WIRE_PUBKEY_LEN];
        wire.copy_from_slice(pk.as_bytes());
        let mut h = Sha256::new();
        h.update(seed);
        h.update(b"vector-hawk-sig-entropy");
        let entropy: [u8; 32] = h.finalize().into();
        Self { wire, sk, entropy }
    }

    /// The 1024-byte wire public key (PDA seed input via [`hawk512_identity`]).
    pub fn wire_pubkey(&self) -> &[u8; HAWK512_WIRE_PUBKEY_LEN] {
        &self.wire
    }
}

impl SchemeMeta for Hawk512 {
    const PROGRAM_ID: Address = HAWK512.program_id;
    const SIGNATURE_LEN: usize = HAWK512_SIGNATURE_LEN;
    const IDENTITY_LEN: usize = 32;
    const STORED_IDENTITY_LEN: usize = HAWK512_STORED_IDENTITY_LEN;
}

impl Signer for Hawk512 {
    fn identity(&self) -> Vec<u8> {
        hawk512_identity(&self.wire).to_vec()
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.wire.to_vec())
    }

    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        // Per-message signing randomness: sha256(entropy || digest). Fresh per
        // distinct message, secret (entropy is private), and reproducible.
        let mut h = Sha256::new();
        h.update(self.entropy);
        h.update(digest);
        let sig_seed: [u8; 32] = h.finalize().into();
        let mut rng = SeededRng::new(&sig_seed);
        let sig = hawk::sign(digest, &self.sk, &mut rng).expect("hawk sign");
        sig.as_bytes().to_vec()
    }
}

impl crate::scheme::Registration for Hawk512 {
    fn advance_pre_instructions(&self) -> Vec<Instruction> {
        // Hawk's on-chain verify draws ~410k CU; commit a budget bump as a signed pre-ix.
        vec![crate::instructions::set_compute_unit_limit(600_000)]
    }

    fn registration_groups(&self, payer: &Address) -> Vec<Vec<Instruction>> {
        let wire = self.wire_pubkey();
        vec![
            vec![create_initialize_hawk512(payer, wire)],
            vec![create_hawk512_store_wire(wire)],
            vec![
                crate::instructions::set_compute_unit_limit(600_000),
                create_hawk512_finalize(wire),
            ],
        ]
    }
}

impl Verifier for Hawk512 {
    fn verify(
        identity: &[u8],
        public_key: Option<&[u8]>,
        digest: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        let Some(wire) = public_key else {
            return false;
        };
        let Ok(wire_arr) = <[u8; HAWK512_WIRE_PUBKEY_LEN]>::try_from(wire) else {
            return false;
        };
        if hawk512_identity(&wire_arr).as_slice() != identity {
            return false;
        }
        // Offline verify via the `hawk512` crate (a KAT-validated port of the
        // HAWK reference) — the same algorithm `solana-hawk512`'s on-chain
        // `verify` / `verify_with_prepared` implements, and the verifier the
        // `hawk512::sign` signatures are KAT-checked against. The message is
        // the 32-byte digest; `M = SHAKE256(digest || hpub)` is folded in
        // internally, identical to on-chain.
        let Ok(pk) = hawk::PublicKey::try_from(wire) else {
            return false;
        };
        let Ok(sig) = hawk::Signature::try_from(signature) else {
            return false;
        };
        hawk::verify(digest, &sig, &pk).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::{Signer, Verifier};
    #[test]
    fn sign_then_verify_roundtrip() {
        let k = Hawk512::from_seed(b"vector-test-hawk");
        let digest = [2u8; 32];
        let sig = k.sign(&digest);
        assert_eq!(sig.len(), HAWK512_SIGNATURE_LEN);
        let pk = k.public_key().unwrap();
        assert!(Hawk512::verify(&k.identity(), Some(&pk), &digest, &sig));
        let mut bad = digest;
        bad[0] ^= 1;
        assert!(!Hawk512::verify(&k.identity(), Some(&pk), &bad, &sig));
    }
    #[test]
    fn sign_is_deterministic_per_message() {
        let k = Hawk512::from_seed(b"vector-test-hawk");
        assert_eq!(k.sign(&[2u8; 32]), k.sign(&[2u8; 32])); // same msg -> same sig (per-msg derivation)
    }
}
