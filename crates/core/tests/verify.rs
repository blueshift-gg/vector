//! Offline verification tests: per-scheme sign → verify round trips,
//! tamper detection, on-chain-acceptance parity for malleated (high-S)
//! secp256k1 signatures, and the cross-language digest pin shared with
//! `sdk/ts/test/verify.test.ts`.

use blueshift_vector::{
    advance_vector_digest, ed25519_pubkey, revocation_digest, secp256k1_compressed_pubkey,
    secp256k1_eip191_eth_address, sign_advance_instruction_ed25519,
    sign_advance_instruction_secp256k1_ecdsa, sign_advance_instruction_secp256k1_eip191,
    sign_revocation_instruction_ed25519, signed, verify_advance_signature, AdvanceSigner,
    VerifyError, ED25519, EIP191, FALCON512, SECP256K1, SYSTEM_PROGRAM_ID,
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use pqcrypto_falcon::falcon512 as pq_falcon;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

const NONCE: [u8; 32] = [0x01; 32];

/// Deterministic pre/post instructions: the advance sits at index 1, so
/// every round trip below also exercises the non-zero sysvar index footer
/// (a zeroed footer only matches an advance at index 0). Byte-identical to
/// `fixedIxLists` in `sdk/ts/test/verify.test.ts`.
fn fixed_ix_lists() -> (Vec<Instruction>, Vec<Instruction>) {
    let pre = Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(Address::new_from_array([0x11; 32]), true),
            AccountMeta::new_readonly(Address::new_from_array([0x22; 32]), false),
        ],
        data: vec![1, 2, 3, 4],
    };
    let post = Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(Address::new_from_array([0x33; 32]), false),
            AccountMeta::new_readonly(Address::new_from_array([0x44; 32]), false),
        ],
        data: vec![9, 9],
    };
    (vec![pre], vec![post])
}

/// Wire signature carried in an `advance` ix: data after the discriminator.
fn signature_of(advance_ix: &Instruction) -> &[u8] {
    &advance_ix.data[9..]
}

// ---------------------------------------------------------------------------
// Sign → verify round trips (advance NOT at index 0 — footer regression)
// ---------------------------------------------------------------------------

#[test]
fn ed25519_round_trip() {
    let key = Ed25519SigningKey::from_bytes(&[0x42; 32]);
    let pubkey = ed25519_pubkey(&key);
    let (pre, post) = fixed_ix_lists();

    let advance = sign_advance_instruction_ed25519(&key, &NONCE, &pre, &post, None);
    let digest = verify_advance_signature(
        AdvanceSigner::new(&ED25519, &pubkey),
        &NONCE,
        &pre,
        &post,
        None,
        signature_of(&advance),
    )
    .expect("round trip must verify");

    let expected = advance_vector_digest(&ED25519, &NONCE, &pubkey, &pre, &post, None);
    assert_eq!(digest, expected, "returned digest is the next nonce");
}

/// Negate `s` — the high-S malleated twin of a (k256-produced) low-S sig.
/// On-chain verifiers accept both `s` normalizations, so the offline
/// verifiers must accept the twin too or PASS/FAIL diverges.
fn malleate_high_s(sig: &k256::ecdsa::Signature) -> k256::ecdsa::Signature {
    use k256::elliptic_curve::scalar::IsHigh;
    assert!(!bool::from(sig.s().is_high()), "k256 signs low-S");
    k256::ecdsa::Signature::from_scalars(*sig.r(), -*sig.s().as_ref()).unwrap()
}

#[test]
fn secp256k1_round_trip_and_high_s_twin() {
    let key = Secp256k1SigningKey::from_slice(&[0x42; 32]).unwrap();
    let pubkey = secp256k1_compressed_pubkey(&key);
    let (pre, post) = fixed_ix_lists();

    let advance = sign_advance_instruction_secp256k1_ecdsa(&key, &NONCE, &pre, &post, None);
    let wire = signature_of(&advance);
    verify_advance_signature(
        AdvanceSigner::new(&SECP256K1, &pubkey),
        &NONCE,
        &pre,
        &post,
        None,
        wire,
    )
    .expect("round trip must verify");

    let high_s = malleate_high_s(&k256::ecdsa::Signature::from_slice(wire).unwrap());
    verify_advance_signature(
        AdvanceSigner::new(&SECP256K1, &pubkey),
        &NONCE,
        &pre,
        &post,
        None,
        &high_s.to_bytes(),
    )
    .expect("high-S twin must verify offline, matching on-chain acceptance");
}

#[test]
fn eip191_round_trip_high_s_twin_and_legacy_v() {
    let key = Secp256k1SigningKey::from_slice(&[0x43; 32]).unwrap();
    let eth_address = secp256k1_eip191_eth_address(&key);
    let (pre, post) = fixed_ix_lists();

    let advance = sign_advance_instruction_secp256k1_eip191(&key, &NONCE, &pre, &post, None);
    let wire = signature_of(&advance);
    verify_advance_signature(
        AdvanceSigner::new(&EIP191, &eth_address),
        &NONCE,
        &pre,
        &post,
        None,
        wire,
    )
    .expect("round trip must verify");

    // High-S twin: the recovery id's parity bit flips with the negated s,
    // recovering the same key — exactly what `sol_secp256k1_recover` does
    // on-chain.
    let low_s = k256::ecdsa::Signature::from_slice(&wire[..64]).unwrap();
    let mut malleated = malleate_high_s(&low_s).to_bytes().to_vec();
    malleated.push(wire[64] ^ 1);
    verify_advance_signature(
        AdvanceSigner::new(&EIP191, &eth_address),
        &NONCE,
        &pre,
        &post,
        None,
        &malleated,
    )
    .expect("high-S eip191 twin must verify offline, matching on-chain acceptance");

    // The 27/28 recovery byte wallets emit is the same signature: the
    // program takes `v % 27`.
    let mut legacy = wire.to_vec();
    legacy[64] += 27;
    verify_advance_signature(
        AdvanceSigner::new(&EIP191, &eth_address),
        &NONCE,
        &pre,
        &post,
        None,
        &legacy,
    )
    .expect("a wallet's v must verify");
}

#[test]
fn falcon512_round_trip() {
    let (pk, sk) = pq_falcon::keypair();
    let mut wire = [0u8; FALCON512.identity_len];
    wire.copy_from_slice(pk.as_bytes());
    let (pre, post) = fixed_ix_lists();

    let digest = advance_vector_digest(&FALCON512, &NONCE, &wire, &pre, &post, None);
    // Zero-pad the variable-length detached signature to the 666-byte wire.
    let detached = pq_falcon::detached_sign(&signed(&digest), &sk);
    let mut signature = [0u8; FALCON512.signature_len];
    signature[..detached.as_bytes().len()].copy_from_slice(detached.as_bytes());

    let verified = verify_advance_signature(
        AdvanceSigner::new(&FALCON512, &wire),
        &NONCE,
        &pre,
        &post,
        None,
        &signature,
    )
    .expect("round trip must verify");
    assert_eq!(verified, digest);

    // Same signature against a tampered nonce must fail.
    let mut bad_nonce = NONCE;
    bad_nonce[0] ^= 0x01;
    assert_eq!(
        verify_advance_signature(
            AdvanceSigner::new(&FALCON512, &wire),
            &bad_nonce,
            &pre,
            &post,
            None,
            &signature
        ),
        Err(VerifyError::SignatureInvalid),
    );
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

#[test]
fn tampering_any_committed_byte_fails_verification() {
    let key = Ed25519SigningKey::from_bytes(&[0x42; 32]);
    let pubkey = ed25519_pubkey(&key);
    let (pre, post) = fixed_ix_lists();
    let advance = sign_advance_instruction_ed25519(&key, &NONCE, &pre, &post, None);
    let sig = signature_of(&advance);
    let verify =
        |pubkey: &[u8; 32], nonce: &[u8; 32], pre: &[Instruction], post: &[Instruction]| {
            verify_advance_signature(
                AdvanceSigner::new(&ED25519, pubkey),
                nonce,
                pre,
                post,
                None,
                sig,
            )
        };

    // Instruction data.
    let mut tampered = pre.clone();
    tampered[0].data[0] ^= 0x01;
    assert!(verify(&pubkey, &NONCE, &tampered, &post).is_err());

    // Account pubkey.
    let mut tampered = post.clone();
    tampered[0].accounts[0].pubkey = Address::new_from_array([0x55; 32]);
    assert!(verify(&pubkey, &NONCE, &pre, &tampered).is_err());

    // Nonce.
    let mut bad_nonce = NONCE;
    bad_nonce[31] ^= 0x01;
    assert!(verify(&pubkey, &bad_nonce, &pre, &post).is_err());

    // Identity (a different — still valid — pubkey).
    let other = ed25519_pubkey(&Ed25519SigningKey::from_bytes(&[0x43; 32]));
    assert!(verify(&other, &NONCE, &pre, &post).is_err());
}

// ---------------------------------------------------------------------------
// Cross-language digest pin
// ---------------------------------------------------------------------------

/// Digest of the deterministic layout in `fixed_ix_lists` (ed25519 identity
/// from seed 0x42·32, nonce 0x01·32, no fee payer, advance at index 1).
/// `sdk/ts/test/verify.test.ts` pins the SAME constant — if either
/// implementation drifts (hashing, sysvar serialization, flag promotion,
/// index footer), its half of the pin breaks.
const PINNED_DIGEST_HEX: &str = "c7a416250641b0799af333015a2b87923131f8cab638b3daafc277e808e74280";

#[test]
fn digest_matches_the_cross_language_pin() {
    let key = Ed25519SigningKey::from_bytes(&[0x42; 32]);
    let pubkey = ed25519_pubkey(&key);
    let (pre, post) = fixed_ix_lists();

    let digest = advance_vector_digest(&ED25519, &NONCE, &pubkey, &pre, &post, None);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, PINNED_DIGEST_HEX);

    // And the pinned digest is exactly what a signer commits to.
    let advance = sign_advance_instruction_ed25519(&key, &NONCE, &pre, &post, None);
    let verified = verify_advance_signature(
        AdvanceSigner::new(&ED25519, &pubkey),
        &NONCE,
        &pre,
        &post,
        None,
        signature_of(&advance),
    )
    .unwrap();
    assert_eq!(verified, digest);
}

// ---------------------------------------------------------------------------
// Revocation (inert advance)
// ---------------------------------------------------------------------------

/// Revocation digest for (ed25519 identity from seed 0x42·32, nonce
/// 0x01·32): an inert advance, empty pre/post, no fee payer.
/// `sdk/ts/test/verify.test.ts` pins the SAME constant — if either
/// implementation drifts, its half of the pin breaks.
const PINNED_REVOCATION_DIGEST_HEX: &str =
    "40ad59cf6f9853f02d2668e092573e6b7b8131cc0c335dd29a03747759b450cf";

#[test]
fn revocation_round_trip_and_cross_language_pin() {
    let key = Ed25519SigningKey::from_bytes(&[0x42; 32]);
    let pubkey = ed25519_pubkey(&key);

    // A revocation is just an advance with empty pre/post, so it verifies
    // through the ordinary advance verifier with empty slices.
    let revocation = sign_revocation_instruction_ed25519(&key, &NONCE);
    let digest = verify_advance_signature(
        AdvanceSigner::new(&ED25519, &pubkey),
        &NONCE,
        &[],
        &[],
        None,
        signature_of(&revocation),
    )
    .expect("revocation round trip must verify");

    assert_eq!(digest, revocation_digest(&ED25519, &NONCE, &pubkey));
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, PINNED_REVOCATION_DIGEST_HEX);
}

// ---------------------------------------------------------------------------
// Several signers, nonce accounts, expiry
// ---------------------------------------------------------------------------

mod multi {
    use super::*;
    use blueshift_vector::{
        advance_message, create_multi_advance_instruction, find_vector_pda, signed_nonce,
        signer_digest, verify_advance, AdvanceEntry, SignerNonce, NEVER_EXPIRES,
    };
    use sha2::{Digest, Sha256};

    const VECTOR_NONCE: [u8; 32] = [0x07; 32];
    const NONCE_ACCOUNT_NONCE: [u8; 32] = [0x08; 32];

    struct Two {
        alice: Ed25519SigningKey,
        alice_id: [u8; 32],
        bob: Secp256k1SigningKey,
        bob_id: [u8; 33],
        nonce_account: Address,
        pre: Vec<Instruction>,
        post: Vec<Instruction>,
    }

    impl Two {
        fn new() -> Self {
            let alice = Ed25519SigningKey::from_bytes(&[0x42; 32]);
            let bob = Secp256k1SigningKey::from_bytes(&[0x24; 32].into()).unwrap();
            let (pre, post) = fixed_ix_lists();
            Self {
                alice_id: ed25519_pubkey(&alice),
                bob_id: secp256k1_compressed_pubkey(&bob),
                alice,
                bob,
                nonce_account: Address::new_from_array([0x55; 32]),
                pre,
                post,
            }
        }

        /// Alice over her own nonce, Bob over a nonce account (if `listed`),
        /// all good through `valid_until`: the signers and signatures.
        fn sign(&self, listed: bool, valid_until: u64) -> (Vec<AdvanceSigner<'_>>, Vec<Vec<u8>>) {
            let signers = vec![
                AdvanceSigner::new(&ED25519, &self.alice_id),
                AdvanceSigner {
                    nonce_account: listed.then_some(self.nonce_account),
                    ..AdvanceSigner::new(&SECP256K1, &self.bob_id)
                },
            ];
            let message = advance_message(valid_until, &signers, &self.pre, &self.post, None);
            let alice_digest = signer_digest(
                &message,
                &VECTOR_NONCE,
                &find_vector_pda(&ED25519, &self.alice_id).0,
                &[],
            );
            let bob_nonce = if listed {
                signed_nonce(&NONCE_ACCOUNT_NONCE, &VECTOR_NONCE)
            } else {
                VECTOR_NONCE
            };
            let bob_digest = signer_digest(
                &message,
                &bob_nonce,
                &find_vector_pda(&SECP256K1, &self.bob_id).0,
                &[],
            );
            use ed25519_dalek::Signer;
            use k256::ecdsa::signature::hazmat::PrehashSigner;
            let alice = self.alice.sign(&signed(&alice_digest)).to_bytes().to_vec();
            let (bob, _): (k256::ecdsa::Signature, _) = self
                .bob
                .sign_prehash(&Sha256::digest(signed(&bob_digest)))
                .map(|signature: k256::ecdsa::Signature| (signature, ()))
                .unwrap();
            (signers, vec![alice, bob.to_bytes().to_vec()])
        }

        fn entries<'a>(
            &self,
            signers: &[AdvanceSigner<'a>],
            signatures: &'a [Vec<u8>],
            bob_nonce: SignerNonce,
        ) -> Vec<AdvanceEntry<'a>> {
            vec![
                AdvanceEntry::new(
                    signers[0],
                    SignerNonce::Vector(VECTOR_NONCE),
                    &signatures[0],
                ),
                AdvanceEntry::new(signers[1], bob_nonce, &signatures[1]),
            ]
        }
    }

    #[test]
    fn two_signers_verify_over_one_message() {
        let two = Two::new();
        let (signers, signatures) = two.sign(false, NEVER_EXPIRES);
        let entries = two.entries(&signers, &signatures, SignerNonce::Vector(VECTOR_NONCE));

        // What the transaction carries agrees with what is checked.
        let advance = create_multi_advance_instruction(
            NEVER_EXPIRES,
            &signers
                .iter()
                .zip(&signatures)
                .map(|(&signer, signature)| (signer, &signature[..]))
                .collect::<Vec<_>>(),
        );
        assert_eq!(advance.accounts.len(), 3);

        let digests =
            verify_advance(NEVER_EXPIRES, &entries, &two.pre, &two.post, None, None).unwrap();
        assert_eq!(digests.len(), 2);
        assert_ne!(digests[0], digests[1]);

        // Each signature is good for its own signer only.
        let swapped = [signatures[1].clone(), signatures[0].clone()];
        let wrong = two.entries(&signers, &swapped, SignerNonce::Vector(VECTOR_NONCE));
        assert!(verify_advance(NEVER_EXPIRES, &wrong, &two.pre, &two.post, None, None).is_err());

        // And each covers the whole transaction, so the other's too: change
        // what follows the advance and both fail.
        let mut post = two.post.clone();
        post[0].data.push(0);
        assert_eq!(
            verify_advance(NEVER_EXPIRES, &entries, &two.pre, &post, None, None),
            Err(VerifyError::SignatureInvalid)
        );
        // The second alone fails when only it was signed over another nonce.
        let mut entries = entries;
        entries[1].nonce = SignerNonce::Vector([0x09; 32]);
        assert_eq!(
            verify_advance(NEVER_EXPIRES, &entries, &two.pre, &two.post, None, None),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn a_signature_over_a_nonce_account_verifies_with_both_nonces() {
        let two = Two::new();
        let (signers, signatures) = two.sign(true, NEVER_EXPIRES);
        let account = SignerNonce::Account {
            account: NONCE_ACCOUNT_NONCE,
            vector: VECTOR_NONCE,
        };

        let entries = two.entries(&signers, &signatures, account);
        let digests =
            verify_advance(NEVER_EXPIRES, &entries, &two.pre, &two.post, None, None).unwrap();
        assert_eq!(digests.len(), 2);

        // Already combined is the same thing.
        let combined = SignerNonce::Signed(signed_nonce(&NONCE_ACCOUNT_NONCE, &VECTOR_NONCE));
        let entries = two.entries(&signers, &signatures, combined);
        assert_eq!(
            verify_advance(NEVER_EXPIRES, &entries, &two.pre, &two.post, None, None).unwrap(),
            digests
        );

        // Moving the vector's own nonce cancels the nonce account's signatures.
        let moved = SignerNonce::Account {
            account: NONCE_ACCOUNT_NONCE,
            vector: [0x99; 32],
        };
        let entries = two.entries(&signers, &signatures, moved);
        assert_eq!(
            verify_advance(NEVER_EXPIRES, &entries, &two.pre, &two.post, None, None),
            Err(VerifyError::SignatureInvalid)
        );

        // A listed nonce account and a bare vector nonce do not go together.
        let entries = two.entries(&signers, &signatures, SignerNonce::Vector(VECTOR_NONCE));
        assert_eq!(
            verify_advance(NEVER_EXPIRES, &entries, &two.pre, &two.post, None, None),
            Err(VerifyError::NonceMismatch)
        );
    }

    #[test]
    fn a_transaction_expires_after_its_valid_until() {
        let two = Two::new();
        let (signers, signatures) = two.sign(false, 5);
        let entries = two.entries(&signers, &signatures, SignerNonce::Vector(VECTOR_NONCE));

        for slot in [None, Some(4), Some(5)] {
            verify_advance(5, &entries, &two.pre, &two.post, None, slot).unwrap();
        }
        assert_eq!(
            verify_advance(5, &entries, &two.pre, &two.post, None, Some(6)),
            Err(VerifyError::Expired)
        );

        // A later `valid_until` than was signed is no one's signature: the
        // message covers it, so both signatures fail, not only one.
        assert_eq!(
            verify_advance(100, &entries, &two.pre, &two.post, None, Some(6)),
            Err(VerifyError::SignatureInvalid)
        );
        let mut alone = entries.clone();
        alone.truncate(1);
        assert_eq!(
            verify_advance(100, &alone, &two.pre, &two.post, None, Some(6)),
            Err(VerifyError::SignatureInvalid)
        );
    }
}
