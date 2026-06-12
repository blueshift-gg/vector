//! Offline verification tests: per-scheme sign → verify round trips,
//! tamper detection, on-chain-acceptance parity for malleated (high-S)
//! secp256k1 signatures, and the cross-language digest pin shared with
//! `sdk/ts/test/verify.test.ts`.

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hawk512::{self as hawk, xof::RngContext as HawkRngContext, Rng as HawkRng};
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use pqcrypto_falcon::falcon512 as pq_falcon;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use vector_core::{
    advance_vector_digest_with_fee_payer, ed25519_pubkey, falcon512_identity, hawk512_identity,
    revocation_digest, secp256k1_compressed_pubkey, secp256k1_eip191_eth_address,
    sign_advance_instruction_ed25519, sign_advance_instruction_secp256k1_ecdsa,
    sign_advance_instruction_secp256k1_eip191, sign_revocation_instruction_ed25519,
    verify_advance_signature_ed25519, verify_advance_signature_falcon512,
    verify_advance_signature_hawk512, verify_advance_signature_secp256k1_ecdsa,
    verify_advance_signature_secp256k1_eip191, VerifyError, ED25519, FALCON512,
    FALCON512_SIGNATURE_LEN, FALCON512_WIRE_PUBKEY_LEN, HAWK512, HAWK512_WIRE_PUBKEY_LEN,
    SYSTEM_PROGRAM_ID,
};

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
    &advance_ix.data[1..]
}

// ---------------------------------------------------------------------------
// Sign → verify round trips (advance NOT at index 0 — footer regression)
// ---------------------------------------------------------------------------

#[test]
fn ed25519_round_trip() {
    let key = Ed25519SigningKey::from_bytes(&[0x42; 32]);
    let pubkey = ed25519_pubkey(&key);
    let (pre, post) = fixed_ix_lists();

    let advance = sign_advance_instruction_ed25519(&key, &NONCE, &pre, &post);
    let digest = verify_advance_signature_ed25519(
        &pubkey,
        &NONCE,
        &pre,
        &post,
        None,
        signature_of(&advance),
    )
    .expect("round trip must verify");

    let expected =
        advance_vector_digest_with_fee_payer(&ED25519, &NONCE, &pubkey, &pre, &post, None);
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

    let advance = sign_advance_instruction_secp256k1_ecdsa(&key, &NONCE, &pre, &post);
    let wire = signature_of(&advance);
    verify_advance_signature_secp256k1_ecdsa(&pubkey, &NONCE, &pre, &post, None, wire)
        .expect("round trip must verify");

    let high_s = malleate_high_s(&k256::ecdsa::Signature::from_slice(wire).unwrap());
    verify_advance_signature_secp256k1_ecdsa(&pubkey, &NONCE, &pre, &post, None, &high_s.to_bytes())
        .expect("high-S twin must verify offline, matching on-chain acceptance");
}

#[test]
fn eip191_round_trip_high_s_twin_and_legacy_v() {
    let key = Secp256k1SigningKey::from_slice(&[0x43; 32]).unwrap();
    let eth_address = secp256k1_eip191_eth_address(&key);
    let (pre, post) = fixed_ix_lists();

    let advance = sign_advance_instruction_secp256k1_eip191(&key, &NONCE, &pre, &post);
    let wire = signature_of(&advance);
    verify_advance_signature_secp256k1_eip191(&eth_address, &NONCE, &pre, &post, None, wire)
        .expect("round trip must verify");

    // High-S twin: the recovery id's parity bit flips with the negated s,
    // recovering the same key — exactly what `sol_secp256k1_recover` does
    // on-chain.
    let low_s = k256::ecdsa::Signature::from_slice(&wire[..64]).unwrap();
    let mut malleated = malleate_high_s(&low_s).to_bytes().to_vec();
    malleated.push(wire[64] ^ 1);
    verify_advance_signature_secp256k1_eip191(&eth_address, &NONCE, &pre, &post, None, &malleated)
        .expect("high-S eip191 twin must verify offline, matching on-chain acceptance");

    // Legacy 27/28 recovery byte (what Ethereum tooling emits) is rejected
    // with subtract-27 guidance: it would fail `sol_secp256k1_recover`
    // on-chain, so accepting it offline would green-light a dead artifact.
    let mut legacy = wire.to_vec();
    legacy[64] += 27;
    let err =
        verify_advance_signature_secp256k1_eip191(&eth_address, &NONCE, &pre, &post, None, &legacy)
            .expect_err("legacy 27/28 form must be rejected");
    assert!(matches!(err, VerifyError::MalformedSignature(_)));
    assert!(
        err.to_string().contains("subtract 27"),
        "error must tell the caller how to fix it: {err}",
    );
}

#[test]
fn falcon512_round_trip() {
    let (pk, sk) = pq_falcon::keypair();
    let mut wire = [0u8; FALCON512_WIRE_PUBKEY_LEN];
    wire.copy_from_slice(pk.as_bytes());
    let (pre, post) = fixed_ix_lists();

    let digest = advance_vector_digest_with_fee_payer(
        &FALCON512,
        &NONCE,
        &falcon512_identity(&wire),
        &pre,
        &post,
        None,
    );
    // Zero-pad the variable-length detached signature to the 666-byte wire.
    let detached = pq_falcon::detached_sign(&digest, &sk);
    let mut signature = [0u8; FALCON512_SIGNATURE_LEN];
    signature[..detached.as_bytes().len()].copy_from_slice(detached.as_bytes());

    let verified = verify_advance_signature_falcon512(&wire, &NONCE, &pre, &post, None, &signature)
        .expect("round trip must verify");
    assert_eq!(verified, digest);

    // Same signature against a tampered nonce must fail.
    let mut bad_nonce = NONCE;
    bad_nonce[0] ^= 0x01;
    assert_eq!(
        verify_advance_signature_falcon512(&wire, &bad_nonce, &pre, &post, None, &signature),
        Err(VerifyError::SignatureInvalid),
    );
}

/// `hawk512::Rng` adapter over a continuous `SHAKE256(seed)` squeeze
/// (mirrors the adapter in `tests/hawk512.rs`).
struct SeededRng(HawkRngContext);

impl HawkRng for SeededRng {
    fn fill(&mut self, out: &mut [u8]) {
        let v = self.0.random(out.len());
        out.copy_from_slice(&v);
    }
}

#[test]
fn hawk512_round_trip() {
    let mut rng = SeededRng(HawkRngContext::new(b"vector-core-verify"));
    let (pk, sk) = hawk::keygen(&mut rng).expect("hawk keygen");
    let wire: &[u8; HAWK512_WIRE_PUBKEY_LEN] = pk.as_bytes().try_into().unwrap();
    let (pre, post) = fixed_ix_lists();

    let digest = advance_vector_digest_with_fee_payer(
        &HAWK512,
        &NONCE,
        &hawk512_identity(wire),
        &pre,
        &post,
        None,
    );
    let sig = hawk::sign(&digest, &sk, &mut rng).expect("hawk sign");

    let verified =
        verify_advance_signature_hawk512(wire, &NONCE, &pre, &post, None, sig.as_bytes())
            .expect("round trip must verify");
    assert_eq!(verified, digest);

    let mut bad_nonce = NONCE;
    bad_nonce[0] ^= 0x01;
    assert_eq!(
        verify_advance_signature_hawk512(wire, &bad_nonce, &pre, &post, None, sig.as_bytes()),
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
    let advance = sign_advance_instruction_ed25519(&key, &NONCE, &pre, &post);
    let sig = signature_of(&advance);
    let verify =
        |pubkey: &[u8; 32], nonce: &[u8; 32], pre: &[Instruction], post: &[Instruction]| {
            verify_advance_signature_ed25519(pubkey, nonce, pre, post, None, sig)
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
const PINNED_DIGEST_HEX: &str = "fb561cf20b01b2940889b1652f732ea100256e74f10675a3e169b1895b0a9e4f";

#[test]
fn digest_matches_the_cross_language_pin() {
    let key = Ed25519SigningKey::from_bytes(&[0x42; 32]);
    let pubkey = ed25519_pubkey(&key);
    let (pre, post) = fixed_ix_lists();

    let digest = advance_vector_digest_with_fee_payer(&ED25519, &NONCE, &pubkey, &pre, &post, None);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, PINNED_DIGEST_HEX);

    // And the pinned digest is exactly what a signer commits to.
    let advance = sign_advance_instruction_ed25519(&key, &NONCE, &pre, &post);
    let verified = verify_advance_signature_ed25519(
        &pubkey,
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
    "53e3d3f9a7c687ed3dbfbbee0da290586acb5f4d64d690221134d29ce9a25aba";

#[test]
fn revocation_round_trip_and_cross_language_pin() {
    let key = Ed25519SigningKey::from_bytes(&[0x42; 32]);
    let pubkey = ed25519_pubkey(&key);

    // A revocation is just an advance with empty pre/post, so it verifies
    // through the ordinary advance verifier with empty slices.
    let revocation = sign_revocation_instruction_ed25519(&key, &NONCE);
    let digest = verify_advance_signature_ed25519(
        &pubkey,
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
