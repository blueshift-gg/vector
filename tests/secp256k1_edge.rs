//! Boundary values for the secp256k1 and EIP-191 schemes: signature scalars
//! at and beyond the group order, high-S, wrong message or key, edge-case
//! public keys, and every recovery byte `v`.
//!
//! The Wycheproof ECDSA secp256k1 SHA-256 vectors are on this machine (in the
//! `libsecp256k1` crate), but they are not used here: they sign arbitrary
//! messages, while an `Advance` only verifies the SHA-256 of `"vector:" ||
//! digest` for a digest the transaction determines. So the cases below are
//! generated with `k256`; none of them is a Wycheproof vector.

use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey as Secp256k1SigningKey};
use mollusk_svm::{
    program::keyed_account_for_system_program,
    result::{Check, ProgramResult},
};
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use vector_signer::{
    advance_vector_digest, create_advance_instruction, create_initialize_instruction,
    eip191_envelope_hash, find_vector_pda, secp256k1_compressed_pubkey,
    secp256k1_eip191_eth_address, signed, EIP191, SECP256K1,
};

use crate::common::{build_vector_account, mollusk, process_transaction, NONCE};

/// The order of the group, big-endian.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// The field's prime, big-endian.
const P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

fn key_from(private: [u8; 32]) -> Secp256k1SigningKey {
    Secp256k1SigningKey::from_bytes(&private.into()).unwrap()
}

/// The private key `k`, for a small `k`.
fn small(k: u8) -> Secp256k1SigningKey {
    let mut private = [0u8; 32];
    private[31] = k;
    key_from(private)
}

/// `n - 1`, the private key of `-G`.
fn n_minus_one() -> Secp256k1SigningKey {
    let mut private = N;
    private[31] -= 1;
    key_from(private)
}

/// `N` with its last byte raised by `add` (no carry for the values used).
fn n_plus(add: u8) -> [u8; 32] {
    let mut value = N;
    value[31] += add;
    value
}

fn rs(r: &[u8; 32], s: &[u8; 32]) -> [u8; 64] {
    [&r[..], &s[..]].concat().try_into().unwrap()
}

/// A secp256k1 account for `key` and the digest an empty `Advance` signs.
struct Account1 {
    identity: [u8; 33],
    vector: Address,
    accounts: Vec<(Address, Account)>,
    digest: [u8; 32],
}

fn world(key: &Secp256k1SigningKey) -> Account1 {
    let identity = secp256k1_compressed_pubkey(key);
    let (vector, _) = find_vector_pda(&SECP256K1, &identity);
    let lamports = mollusk()
        .sysvars
        .rent
        .minimum_balance(SECP256K1.account_len);
    let accounts = vec![(
        vector,
        build_vector_account(NONCE, &SECP256K1, &identity, lamports, &identity),
    )];
    let digest = advance_vector_digest(&SECP256K1, &NONCE, &identity, &[], &[], None);
    Account1 {
        identity,
        vector,
        accounts,
        digest,
    }
}

/// What the program verifies against: the SHA-256 of `"vector:" || digest`.
fn prehash(digest: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(signed(digest)).into()
}

/// The `r || s` of `key` over `prehash`, `s` low.
fn sign(key: &Secp256k1SigningKey, prehash: &[u8; 32]) -> [u8; 64] {
    let (signature, _): (Signature, _) = key.sign_prehash(prehash).unwrap();
    signature.to_bytes().into()
}

/// Run an `Advance` with `signature` on `world`'s account; `None` is success.
fn advance(world: &Account1, signature: &[u8], expected: Option<ProgramError>) {
    let ix = create_advance_instruction(&SECP256K1, &world.identity, signature);
    let check = match expected {
        None => Check::success(),
        Some(error) => Check::err(error),
    };
    process_transaction(&mollusk(), &[&ix], &world.accounts, &[check]);
}

const REJECTED: Option<ProgramError> = Some(ProgramError::MissingRequiredSignature);

#[test]
fn a_valid_signature_is_the_control() {
    let world = world(&small(3));
    advance(&world, &sign(&small(3), &prehash(&world.digest)), None);
}

/// `(r, n - s)` verifies too. It is harmless here: a signature is no nonce,
/// nothing is keyed on its bytes, and the nonce that stops replay is the
/// digest, which the signature does not change.
#[test]
fn the_high_s_twin_of_a_valid_signature_is_accepted() {
    let key = small(3);
    let world = world(&key);
    let (signature, _): (Signature, _) = key.sign_prehash(&prehash(&world.digest)).unwrap();
    let high_s: [u8; 32] = (-*signature.s().as_ref()).to_bytes().into();
    assert!(high_s > signature.s().to_bytes().into());
    let r: [u8; 32] = signature.r().to_bytes().into();
    advance(&world, &rs(&r, &high_s), None);
}

#[test]
fn scalars_at_and_beyond_the_group_order_fail() {
    let key = small(3);
    let world = world(&key);
    let good = sign(&key, &prehash(&world.digest));
    let (good_r, good_s): ([u8; 32], [u8; 32]) = (
        good[..32].try_into().unwrap(),
        good[32..].try_into().unwrap(),
    );
    let bad = [
        [0u8; 32],
        N,
        n_plus(1),
        [0xff; 32],
        // n + (a real r) would equal r modulo n if the check were missing.
        n_plus(good_r[31]),
    ];
    for value in bad {
        advance(&world, &rs(&value, &good_s), REJECTED);
        advance(&world, &rs(&good_r, &value), REJECTED);
    }
    // Both at once, and the all-zero signature.
    advance(&world, &[0u8; 64], REJECTED);
    advance(&world, &rs(&N, &N), REJECTED);
    advance(&world, &[0xff; 64], REJECTED);
    // r = 1 and s = 1 are in range, and are not this signature.
    let mut one = [0u8; 32];
    one[31] = 1;
    advance(&world, &rs(&one, &good_s), REJECTED);
    advance(&world, &rs(&good_r, &one), REJECTED);
    // A real signature with a bit flipped in each half.
    for bit in [0usize, 100, 255, 256, 400, 511] {
        let mut flipped = good;
        flipped[bit / 8] ^= 1 << (bit % 8);
        advance(&world, &flipped, REJECTED);
    }
}

#[test]
fn a_signature_for_a_different_message_fails() {
    let key = small(3);
    let world = world(&key);
    let other_digest = [0x42u8; 32];
    assert_ne!(other_digest, world.digest);
    advance(&world, &sign(&key, &prehash(&other_digest)), REJECTED);
    // The bare digest, and the digest's own hash, without the prefix.
    advance(&world, &sign(&key, &world.digest), REJECTED);
    advance(
        &world,
        &sign(&key, &Sha256::digest(world.digest).into()),
        REJECTED,
    );
}

#[test]
fn a_signature_under_a_different_key_fails() {
    let world = world(&small(3));
    advance(&world, &sign(&small(4), &prehash(&world.digest)), REJECTED);
    advance(
        &world,
        &sign(&n_minus_one(), &prehash(&world.digest)),
        REJECTED,
    );
}

/// The generator, its negation and its double are valid keys, and sign.
#[test]
fn keys_at_the_generator_initialize_and_sign() {
    for key in [small(1), n_minus_one(), small(2)] {
        let identity = secp256k1_compressed_pubkey(&key);
        let (system, system_account) = keyed_account_for_system_program();
        let payer = Address::new_unique();
        let (vector, _) = find_vector_pda(&SECP256K1, &identity);
        let init = create_initialize_instruction(&payer, &SECP256K1, &identity);
        let result = mollusk().process_instruction(
            &init,
            &[
                (payer, Account::new(1_000_000_000, 0, &system)),
                (vector, Account::default()),
                (system, system_account),
            ],
        );
        assert!(result.program_result.is_ok(), "{identity:02x?}");

        let world = world(&key);
        assert_eq!(world.vector, vector);
        advance(&world, &sign(&key, &prehash(&world.digest)), None);
        // And no other key's signature passes for it.
        advance(&world, &sign(&small(5), &prehash(&world.digest)), REJECTED);
    }
}

fn initialize_result(key: &[u8]) -> ProgramResult {
    let (system, system_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();
    let (vector, _) = find_vector_pda(&SECP256K1, key);
    let init = create_initialize_instruction(&payer, &SECP256K1, key);
    mollusk()
        .process_instruction(
            &init,
            &[
                (payer, Account::new(1_000_000_000, 0, &system)),
                (vector, Account::default()),
                (system, system_account),
            ],
        )
        .program_result
}

fn compressed(prefix: u8, x: &[u8; 32]) -> [u8; 33] {
    let mut key = [0u8; 33];
    key[0] = prefix;
    key[1..].copy_from_slice(x);
    key
}

#[test]
fn edge_case_public_keys_are_refused() {
    let invalid = ProgramResult::Failure(ProgramError::InvalidInstructionData);
    let mut zero = [0u8; 32];
    let mut generator_x = [0u8; 32];
    generator_x.copy_from_slice(&secp256k1_compressed_pubkey(&small(1))[1..]);
    assert_ne!(zero, generator_x);

    // x = 0, n, p and 2^256-1 under both parities. x = p and 2^256-1 are not
    // field elements. x = 0 and x = n are, so the curve decides, and the program must
    // agree with it (but for the x = n case below).
    for x in [zero, N, P, [0xff; 32]] {
        for prefix in [2u8, 3] {
            let key = compressed(prefix, &x);
            let on_curve = k256::PublicKey::from_sec1_bytes(&key).is_ok();
            // Real behavior: x = n has a point, and the program still refuses
            // it (its `lift_x` takes x below the group order). A false
            // refusal, not a false accept: nobody knows that point's private
            // key, so no account is lost by it.
            let expected = if on_curve && x != N {
                ProgramResult::Success
            } else {
                invalid.clone()
            };
            assert_eq!(initialize_result(&key), expected, "{key:02x?}");
        }
    }
    assert!(k256::PublicKey::from_sec1_bytes(&compressed(2, &P)).is_err());

    // A valid x under a prefix that does not mean compressed.
    for prefix in [0x00, 0x01, 0x04, 0x05, 0xff] {
        assert_eq!(
            initialize_result(&compressed(prefix, &generator_x)),
            invalid,
            "prefix {prefix:#x}"
        );
    }
    zero[31] = 1;
    // x = 1 as a control: whichever way the curve goes, the program agrees.
    let key = compressed(2, &zero);
    assert_eq!(
        initialize_result(&key).is_ok(),
        k256::PublicKey::from_sec1_bytes(&key).is_ok()
    );
}

/// Keccak-256 (the `sha3` crate is not a dependency of these tests).
fn keccak256(input: &[u8]) -> [u8; 32] {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const ROT: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const PI: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];
    const RATE: usize = 136;
    let mut padded = input.to_vec();
    padded.push(0x01);
    while !padded.len().is_multiple_of(RATE) {
        padded.push(0);
    }
    *padded.last_mut().unwrap() |= 0x80;
    let mut state = [0u64; 25];
    for block in padded.chunks(RATE) {
        for (i, lane) in block.chunks(8).enumerate() {
            state[i] ^= u64::from_le_bytes(lane.try_into().unwrap());
        }
        for rc in RC {
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for x in 0..5 {
                let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
                for y in 0..5 {
                    state[x + 5 * y] ^= d;
                }
            }
            let mut last = state[1];
            for i in 0..24 {
                let next = state[PI[i]];
                state[PI[i]] = last.rotate_left(ROT[i]);
                last = next;
            }
            for y in 0..5 {
                let row: [u64; 5] = std::array::from_fn(|x| state[x + 5 * y]);
                for x in 0..5 {
                    state[x + 5 * y] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
                }
            }
            state[0] ^= rc;
        }
    }
    let mut out = [0u8; 32];
    for (i, lane) in state[..4].iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// An EIP-191 account and an `Advance` signed for it by `key`, whose `v` is
/// the last byte of the data.
fn eip191_advance(key: &Secp256k1SigningKey) -> (Instruction, Vec<(Address, Account)>, [u8; 32]) {
    let identity = secp256k1_eip191_eth_address(key);
    let (vector, _) = find_vector_pda(&EIP191, &identity);
    let lamports = mollusk().sysvars.rent.minimum_balance(EIP191.account_len);
    let accounts = vec![(
        vector,
        build_vector_account(NONCE, &EIP191, &identity, lamports, &identity),
    )];
    let digest = advance_vector_digest(&EIP191, &NONCE, &identity, &[], &[], None);
    let (signature, recovery): (Signature, _) =
        key.sign_prehash(&eip191_envelope_hash(&digest)).unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&signature.to_bytes());
    bytes[64] = recovery.to_byte();
    (
        create_advance_instruction(&EIP191, &identity, &bytes),
        accounts,
        digest,
    )
}

fn run_with_v(
    ix: &Instruction,
    accounts: &[(Address, Account)],
    v: u8,
    expected: Option<ProgramError>,
) {
    let mut ix = ix.clone();
    *ix.data.last_mut().unwrap() = v;
    let check = match expected {
        None => Check::success(),
        Some(error) => Check::err(error),
    };
    process_transaction(&mollusk(), &[&ix], accounts, &[check]);
}

#[test]
fn eip191_takes_only_the_recovery_ids_v() {
    for k in [3u8, 4, 5, 6] {
        let (ix, accounts, _) = eip191_advance(&small(k));
        let recovery = *ix.data.last().unwrap();
        assert!(recovery <= 1);
        let wrong = 1 - recovery;

        // The right id as 0 or 1, as 27 or 28, and (see below) as 54 or 55.
        for v in [recovery, recovery + 27] {
            run_with_v(&ix, &accounts, v, None);
        }
        // The other id recovers another key.
        for v in [wrong, wrong + 27] {
            run_with_v(&ix, &accounts, v, REJECTED);
        }
        // Not recovery ids.
        for v in [2, 3, 29, 30, 255] {
            run_with_v(&ix, &accounts, v, REJECTED);
        }
        // Known malleability only: the program reads `v % 27`, so 54 and 55
        // are accepted as 0 and 1. The signed digest does not cover `v`, and
        // the same signature is already good as 0/1 and 27/28, so this
        // gives a replay nothing: the nonce is what stops one.
        run_with_v(&ix, &accounts, recovery + 54, None);
        run_with_v(&ix, &accounts, wrong + 54, REJECTED);
    }
}

#[test]
fn eip191_refuses_a_personal_sign_of_another_length() {
    let key = small(3);
    let (ix, accounts, digest) = eip191_advance(&key);
    let recovery = *ix.data.last().unwrap();
    let keccak = |length: &str, message: &[u8]| -> [u8; 32] {
        keccak256(
            &[
                format!("\x19Ethereum Signed Message:\n{length}").as_bytes(),
                message,
            ]
            .concat(),
        )
    };
    // The 32 bytes of the digest alone, and the 39 bytes under another
    // length, are the messages a careless wallet flow would sign.
    let other = [
        keccak("32", &digest),
        keccak("32", &signed(&digest)),
        keccak("39", &digest),
        keccak("7", b"vector:"),
    ];
    // The control: the envelope the program means (this also checks `keccak256`).
    assert_eq!(
        keccak("39", &signed(&digest)),
        eip191_envelope_hash(&digest)
    );
    for hash in other {
        for v in [0u8, 1] {
            let (signature, _): (Signature, _) = key.sign_prehash(&hash).unwrap();
            let mut ix = ix.clone();
            let end = ix.data.len();
            ix.data[end - 65..end - 1].copy_from_slice(&signature.to_bytes());
            run_with_v(&ix, &accounts, v, REJECTED);
        }
    }
    let _ = recovery;
}
