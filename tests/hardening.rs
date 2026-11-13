//! What the 2.0 review closed: a signature is only ever over `"vector:" ||
//! digest`; a nonce account is not a vector account; a vector does not close
//! in its creation slot; a transaction expires at its `valid_until`; EIP-191
//! takes a wallet's `v`; and a secp256k1 key must be a point.

use ed25519_dalek::{Signer, SigningKey};
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use mollusk_svm::{program::keyed_account_for_system_program, result::Check, Mollusk};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use vector_core::{
    advance_message, create_close_subinstruction, create_initialize_instruction,
    create_initialize_nonce_instruction, create_multi_advance_instruction,
    create_passthrough_instruction, ed25519_pubkey, find_vector_pda, secp256k1_eip191_eth_address,
    sign_advance_instruction_secp256k1_eip191, signed, signer_digest, AdvanceSigner, NonceAccount,
    VectorError, ED25519, EIP191, PROGRAM_ID, SECP256K1,
};

use crate::common::{build_vector_account, mollusk, process_transaction, NONCE};

const RENT: u64 = 1_500_000;

fn at(slot: u64) -> Mollusk {
    let mut mollusk = mollusk();
    mollusk.warp_to_slot(slot);
    mollusk
}

fn nonce_account(vector: &Address, created: u64) -> Account {
    Account {
        lamports: RENT,
        data: [&[0x11; 32][..], vector.as_ref(), &created.to_le_bytes()].concat(),
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

/// A funded Ed25519 vector, created in slot 0.
struct World {
    key: SigningKey,
    identity: [u8; 32],
    vector: Address,
    receiver: Address,
    accounts: Vec<(Address, Account)>,
}

impl World {
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[9; 32]);
        let identity = ed25519_pubkey(&key);
        let (vector, _) = find_vector_pda(&ED25519, &identity);
        let receiver = Address::new_unique();
        let accounts = vec![
            (
                vector,
                build_vector_account(NONCE, &ED25519, &identity, 10_000_000_000, &identity),
            ),
            (receiver, Account::new(1_000_000, 0, &Address::default())),
        ];
        Self {
            key,
            identity,
            vector,
            receiver,
            accounts,
        }
    }

    fn close(&self) -> Instruction {
        create_passthrough_instruction(
            &ED25519,
            &self.identity,
            &[create_close_subinstruction(
                &ED25519,
                &self.identity,
                &self.receiver,
            )],
        )
    }

    /// An `Advance` and `post`, signed over the vector's own nonce, by
    /// `sign_over`, which turns what the key signs into a signature.
    fn advance(
        &self,
        valid_until: u64,
        post: &[Instruction],
        sign_over: impl Fn(&[u8; 32]) -> [u8; 64],
    ) -> Vec<Instruction> {
        let signer = AdvanceSigner::new(&ED25519, &self.identity);
        let message = advance_message(valid_until, &[signer], &[], post, None);
        let digest = signer_digest(&message, &NONCE, &self.vector, &[]);
        let signature = sign_over(&digest);
        let advance = create_multi_advance_instruction(valid_until, &[(signer, &signature[..])]);
        [vec![advance], post.to_vec()].concat()
    }

    fn signs(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.key.sign(&signed(digest)).to_bytes()
    }
}

#[test]
fn a_key_signs_the_prefix_and_never_the_bare_digest() {
    let world = World::new();
    let close = world.close();
    let mollusk = at(1);

    let good = world.advance(u64::MAX, std::slice::from_ref(&close), |d| world.signs(d));
    process_transaction(
        &mollusk,
        &good.iter().collect::<Vec<_>>(),
        &world.accounts,
        &[Check::success()],
    );

    // What a login challenge would have the key sign: 32 bytes, no prefix.
    let bare = world.advance(u64::MAX, &[close], |d| world.key.sign(d).to_bytes());
    process_transaction(
        &mollusk,
        &bare.iter().collect::<Vec<_>>(),
        &world.accounts,
        &[Check::err(ProgramError::MissingRequiredSignature)],
    );
}

#[test]
fn a_nonce_accounts_keypair_cannot_spend_it_as_a_vector() {
    let nonce = Address::new_unique();
    let thief = Address::new_unique();
    let accounts = vec![
        (nonce, nonce_account(&Address::new_unique(), 0)),
        (thief, Account::new(0, 0, &Address::default())),
    ];
    // The nonce account's own keypair signs a top-level Withdraw or Close.
    for data in [[&[3u8][..], &RENT.to_le_bytes()].concat(), vec![4u8]] {
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(nonce, true),
                AccountMeta::new(thief, false),
            ],
            data,
        };
        let result = at(5).process_instruction(&ix, &accounts);
        assert!(
            result.program_result.is_err(),
            "{:?}",
            result.program_result
        );
    }
}

#[test]
fn a_nonce_account_is_not_a_vector_of_a_nonce_account() {
    let fake = Address::new_unique();
    let new_nonce = Address::new_unique();
    // Created in a slot whose low byte is Ed25519's scheme byte.
    let accounts = vec![
        (
            new_nonce,
            Account::new(RENT, NonceAccount::LEN, &PROGRAM_ID),
        ),
        (fake, nonce_account(&Address::new_unique(), 1)),
    ];
    let init = create_initialize_nonce_instruction(&new_nonce, &fake);
    let result = at(5).process_instruction(&init, &accounts);
    assert!(
        result.program_result.is_err(),
        "{:?}",
        result.program_result
    );
}

#[test]
fn a_vector_closes_after_the_slot_it_was_created_in() {
    let world = World::new();
    let close = world.close();
    let transaction = world.advance(u64::MAX, &[close], |d| world.signs(d));
    let transaction: Vec<_> = transaction.iter().collect();

    // Created in slot 0.
    process_transaction(
        &at(0),
        &transaction,
        &world.accounts,
        &[Check::err(VectorError::FreshVector.into())],
    );
    process_transaction(&at(1), &transaction, &world.accounts, &[Check::success()]);
}

#[test]
fn a_signature_is_good_through_its_valid_until_slot() {
    let world = World::new();
    let post = [world.close()];
    let transaction = world.advance(5, &post, |d| world.signs(d));
    let transaction: Vec<_> = transaction.iter().collect();

    process_transaction(&at(5), &transaction, &world.accounts, &[Check::success()]);
    process_transaction(
        &at(6),
        &transaction,
        &world.accounts,
        &[Check::err(VectorError::Expired.into())],
    );

    // No one else can extend it: the message covers `valid_until`.
    let mut extended = transaction
        .iter()
        .map(|ix| (*ix).clone())
        .collect::<Vec<_>>();
    extended[0].data[1..9].copy_from_slice(&100u64.to_le_bytes());
    process_transaction(
        &at(6),
        &extended.iter().collect::<Vec<_>>(),
        &world.accounts,
        &[Check::err(ProgramError::MissingRequiredSignature)],
    );
}

#[test]
fn eip191_takes_a_wallets_v() {
    let key = Secp256k1SigningKey::from_bytes(&[3u8; 32].into()).unwrap();
    let address = secp256k1_eip191_eth_address(&key);
    let (vector, _) = find_vector_pda(&EIP191, &address);
    let account = build_vector_account(NONCE, &EIP191, &address, 10_000_000_000, &address);
    let receiver = Address::new_unique();
    let post = create_passthrough_instruction(
        &EIP191,
        &address,
        &[create_close_subinstruction(&EIP191, &address, &receiver)],
    );
    let advance = sign_advance_instruction_secp256k1_eip191(
        &key,
        &NONCE,
        &[],
        std::slice::from_ref(&post),
        None,
    );
    let accounts = vec![
        (vector, account),
        (receiver, Account::new(1_000_000, 0, &Address::default())),
    ];
    for add in [0, 27] {
        let mut advance = advance.clone();
        *advance.data.last_mut().unwrap() += add;
        process_transaction(&at(1), &[&advance, &post], &accounts, &[Check::success()]);
    }
}

#[test]
fn secp256k1_initialize_takes_a_point_only() {
    let mollusk = mollusk();
    let (system, system_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();

    // The first x with no point on the curve.
    let off_curve = (0u8..=255)
        .map(|x| {
            let mut key = [2u8; 33];
            key[1..].fill(0);
            key[32] = x;
            key
        })
        .find(|key| k256::PublicKey::from_sec1_bytes(key).is_err())
        .expect("an x with no point");
    let on_curve = vector_core::secp256k1_compressed_pubkey(
        &Secp256k1SigningKey::from_bytes(&[3u8; 32].into()).unwrap(),
    );

    for (key, expected) in [
        (off_curve, Some(ProgramError::InvalidInstructionData)),
        (on_curve, None),
    ] {
        let init = create_initialize_instruction(&payer, &SECP256K1, &key);
        let (vector, _) = find_vector_pda(&SECP256K1, &key);
        let accounts = [
            (payer, Account::new(1_000_000_000, 0, &system)),
            (vector, Account::default()),
            (system, system_account.clone()),
        ];
        let result = mollusk.process_instruction(&init, &accounts);
        match expected {
            Some(error) => assert_eq!(
                result.program_result,
                mollusk_svm::result::ProgramResult::Failure(error)
            ),
            None => assert!(result.program_result.is_ok()),
        }
    }
}

/// A point of small order cannot sign, or lets anyone sign: neither is a key.
/// Nor is a second encoding of a point, y at least p.
#[test]
fn ed25519_initialize_refuses_small_order_and_non_canonical_keys() {
    let mollusk = mollusk();
    let (system, system_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();

    // y = p, p + 1 and p + 2: second encodings of the points with y = 0, 1
    // and 2, with either sign bit.
    let mut weak: Vec<[u8; 32]> = Vec::new();
    for (low, high) in [(0xedu8, 0x7fu8), (0xee, 0x7f), (0xef, 0x7f)] {
        for sign in [0u8, 0x80] {
            let mut key = [0xff; 32];
            key[0] = low;
            key[31] = high | sign;
            weak.push(key);
        }
    }
    // The eight canonical ones.
    for hex in [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ] {
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let key: [u8; 32] = bytes.try_into().unwrap();
        // Dalek calls each one weak: these are the torsion points.
        assert!(
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .unwrap()
                .is_weak(),
            "{hex}"
        );
        weak.push(key);
    }

    let good = vector_core::ed25519_pubkey(&SigningKey::from_bytes(&[5; 32]));
    for (key, ok) in weak.iter().map(|key| (*key, false)).chain([(good, true)]) {
        let init = create_initialize_instruction(&payer, &ED25519, &key);
        let (vector, _) = find_vector_pda(&ED25519, &key);
        let accounts = [
            (payer, Account::new(1_000_000_000, 0, &system)),
            (vector, Account::default()),
            (system, system_account.clone()),
        ];
        let result = mollusk.process_instruction(&init, &accounts);
        if ok {
            assert!(result.program_result.is_ok());
        } else {
            assert_eq!(
                result.program_result,
                mollusk_svm::result::ProgramResult::Failure(ProgramError::InvalidInstructionData),
                "{key:02x?}"
            );
        }
    }
}
