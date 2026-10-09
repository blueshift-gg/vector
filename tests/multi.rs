//! Several signers in one `Advance`. Each signs the same message — the
//! transaction with the signatures cut out — so the tests here are about
//! what that cut must never allow: an unsigned byte, a signature that works
//! somewhere else, or a `Passthrough` for an account that did not sign.

use ed25519_dalek::{Signer, SigningKey};
use k256::ecdsa::{
    signature::hazmat::PrehashSigner, Signature as Secp256k1Signature,
    SigningKey as Secp256k1SigningKey,
};
use mollusk_svm::{result::types::TransactionProgramResult, Mollusk};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use vector_core::{
    advance_message, create_multi_advance_instruction, create_passthrough_instruction,
    create_withdraw_subinstruction, ed25519_pubkey, find_vector_pda, secp256k1_compressed_pubkey,
    sign_advance_instruction_ed25519, signer_digest, Scheme, ED25519, SECP256K1,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, process_transaction, NONCE,
    SECP256K1_PRIVKEY,
};

const FUNDS: u64 = 5_000_000_000;

/// Three accounts — two Ed25519, one secp256k1 — and somewhere to send to.
struct World {
    mollusk: Mollusk,
    alice: SigningKey,
    bob: Secp256k1SigningKey,
    carol: SigningKey,
    receiver: Address,
    accounts: Vec<(Address, Account)>,
}

impl World {
    fn new() -> Self {
        let mollusk = mollusk();
        let alice = SigningKey::from_bytes(&[1; 32]);
        let bob = Secp256k1SigningKey::from_bytes(&SECP256K1_PRIVKEY.into()).unwrap();
        let carol = SigningKey::from_bytes(&[3; 32]);
        let receiver = Address::new_unique();
        let mut accounts = vec![(receiver, Account::new(1_000_000, 0, &Address::default()))];
        for (scheme, identity) in [
            (&ED25519, ed25519_pubkey(&alice).to_vec()),
            (&SECP256K1, secp256k1_compressed_pubkey(&bob).to_vec()),
            (&ED25519, ed25519_pubkey(&carol).to_vec()),
        ] {
            let (vector, bump) = find_vector_pda(scheme, &identity);
            accounts.push((
                vector,
                build_vector_account(NONCE, scheme, bump, FUNDS, &identity),
            ));
        }
        Self {
            mollusk,
            alice,
            bob,
            carol,
            receiver,
            accounts,
        }
    }

    /// A `Passthrough` withdrawing `lamports` from the account to the receiver.
    fn withdraw(&self, scheme: &Scheme, identity: &[u8], lamports: u64) -> Instruction {
        let withdraw = create_withdraw_subinstruction(scheme, identity, &self.receiver, lamports);
        create_passthrough_instruction(scheme, identity, &[withdraw])
    }

    /// Alice and Bob sign one `Advance`; each then withdraws from their own
    /// account. Returns the transaction and their two digests.
    fn alice_and_bob(&self) -> (Vec<Instruction>, [u8; 32], [u8; 32]) {
        let alice = ed25519_pubkey(&self.alice);
        let bob = secp256k1_compressed_pubkey(&self.bob);
        let post = [
            self.withdraw(&ED25519, &alice, 1_000_000_000),
            self.withdraw(&SECP256K1, &bob, 2_000_000_000),
        ];
        let message = advance_message(&[(&ED25519, &alice), (&SECP256K1, &bob)], &[], &post, None);
        let alice_digest = signer_digest(&message, &NONCE, &alice);
        let bob_digest = signer_digest(&message, &NONCE, &bob);
        let alice_signature = self.alice.sign(&alice_digest).to_bytes();
        let bob_signature: Secp256k1Signature = self.bob.sign_prehash(&bob_digest).unwrap();
        let advance = create_multi_advance_instruction(&[
            (&ED25519, &alice, &alice_signature),
            (&SECP256K1, &bob, &bob_signature.to_bytes()),
        ]);
        let [first, second] = post;
        (vec![advance, first, second], alice_digest, bob_digest)
    }

    fn run(&self, transaction: &[Instruction]) -> TransactionProgramResult {
        self.run_with(transaction, &self.accounts).0
    }

    fn run_with(
        &self,
        transaction: &[Instruction],
        accounts: &[(Address, Account)],
    ) -> (TransactionProgramResult, Vec<(Address, Account)>) {
        let result = process_transaction(
            &self.mollusk,
            &transaction.iter().collect::<Vec<_>>(),
            accounts,
            &[],
        );
        (result.program_result, result.resulting_accounts)
    }

    /// A changed transaction must fail and leave every account as it was.
    fn assert_rejected(&self, transaction: &[Instruction], what: &str) {
        // An address the change introduced still needs an account to load.
        let mut accounts = self.accounts.clone();
        for meta in transaction.iter().flat_map(|ix| &ix.accounts) {
            let known = accounts.iter().any(|(key, _)| *key == meta.pubkey);
            let builtin = [vector_core::INSTRUCTIONS_SYSVAR_ID, vector_core::PROGRAM_ID];
            if !known && !builtin.contains(&meta.pubkey) {
                accounts.push((meta.pubkey, Account::default()));
            }
        }
        let (result, after) = self.run_with(transaction, &accounts);
        assert_ne!(result, TransactionProgramResult::Success, "{what}");
        assert_eq!(after, accounts, "{what}");
    }
}

#[test]
fn two_schemes_sign_one_advance() {
    let world = World::new();
    let (transaction, alice_digest, bob_digest) = world.alice_and_bob();
    let (result, after) = world.run_with(&transaction, &world.accounts);
    assert_eq!(result, TransactionProgramResult::Success);

    let account = |key: &Address| &after.iter().find(|(k, _)| k == key).unwrap().1;
    let alice = ed25519_pubkey(&world.alice);
    let bob = secp256k1_compressed_pubkey(&world.bob);
    let (alice_vector, alice_bump) = find_vector_pda(&ED25519, &alice);
    let (bob_vector, bob_bump) = find_vector_pda(&SECP256K1, &bob);
    // Each account's next nonce is its own digest of the shared message.
    assert_ne!(alice_digest, bob_digest);
    assert_eq!(
        account(&alice_vector).data,
        expected_advanced_data(alice_digest, &ED25519, alice_bump, &alice)
    );
    assert_eq!(
        account(&bob_vector).data,
        expected_advanced_data(bob_digest, &SECP256K1, bob_bump, &bob)
    );
    assert_eq!(account(&alice_vector).lamports, FUNDS - 1_000_000_000);
    assert_eq!(account(&bob_vector).lamports, FUNDS - 2_000_000_000);
    assert_eq!(account(&world.receiver).lamports, 1_000_000 + 3_000_000_000);

    // Both nonces moved, so the same transaction cannot land twice.
    let (replay, _) = world.run_with(&transaction, &after);
    assert_eq!(
        replay,
        TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
    );
}

/// The message covers every byte that is not a signature, and a signature
/// only verifies as it is. So no single change to the transaction survives.
#[test]
fn every_change_to_the_transaction_is_rejected() {
    let world = World::new();
    let (transaction, ..) = world.alice_and_bob();
    assert_eq!(world.run(&transaction), TransactionProgramResult::Success);
    let stranger = Address::new_unique();

    for i in 0..transaction.len() {
        for byte in 0..transaction[i].data.len() {
            let mut changed = transaction.clone();
            changed[i].data[byte] ^= 1;
            world.assert_rejected(&changed, &format!("instruction {i}, data byte {byte}"));
        }
        for extra in [true, false] {
            let mut changed = transaction.clone();
            if extra {
                changed[i].data.push(0);
            } else {
                changed[i].data.pop();
            }
            world.assert_rejected(&changed, &format!("instruction {i}, data length"));
        }
        for account in 0..transaction[i].accounts.len() {
            let what = format!("instruction {i}, account {account}");
            let mut changed = transaction.clone();
            changed[i].accounts[account].pubkey = stranger;
            world.assert_rejected(&changed, &what);
            // A transaction has one writable flag per address, not per
            // instruction, and the runtime ignores it for sysvars and programs.
            let key = transaction[i].accounts[account].pubkey;
            if ![vector_core::INSTRUCTIONS_SYSVAR_ID, vector_core::PROGRAM_ID].contains(&key) {
                let mut changed = transaction.clone();
                for meta in changed.iter_mut().flat_map(|ix| &mut ix.accounts) {
                    meta.is_writable ^= meta.pubkey == key;
                }
                world.assert_rejected(&changed, &what);
            }
            let mut changed = transaction.clone();
            changed[i].accounts.remove(account);
            world.assert_rejected(&changed, &what);
        }
        let mut changed = transaction.clone();
        changed[i]
            .accounts
            .push(AccountMeta::new_readonly(stranger, false));
        world.assert_rejected(&changed, &format!("instruction {i}, one more account"));

        let mut changed = transaction.clone();
        changed.remove(i);
        world.assert_rejected(&changed, &format!("without instruction {i}"));
        let mut changed = transaction.clone();
        changed.insert(i, transaction[i].clone());
        world.assert_rejected(&changed, &format!("instruction {i} twice"));
    }
    let mut changed = transaction.clone();
    changed.swap(1, 2);
    world.assert_rejected(&changed, "passthroughs in the other order");
}

/// Alice and Carol use the same scheme, so their signatures have the same
/// length and nothing but the digest tells them apart.
#[test]
fn a_signature_only_works_for_its_own_account() {
    let world = World::new();
    let alice = ed25519_pubkey(&world.alice);
    let carol = ed25519_pubkey(&world.carol);
    let post = [world.withdraw(&ED25519, &alice, 1_000_000_000)];
    let message = advance_message(&[(&ED25519, &alice), (&ED25519, &carol)], &[], &post, None);
    let alice_signature = world
        .alice
        .sign(&signer_digest(&message, &NONCE, &alice))
        .to_bytes();
    let carol_signature = world
        .carol
        .sign(&signer_digest(&message, &NONCE, &carol))
        .to_bytes();
    let advance = |signers: &[(&Scheme, &[u8], &[u8])]| {
        vec![create_multi_advance_instruction(signers), post[0].clone()]
    };

    let honest = advance(&[
        (&ED25519, &alice, &alice_signature),
        (&ED25519, &carol, &carol_signature),
    ]);
    assert_eq!(world.run(&honest), TransactionProgramResult::Success);

    world.assert_rejected(
        &advance(&[
            (&ED25519, &alice, &carol_signature),
            (&ED25519, &carol, &alice_signature),
        ]),
        "signatures swapped",
    );
    world.assert_rejected(
        &advance(&[
            (&ED25519, &carol, &carol_signature),
            (&ED25519, &alice, &alice_signature),
        ]),
        "signers in the other order",
    );
    world.assert_rejected(
        &advance(&[
            (&ED25519, &alice, &alice_signature),
            (&ED25519, &alice, &alice_signature),
        ]),
        "one signature used twice",
    );
    // What Alice signed with Carol does not hold without her.
    world.assert_rejected(
        &advance(&[(&ED25519, &alice, &alice_signature)]),
        "a co-signer dropped",
    );
}

/// `Passthrough` trusts any earlier `Advance` that lists its account, so
/// listing an account must be impossible without that account's signature.
#[test]
fn passthrough_needs_its_own_account_to_have_signed() {
    let world = World::new();
    let alice = ed25519_pubkey(&world.alice);
    let bob = secp256k1_compressed_pubkey(&world.bob);
    let (bob_vector, _) = find_vector_pda(&SECP256K1, &bob);
    let take_from_bob = world.withdraw(&SECP256K1, &bob, 2_000_000_000);

    // Alice signs a transaction that withdraws from Bob.
    let advance = sign_advance_instruction_ed25519(
        &world.alice,
        &NONCE,
        &[],
        std::slice::from_ref(&take_from_bob),
        None,
    );
    assert_eq!(
        world.run(&[advance.clone(), take_from_bob.clone()]),
        TransactionProgramResult::Failure(1, ProgramError::MissingRequiredSignature)
    );

    // She cannot list Bob's account in her `Advance` either, wherever it goes.
    for position in 0..=advance.accounts.len() {
        let mut listed = advance.clone();
        listed
            .accounts
            .insert(position, AccountMeta::new(bob_vector, false));
        world.assert_rejected(
            &[listed, take_from_bob.clone()],
            &format!("Bob's account listed at {position}"),
        );
    }

    // Nor by claiming his scheme byte without his signature.
    let mut claimed = advance.clone();
    claimed
        .accounts
        .insert(1, AccountMeta::new(bob_vector, false));
    claimed.data.insert(2, SECP256K1.id);
    world.assert_rejected(&[claimed, take_from_bob.clone()], "Bob's scheme claimed");

    // With no signers at all there is nothing to verify, and nothing passes.
    let mut nobody = advance.clone();
    nobody.accounts.remove(0);
    nobody.data.truncate(1);
    assert_eq!(
        world.run(&[nobody, world.withdraw(&ED25519, &alice, 1)]),
        TransactionProgramResult::Failure(0, ProgramError::NotEnoughAccountKeys)
    );
}

/// `Advance` and `Passthrough` read the transaction's instruction list, so
/// neither may run inside another instruction. Alice signs a transaction
/// whose `Passthrough` calls back into the program for Bob's account.
#[test]
fn advance_and_passthrough_cannot_be_called_from_inside_a_passthrough() {
    let world = World::new();
    let alice = ed25519_pubkey(&world.alice);
    let bob = secp256k1_compressed_pubkey(&world.bob);
    let (transaction, ..) = world.alice_and_bob();
    for inner in [
        transaction[0].clone(),
        world.withdraw(&SECP256K1, &bob, 2_000_000_000),
    ] {
        let outer = create_passthrough_instruction(&ED25519, &alice, &[inner]);
        let advance = sign_advance_instruction_ed25519(
            &world.alice,
            &NONCE,
            &[],
            std::slice::from_ref(&outer),
            None,
        );
        assert_eq!(
            world.run(&[advance, outer]),
            TransactionProgramResult::Failure(1, ProgramError::IncorrectAuthority)
        );
    }
}

/// A `Passthrough` only counts an `Advance` that has already run.
#[test]
fn passthrough_before_its_advance_is_rejected() {
    let world = World::new();
    let alice = ed25519_pubkey(&world.alice);
    let withdraw = world.withdraw(&ED25519, &alice, 1_000_000_000);
    let advance = sign_advance_instruction_ed25519(
        &world.alice,
        &NONCE,
        std::slice::from_ref(&withdraw),
        &[],
        None,
    );
    assert_eq!(
        world.run(&[withdraw, advance]),
        TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
    );
}

/// Random damage, several changes at a time: nothing but the signed
/// transaction itself is accepted.
#[test]
fn random_changes_are_rejected() {
    let world = World::new();
    let (transaction, ..) = world.alice_and_bob();
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut random = |below: usize| {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % below as u64) as usize
    };
    for round in 0..2_000 {
        let mut changed = transaction.clone();
        for _ in 0..=random(3) {
            let i = random(changed.len());
            let ix = &mut changed[i];
            match random(6) {
                0 if !ix.data.is_empty() => {
                    let at = random(ix.data.len());
                    ix.data[at] = random(256) as u8;
                }
                1 => ix.data.truncate(random(ix.data.len() + 1)),
                2 => ix.data.extend((0..random(80)).map(|_| 0)),
                3 if ix.accounts.len() > 1 => {
                    let (a, b) = (random(ix.accounts.len()), random(ix.accounts.len()));
                    ix.accounts.swap(a, b);
                }
                4 if !ix.accounts.is_empty() => {
                    // Borrow an account from elsewhere in the transaction.
                    let (from, to) = (random(transaction.len()), random(ix.accounts.len()));
                    let pool = &transaction[from].accounts;
                    ix.accounts[to] = pool[random(pool.len())].clone();
                }
                5 if changed.len() > 1 => {
                    let other = random(changed.len());
                    changed.swap(i, other);
                }
                _ => {}
            }
        }
        if changed != transaction {
            world.assert_rejected(&changed, &format!("round {round}"));
        }
    }
}
