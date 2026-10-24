//! Nonce accounts: more nonces for one vector, each its own chain, so the
//! vector's transactions land in any order and its key still signs. Moving
//! the vector's own nonce cancels them all.

use ed25519_dalek::{Signer, SigningKey};
use mollusk_svm::{result::types::TransactionProgramResult, Mollusk};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use vector_core::{
    advance_message, create_close_nonce_subinstruction, create_initialize_nonce_instruction,
    create_multi_advance_instruction, create_passthrough_instruction,
    create_withdraw_subinstruction, ed25519_pubkey, find_vector_pda, signed_nonce, signer_digest,
    AdvanceSigner, NonceAccount, VectorError, ED25519, PROGRAM_ID, WINTERNITZ,
};

use crate::common::{build_vector_account, mollusk, process_transaction, NONCE};

const FUNDS: u64 = 10_000_000_000;
const RENT: u64 = 1_500_000;

/// The nonce accounts' first nonce, any value but the vector's.
const FIRST: [u8; 32] = [0x11; 32];

/// `mollusk()` at `slot`.
fn at(slot: u64) -> Mollusk {
    let mut mollusk = mollusk();
    mollusk.warp_to_slot(slot);
    mollusk
}

/// A nonce account of `vector` holding `nonce`, created in slot 0.
fn nonce_account(vector: &Address, nonce: [u8; 32]) -> Account {
    Account {
        lamports: RENT,
        data: [&nonce[..], vector.as_ref(), &0u64.to_le_bytes()].concat(),
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

/// The nonce `address` holds: a nonce account's, or a vector's own.
fn nonce_of(accounts: &[(Address, Account)], address: &Address) -> [u8; 32] {
    account(accounts, address).data[..32].try_into().unwrap()
}

fn account<'a>(accounts: &'a [(Address, Account)], address: &Address) -> &'a Account {
    &accounts.iter().find(|(key, _)| key == address).unwrap().1
}

struct World {
    key: SigningKey,
    identity: [u8; 32],
    vector: Address,
    receiver: Address,
    nonces: [Address; 2],
    accounts: Vec<(Address, Account)>,
}

impl World {
    /// An Ed25519 vector at `NONCE`, with two nonce accounts at `FIRST`.
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[5; 32]);
        let identity = ed25519_pubkey(&key);
        let (vector, _) = find_vector_pda(&ED25519, &identity);
        let receiver = Address::new_unique();
        let nonces = [0x40, 0x41].map(|byte| Address::new_from_array([byte; 32]));
        let mut accounts = vec![
            (
                vector,
                build_vector_account(NONCE, &ED25519, &identity, FUNDS, &identity),
            ),
            (receiver, Account::new(1_000_000, 0, &Address::default())),
        ];
        accounts.extend(nonces.map(|nonce| (nonce, nonce_account(&vector, FIRST))));
        Self {
            key,
            identity,
            vector,
            receiver,
            nonces,
            accounts,
        }
    }

    /// A `Passthrough` running `instruction` as the vector.
    fn passthrough(&self, instruction: Instruction) -> Instruction {
        create_passthrough_instruction(&ED25519, &self.identity, &[instruction])
    }

    /// A `Passthrough` withdrawing `lamports` to the receiver.
    fn withdraw(&self, lamports: u64) -> Instruction {
        self.passthrough(create_withdraw_subinstruction(
            &ED25519,
            &self.identity,
            &self.receiver,
            lamports,
        ))
    }

    /// One `Advance`, an entry per `(nonce account, what it signs over)`,
    /// then `post`. Returns the transaction and each entry's digest.
    fn sign(
        &self,
        entries: &[(Option<Address>, [u8; 32])],
        post: &[Instruction],
    ) -> (Vec<Instruction>, Vec<[u8; 32]>) {
        let signers: Vec<_> = entries
            .iter()
            .map(|&(nonce_account, _)| AdvanceSigner {
                nonce_account,
                ..AdvanceSigner::new(&ED25519, &self.identity)
            })
            .collect();
        let message = advance_message(&signers, &[], post, None);
        let digests: Vec<_> = entries
            .iter()
            .map(|(_, nonce)| signer_digest(&message, nonce, &self.vector, &[]))
            .collect();
        let signatures: Vec<_> = digests
            .iter()
            .map(|digest| self.key.sign(digest).to_bytes())
            .collect();
        let advance = create_multi_advance_instruction(
            &signers
                .iter()
                .zip(&signatures)
                .map(|(&signer, signature)| (signer, &signature[..]))
                .collect::<Vec<_>>(),
        );
        ([vec![advance], post.to_vec()].concat(), digests)
    }

    /// What a signature over a nonce account at `FIRST` is over, while the
    /// vector's own nonce is `NONCE`.
    fn over(nonce: Address) -> (Option<Address>, [u8; 32]) {
        (Some(nonce), signed_nonce(&FIRST, &NONCE))
    }

    /// Run `transaction` in slot 1, after the nonce accounts' creation.
    fn run(
        &self,
        transaction: &[Instruction],
        accounts: &[(Address, Account)],
    ) -> (TransactionProgramResult, Vec<(Address, Account)>) {
        let result = process_transaction(
            &at(1),
            &transaction.iter().collect::<Vec<_>>(),
            accounts,
            &[],
        );
        (result.program_result, result.resulting_accounts)
    }

    /// `transaction` must fail with `error` at instruction `index`, and
    /// change nothing.
    fn refused(
        &self,
        transaction: &[Instruction],
        accounts: &[(Address, Account)],
        index: usize,
        error: ProgramError,
    ) {
        let (result, after) = self.run(transaction, accounts);
        assert_eq!(result, TransactionProgramResult::Failure(index, error));
        assert_eq!(after, accounts);
    }
}

#[test]
fn initialize_nonce_makes_a_created_account_a_nonce_account() {
    let world = World::new();
    let failure = |error| mollusk_svm::result::ProgramResult::Failure(error);
    let nonce = Address::new_from_array([7; 32]);
    // As the System `create_account` leaves it.
    let created = Account::new(RENT, NonceAccount::LEN, &PROGRAM_ID);
    let accounts = vec![(nonce, created.clone()), world.accounts[0].clone()];
    let init = create_initialize_nonce_instruction(&nonce, &world.vector);

    let result = at(5).process_instruction(&init, &accounts);
    assert!(result.program_result.is_ok(), "{:?}", result.program_result);
    let data = &result.get_account(&nonce).unwrap().data;
    assert_eq!(data[32..64], world.vector.to_bytes());
    assert_eq!(data[64..], 5u64.to_le_bytes());
    println!("initialize nonce: {} CUs", result.compute_units_consumed);
    // The first nonce takes in the slot: created again in another slot, the
    // account starts somewhere new.
    let again = at(6).process_instruction(&init, &accounts);
    assert_ne!(again.get_account(&nonce).unwrap().data[..32], data[..32]);

    // Once only.
    assert_eq!(
        at(5)
            .process_instruction(&init, &result.resulting_accounts)
            .program_result,
        failure(ProgramError::AccountAlreadyInitialized)
    );

    // The nonce account signs, so no one initializes it between its
    // creation and its owner's InitializeNonce.
    let mut unsigned = init.clone();
    unsigned.accounts[0].is_signer = false;
    assert_eq!(
        at(5)
            .process_instruction(&unsigned, &accounts)
            .program_result,
        failure(ProgramError::MissingRequiredSignature)
    );

    // For an account that is not a vector.
    let mut stranger = accounts.clone();
    stranger[1].1.owner = Address::new_unique();
    assert_eq!(
        at(5).process_instruction(&init, &stranger).program_result,
        failure(ProgramError::InvalidAccountOwner)
    );

    // For a vector whose key rotates: two nonces would be two signatures by
    // one key.
    let identity = [7; 41];
    let (winternitz, _) = find_vector_pda(&WINTERNITZ, &identity);
    let accounts = vec![
        (nonce, created),
        (
            winternitz,
            build_vector_account(NONCE, &WINTERNITZ, &identity, FUNDS, &identity),
        ),
    ];
    let init = create_initialize_nonce_instruction(&nonce, &winternitz);
    assert_eq!(
        at(5).process_instruction(&init, &accounts).program_result,
        failure(VectorError::KeyRotates.into())
    );
}

/// A nonce account neither signs nor closes in the slot it was created in,
/// so it is never closed and created again at a nonce it held.
#[test]
fn a_nonce_account_waits_out_its_creation_slot() {
    let world = World::new();
    let [zero, _] = world.nonces;
    let (advance, _) = world.sign(&[World::over(zero)], &[]);
    let close = world.passthrough(create_close_nonce_subinstruction(
        &ED25519,
        &world.identity,
        &zero,
        &world.receiver,
    ));
    let (close, _) = world.sign(&[(None, NONCE)], &[close]);

    for (transaction, index) in [(&advance, 0), (&close, 1)] {
        let result = process_transaction(
            &at(0),
            &transaction.iter().collect::<Vec<_>>(),
            &world.accounts,
            &[],
        );
        assert_eq!(
            result.program_result,
            TransactionProgramResult::Failure(index, VectorError::FreshNonce.into())
        );
        let (result, _) = world.run(transaction, &world.accounts);
        assert_eq!(result, TransactionProgramResult::Success);
    }
}

#[test]
fn transactions_over_different_nonce_accounts_land_in_any_order() {
    let world = World::new();
    let [zero, one] = world.nonces;
    let (over_zero, zero_digest) =
        world.sign(&[World::over(zero)], &[world.withdraw(1_000_000_000)]);
    let (over_one, one_digest) = world.sign(&[World::over(one)], &[world.withdraw(2_000_000_000)]);

    let mut accounts = world.accounts.clone();
    for (transaction, holder, digest) in [
        (&over_one, one, one_digest[0]),
        (&over_zero, zero, zero_digest[0]),
    ] {
        let before = accounts.clone();
        let outcome = process_transaction(
            &at(1),
            &transaction.iter().collect::<Vec<_>>(),
            &accounts,
            &[],
        );
        println!(
            "ed25519 advance + withdraw over a nonce account: {} CUs",
            outcome.compute_units_consumed
        );
        let (result, after) = (outcome.program_result, outcome.resulting_accounts);
        assert_eq!(result, TransactionProgramResult::Success);
        // Only the nonce it signed over moved; the vector's stayed.
        for address in [world.vector, zero, one] {
            let expected = if address == holder {
                digest
            } else {
                nonce_of(&before, &address)
            };
            assert_eq!(nonce_of(&after, &address), expected);
        }
        world.refused(
            transaction,
            &after,
            0,
            ProgramError::MissingRequiredSignature,
        );
        accounts = after;
    }
    assert_eq!(
        account(&accounts, &world.receiver).lamports,
        1_000_000 + 3_000_000_000
    );
}

#[test]
fn a_nonce_account_serves_its_own_vector_only() {
    let world = World::new();
    let [zero, one] = world.nonces;

    // Nonce account 0 says it belongs to another vector.
    let mut accounts = world.accounts.clone();
    accounts[2].1 = nonce_account(&Address::new_unique(), FIRST);
    let (transaction, _) = world.sign(&[World::over(zero)], &[]);
    world.refused(&transaction, &accounts, 0, VectorError::ForeignNonce.into());

    // A copy of nonce account 0 that the program does not own: anyone could
    // write it back to a nonce already used, so it is not a nonce account,
    // and the signature is checked against the vector's own nonce.
    let mut accounts = world.accounts.clone();
    accounts[2].1.owner = Address::new_unique();
    world.refused(
        &transaction,
        &accounts,
        0,
        ProgramError::MissingRequiredSignature,
    );

    // A signature over nonce account 0, sent with nonce account 1, whose
    // nonce differs.
    let mut accounts = world.accounts.clone();
    accounts[3].1 = nonce_account(&world.vector, [0x22; 32]);
    let mut swapped = transaction.clone();
    swapped[0].accounts[1].pubkey = one;
    world.refused(
        &swapped,
        &accounts,
        0,
        ProgramError::MissingRequiredSignature,
    );

    // Closing another vector's nonce account.
    let mut accounts = world.accounts.clone();
    accounts[2].1 = nonce_account(&Address::new_unique(), FIRST);
    let close = world.passthrough(create_close_nonce_subinstruction(
        &ED25519,
        &world.identity,
        &zero,
        &world.receiver,
    ));
    let (transaction, _) = world.sign(&[(None, NONCE)], &[close]);
    world.refused(&transaction, &accounts, 1, VectorError::ForeignNonce.into());
}

/// Moving the vector's own nonce, with one entry, cancels every signature
/// outstanding over it and over every nonce account of the vector.
#[test]
fn moving_the_vectors_nonce_cancels_every_nonce_account() {
    let world = World::new();
    let [zero, one] = world.nonces;
    let outstanding: Vec<_> = [(None, NONCE), World::over(zero), World::over(one)]
        .iter()
        .map(|&entry| world.sign(&[entry], &[world.withdraw(1)]).0)
        .collect();

    let (cancel, digests) = world.sign(&[(None, NONCE)], &[]);
    let (result, after) = world.run(&cancel, &world.accounts);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(nonce_of(&after, &world.vector), digests[0]);
    for transaction in &outstanding {
        world.refused(
            transaction,
            &after,
            0,
            ProgramError::MissingRequiredSignature,
        );
    }

    // The nonce accounts did not move; signed over the vector's new nonce,
    // they work again.
    let (resigned, _) = world.sign(
        &[(Some(zero), signed_nonce(&FIRST, &digests[0]))],
        &[world.withdraw(1)],
    );
    let (result, _) = world.run(&resigned, &after);
    assert_eq!(result, TransactionProgramResult::Success);
}

/// `Close` with a nonce account sends that account's lamports, not the
/// vector's, and removes it.
#[test]
fn close_closes_a_nonce_account() {
    let world = World::new();
    let [zero, _] = world.nonces;
    let close = world.passthrough(create_close_nonce_subinstruction(
        &ED25519,
        &world.identity,
        &zero,
        &world.receiver,
    ));
    let (transaction, _) = world.sign(&[(None, NONCE)], &[close]);
    let (result, after) = world.run(&transaction, &world.accounts);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(account(&after, &zero).lamports, 0);
    assert_eq!(account(&after, &world.receiver).lamports, 1_000_000 + RENT);
    assert_eq!(account(&after, &world.vector).lamports, FUNDS);
}
