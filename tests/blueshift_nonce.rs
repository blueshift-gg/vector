//! `blueshift-nonce` as a durable nonce user would drive it: a Solana
//! `Keypair` is the nonce authority and signs offline; whoever submits signs
//! a plain `Transaction`; a System `Transfer` runs from its system account.

use blueshift_nonce::{
    close_nonce_account, create_nonce_account, data_from_account, state_from_account,
    system_account, vector, Error, NoncedMessage, NoncedTransaction, State,
};
use mollusk_svm::{
    program::keyed_account_for_system_program, result::types::TransactionProgramResult, Mollusk,
};
use solana_account::Account;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program_error::ProgramError;
use solana_signer::{Signer, SignerError};
use solana_system_interface::instruction::{create_account, transfer};
use solana_transaction::Transaction;
use vector_core::{signed_nonce, NonceAccount, ED25519, PROGRAM_ID};

use crate::common::{build_vector_account, mollusk, process_transaction, NONCE};

/// The nonce account's first nonce, any value.
const FIRST: [u8; 32] = [0x11; 32];

/// `mollusk()` in slot 1, after the nonce account's creation in slot 0.
fn later() -> Mollusk {
    let mut mollusk = mollusk();
    mollusk.warp_to_slot(1);
    mollusk
}

struct World {
    authority: Keypair,
    nonce: Address,
    receiver: Address,
    accounts: Vec<(Address, Account)>,
}

impl World {
    fn new() -> Self {
        let authority = Keypair::new_from_array([9; 32]);
        let pubkey = authority.pubkey();
        let nonce = Address::new_from_array([0x55; 32]);
        let receiver = Address::new_unique();
        let rent = mollusk().sysvars.rent.minimum_balance(ED25519.account_len);
        let accounts = vec![
            (
                vector(&pubkey),
                build_vector_account(NONCE, &ED25519, pubkey.as_ref(), rent, pubkey.as_ref()),
            ),
            (
                nonce,
                Account {
                    lamports: 1_500_000,
                    data: [&FIRST[..], vector(&pubkey).as_ref(), &0u64.to_le_bytes()].concat(),
                    owner: PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            ),
            (
                system_account(&pubkey),
                Account::new(5_000_000_000, 0, &Address::default()),
            ),
            (receiver, Account::new(1_000_000, 0, &Address::default())),
            keyed_account_for_system_program(),
        ];
        Self {
            authority,
            nonce,
            receiver,
            accounts,
        }
    }

    fn account(&self, address: &Address) -> &Account {
        &self
            .accounts
            .iter()
            .find(|(key, _)| key == address)
            .unwrap()
            .1
    }

    /// The nonce account's [`Data`](blueshift_nonce::Data) in `accounts`.
    fn data(&self, accounts: &[(Address, Account)]) -> blueshift_nonce::Data {
        let account =
            |address: &Address| &accounts.iter().find(|(key, _)| key == address).unwrap().1;
        data_from_account(
            account(&self.nonce),
            account(&vector(&self.authority.pubkey())),
        )
        .unwrap()
    }

    /// `message`, signed by the nonce authority over `nonce`.
    fn signed(&self, message: &NoncedMessage, nonce: Hash) -> Transaction {
        let mut transaction = NoncedTransaction::new_unsigned(message.clone());
        transaction
            .try_partial_sign(&[&self.authority], nonce)
            .unwrap();
        transaction.into()
    }

    /// Run `transaction`'s instructions as the runtime would.
    fn submit(
        &self,
        transaction: &Transaction,
        accounts: &[(Address, Account)],
    ) -> (TransactionProgramResult, Vec<(Address, Account)>) {
        let message = &transaction.message;
        let instructions: Vec<_> = message
            .instructions
            .iter()
            .map(|ix| Instruction {
                program_id: message.account_keys[ix.program_id_index as usize],
                accounts: ix
                    .accounts
                    .iter()
                    .map(|&i| AccountMeta {
                        pubkey: message.account_keys[i as usize],
                        is_signer: message.is_signer(i as usize),
                        is_writable: message.is_maybe_writable_with_reserved_addresses(
                            i as usize,
                            None::<&std::collections::HashSet<Address>>,
                        ),
                    })
                    .collect(),
                data: ix.data.clone(),
            })
            .collect();
        let result = process_transaction(
            &later(),
            &instructions.iter().collect::<Vec<_>>(),
            accounts,
            &[],
        );
        (result.program_result, result.resulting_accounts)
    }
}

#[test]
fn a_keypair_signs_a_transfer_offline_over_a_nonce_account() {
    let world = World::new();
    let pubkey = world.authority.pubkey();

    // Read the nonce: the nonce account's, with the vector's own in it.
    let data = world.data(&world.accounts);
    assert!(data.is_authority(&pubkey));
    assert!(!data.is_authority(&Address::new_unique()));
    assert_eq!(
        data.blockhash(),
        Hash::new_from_array(signed_nonce(&FIRST, &NONCE))
    );

    // Sign offline, then check it as the program will. The transfer names
    // the authority, as it would under durable nonces.
    let fee_payer = Keypair::new();
    let pay = transfer(&pubkey, &world.receiver, 2_000_000_000);
    let message =
        NoncedMessage::new_with_nonce(vec![pay], Some(&fee_payer.pubkey()), &world.nonce, &pubkey);
    let signature = message.sign(&data.blockhash(), &world.authority).unwrap();
    assert_eq!(message.verify(&data.blockhash(), &signature), Ok(()));
    assert_eq!(
        message.verify(&Hash::new_from_array(NONCE), &signature),
        Err(Error::InvalidSignature)
    );
    // Only the nonce authority signs.
    assert!(message.sign(&data.blockhash(), &Keypair::new()).is_err());

    // It travels as a plain `Transaction`, which the fee payer signs as any
    // other, over a recent blockhash.
    let signed = world.signed(&message, data.blockhash());
    let bytes = bincode::serialize(&signed).unwrap();
    let mut transaction: Transaction = bincode::deserialize(&bytes).unwrap();
    assert!(!transaction.is_signed());
    transaction
        .try_partial_sign(&[&fee_payer], Hash::new_from_array([3; 32]))
        .unwrap();
    assert!(transaction.verify().is_ok());

    let (result, after) = world.submit(&transaction, &world.accounts);
    assert_eq!(result, TransactionProgramResult::Success);
    let account = |address: &Address| &after.iter().find(|(key, _)| key == address).unwrap().1;
    assert_eq!(account(&world.receiver).lamports, 1_000_000 + 2_000_000_000);
    // The nonce account moved to the digest that was signed; the vector's
    // own nonce did not.
    assert_eq!(
        account(&world.nonce).data[..32],
        message.digest(&data.blockhash())
    );
    assert_eq!(account(&vector(&pubkey)).data[..32], NONCE);

    // The same signed message never lands twice.
    let (replay, _) = world.submit(&transaction, &after);
    assert_eq!(
        replay,
        TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
    );
}

#[test]
fn only_nonce_accounts_read_as_nonce_accounts() {
    let world = World::new();
    let vector_account = world.account(&vector(&world.authority.pubkey()));
    let read = |address: &Address| state_from_account(world.account(address), vector_account);
    assert!(matches!(read(&world.nonce), Ok(State::Initialized(_))));
    // A vector account is the program's, but not a nonce account.
    assert_eq!(
        read(&vector(&world.authority.pubkey())),
        Err(Error::UnexpectedDataSize)
    );
    assert_eq!(read(&world.receiver), Err(Error::InvalidAccountOwner));
    // Created and assigned, but `InitializeNonce` never ran.
    let created = Account::new(1, NonceAccount::LEN, &PROGRAM_ID);
    assert_eq!(
        state_from_account(&created, vector_account),
        Ok(State::Uninitialized)
    );
    assert_eq!(
        data_from_account(&created, vector_account),
        Err(Error::InvalidStateForOperation)
    );
}

/// `create_nonce_account` takes the System program's arguments.
#[test]
fn create_nonce_account_makes_a_nonce_account() {
    let world = World::new();
    let payer = Address::new_unique();
    let nonce = Address::new_unique();
    let instructions = create_nonce_account(&payer, &nonce, &world.authority.pubkey(), 1_500_000);
    let mut accounts = world.accounts.clone();
    accounts.push((payer, Account::new(1_000_000_000, 0, &Address::default())));
    accounts.push((nonce, Account::default()));
    let result = process_transaction(
        &later(),
        &instructions.iter().collect::<Vec<_>>(),
        &accounts,
        &[],
    );
    assert_eq!(result.program_result, TransactionProgramResult::Success);
    let account = |address: &Address| {
        &result
            .resulting_accounts
            .iter()
            .find(|(key, _)| key == address)
            .unwrap()
            .1
    };
    let data =
        data_from_account(account(&nonce), account(&vector(&world.authority.pubkey()))).unwrap();
    assert!(data.is_authority(&world.authority.pubkey()));
    assert_eq!(account(&nonce).data[64..], 1u64.to_le_bytes());
}

/// `close_nonce_account` is `withdraw_nonce_account` for all the lamports:
/// signed in a `NoncedMessage`, it returns the rent.
#[test]
fn close_nonce_account_returns_the_rent() {
    let world = World::new();
    let pubkey = world.authority.pubkey();
    let close = close_nonce_account(&world.nonce, &pubkey, &world.receiver);
    let message = NoncedMessage::new_with_nonce(vec![close], None, &world.nonce, &pubkey);
    let transaction = world.signed(&message, world.data(&world.accounts).blockhash());
    let (result, after) = world.submit(&transaction, &world.accounts);
    assert_eq!(result, TransactionProgramResult::Success);
    let account = |address: &Address| &after.iter().find(|(key, _)| key == address).unwrap().1;
    assert_eq!(account(&world.nonce).lamports, 0);
    assert_eq!(account(&world.receiver).lamports, 1_000_000 + 1_500_000);
}

/// A signer other than the nonce authority, such as a new account, signs
/// when the transaction is submitted, as the fee payer does.
#[test]
fn other_signers_sign_with_the_fee_payer() {
    let world = World::new();
    let pubkey = world.authority.pubkey();
    let nonce = world.data(&world.accounts).blockhash();
    let (fee_payer, new_account) = (Keypair::new(), Keypair::new());
    let create = create_account(&pubkey, &new_account.pubkey(), 1_000_000, 0, &PROGRAM_ID);
    let message = NoncedMessage::new_with_nonce(
        vec![create],
        Some(&fee_payer.pubkey()),
        &world.nonce,
        &pubkey,
    );

    let mut transaction = NoncedTransaction::new_unsigned(message);
    // The nonce authority signs alone, and only signers sign.
    assert!(matches!(
        transaction.try_partial_sign(&[&world.authority, &fee_payer], nonce),
        Err(SignerError::Custom(_))
    ));
    assert_eq!(
        transaction.try_partial_sign(&[&Keypair::new()], nonce),
        Err(SignerError::KeypairPubkeyMismatch)
    );
    transaction
        .try_partial_sign(&[&world.authority], nonce)
        .unwrap();
    transaction
        .try_partial_sign(&[&fee_payer, &new_account], Hash::new_from_array([3; 32]))
        .unwrap();
    assert!(transaction.transaction().verify().is_ok());

    let mut accounts = world.accounts.clone();
    accounts.push((new_account.pubkey(), Account::default()));
    let (result, after) = world.submit(transaction.transaction(), &accounts);
    assert_eq!(result, TransactionProgramResult::Success);
    let created = &after
        .iter()
        .find(|(key, _)| *key == new_account.pubkey())
        .unwrap()
        .1;
    assert_eq!((created.lamports, created.owner), (1_000_000, PROGRAM_ID));
}
