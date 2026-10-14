//! Where a `Passthrough` finds its `Advance`, and `SystemPassthrough`.

use ed25519_dalek::SigningKey;
use mollusk_svm::{
    program::keyed_account_for_system_program, result::types::TransactionProgramResult,
};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_system_interface::instruction::transfer;
use vector_core::{
    create_passthrough_instruction, create_system_passthrough_instruction,
    create_withdraw_subinstruction, ed25519_pubkey, find_system_pda, find_vector_pda,
    set_advance_position, sign_advance_instruction_ed25519, ED25519,
};

use crate::common::{build_vector_account, mollusk, process_transaction, NONCE};

struct World {
    key: SigningKey,
    identity: [u8; 32],
    vector: Address,
    system: Address,
    receiver: Address,
    accounts: Vec<(Address, Account)>,
}

impl World {
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[3; 32]);
        let identity = ed25519_pubkey(&key);
        let (vector, _) = find_vector_pda(&ED25519, &identity);
        let (system, _) = find_system_pda(&vector);
        let receiver = Address::new_unique();
        let rent = mollusk()
            .sysvars
            .rent
            .minimum_balance(ED25519.account_len());
        let (system_program, system_program_account) = keyed_account_for_system_program();
        let accounts = vec![
            (
                vector,
                build_vector_account(NONCE, &ED25519, &identity, rent + 5_000_000, &identity),
            ),
            (system, Account::new(7_000_000, 0, &system_program)),
            (receiver, Account::new(1_000_000, 0, &system_program)),
            (system_program, system_program_account),
        ];
        Self {
            key,
            identity,
            vector,
            system,
            receiver,
            accounts,
        }
    }

    /// Sign `transaction` with the `Advance` inserted at `advance_index`, and
    /// run it.
    fn run(
        &self,
        mut transaction: Vec<Instruction>,
        advance_index: usize,
    ) -> (TransactionProgramResult, Vec<(Address, Account)>) {
        let (pre, post) = transaction.split_at(advance_index);
        let advance = sign_advance_instruction_ed25519(&self.key, &NONCE, pre, post, None);
        transaction.insert(advance_index, advance);
        let result = process_transaction(
            &mollusk(),
            &transaction.iter().collect::<Vec<_>>(),
            &self.accounts,
            &[],
        );
        if result.program_result == TransactionProgramResult::Success {
            println!(
                "ed25519 advance + passthrough at {advance_index}: {} CUs",
                result.compute_units_consumed
            );
        }
        (result.program_result, result.resulting_accounts)
    }

    fn lamports(accounts: &[(Address, Account)], address: &Address) -> u64 {
        accounts
            .iter()
            .find(|(key, _)| key == address)
            .unwrap()
            .1
            .lamports
    }
}

#[test]
fn system_passthrough_signs_as_the_system_pda() {
    let world = World::new();
    let pay = transfer(&world.system, &world.receiver, 4_000_000);
    let system_passthrough =
        create_system_passthrough_instruction(&ED25519, &world.identity, &[pay]);
    let (result, accounts) = world.run(vec![system_passthrough], 0);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(World::lamports(&accounts, &world.system), 3_000_000);
    assert_eq!(World::lamports(&accounts, &world.receiver), 5_000_000);

    // The account itself cannot pay through the System program: the
    // program owns it.
    let mut as_vector = transfer(&world.vector, &world.receiver, 4_000_000);
    as_vector.accounts[0].is_signer = false;
    let passthrough = create_passthrough_instruction(&ED25519, &world.identity, &[as_vector]);
    let (result, _) = world.run(vec![passthrough], 0);
    assert!(matches!(result, TransactionProgramResult::Failure(1, _)));

    // Another system account is not the account's system PDA.
    let other = Address::new_unique();
    let mut wrong = create_system_passthrough_instruction(
        &ED25519,
        &world.identity,
        &[transfer(&other, &world.receiver, 1)],
    );
    wrong.accounts[2].pubkey = other;
    // Only the program could make it a signer.
    for meta in &mut wrong.accounts {
        meta.is_signer = false;
    }
    let mut world = world;
    world
        .accounts
        .push((other, Account::new(1_000_000, 0, &Address::default())));
    let (result, accounts) = world.run(vec![wrong], 0);
    assert_eq!(
        result,
        TransactionProgramResult::Failure(1, ProgramError::InvalidSeeds)
    );
    assert_eq!(World::lamports(&accounts, &other), 1_000_000);
}

#[test]
fn passthrough_finds_its_advance_by_index() {
    let world = World::new();
    let withdraw = |lamports| {
        create_passthrough_instruction(
            &ED25519,
            &world.identity,
            &[create_withdraw_subinstruction(
                &ED25519,
                &world.identity,
                &world.receiver,
                lamports,
            )],
        )
    };
    // Something before the `Advance`: the passthrough says where it is.
    let before = transfer(&world.receiver, &world.receiver, 0);
    let mut moved = withdraw(1_000_000);
    set_advance_position(&mut moved, 1, 0);
    let (result, accounts) = world.run(vec![before.clone(), moved], 1);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(World::lamports(&accounts, &world.receiver), 2_000_000);

    // Pointing anywhere else finds no `Advance` listing the account: not
    // the default position, not the account's own index, not the sysvar,
    // not itself, not past itself.
    for (advance_index, account_index) in [(0, 0), (1, 1), (2, 0), (3, 0)] {
        let mut wrong = withdraw(1_000_000);
        set_advance_position(&mut wrong, advance_index, account_index);
        let (result, accounts) = world.run(vec![before.clone(), wrong], 1);
        assert_eq!(
            result,
            TransactionProgramResult::Failure(2, ProgramError::MissingRequiredSignature),
            "{advance_index}, {account_index}"
        );
        assert_eq!(accounts, world.accounts);
    }
}
