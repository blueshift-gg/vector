//! One program serves every scheme, so an account registered under one must
//! never reach another's verifier. Winternitz and XMSS are the sharpest
//! case: their accounts have the same length and layout.

use mollusk_svm::{program::keyed_account_for_system_program, result::ProgramResult};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use vector_core::{
    create_advance_instruction, create_expand_mldsa44, create_initialize_instruction,
    create_passthrough_instruction, find_vector_pda, Scheme, MLDSA44, PROGRAM_ID, WINTERNITZ, XMSS,
};

use crate::common::{build_vector_account, mollusk, NONCE};

const IDENTITY: [u8; 32] = [7; 32];

/// A Winternitz account at its own PDA, holding `IDENTITY` and a 41-byte key.
fn winternitz_account() -> (Address, Account) {
    let (vector, bump) = find_vector_pda(&WINTERNITZ, &IDENTITY);
    let stored = [IDENTITY.as_slice(), &[9; 41]].concat();
    (
        vector,
        build_vector_account(NONCE, &WINTERNITZ, bump, 10_000_000, &stored),
    )
}

/// `instruction`, built for the Winternitz account, claiming `scheme`.
fn claiming(mut instruction: Instruction, scheme: &Scheme) -> Instruction {
    instruction.data[1] = scheme.id;
    instruction
}

#[test]
fn the_same_identity_has_a_different_address_under_each_scheme() {
    assert_eq!(WINTERNITZ.identity_len, XMSS.identity_len);
    assert_ne!(
        find_vector_pda(&WINTERNITZ, &IDENTITY).0,
        find_vector_pda(&XMSS, &IDENTITY).0
    );
}

#[test]
fn advance_refuses_an_account_of_another_scheme() {
    let mollusk = mollusk();
    let (vector, account) = winternitz_account();
    assert_eq!(WINTERNITZ.account_len(), XMSS.account_len());
    // The signature never matters: the scheme is checked before it is read.
    let advance = create_advance_instruction(&WINTERNITZ, &IDENTITY, &[0; 1037]);
    let result = mollusk.process_instruction(&claiming(advance, &XMSS), &[(vector, account)]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidAccountData)
    );
}

#[test]
fn passthrough_refuses_an_account_of_another_scheme() {
    let mollusk = mollusk();
    let (vector, account) = winternitz_account();
    let passthrough = create_passthrough_instruction(&WINTERNITZ, &IDENTITY, &[]);
    let result = mollusk.process_instruction(&claiming(passthrough, &XMSS), &[(vector, account)]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidAccountData)
    );
}

#[test]
fn expand_refuses_an_account_of_another_scheme() {
    let mollusk = mollusk();
    let (vector, account) = winternitz_account();
    let mut expand = create_expand_mldsa44(&[0; 1312]);
    expand.accounts[0].pubkey = vector;
    assert_eq!(expand.data[1], MLDSA44.id);
    let result = mollusk.process_instruction(&expand, &[(vector, account)]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidAccountData)
    );
}

#[test]
fn initialize_derives_the_address_from_the_scheme_it_is_given() {
    let mollusk = mollusk();
    let (system_program, system_program_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();
    // The Winternitz address for this key, with an instruction claiming XMSS.
    let initialize = create_initialize_instruction(&payer, &WINTERNITZ, &IDENTITY, &[9; 41]);
    let vector = initialize.accounts[1].pubkey;
    let result = mollusk.process_instruction(
        &claiming(initialize, &XMSS),
        &[
            (payer, Account::new(1_000_000_000, 0, &system_program)),
            (vector, Account::default()),
            (system_program, system_program_account),
        ],
    );
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidAccountData)
    );
}

#[test]
fn an_unknown_scheme_or_a_missing_scheme_byte_is_refused() {
    let mollusk = mollusk();
    let (vector, account) = winternitz_account();
    let advance = create_advance_instruction(&WINTERNITZ, &IDENTITY, &[0; 849]);
    for data in [vec![1], vec![1, 7], vec![1, 255], vec![]] {
        let instruction = Instruction {
            program_id: PROGRAM_ID,
            accounts: advance.accounts.clone(),
            data,
        };
        let result = mollusk.process_instruction(&instruction, &[(vector, account.clone())]);
        assert_eq!(
            result.program_result,
            ProgramResult::Failure(ProgramError::InvalidInstructionData)
        );
    }
}
