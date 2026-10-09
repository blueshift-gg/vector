//! One program serves every scheme. An account's header says which scheme
//! it belongs to, and the program routes on that. Winternitz and XMSS are
//! the sharpest case: their accounts have the same length and layout.

use mollusk_svm::{program::keyed_account_for_system_program, result::ProgramResult};
use solana_account::Account;
use solana_address::Address;
use solana_program_error::ProgramError;
use vector_core::{
    create_expand_mldsa44, create_initialize_instruction, create_passthrough_instruction,
    find_vector_pda, WINTERNITZ, XMSS,
};

use crate::common::{build_vector_account, mollusk, NONCE};

const IDENTITY: [u8; 32] = [7; 32];

#[test]
fn the_same_identity_has_a_different_address_under_each_scheme() {
    assert_eq!(WINTERNITZ.identity_len, XMSS.identity_len);
    assert_ne!(
        find_vector_pda(&WINTERNITZ, &IDENTITY).0,
        find_vector_pda(&XMSS, &IDENTITY).0
    );
}

#[test]
fn initialize_derives_the_address_from_the_scheme_it_is_given() {
    let mollusk = mollusk();
    let (system_program, system_program_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();
    // The Winternitz address for this key, with an instruction saying XMSS.
    let mut initialize = create_initialize_instruction(&payer, &WINTERNITZ, &IDENTITY, &[9; 41]);
    let vector = initialize.accounts[1].pubkey;
    let accounts = [
        (payer, Account::new(1_000_000_000, 0, &system_program)),
        (vector, Account::default()),
        (system_program, system_program_account),
    ];
    for (scheme, error) in [
        (XMSS.id, ProgramError::InvalidAccountData),
        (7, ProgramError::InvalidInstructionData),
    ] {
        initialize.data[1] = scheme;
        let result = mollusk.process_instruction(&initialize, &accounts);
        assert_eq!(result.program_result, ProgramResult::Failure(error));
    }
}

/// `Expand` exists for ML-DSA-44 only, and the account's header decides.
#[test]
fn an_instruction_runs_as_the_scheme_in_the_account_header() {
    let mollusk = mollusk();
    let (vector, bump) = find_vector_pda(&WINTERNITZ, &IDENTITY);
    let stored = [IDENTITY.as_slice(), &[9; 41]].concat();
    let account = build_vector_account(NONCE, &WINTERNITZ, bump, 10_000_000, &stored);
    let mut expand = create_expand_mldsa44(&[0; 1312]);
    expand.accounts[0].pubkey = vector;
    let result = mollusk.process_instruction(&expand, &[(vector, account.clone())]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidInstructionData)
    );

    // An account the program does not own has no scheme to read.
    let mut foreign = account;
    foreign.owner = Address::new_unique();
    let passthrough = create_passthrough_instruction(&WINTERNITZ, &IDENTITY, &[]);
    let result = mollusk.process_instruction(&passthrough, &[(vector, foreign)]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidAccountOwner)
    );
}
