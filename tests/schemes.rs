//! One program serves every scheme. An account's header says which scheme
//! it belongs to, and the program routes on that. Winternitz and XMSS are
//! the sharpest case: their accounts have the same length and layout.

use mollusk_svm::{program::keyed_account_for_system_program, result::ProgramResult};
use solana_account::Account;
use solana_address::Address;
use solana_program_error::ProgramError;
use vector_core::{
    create_initialize_instruction, create_initialize_mldsa44, create_passthrough_instruction,
    create_rotating_advance_instruction, find_vector_pda, VectorAccount, ED25519, EIP191,
    FALCON512, MLDSA44, SECP256K1, WINTERNITZ, XMSS,
};

use crate::common::{build_vector_account, mollusk, NONCE};

/// A Winternitz or XMSS key: both are 41 bytes.
const KEY: [u8; 41] = [7; 41];

#[test]
fn the_same_identity_has_a_different_address_under_each_scheme() {
    assert_eq!(WINTERNITZ.identity_len, XMSS.identity_len);
    assert_ne!(
        find_vector_pda(&WINTERNITZ, &KEY).0,
        find_vector_pda(&XMSS, &KEY).0
    );
}

#[test]
fn initialize_derives_the_address_from_the_scheme_it_is_given() {
    let mollusk = mollusk();
    let (system_program, system_program_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();
    // The Winternitz address for this key, with an instruction saying XMSS.
    let mut initialize = create_initialize_instruction(&payer, &WINTERNITZ, &KEY);
    let vector = initialize.accounts[1].pubkey;
    let accounts = [
        (payer, Account::new(1_000_000_000, 0, &system_program)),
        (vector, Account::default()),
        (system_program, system_program_account),
    ];
    initialize.data[1] = XMSS.id;
    let result = mollusk.process_instruction(&initialize, &accounts);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidAccountData)
    );

    // A scheme that does not exist has an address too, and nothing behind it.
    for scheme in [0, 8] {
        let (address, _) = Address::find_program_address(
            &[b"vector", &[scheme], &vector_core::vector_seed(&KEY)],
            &vector_core::PROGRAM_ID,
        );
        initialize.data[1] = scheme;
        initialize.accounts[1].pubkey = address;
        let mut accounts = accounts.clone();
        accounts[1].0 = address;
        let result = mollusk.process_instruction(&initialize, &accounts);
        assert_eq!(
            result.program_result,
            ProgramResult::Failure(ProgramError::InvalidInstructionData)
        );
    }
}

/// Only ML-DSA-44 grows after its first `Initialize`, and the account's
/// header decides.
#[test]
fn an_instruction_runs_as_the_scheme_in_the_account_header() {
    let mollusk = mollusk();
    let (vector, _) = find_vector_pda(&WINTERNITZ, &KEY);
    let account = build_vector_account(NONCE, &WINTERNITZ, &KEY, 10_000_000, &KEY);
    let payer = Address::new_unique();
    let mut grow = create_initialize_mldsa44(&payer, &[0; 1312])[1].clone();
    grow.accounts[1].pubkey = vector;
    let (system, system_account) = keyed_account_for_system_program();
    let result = mollusk.process_instruction(
        &grow,
        &[
            (payer, Account::new(1_000_000_000, 0, &system)),
            (vector, account.clone()),
            (system, system_account),
        ],
    );
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidAccountData)
    );

    // Anyone can assign a zeroed account to the program. It belongs to no
    // scheme, so no `Advance` lists it and nothing runs on it.
    let zeroed = Account::new(
        10_000_000,
        WINTERNITZ.account_len(),
        &vector_core::PROGRAM_ID,
    );
    let advance = create_rotating_advance_instruction(&WINTERNITZ, &KEY, &[9; 41], &[0; 849]);
    for instruction in [
        &advance,
        &create_passthrough_instruction(&WINTERNITZ, &KEY, &[]),
    ] {
        let result = mollusk.process_instruction(instruction, &[(vector, zeroed.clone())]);
        assert!(matches!(
            result.program_result,
            ProgramResult::Failure(
                ProgramError::InvalidAccountData
                    | ProgramError::InvalidInstructionData
                    | ProgramError::MissingRequiredSignature
            )
        ));
    }

    // An account the program does not own has no scheme to read, and no
    // `Advance` can list it.
    let mut foreign = account;
    foreign.owner = Address::new_unique();
    let result = mollusk.process_instruction(&advance, &[(vector, foreign)]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidAccountOwner)
    );
}

/// The TypeScript SDK types every scheme's numbers by hand. The fixture is
/// what the program says they are, and the TypeScript tests check the SDK
/// against it.
#[test]
fn the_schemes_fixture_is_the_programs() {
    let schemes = [ED25519, EIP191, SECP256K1, FALCON512, MLDSA44, WINTERNITZ, XMSS]
        .map(|scheme| {
            format!(
                r#"    {{ "id": {}, "signatureLen": {}, "identityLen": {}, "storedIdentityLen": {}, "nextKeyLen": {} }}"#,
                scheme.id,
                scheme.signature_len,
                scheme.identity_len,
                scheme.stored_identity_len,
                scheme.next_key_len,
            )
        })
        .join(",\n");
    let expected = format!(
        "{{\n  \"headerLen\": {},\n  \"schemes\": [\n{schemes}\n  ]\n}}\n",
        VectorAccount::HEADER_LEN,
    );
    let fixture = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/schemes.json"
    ))
    .unwrap();
    assert_eq!(fixture, expected);
}
