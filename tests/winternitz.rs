//! One-time authorization through Vector's existing handlers.

use mollusk_svm::{program::keyed_account_for_system_program, result::Check};
use solana_account::Account;
use solana_address::Address;
use solana_program_error::ProgramError;
use solana_winternitz::winternitz;
use vector_core::{
    advance_vector_digest, create_advance_instruction, create_close_subinstruction,
    create_initialize_winternitz, create_rotating_passthrough_instruction, find_vector_pda,
    winternitz_identity, PROGRAM_ID, WINTERNITZ,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, process_transaction, NONCE,
};

#[test]
fn initialize_and_client_encoding() {
    let mollusk = mollusk();
    let public_key = core::array::from_fn(|i| i as u8);
    let identity = winternitz_identity(&public_key);
    let (vector, bump) = find_vector_pda(&WINTERNITZ, &identity);
    // Shared with sdk/ts/test/winternitz.test.ts.
    assert_eq!(
        vector.to_string(),
        "Er2fQZXAf3ZoVHiDQAgJGReN5qUz2oh6t8qfU3GGSb9Y"
    );
    assert_eq!(bump, 255);
    let receiver = Address::new_from_array([9; 32]);
    let close = create_close_subinstruction(&WINTERNITZ, &identity, &receiver);
    let passthrough =
        create_rotating_passthrough_instruction(&WINTERNITZ, &identity, &[7; 41], &[close]);
    assert_eq!(
        advance_vector_digest(&WINTERNITZ, &NONCE, &identity, &[], &[passthrough]),
        [
            210, 109, 131, 65, 120, 211, 163, 87, 63, 206, 151, 127, 180, 186, 236, 239, 209, 135,
            2, 181, 150, 1, 124, 79, 135, 90, 130, 26, 239, 219, 152, 223
        ],
    );

    let (system, system_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();
    let accounts = [
        (payer, Account::new(1_000_000_000, 0, &system)),
        (vector, Account::default()),
        (system, system_account),
    ];
    let initialize = create_initialize_winternitz(&payer, &public_key);
    let result = mollusk.process_and_validate_instruction(
        &initialize,
        &accounts,
        &[
            Check::success(),
            Check::account(&vector)
                .owner(&PROGRAM_ID)
                .space(WINTERNITZ.account_len())
                .build(),
        ],
    );
    let stored = &result
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == vector)
        .unwrap()
        .1
        .data;
    assert_eq!(stored[32..34], [WINTERNITZ.id, bump]);
    assert_eq!(&stored[34..66], &identity);
    assert_eq!(&stored[66..], &public_key);

    for length in [40, 42] {
        let mut malformed = initialize.clone();
        malformed.data.resize(2 + length, 0);
        mollusk.process_and_validate_instruction(
            &malformed,
            &accounts,
            &[
                Check::err(ProgramError::InvalidInstructionData),
                Check::account(&vector).space(0).build(),
            ],
        );
    }
}

#[test]
fn signature_binds_close_and_rejects_replay() {
    let directory = tempfile::tempdir().unwrap();
    let mut signer = winternitz::SigningKey::create(directory.path().join("signer.key")).unwrap();
    let public_key = signer.verifying_key().to_bytes();
    let identity = winternitz_identity(&public_key);
    let stored = [identity.as_slice(), public_key.as_slice()].concat();
    let mollusk = mollusk();
    let (vector, bump) = find_vector_pda(&WINTERNITZ, &identity);
    let lamports = mollusk
        .sysvars
        .rent
        .minimum_balance(WINTERNITZ.account_len())
        + 5_000_000;
    let account = build_vector_account(NONCE, &WINTERNITZ, bump, lamports, &stored);
    let receiver = Address::new_unique();
    let other = Address::new_unique();
    let close = create_close_subinstruction(&WINTERNITZ, &identity, &receiver);
    // Keeps the current key: the test is about the signature, not rotation.
    let passthrough =
        create_rotating_passthrough_instruction(&WINTERNITZ, &identity, &public_key, &[close]);
    let digest = advance_vector_digest(
        &WINTERNITZ,
        &NONCE,
        &identity,
        &[],
        std::slice::from_ref(&passthrough),
    );
    let signature = signer.sign(&digest).unwrap().to_bytes();
    let advance = create_advance_instruction(&WINTERNITZ, &identity, &signature);
    let expected = expected_advanced_data(digest, &WINTERNITZ, bump, &stored);

    let other_close = create_close_subinstruction(&WINTERNITZ, &identity, &other);
    let changed_action = create_rotating_passthrough_instruction(
        &WINTERNITZ,
        &identity,
        &public_key,
        &[other_close],
    );
    let mut tampered = signature;
    tampered[winternitz::SIGNATURE_LEN - 1] ^= 1;
    let mut wrong_key = account.clone();
    wrong_key.data[66] ^= 1;
    let mut advanced = account.clone();
    advanced.data = expected.clone();

    // Reuse the one signature across adversarial inputs, never sign twice.
    for (bytes, state, action, error) in [
        (
            signature.as_slice(),
            account.clone(),
            changed_action,
            ProgramError::MissingRequiredSignature,
        ),
        (
            tampered.as_slice(),
            account.clone(),
            passthrough.clone(),
            ProgramError::MissingRequiredSignature,
        ),
        (
            &signature[..winternitz::SIGNATURE_LEN - 1],
            account.clone(),
            passthrough.clone(),
            ProgramError::InvalidInstructionData,
        ),
        (
            signature.as_slice(),
            wrong_key,
            passthrough.clone(),
            ProgramError::MissingRequiredSignature,
        ),
        (
            signature.as_slice(),
            advanced,
            passthrough.clone(),
            ProgramError::MissingRequiredSignature,
        ),
    ] {
        let invalid = create_advance_instruction(&WINTERNITZ, &identity, bytes);
        process_transaction(
            &mollusk,
            &[&invalid, &action],
            &[
                (vector, state.clone()),
                (receiver, Account::new(1_000_000, 0, &Address::default())),
                (other, Account::new(1_000_000, 0, &Address::default())),
            ],
            &[
                Check::err(error),
                Check::account(&vector).data(&state.data).build(),
            ],
        );
    }

    let result = process_transaction(
        &mollusk,
        &[&advance, &passthrough],
        &[
            (vector, account),
            (receiver, Account::new(1_000_000, 0, &Address::default())),
        ],
        &[
            Check::success(),
            Check::account(&vector).data(&expected).build(),
            Check::account(&vector).lamports(0).build(),
            Check::account(&receiver)
                .lamports(1_000_000 + lamports)
                .build(),
        ],
    );
    println!(
        "winternitz advance + close: {} CUs",
        result.compute_units_consumed
    );
}
