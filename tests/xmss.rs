//! Exercise the linked XMSS verifier through Vector's SBF authorization flow.

use mollusk_svm::{program::keyed_account_for_system_program, result::Check};
use solana_account::Account;
use solana_address::Address;
use solana_program_error::ProgramError;
use solana_winternitz::{xmss, Signer};
use vector_core::{
    advance_vector_digest, create_advance_instruction, create_initialize_xmss,
    create_passthrough_instruction, create_rotate_subinstruction, create_withdraw_subinstruction,
    find_vector_pda, xmss_identity, XMSS,
};

use crate::common::{build_vector_account, expected_advanced_data, mollusk, NONCE};

#[test]
fn initialize_checks_key_length_and_pda() {
    let mollusk = mollusk(&XMSS);
    let public_key = core::array::from_fn(|i| i as u8);
    let identity = xmss_identity(&public_key);
    let (system, system_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();
    let (vector, bump) = find_vector_pda(&XMSS, &identity);
    // Shared with sdk/ts/test/xmss.test.ts.
    assert_eq!(
        vector.to_string(),
        "FVsCnwNqcdFb2EU6B6rK3UsJEQEDZPTgZoqvT1LrJYZ5"
    );
    assert_eq!(bump, 255);
    let receiver = Address::new_from_array([9; 32]);
    let withdraw = create_withdraw_subinstruction(&XMSS, &identity, &receiver, 1234);
    let rotate = create_rotate_subinstruction(&XMSS, &identity, &[7; 41]);
    let passthrough = create_passthrough_instruction(&XMSS, &identity, &[rotate, withdraw]);
    assert_eq!(
        advance_vector_digest(&XMSS, &NONCE, &identity, &[], &[passthrough]),
        [
            43, 149, 73, 28, 183, 157, 6, 233, 213, 240, 56, 226, 183, 85, 55, 93, 101, 130, 199,
            88, 57, 188, 61, 104, 26, 251, 177, 206, 209, 175, 32, 218
        ],
    );
    let accounts = [
        (payer, Account::new(1_000_000_000, 0, &system)),
        (vector, Account::default()),
        (system, system_account),
    ];
    let initialize = create_initialize_xmss(&payer, &public_key);
    let result = mollusk.process_and_validate_instruction(
        &initialize,
        &accounts,
        &[
            Check::success(),
            Check::account(&vector)
                .owner(&XMSS.program_id)
                .space(XMSS.account_len())
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
    assert_eq!(stored[32], bump);
    assert_eq!(&stored[33..65], &identity);
    assert_eq!(&stored[65..], &public_key);

    for length in [40, 42] {
        let mut malformed = initialize.clone();
        malformed.data.resize(1 + length, 0);
        mollusk.process_and_validate_instruction(
            &malformed,
            &accounts,
            &[
                Check::err(ProgramError::InvalidInstructionData),
                Check::account(&vector).space(0).build(),
            ],
        );
    }
    let mut wrong_pda = initialize;
    let other = Address::new_unique();
    wrong_pda.accounts[1].pubkey = other;
    let mut wrong_accounts = accounts;
    wrong_accounts[1].0 = other;
    mollusk.process_and_validate_instruction(
        &wrong_pda,
        &wrong_accounts,
        &[Check::err(ProgramError::InvalidAccountData)],
    );
}

#[test]
fn advance_rejects_replay_wrong_key_and_malformed_signatures() {
    let directory = tempfile::tempdir().unwrap();
    let mut signer =
        Signer::<xmss::SecretKey>::create(directory.path().join("signer.key")).unwrap();
    let public_key = signer.public_key().0;
    let identity = xmss_identity(&public_key);
    let stored = [identity.as_slice(), public_key.as_slice()].concat();
    let mollusk = mollusk(&XMSS);
    let (vector, bump) = find_vector_pda(&XMSS, &identity);
    let account = build_vector_account(
        NONCE,
        &XMSS,
        bump,
        mollusk.sysvars.rent.minimum_balance(XMSS.account_len()),
        &stored,
    );
    let digest = advance_vector_digest(&XMSS, &NONCE, &identity, &[], &[]);
    let signature = signer.sign(&digest).unwrap();
    let advance = create_advance_instruction(&XMSS, &identity, &signature.0);
    let expected = expected_advanced_data(digest, &XMSS, bump, &stored);
    let result = mollusk.process_and_validate_instruction_chain(
        &[(
            &advance,
            &[
                Check::success(),
                Check::account(&vector).data(&expected).build(),
            ],
        )],
        &[(vector, account.clone())],
    );
    println!("xmss advance: {} CUs", result.compute_units_consumed);

    // A new nonce invalidates the old authorization without consuming a
    // second leaf. Reusing the signature bytes is not signing twice.
    let mut advanced = account.clone();
    advanced.data = expected.clone();
    mollusk.process_and_validate_instruction_chain(
        &[(
            &advance,
            &[
                Check::err(ProgramError::MissingRequiredSignature),
                Check::account(&vector).data(&expected).build(),
            ],
        )],
        &[(vector, advanced)],
    );

    for offset in [0, 33, account.data.len() - 1] {
        let mut changed = account.clone();
        changed.data[offset] ^= 1;
        mollusk.process_and_validate_instruction_chain(
            &[(
                &advance,
                &[
                    Check::err(ProgramError::MissingRequiredSignature),
                    Check::account(&vector).data(&changed.data).build(),
                ],
            )],
            &[(vector, changed.clone())],
        );
    }

    let mut tampered = signature.0;
    tampered[xmss::SIGNATURE_LENGTH - 1] ^= 1;
    let mut out_of_range = signature.0;
    out_of_range[..4].copy_from_slice(&xmss::LEAVES.to_be_bytes());
    for (bytes, error) in [
        (tampered.as_slice(), ProgramError::MissingRequiredSignature),
        (
            out_of_range.as_slice(),
            ProgramError::MissingRequiredSignature,
        ),
        (
            &signature.0[..xmss::SIGNATURE_LENGTH - 1],
            ProgramError::InvalidInstructionData,
        ),
    ] {
        let invalid = create_advance_instruction(&XMSS, &identity, bytes);
        mollusk.process_and_validate_instruction_chain(
            &[(
                &invalid,
                &[
                    Check::err(error),
                    Check::account(&vector).data(&account.data).build(),
                ],
            )],
            &[(vector, account.clone())],
        );
    }
}

#[test]
fn advance_binds_and_authorizes_withdrawal() {
    let directory = tempfile::tempdir().unwrap();
    let mut signer =
        Signer::<xmss::SecretKey>::create(directory.path().join("signer.key")).unwrap();
    let public_key = signer.public_key().0;
    let identity = xmss_identity(&public_key);
    let stored = [identity.as_slice(), public_key.as_slice()].concat();
    // Abandoned authorizations spend leaves even when no transaction lands.
    signer.sign(&[0; 32]).unwrap();

    let mollusk = mollusk(&XMSS);
    let (vector, bump) = find_vector_pda(&XMSS, &identity);
    let rent = mollusk.sysvars.rent.minimum_balance(XMSS.account_len());
    let account = build_vector_account(NONCE, &XMSS, bump, rent + 5_000_000, &stored);
    let receiver = Address::new_unique();
    let accounts = [
        (vector, account.clone()),
        (receiver, Account::new(1_000_000, 0, &Address::default())),
    ];
    let withdraw = create_withdraw_subinstruction(&XMSS, &identity, &receiver, 3_000_000);
    let passthrough = create_passthrough_instruction(&XMSS, &identity, &[withdraw]);
    let digest = advance_vector_digest(
        &XMSS,
        &NONCE,
        &identity,
        &[],
        std::slice::from_ref(&passthrough),
    );
    let signature = signer.sign(&digest).unwrap();
    assert_eq!(signature.leaf(), 1);
    let advance = create_advance_instruction(&XMSS, &identity, &signature.0);

    // The signature must bind the downstream action, not just the nonce.
    let changed_withdraw = create_withdraw_subinstruction(&XMSS, &identity, &receiver, 4_000_000);
    let changed = create_passthrough_instruction(&XMSS, &identity, &[changed_withdraw]);
    mollusk.process_and_validate_instruction_chain(
        &[
            (
                &advance,
                &[
                    Check::err(ProgramError::MissingRequiredSignature),
                    Check::account(&vector).data(&account.data).build(),
                ],
            ),
            (&changed, &[]),
        ],
        &accounts,
    );

    let expected = expected_advanced_data(digest, &XMSS, bump, &stored);
    mollusk.process_and_validate_instruction_chain(
        &[
            (
                &advance,
                &[
                    Check::success(),
                    Check::account(&vector).data(&expected).build(),
                ],
            ),
            (
                &passthrough,
                &[
                    Check::success(),
                    Check::account(&vector).lamports(rent + 2_000_000).build(),
                    Check::account(&receiver).lamports(4_000_000).build(),
                ],
            ),
        ],
        &accounts,
    );
}
