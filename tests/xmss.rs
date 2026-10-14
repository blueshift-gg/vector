//! Exercise the linked XMSS verifier through Vector's SBF authorization flow.

use mollusk_svm::{program::keyed_account_for_system_program, result::Check};
use solana_account::Account;
use solana_address::Address;
use solana_program_error::ProgramError;
use solana_winternitz::xmss;
use vector_core::{
    advance_vector_digest, create_advance_instruction, create_initialize_xmss,
    create_rotating_passthrough_instruction, create_withdraw_subinstruction, find_vector_pda,
    PROGRAM_ID, XMSS,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, process_transaction, xmss_stored, NONCE,
};

#[test]
fn initialize_checks_key_length_and_pda() {
    let mollusk = mollusk();
    let public_key = core::array::from_fn(|i| i as u8);
    let identity = public_key;
    let (system, system_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();
    let (vector, bump) = find_vector_pda(&XMSS, &identity);
    // Shared with sdk/ts/test/xmss.test.ts.
    assert_eq!(
        vector.to_string(),
        "4kd7ArVtukusWaCpQgEZsqabWcnQbB4KjjwYnHVExk7c"
    );
    assert_eq!(bump, 255);
    let receiver = Address::new_from_array([9; 32]);
    let withdraw = create_withdraw_subinstruction(&XMSS, &identity, &receiver, 1234);
    let passthrough =
        create_rotating_passthrough_instruction(&XMSS, &identity, Some(&[7; 41]), &[withdraw]);
    assert_eq!(
        advance_vector_digest(&XMSS, &NONCE, &identity, &[], &[passthrough], None),
        [
            119, 36, 30, 204, 237, 43, 13, 129, 134, 249, 41, 77, 119, 115, 69, 212, 1, 150, 172,
            4, 213, 66, 154, 116, 192, 139, 199, 238, 5, 254, 86, 156
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
                .owner(&PROGRAM_ID)
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
    assert_eq!(&stored[32..64], &vector_core::vector_seed(&identity));
    let (_, system_bump) = vector_core::find_system_pda(&vector);
    assert_eq!(stored[64..68], [XMSS.id, bump, system_bump, 0]);
    assert_eq!(&stored[68..], &xmss_stored(&public_key, 0));

    // A key of another length has another address, and the scheme refuses it.
    for length in [40, 42] {
        let key = vec![0; length];
        let (address, _) = Address::find_program_address(
            &[b"vector", &[XMSS.id], &vector_core::vector_seed(&key)],
            &PROGRAM_ID,
        );
        let mut malformed = initialize.clone();
        malformed.accounts[1].pubkey = address;
        malformed.data.splice(2.., key);
        let mut accounts = accounts.to_vec();
        accounts[1].0 = address;
        mollusk.process_and_validate_instruction(
            &malformed,
            &accounts,
            &[
                Check::err(ProgramError::InvalidInstructionData),
                Check::account(&address).space(0).build(),
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
    let mut signer = xmss::SigningKey::create(directory.path().join("signer.key")).unwrap();
    let public_key = signer.verifying_key().to_bytes();
    let identity = public_key;
    let stored = xmss_stored(&public_key, 0);
    let mollusk = mollusk();
    let (vector, _) = find_vector_pda(&XMSS, &identity);
    let account = build_vector_account(
        NONCE,
        &XMSS,
        &identity,
        mollusk.sysvars.rent.minimum_balance(XMSS.account_len()),
        &stored,
    );
    let digest = advance_vector_digest(&XMSS, &NONCE, &identity, &[], &[], None);
    let signature = signer.sign(&digest).unwrap();
    let advance = create_advance_instruction(&XMSS, &identity, signature.as_bytes());
    // Leaf 0 signed, so leaf 1 is the lowest that may sign next.
    let expected = expected_advanced_data(digest, &XMSS, &identity, &xmss_stored(&public_key, 1));
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

    for offset in [0, 68, account.data.len() - 1] {
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

    let mut tampered = signature.to_bytes();
    tampered[xmss::SIGNATURE_LEN - 1] ^= 1;
    let mut out_of_range = signature.to_bytes();
    out_of_range[..4].copy_from_slice(&xmss::LEAVES.to_be_bytes());
    for (bytes, error) in [
        (tampered.as_slice(), ProgramError::MissingRequiredSignature),
        (
            out_of_range.as_slice(),
            ProgramError::MissingRequiredSignature,
        ),
        (
            &signature.as_bytes()[..xmss::SIGNATURE_LEN - 1],
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
    let mut signer = xmss::SigningKey::create(directory.path().join("signer.key")).unwrap();
    let public_key = signer.verifying_key().to_bytes();
    let identity = public_key;
    let stored = xmss_stored(&public_key, 0);
    // Abandoned authorizations spend leaves even when no transaction lands.
    signer.sign(&[0; 32]).unwrap();

    let mollusk = mollusk();
    let (vector, _) = find_vector_pda(&XMSS, &identity);
    let rent = mollusk.sysvars.rent.minimum_balance(XMSS.account_len());
    let account = build_vector_account(NONCE, &XMSS, &identity, rent + 5_000_000, &stored);
    let receiver = Address::new_unique();
    let accounts = [
        (vector, account.clone()),
        (receiver, Account::new(1_000_000, 0, &Address::default())),
    ];
    let withdraw = create_withdraw_subinstruction(&XMSS, &identity, &receiver, 3_000_000);
    let passthrough = create_rotating_passthrough_instruction(&XMSS, &identity, None, &[withdraw]);
    let digest = advance_vector_digest(
        &XMSS,
        &NONCE,
        &identity,
        &[],
        std::slice::from_ref(&passthrough),
        None,
    );
    let signature = signer.sign(&digest).unwrap();
    assert_eq!(signature.leaf(), 1);
    let advance = create_advance_instruction(&XMSS, &identity, signature.as_bytes());

    // The signature must bind the downstream action, not just the nonce.
    let changed_withdraw = create_withdraw_subinstruction(&XMSS, &identity, &receiver, 4_000_000);
    let changed =
        create_rotating_passthrough_instruction(&XMSS, &identity, None, &[changed_withdraw]);
    process_transaction(
        &mollusk,
        &[&advance, &changed],
        &accounts,
        &[
            Check::err(ProgramError::MissingRequiredSignature),
            Check::account(&vector).data(&account.data).build(),
        ],
    );

    // Leaf 0 was abandoned and leaf 1 signed: a signer may skip leaves.
    let expected = expected_advanced_data(digest, &XMSS, &identity, &xmss_stored(&public_key, 2));
    process_transaction(
        &mollusk,
        &[&advance, &passthrough],
        &accounts,
        &[
            Check::success(),
            Check::account(&vector).data(&expected).build(),
            Check::account(&vector).lamports(rent + 2_000_000).build(),
            Check::account(&receiver).lamports(4_000_000).build(),
        ],
    );
}
