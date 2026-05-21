//! Plain secp256k1 ECDSA program tests.

use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use mollusk_svm::{program::keyed_account_for_system_program, result::Check};
use solana_account::Account;
use solana_address::Address;
use vector_core::{
    advance_vector_digest, create_close_subinstruction, create_initialize_secp256k1_ecdsa,
    create_passthrough_instruction, create_withdraw_subinstruction, find_vector_pda,
    secp256k1_compressed_pubkey, sign_advance_instruction_secp256k1_ecdsa, SECP256K1,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, run_round_trip_spl, NONCE,
    SECP256K1_PRIVKEY,
};

fn signing_key() -> Secp256k1SigningKey {
    Secp256k1SigningKey::from_bytes(&SECP256K1_PRIVKEY.into()).unwrap()
}

#[test]
fn initialize() {
    let mollusk = mollusk(&SECP256K1);
    let key = signing_key();
    let identity = secp256k1_compressed_pubkey(&key);

    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, _bump) = find_vector_pda(&SECP256K1, &identity);
    let vector_account = Account::default();

    let init_ix = create_initialize_secp256k1_ecdsa(&payer, &identity);

    let accounts = vec![
        (payer, payer_account),
        (vector, vector_account),
        (system_program, system_program_account),
    ];

    mollusk.process_and_validate_instruction(
        &init_ix,
        &accounts,
        &[
            Check::success(),
            Check::account(&vector)
                .owner(&SECP256K1.program_id)
                .space(SECP256K1.account_len())
                .build(),
        ],
    );
}

#[test]
fn advance_empty() {
    let mollusk = mollusk(&SECP256K1);
    let key = signing_key();
    let identity = secp256k1_compressed_pubkey(&key);

    let (vector, bump) = find_vector_pda(&SECP256K1, &identity);
    let vector_account = build_vector_account(
        NONCE,
        &SECP256K1,
        bump,
        mollusk
            .sysvars
            .rent
            .minimum_balance(SECP256K1.account_len()),
        &identity,
    );

    let advance_ix = sign_advance_instruction_secp256k1_ecdsa(&key, &NONCE, &[], &[]);

    let next_nonce = advance_vector_digest(&SECP256K1, &NONCE, &identity, &[], &[]);
    let expected_vector_data = expected_advanced_data(next_nonce, &SECP256K1, bump, &identity);

    let accounts = vec![(vector, vector_account)];

    let result = mollusk.process_and_validate_instruction_chain(
        &[(
            &advance_ix,
            &[
                Check::success(),
                Check::account(&vector).data(&expected_vector_data).build(),
            ],
        )],
        &accounts,
    );
    println!("secp256k1 advance: {} CUs", result.compute_units_consumed);
}

#[test]
fn advance_round_trips_spl_mint_authority() {
    let key = signing_key();
    let identity = secp256k1_compressed_pubkey(&key);
    run_round_trip_spl(&SECP256K1, &identity, &identity, |nonce, pre, post| {
        sign_advance_instruction_secp256k1_ecdsa(&key, nonce, pre, post)
    });
}

#[test]
fn close_via_advance() {
    let mollusk = mollusk(&SECP256K1);
    let key = signing_key();
    let identity = secp256k1_compressed_pubkey(&key);

    let vector_lamports = mollusk
        .sysvars
        .rent
        .minimum_balance(SECP256K1.account_len());
    let (vector, bump) = find_vector_pda(&SECP256K1, &identity);
    let vector_account = build_vector_account(NONCE, &SECP256K1, bump, vector_lamports, &identity);

    let eoa_starting_lamports = 10_000_000_000_u64;
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(eoa_starting_lamports, 0, &Address::default()),
    );

    let close_sub = create_close_subinstruction(&SECP256K1, &identity, &eoa);
    let passthrough_ix = create_passthrough_instruction(&SECP256K1, &identity, &[close_sub]);
    let advance_ix = sign_advance_instruction_secp256k1_ecdsa(
        &key,
        &NONCE,
        &[],
        std::slice::from_ref(&passthrough_ix),
    );

    let accounts = vec![(vector, vector_account), (eoa, eoa_account)];

    mollusk.process_and_validate_instruction_chain(
        &[
            (&advance_ix, &[Check::success()]),
            (
                &passthrough_ix,
                &[
                    Check::success(),
                    Check::account(&vector).lamports(0).build(),
                    Check::account(&eoa)
                        .lamports(eoa_starting_lamports + vector_lamports)
                        .build(),
                ],
            ),
        ],
        &accounts,
    );
}

#[test]
fn withdraw_via_advance() {
    let mollusk = mollusk(&SECP256K1);
    let key = signing_key();
    let identity = secp256k1_compressed_pubkey(&key);

    let rent_min = mollusk
        .sysvars
        .rent
        .minimum_balance(SECP256K1.account_len());
    let starting_vector_lamports = rent_min + 5_000_000;
    let withdraw_amount = 3_000_000u64;

    let (vector, bump) = find_vector_pda(&SECP256K1, &identity);
    let vector_account =
        build_vector_account(NONCE, &SECP256K1, bump, starting_vector_lamports, &identity);

    let eoa_starting_lamports = 10_000_000_000_u64;
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(eoa_starting_lamports, 0, &Address::default()),
    );

    let withdraw_sub = create_withdraw_subinstruction(&SECP256K1, &identity, &eoa, withdraw_amount);
    let passthrough_ix = create_passthrough_instruction(&SECP256K1, &identity, &[withdraw_sub]);
    let advance_ix = sign_advance_instruction_secp256k1_ecdsa(
        &key,
        &NONCE,
        &[],
        std::slice::from_ref(&passthrough_ix),
    );

    let accounts = vec![(vector, vector_account), (eoa, eoa_account)];

    mollusk.process_and_validate_instruction_chain(
        &[
            (&advance_ix, &[Check::success()]),
            (
                &passthrough_ix,
                &[
                    Check::success(),
                    Check::account(&vector)
                        .lamports(starting_vector_lamports - withdraw_amount)
                        .build(),
                    Check::account(&eoa)
                        .lamports(eoa_starting_lamports + withdraw_amount)
                        .build(),
                ],
            ),
        ],
        &accounts,
    );
}
