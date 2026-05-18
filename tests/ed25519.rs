//! Ed25519 program tests.

use ed25519_dalek::SigningKey;
use mollusk_svm::{program::keyed_account_for_system_program, result::Check};
use solana_account::Account;
use solana_address::Address;
use vector_core::{
    advance_vector_digest, create_close_subinstruction, create_initialize_ed25519,
    create_withdraw_subinstruction, ed25519_pubkey, find_vector_pda,
    sign_advance_instruction_ed25519, ED25519,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, run_round_trip_spl, NONCE,
};

const SIGNER_PRIVKEY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
];

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNER_PRIVKEY)
}

#[test]
fn initialize() {
    let mollusk = mollusk(&ED25519);
    let key = signing_key();
    let pubkey = ed25519_pubkey(&key);

    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, _bump) = find_vector_pda(&ED25519, &pubkey);
    let vector_account = Account::default();

    let init_ix = create_initialize_ed25519(&payer, &pubkey);

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
                .owner(&ED25519.program_id)
                .space(ED25519.account_len())
                .build(),
        ],
    );
}

#[test]
fn advance_empty() {
    let mollusk = mollusk(&ED25519);
    let key = signing_key();
    let pubkey = ed25519_pubkey(&key);

    let (vector, bump) = find_vector_pda(&ED25519, &pubkey);
    let vector_account = build_vector_account(
        NONCE,
        &ED25519,
        bump,
        mollusk.sysvars.rent.minimum_balance(ED25519.account_len()),
        &pubkey,
    );

    let advance_ix = sign_advance_instruction_ed25519(&key, &NONCE, &[], &[], &[]);

    let next_nonce = advance_vector_digest(&ED25519, &NONCE, &pubkey, &[], &[], &[]);
    let expected_vector_data = expected_advanced_data(next_nonce, &ED25519, bump, &pubkey);

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
    println!("ed25519 advance: {} CUs", result.compute_units_consumed);
}

#[test]
fn advance_round_trips_spl_mint_authority() {
    let key = signing_key();
    let pubkey = ed25519_pubkey(&key);
    run_round_trip_spl(&ED25519, &pubkey, &pubkey, |nonce, sub, pre, post| {
        sign_advance_instruction_ed25519(&key, nonce, sub, pre, post)
    });
}

#[test]
fn close_via_advance() {
    let mollusk = mollusk(&ED25519);
    let key = signing_key();
    let pubkey = ed25519_pubkey(&key);

    let vector_lamports = mollusk.sysvars.rent.minimum_balance(ED25519.account_len());
    let (vector, bump) = find_vector_pda(&ED25519, &pubkey);
    let vector_account = build_vector_account(NONCE, &ED25519, bump, vector_lamports, &pubkey);

    let eoa_starting_lamports = 1_0000_000_000u64;
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(eoa_starting_lamports, 0, &Address::default()),
    );

    let close_sub = create_close_subinstruction(&ED25519, &pubkey, &eoa);
    let advance_ix = sign_advance_instruction_ed25519(&key, &NONCE, &[close_sub], &[], &[]);

    let accounts = vec![(vector, vector_account), (eoa, eoa_account)];

    mollusk.process_and_validate_instruction_chain(
        &[(
            &advance_ix,
            &[
                Check::success(),
                Check::account(&vector).lamports(0).build(),
                Check::account(&eoa)
                    .lamports(eoa_starting_lamports + vector_lamports)
                    .build(),
            ],
        )],
        &accounts,
    );
}

#[test]
fn withdraw_via_advance() {
    let mollusk = mollusk(&ED25519);
    let key = signing_key();
    let pubkey = ed25519_pubkey(&key);

    let rent_min = mollusk.sysvars.rent.minimum_balance(ED25519.account_len());
    let starting_vector_lamports = rent_min + 5_000_000;
    let withdraw_amount = 3_000_000u64;

    let (vector, bump) = find_vector_pda(&ED25519, &pubkey);
    let vector_account =
        build_vector_account(NONCE, &ED25519, bump, starting_vector_lamports, &pubkey);

    let eoa_starting_lamports = 1_0000_000_000u64;
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(eoa_starting_lamports, 0, &Address::default()),
    );

    let withdraw_sub = create_withdraw_subinstruction(&ED25519, &pubkey, &eoa, withdraw_amount);
    let advance_ix = sign_advance_instruction_ed25519(&key, &NONCE, &[withdraw_sub], &[], &[]);

    let accounts = vec![(vector, vector_account), (eoa, eoa_account)];

    mollusk.process_and_validate_instruction_chain(
        &[(
            &advance_ix,
            &[
                Check::success(),
                Check::account(&vector)
                    .lamports(starting_vector_lamports - withdraw_amount)
                    .build(),
                Check::account(&eoa)
                    .lamports(eoa_starting_lamports + withdraw_amount)
                    .build(),
            ],
        )],
        &accounts,
    );
}
