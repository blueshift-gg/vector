//! EIP-191 (Ethereum-style secp256k1) program tests.

use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use mollusk_svm::{program::keyed_account_for_system_program, result::Check};
use solana_account::Account;
use solana_address::Address;
use vector_core::{
    advance_vector_digest, create_close_subinstruction, create_initialize_secp256k1_eip191,
    find_vector_pda, secp256k1_eip191_eth_address, sign_advance_instruction_secp256k1_eip191,
    EIP191,
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
    let mollusk = mollusk(&EIP191);
    let key = signing_key();
    let identity = secp256k1_eip191_eth_address(&key);

    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, _bump) = find_vector_pda(&EIP191, &identity);
    let vector_account = Account::default();

    let init_ix = create_initialize_secp256k1_eip191(&payer, &identity);

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
                .owner(&EIP191.program_id)
                .space(EIP191.account_len())
                .build(),
        ],
    );
}

#[test]
fn advance_empty() {
    let mollusk = mollusk(&EIP191);
    let key = signing_key();
    let identity = secp256k1_eip191_eth_address(&key);

    let (vector, bump) = find_vector_pda(&EIP191, &identity);
    let vector_account = build_vector_account(
        NONCE,
        &EIP191,
        bump,
        mollusk.sysvars.rent.minimum_balance(EIP191.account_len()),
        &identity,
    );

    let advance_ix = sign_advance_instruction_secp256k1_eip191(&key, &NONCE, &[], &[], &[]);

    let next_nonce = advance_vector_digest(&EIP191, &NONCE, &identity, &[], &[], &[]);
    let expected_vector_data = expected_advanced_data(next_nonce, &EIP191, bump, &identity);

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
    println!("eip191 advance: {} CUs", result.compute_units_consumed);
}

#[test]
fn advance_round_trips_spl_mint_authority() {
    let key = signing_key();
    let identity = secp256k1_eip191_eth_address(&key);
    run_round_trip_spl(&EIP191, &identity, &identity, |nonce, sub, pre, post| {
        sign_advance_instruction_secp256k1_eip191(&key, nonce, sub, pre, post)
    });
}

#[test]
fn close_via_advance() {
    let mollusk = mollusk(&EIP191);
    let key = signing_key();
    let identity = secp256k1_eip191_eth_address(&key);

    let vector_lamports = mollusk.sysvars.rent.minimum_balance(EIP191.account_len());
    let (vector, bump) = find_vector_pda(&EIP191, &identity);
    let vector_account = build_vector_account(NONCE, &EIP191, bump, vector_lamports, &identity);

    let eoa_starting_lamports = 1_0000_000_000u64;
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(eoa_starting_lamports, 0, &Address::default()),
    );

    let close_sub = create_close_subinstruction(&EIP191, &identity, &eoa);
    let advance_ix = sign_advance_instruction_secp256k1_eip191(&key, &NONCE, &[close_sub], &[], &[]);

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
