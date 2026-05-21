//! Falcon-512 program tests.
//!
//! The client identity is `sha256(wire_pubkey)` (32 bytes) — the PDA seed and
//! the bytes folded into the advance digest. The on-chain account stores that
//! hash followed by the 1024-byte prepared pubkey (1056 bytes total), which
//! the test reconstructs off-chain via `solana-falcon512`.

use mollusk_svm::{program::keyed_account_for_system_program, result::Check};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _};
use solana_account::Account;
use solana_address::Address;
use solana_falcon512::Falcon512Pubkey;
use vector_core::{
    advance_vector_digest, create_advance_instruction, create_close_subinstruction,
    create_initialize_falcon512, create_passthrough_instruction, create_withdraw_subinstruction,
    falcon512_identity, find_vector_pda, FALCON512, FALCON512_SIGNATURE_LEN,
    FALCON512_WIRE_PUBKEY_LEN,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, run_round_trip_spl, NONCE,
};

/// Sign via PQClean and zero-pad the variable-length detached signature to
/// the wire-format 666 bytes the on-chain verifier expects.
fn sign(msg: &[u8], sk: &falcon512::SecretKey) -> [u8; FALCON512_SIGNATURE_LEN] {
    let sig = falcon512::detached_sign(msg, sk);
    let sig_bytes = sig.as_bytes();
    assert!(sig_bytes.len() <= FALCON512_SIGNATURE_LEN);
    let mut out = [0u8; FALCON512_SIGNATURE_LEN];
    out[..sig_bytes.len()].copy_from_slice(sig_bytes);
    out
}

fn wire_pubkey(pk: &falcon512::PublicKey) -> [u8; FALCON512_WIRE_PUBKEY_LEN] {
    let bytes = pk.as_bytes();
    assert_eq!(bytes.len(), FALCON512_WIRE_PUBKEY_LEN);
    let mut out = [0u8; FALCON512_WIRE_PUBKEY_LEN];
    out.copy_from_slice(bytes);
    out
}

/// On-chain stored identity: `sha256(wire)[32] || pad[1] ||
/// prepared_pubkey[1024]` (mirrors `populate_identity`).
fn stored_identity(wire: &[u8; FALCON512_WIRE_PUBKEY_LEN]) -> Vec<u8> {
    let pk = Falcon512Pubkey::try_from_slice(wire).expect("valid wire pubkey");
    let prepared = pk.try_prepare_pubkey().expect("preparable pubkey");
    let mut out = falcon512_identity(wire).to_vec();
    out.push(0); // alignment pad
    out.extend_from_slice(prepared.as_bytes());
    out
}

#[test]
fn initialize() {
    let mollusk = mollusk(&FALCON512);

    let (pk, _sk) = falcon512::keypair();
    let wire = wire_pubkey(&pk);
    let identity = falcon512_identity(&wire);

    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, _bump) = find_vector_pda(&FALCON512, &identity);
    let vector_account = Account::default();

    let init_ix = create_initialize_falcon512(&payer, &wire);

    let accounts = vec![
        (payer, payer_account),
        (vector, vector_account),
        (system_program, system_program_account),
    ];

    let result = mollusk.process_and_validate_instruction(
        &init_ix,
        &accounts,
        &[
            Check::success(),
            Check::account(&vector)
                .owner(&FALCON512.program_id)
                .space(FALCON512.account_len())
                .build(),
        ],
    );
    println!(
        "falcon512 initialize: {} CUs",
        result.compute_units_consumed
    );
}

#[test]
fn advance_empty() {
    let mut mollusk = mollusk(&FALCON512);
    mollusk.compute_budget.compute_unit_limit = 500_000;

    let (pk, sk) = falcon512::keypair();
    let wire = wire_pubkey(&pk);
    let identity = falcon512_identity(&wire);
    let stored = stored_identity(&wire);

    let (vector, bump) = find_vector_pda(&FALCON512, &identity);
    let vector_account = build_vector_account(
        NONCE,
        &FALCON512,
        bump,
        mollusk
            .sysvars
            .rent
            .minimum_balance(FALCON512.account_len()),
        &stored,
    );

    let digest = advance_vector_digest(&FALCON512, &NONCE, &identity, &[], &[]);
    let signature = sign(&digest, &sk);
    let advance_ix = create_advance_instruction(&FALCON512, &identity, &signature);

    let expected_vector_data = expected_advanced_data(digest, &FALCON512, bump, &stored);

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
    println!("falcon512 advance: {} CUs", result.compute_units_consumed);
}

#[test]
fn advance_round_trips_spl_mint_authority() {
    let (pk, sk) = falcon512::keypair();
    let wire = wire_pubkey(&pk);
    let identity = falcon512_identity(&wire);
    let stored = stored_identity(&wire);
    run_round_trip_spl(&FALCON512, &identity, &stored, |nonce, pre, post| {
        let digest = advance_vector_digest(&FALCON512, nonce, &identity, pre, post);
        let signature = sign(&digest, &sk);
        create_advance_instruction(&FALCON512, &identity, &signature)
    });
}

#[test]
fn close_via_advance() {
    let mut mollusk = mollusk(&FALCON512);
    mollusk.compute_budget.compute_unit_limit = 500_000;

    let (pk, sk) = falcon512::keypair();
    let wire = wire_pubkey(&pk);
    let identity = falcon512_identity(&wire);
    let stored = stored_identity(&wire);

    let vector_lamports = mollusk
        .sysvars
        .rent
        .minimum_balance(FALCON512.account_len());
    let (vector, bump) = find_vector_pda(&FALCON512, &identity);
    let vector_account = build_vector_account(NONCE, &FALCON512, bump, vector_lamports, &stored);

    let eoa_starting_lamports = 10_000_000_000_u64;
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(eoa_starting_lamports, 0, &Address::default()),
    );

    let close_sub = create_close_subinstruction(&FALCON512, &identity, &eoa);
    let passthrough_ix = create_passthrough_instruction(&FALCON512, &identity, &[close_sub]);
    let digest = advance_vector_digest(
        &FALCON512,
        &NONCE,
        &identity,
        &[],
        std::slice::from_ref(&passthrough_ix),
    );
    let signature = sign(&digest, &sk);
    let advance_ix = create_advance_instruction(&FALCON512, &identity, &signature);

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
    let mut mollusk = mollusk(&FALCON512);
    mollusk.compute_budget.compute_unit_limit = 500_000;

    let (pk, sk) = falcon512::keypair();
    let wire = wire_pubkey(&pk);
    let identity = falcon512_identity(&wire);
    let stored = stored_identity(&wire);

    let rent_min = mollusk
        .sysvars
        .rent
        .minimum_balance(FALCON512.account_len());
    let starting_vector_lamports = rent_min + 5_000_000;
    let withdraw_amount = 3_000_000u64;

    let (vector, bump) = find_vector_pda(&FALCON512, &identity);
    let vector_account =
        build_vector_account(NONCE, &FALCON512, bump, starting_vector_lamports, &stored);

    let eoa_starting_lamports = 10_000_000_000_u64;
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(eoa_starting_lamports, 0, &Address::default()),
    );

    let withdraw_sub = create_withdraw_subinstruction(&FALCON512, &identity, &eoa, withdraw_amount);
    let passthrough_ix = create_passthrough_instruction(&FALCON512, &identity, &[withdraw_sub]);
    let digest = advance_vector_digest(
        &FALCON512,
        &NONCE,
        &identity,
        &[],
        std::slice::from_ref(&passthrough_ix),
    );
    let signature = sign(&digest, &sk);
    let advance_ix = create_advance_instruction(&FALCON512, &identity, &signature);

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
