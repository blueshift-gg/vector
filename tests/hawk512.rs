//! Hawk-512 program tests — registration by calling `initialize` twice.
//!
//! Hawk-512 is verify-only (no signer crate), so a full `advance`
//! round-trip can't be exercised here. These tests validate the phase-aware
//! `initialize`: one call allocates the ~10 KB base, a second identical call
//! resizes to ~18.5 KB and writes the 18 KB prepared blob, a third is a
//! no-op, and the second call rejects a wire pubkey that doesn't match the
//! committed hash (permissionless but key-bound).

use mollusk_svm::{program::keyed_account_for_system_program, result::Check};
use solana_account::Account;
use solana_address::Address;
use vector_core::{
    create_initialize_hawk512, create_initialize_instruction, find_vector_pda,
    hawk512_identity, VectorAccount, HAWK512, HAWK512_PREPARED_PUBKEY_LEN,
    HAWK512_WIRE_PUBKEY_LEN,
};

use crate::common::mollusk;

/// A real KAT Hawk-512 wire pubkey (from the `solana-hawk512` reference
/// vectors) — needed so `prepare`'s `prepare_into` decode succeeds.
const KAT_PUBKEY: &[u8; HAWK512_WIRE_PUBKEY_LEN] = include_bytes!("fixtures/hawk512_pk.bin");

/// CPI allocation / per-instruction resize cap. `initialize` allocates
/// `min(full, this)` on the first call.
const MAX_PERMITTED_DATA_INCREASE: usize = 10 * 1024;

/// Account offset where the prepared blob begins: 33-byte header + 32-byte
/// hash + 7-byte alignment pad.
const PREPARED_ACCOUNT_OFFSET: usize = 33 + 32 + 7;

#[test]
fn first_initialize_allocates_base_chunk() {
    let mollusk = mollusk(&HAWK512);
    let identity = hawk512_identity(KAT_PUBKEY);

    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, _bump) = find_vector_pda(&HAWK512, &identity);

    let init_ix = create_initialize_hawk512(&payer, KAT_PUBKEY);

    let accounts = vec![
        (payer, payer_account),
        (vector, Account::default()),
        (system_program, system_program_account),
    ];

    // A CPI CreateAccount can't allocate the full ~18.5 KB at once — that is
    // exactly why registration takes two calls. The first allocates
    // `min(full, MAX_PERMITTED_DATA_INCREASE)`.
    let base = HAWK512.account_len().min(MAX_PERMITTED_DATA_INCREASE);
    let result = mollusk.process_and_validate_instruction(
        &init_ix,
        &accounts,
        &[
            Check::success(),
            Check::account(&vector)
                .owner(&HAWK512.program_id)
                .space(base)
                .build(),
        ],
    );
    println!(
        "hawk512 initialize #1 (base {} B, full {} B): {} CUs",
        base,
        HAWK512.account_len(),
        result.compute_units_consumed
    );
}

#[test]
fn second_initialize_prepares_and_third_is_noop() {
    let mut mollusk = mollusk(&HAWK512);
    mollusk.compute_budget.compute_unit_limit = 1_400_000;
    let identity = hawk512_identity(KAT_PUBKEY);

    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, _bump) = find_vector_pda(&HAWK512, &identity);

    // The exact same instruction, sent three times.
    let init_ix = create_initialize_hawk512(&payer, KAT_PUBKEY);

    let accounts = vec![
        (payer, payer_account),
        (vector, Account::default()),
        (system_program, system_program_account),
    ];

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&init_ix, &[Check::success()]), // create
            (&init_ix, &[Check::success()]), // prepare
            (&init_ix, &[Check::success()]), // idempotent no-op
        ],
        &accounts,
    );

    let acc = result.get_account(&vector).expect("vector account exists");
    assert_eq!(acc.data.len(), HAWK512.account_len());
    let prepared = &acc.data[PREPARED_ACCOUNT_OFFSET..];
    assert_eq!(prepared.len(), HAWK512_PREPARED_PUBKEY_LEN);
    assert!(
        prepared.iter().any(|&b| b != 0),
        "prepared pubkey region still zero after the second initialize"
    );
    println!(
        "hawk512 initialize x3 (create+prepare+noop): {} CUs",
        result.compute_units_consumed
    );
}

#[test]
fn prepare_rejects_mismatched_key() {
    let mut mollusk = mollusk(&HAWK512);
    mollusk.compute_budget.compute_unit_limit = 1_400_000;

    let identity = hawk512_identity(KAT_PUBKEY);
    let (vector, bump) = find_vector_pda(&HAWK512, &identity);

    // Hand-build the post-first-call state: a program-owned BASE-sized
    // account holding `sha256(KAT)`, rent-funded for the full size.
    let base = HAWK512.account_len().min(MAX_PERMITTED_DATA_INCREASE);
    let mut data = vec![0u8; base];
    data[32] = bump;
    data[VectorAccount::HEADER_LEN..VectorAccount::HEADER_LEN + 32]
        .copy_from_slice(&identity);
    let vector_account = Account {
        lamports: mollusk.sysvars.rent.minimum_balance(HAWK512.account_len()),
        data,
        owner: HAWK512.program_id,
        executable: false,
        rent_epoch: 0,
    };

    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );

    // Attack: target the account registered for KAT_PUBKEY (so it exists and
    // is program-owned → prepare phase) but feed a *different* wire pubkey.
    // Its sha256 won't match the committed hash.
    let mut wrong = *KAT_PUBKEY;
    wrong[0] ^= 0xff;
    let init_wrong = create_initialize_instruction(&payer, &HAWK512, &identity, &wrong);

    let result = mollusk.process_instruction(
        &init_wrong,
        &[
            (payer, payer_account),
            (vector, vector_account),
            (system_program, system_program_account),
        ],
    );
    assert!(
        result.program_result.is_err(),
        "second initialize must reject a wire pubkey that doesn't match the committed hash"
    );
}
