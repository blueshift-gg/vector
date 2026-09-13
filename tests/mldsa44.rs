//! ML-DSA-44 program tests.
//!
//! The identity is the 1,312-byte public key: the bytes folded into the
//! advance digest, and (hashed) the PDA seed. The account stores it and the
//! key's 20,544-byte expanded form. Registration is `initialize` (10,240
//! bytes: key, row 0) then two `expand` (20,480: rows 1, 2; 21,892: row 3,
//! `tr`), all three in one transaction.

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer};
use mollusk_svm::{
    program::keyed_account_for_system_program,
    result::{types::TransactionProgramResult, Check},
};
use solana_account::Account;
use solana_address::Address;
use solana_program_error::ProgramError;
use vector_core::{
    advance_vector_digest, create_advance_instruction, create_expand_mldsa44,
    create_initialize_mldsa44, create_passthrough_instruction, create_withdraw_subinstruction,
    find_vector_pda, verify_advance_signature_mldsa44, MLDSA44, MLDSA44_EXPAND_STEPS,
    MLDSA44_PUBKEY_LEN, MLDSA44_SIGNATURE_LEN,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, run_round_trip_spl, NONCE,
};

/// The per-transaction compute cap registration has to fit.
const TRANSACTION_CU_LIMIT: u64 = 1_400_000;

fn keypair() -> ([u8; MLDSA44_PUBKEY_LEN], ml_dsa_44::PrivateKey) {
    let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
    (pk.into_bytes(), sk)
}

fn sign(digest: &[u8; 32], sk: &ml_dsa_44::PrivateKey) -> [u8; MLDSA44_SIGNATURE_LEN] {
    sk.try_sign(digest, &[]).unwrap()
}

fn stored_identity(public_key: &[u8; MLDSA44_PUBKEY_LEN]) -> Vec<u8> {
    use solana_ml_dsa::ml_dsa_44::VerifyingKey;
    let mut out = public_key.to_vec();
    out.extend_from_slice(&[0; 3]);
    out.extend_from_slice(
        VerifyingKey::<false>::from_bytes(public_key)
            .prepare()
            .as_bytes(),
    );
    out
}

#[test]
fn register_in_one_transaction() {
    let mut mollusk = mollusk(&MLDSA44);
    mollusk.compute_budget.compute_unit_limit = TRANSACTION_CU_LIMIT;

    let (pk, sk) = keypair();
    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, bump) = find_vector_pda(&MLDSA44, &pk);

    let init_ix = create_initialize_mldsa44(&payer, &pk);
    let expand_ix = create_expand_mldsa44(&pk);
    assert_eq!(MLDSA44_EXPAND_STEPS, 2);
    assert_eq!(MLDSA44.account_len(), 21_892);

    let accounts = vec![
        (payer, payer_account),
        (vector, Account::default()),
        (system_program, system_program_account),
    ];

    let foreign = mollusk.process_instruction(&expand_ix, &accounts);
    assert_eq!(
        foreign.program_result,
        mollusk_svm::result::ProgramResult::Failure(ProgramError::InvalidAccountOwner)
    );
    assert_eq!(foreign.resulting_accounts, accounts);
    let mut malformed = expand_ix.clone();
    malformed.data.push(0);
    let rejected = mollusk.process_instruction(&malformed, &accounts);
    assert_eq!(
        rejected.program_result,
        mollusk_svm::result::ProgramResult::Failure(ProgramError::InvalidInstructionData)
    );
    assert_eq!(rejected.resulting_accounts, accounts);

    let result = mollusk.process_transaction_instructions(
        &[init_ix, expand_ix.clone(), expand_ix.clone()],
        &accounts,
    );
    assert_eq!(result.program_result, TransactionProgramResult::Success);
    assert!(result.compute_units_consumed <= TRANSACTION_CU_LIMIT);
    println!(
        "mldsa44 registration: {} CUs",
        result.compute_units_consumed
    );
    let accounts = result.resulting_accounts;

    // The account holds exactly what the host reconstructs, after the
    // header whose nonce the program derived on chain.
    let registered = accounts.iter().find(|(k, _)| *k == vector).unwrap().clone();
    let data = &registered.1.data;
    assert_eq!(data[32], bump);
    assert_eq!(&data[33..], &stored_identity(&pk)[..]);

    // A third expand is refused.
    let full = mollusk.process_instruction(&expand_ix, std::slice::from_ref(&registered));
    assert_eq!(
        full.program_result,
        mollusk_svm::result::ProgramResult::Failure(ProgramError::InvalidAccountData)
    );

    // Registration is complete: an advance signed with the key verifies.
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[..32]);
    let digest = advance_vector_digest(&MLDSA44, &nonce, &pk, &[], &[]);
    let advance_ix = create_advance_instruction(&MLDSA44, &pk, &sign(&digest, &sk));
    let advanced = mollusk.process_and_validate_instruction_chain(
        &[(&advance_ix, &[Check::success()])],
        &[registered],
    );
    println!("mldsa44 advance: {} CUs", advanced.compute_units_consumed);
}

#[test]
fn advance_before_expand_fails() {
    let mut mollusk = mollusk(&MLDSA44);
    mollusk.compute_budget.compute_unit_limit = TRANSACTION_CU_LIMIT;
    let (pk, sk) = keypair();
    let (vector, bump) = find_vector_pda(&MLDSA44, &pk);
    let stored = stored_identity(&pk);
    let digest = advance_vector_digest(&MLDSA44, &NONCE, &pk, &[], &[]);
    let advance_ix = create_advance_instruction(&MLDSA44, &pk, &sign(&digest, &sk));
    for length in [10_240, 20_480] {
        let mut account = build_vector_account(NONCE, &MLDSA44, bump, 1, &stored);
        account.data.truncate(length);
        let accounts = [(vector, account)];
        let result = mollusk.process_instruction(&advance_ix, &accounts);
        assert_eq!(
            result.program_result,
            mollusk_svm::result::ProgramResult::Failure(ProgramError::AccountDataTooSmall)
        );
        assert_eq!(result.resulting_accounts, accounts);
    }
}

#[test]
fn advance_empty() {
    let mut mollusk = mollusk(&MLDSA44);
    mollusk.compute_budget.compute_unit_limit = 400_000;

    let (pk, sk) = keypair();
    let stored = stored_identity(&pk);

    let (vector, bump) = find_vector_pda(&MLDSA44, &pk);
    let vector_account = build_vector_account(
        NONCE,
        &MLDSA44,
        bump,
        mollusk.sysvars.rent.minimum_balance(MLDSA44.account_len()),
        &stored,
    );

    let digest = advance_vector_digest(&MLDSA44, &NONCE, &pk, &[], &[]);
    let signature = sign(&digest, &sk);
    assert_eq!(
        verify_advance_signature_mldsa44(&pk, &NONCE, &[], &[], None, &signature),
        Ok(digest)
    );
    let advance_ix = create_advance_instruction(&MLDSA44, &pk, &signature);
    let expected_vector_data = expected_advanced_data(digest, &MLDSA44, bump, &stored);

    let result = mollusk.process_and_validate_instruction_chain(
        &[(
            &advance_ix,
            &[
                Check::success(),
                Check::account(&vector).data(&expected_vector_data).build(),
            ],
        )],
        &[(vector, vector_account.clone())],
    );
    println!("mldsa44 advance: {} CUs", result.compute_units_consumed);

    let replay = mollusk.process_instruction(&advance_ix, &result.resulting_accounts);
    assert_eq!(
        replay.program_result,
        mollusk_svm::result::ProgramResult::Failure(ProgramError::MissingRequiredSignature)
    );
    assert_eq!(replay.resulting_accounts, result.resulting_accounts);

    // The external signer must use the program's empty FIPS 204 context.
    let wrong_context = sk.try_sign(&digest, b"another protocol").unwrap();
    let mut tampered = signature;
    tampered[100] ^= 1;
    for invalid in [tampered, wrong_context] {
        assert_eq!(
            verify_advance_signature_mldsa44(&pk, &NONCE, &[], &[], None, &invalid),
            Err(vector_core::VerifyError::SignatureInvalid)
        );
        let bad_ix = create_advance_instruction(&MLDSA44, &pk, &invalid);
        let result = mollusk.process_instruction(&bad_ix, &[(vector, vector_account.clone())]);
        assert_eq!(
            result.program_result,
            mollusk_svm::result::ProgramResult::Failure(ProgramError::MissingRequiredSignature)
        );
    }
}

#[test]
fn client_encoding_matches_typescript() {
    let pk = [0x44; MLDSA44_PUBKEY_LEN];
    let receiver = Address::new_from_array([9; 32]);
    let (pda, bump) = find_vector_pda(&MLDSA44, &pk);
    assert_eq!(
        pda.to_string(),
        "FNjvHupTZp9ZRo53mmh9tV3vv3mADxU5rKo9ataMWUj2"
    );
    assert_eq!(bump, 255);
    let post = create_passthrough_instruction(
        &MLDSA44,
        &pk,
        &[create_withdraw_subinstruction(
            &MLDSA44, &pk, &receiver, 1234,
        )],
    );
    let digest = advance_vector_digest(&MLDSA44, &NONCE, &pk, &[], &[post]);
    assert_eq!(
        digest,
        [
            0xd6, 0xcb, 0x91, 0xbb, 0x61, 0x6d, 0x7e, 0x3e, 0x4a, 0xab, 0xb3, 0x71, 0xc3, 0xb5,
            0x2d, 0xd1, 0xbf, 0x23, 0xc7, 0x59, 0x17, 0x1f, 0xfa, 0x55, 0x5c, 0x63, 0x18, 0x56,
            0x59, 0x1d, 0x65, 0xe8
        ]
    );
}

#[test]
fn advance_round_trips_spl_mint_authority() {
    let (pk, sk) = keypair();
    let stored = stored_identity(&pk);
    run_round_trip_spl(&MLDSA44, &pk, &stored, |nonce, pre, post| {
        let digest = advance_vector_digest(&MLDSA44, nonce, &pk, pre, post);
        create_advance_instruction(&MLDSA44, &pk, &sign(&digest, &sk))
    });
}
