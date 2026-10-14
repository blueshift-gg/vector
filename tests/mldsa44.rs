//! ML-DSA-44 tests.
//!
//! The identity is the 1,312-byte public key. The account stores it and the
//! key's 20,544-byte expanded form. Registration is three `initialize`
//! (10,240 bytes: key, row 0; 20,480: rows 1, 2; 21,924: row 3, `tr`), all
//! in one transaction.

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
    advance_vector_digest, create_advance_instruction, create_initialize_mldsa44,
    create_passthrough_instruction, create_withdraw_subinstruction, find_system_pda,
    find_vector_pda, verify_advance_signature, MLDSA44, MLDSA44_PUBKEY_LEN, MLDSA44_SIGNATURE_LEN,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, process_transaction, run_round_trip_spl,
    NONCE,
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
    out.extend_from_slice(
        VerifyingKey::<false>::from_bytes(public_key)
            .prepare()
            .as_bytes(),
    );
    out
}

#[test]
fn register_in_one_transaction() {
    let mut mollusk = mollusk();
    mollusk.compute_budget.compute_unit_limit = TRANSACTION_CU_LIMIT;

    let (pk, sk) = keypair();
    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, bump) = find_vector_pda(&MLDSA44, &pk);

    let register = create_initialize_mldsa44(&payer, &pk);
    assert_eq!(register.len(), 3);
    assert_eq!(MLDSA44.account_len(), 21_924);
    let grow = &register[1];

    let accounts = vec![
        (payer, payer_account),
        (vector, Account::default()),
        (system_program, system_program_account),
    ];

    // A later call carries no key: on an account that does not exist yet,
    // there is nothing to create it from.
    let early = mollusk.process_instruction(grow, &accounts);
    assert_eq!(
        early.program_result,
        mollusk_svm::result::ProgramResult::Failure(ProgramError::InvalidInstructionData)
    );
    assert_eq!(early.resulting_accounts, accounts);

    let result = process_transaction(
        &mollusk,
        &register.iter().collect::<Vec<_>>(),
        &accounts,
        &[],
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
    let (_, system_bump) = find_system_pda(&vector);
    assert_eq!(data[64..68], [MLDSA44.id, bump, system_bump, 0]);
    assert_eq!(&data[68..], &stored_identity(&pk)[..]);

    // A fourth call is refused.
    let full = mollusk.process_instruction(grow, &accounts);
    assert_eq!(
        full.program_result,
        mollusk_svm::result::ProgramResult::Failure(ProgramError::InvalidAccountData)
    );

    // Registration is complete: an advance signed with the key verifies.
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[..32]);
    let digest = advance_vector_digest(&MLDSA44, &nonce, &pk, &[], &[], None);
    let advance_ix = create_advance_instruction(&MLDSA44, &pk, &sign(&digest, &sk));
    let advanced = mollusk.process_and_validate_instruction_chain(
        &[(&advance_ix, &[Check::success()])],
        &[registered],
    );
    println!("mldsa44 advance: {} CUs", advanced.compute_units_consumed);
}

#[test]
fn advance_before_complete_fails() {
    let mut mollusk = mollusk();
    mollusk.compute_budget.compute_unit_limit = TRANSACTION_CU_LIMIT;
    let (pk, sk) = keypair();
    let (vector, _) = find_vector_pda(&MLDSA44, &pk);
    let stored = stored_identity(&pk);
    let digest = advance_vector_digest(&MLDSA44, &NONCE, &pk, &[], &[], None);
    let advance_ix = create_advance_instruction(&MLDSA44, &pk, &sign(&digest, &sk));
    for length in [10_240, 20_480] {
        let mut account = build_vector_account(NONCE, &MLDSA44, &pk, 1, &stored);
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
    let mut mollusk = mollusk();
    mollusk.compute_budget.compute_unit_limit = 400_000;

    let (pk, sk) = keypair();
    let stored = stored_identity(&pk);

    let (vector, _) = find_vector_pda(&MLDSA44, &pk);
    let vector_account = build_vector_account(
        NONCE,
        &MLDSA44,
        &pk,
        mollusk.sysvars.rent.minimum_balance(MLDSA44.account_len()),
        &stored,
    );

    let digest = advance_vector_digest(&MLDSA44, &NONCE, &pk, &[], &[], None);
    let signature = sign(&digest, &sk);
    assert_eq!(
        verify_advance_signature(&MLDSA44, &pk, &NONCE, &[], &[], None, &signature),
        Ok(digest)
    );
    let advance_ix = create_advance_instruction(&MLDSA44, &pk, &signature);
    let expected_vector_data = expected_advanced_data(digest, &MLDSA44, &pk, &stored);

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
            verify_advance_signature(&MLDSA44, &pk, &NONCE, &[], &[], None, &invalid),
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
        "DSMGfPwdpxKeB7ai2vYrRSzTLPDTXKTFujjBMeGkKfMc"
    );
    assert_eq!(bump, 254);
    let post = create_passthrough_instruction(
        &MLDSA44,
        &pk,
        &[create_withdraw_subinstruction(
            &MLDSA44, &pk, &receiver, 1234,
        )],
    );
    let digest = advance_vector_digest(&MLDSA44, &NONCE, &pk, &[], &[post], None);
    assert_eq!(
        digest,
        [
            18, 85, 155, 132, 58, 123, 150, 220, 120, 39, 40, 218, 232, 177, 228, 4, 12, 165, 34,
            123, 16, 187, 71, 251, 252, 139, 145, 191, 139, 22, 162, 47
        ]
    );
}

#[test]
fn advance_round_trips_spl_mint_authority() {
    let (pk, sk) = keypair();
    let stored = stored_identity(&pk);
    run_round_trip_spl(&MLDSA44, &pk, &stored, |nonce, pre, post| {
        let digest = advance_vector_digest(&MLDSA44, nonce, &pk, pre, post, None);
        create_advance_instruction(&MLDSA44, &pk, &sign(&digest, &sk))
    });
}
