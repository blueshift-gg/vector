//! Full transaction execution: stable PDA, current-key authority and rollback.

use mollusk_svm::result::types::TransactionProgramResult;
use solana_account::Account;
use solana_address::Address;
use solana_program_error::ProgramError;
use solana_winternitz::{winternitz, xmss, OneTime, Signer};
use vector_core::{
    advance_vector_digest_with_fee_payer, create_advance_instruction,
    create_passthrough_instruction, create_rotate_subinstruction, create_withdraw_subinstruction,
    find_vector_pda, pda_seed_from_identity, Scheme, WINTERNITZ, XMSS,
};

use crate::common::{build_vector_account, expected_advanced_data, mollusk, NONCE};

#[test]
fn winternitz_rotates_without_moving_the_account() {
    round_trip::<winternitz::SecretKey>(&WINTERNITZ, |signature| signature.0.to_vec());
}

#[test]
fn xmss_rotates_without_moving_the_account() {
    round_trip::<xmss::SecretKey>(&XMSS, |signature| signature.0.to_vec());
}

fn round_trip<K: OneTime>(scheme: &Scheme, wire: fn(K::Signature) -> Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let mut first = Signer::<K>::create(directory.path().join("first.key")).unwrap();
    let mut second = Signer::<K>::create(directory.path().join("second.key")).unwrap();
    let third = Signer::<K>::create(directory.path().join("third.key")).unwrap();
    let identity = pda_seed_from_identity(&first.public_key().0);
    let (vector, bump) = find_vector_pda(scheme, &identity);
    let stored = [identity.as_slice(), first.public_key().0.as_slice()].concat();
    let mollusk = mollusk(scheme);
    let rent = mollusk.sysvars.rent.minimum_balance(scheme.account_len());
    let receiver = Address::new_unique();
    let accounts = vec![
        (
            vector,
            build_vector_account(NONCE, scheme, bump, rent + 5_000_000, &stored),
        ),
        (receiver, Account::new(1_000_000, 0, &Address::default())),
    ];
    let rotate = create_rotate_subinstruction(scheme, &identity, &second.public_key().0);
    let withdraw = create_withdraw_subinstruction(scheme, &identity, &receiver, 3_000_000);
    // Rotation first also exercises CPI signer seeds after the key changes.
    let passthrough =
        create_passthrough_instruction(scheme, &identity, &[rotate.clone(), withdraw.clone()]);
    let digest = advance_vector_digest_with_fee_payer(
        scheme,
        &NONCE,
        &identity,
        &[],
        std::slice::from_ref(&passthrough),
        None,
    );
    let signature = wire(first.sign(&digest).unwrap());
    let advance = create_advance_instruction(scheme, &identity, &signature);

    for unauthorized in [&rotate, &passthrough] {
        let result =
            mollusk.process_transaction_instructions(std::slice::from_ref(unauthorized), &accounts);
        assert_eq!(
            result.program_result,
            TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
        );
        assert_eq!(result.resulting_accounts, accounts);
    }
    let changed_key = create_rotate_subinstruction(scheme, &identity, &third.public_key().0);
    let changed = create_passthrough_instruction(scheme, &identity, &[changed_key, withdraw]);
    let result = mollusk.process_transaction_instructions(&[advance.clone(), changed], &accounts);
    assert_eq!(
        result.program_result,
        TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
    );
    assert_eq!(result.resulting_accounts, accounts);

    let transaction = [advance, passthrough];
    let result = mollusk.process_transaction_instructions(&transaction, &accounts);
    assert_eq!(result.program_result, TransactionProgramResult::Success);
    let rotated = result.resulting_accounts;
    let stored_second = [identity.as_slice(), second.public_key().0.as_slice()].concat();
    let account = &rotated.iter().find(|(key, _)| *key == vector).unwrap().1;
    assert_eq!(
        account.data,
        expected_advanced_data(digest, scheme, bump, &stored_second)
    );
    assert_eq!(account.lamports, rent + 2_000_000);
    assert_eq!(
        rotated
            .iter()
            .find(|(key, _)| *key == receiver)
            .unwrap()
            .1
            .lamports,
        4_000_000
    );

    let replay = mollusk.process_transaction_instructions(&transaction, &rotated);
    assert_eq!(
        replay.program_result,
        TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
    );
    assert_eq!(replay.resulting_accounts, rotated);

    // The next key signs exactly once. A failed action must roll back both
    // the new key and nonce, allowing these exact bytes to be retried.
    let rotate = create_rotate_subinstruction(scheme, &identity, &third.public_key().0);
    let withdraw = create_withdraw_subinstruction(scheme, &identity, &receiver, 3_000_000);
    let passthrough = create_passthrough_instruction(scheme, &identity, &[rotate, withdraw]);
    let next_digest = advance_vector_digest_with_fee_payer(
        scheme,
        &digest,
        &identity,
        &[],
        std::slice::from_ref(&passthrough),
        None,
    );
    let next_signature = wire(second.sign(&next_digest).unwrap());
    let next_transaction = [
        create_advance_instruction(scheme, &identity, &next_signature),
        passthrough,
    ];
    let failed = mollusk.process_transaction_instructions(&next_transaction, &rotated);
    assert_eq!(
        failed.program_result,
        TransactionProgramResult::Failure(1, ProgramError::InsufficientFunds)
    );
    assert_eq!(failed.resulting_accounts, rotated);

    // Supply the missing funds, then rebroadcast without signing again.
    let mut funded = rotated.clone();
    funded
        .iter_mut()
        .find(|(key, _)| *key == vector)
        .unwrap()
        .1
        .lamports += 2_000_000;
    let retry = mollusk.process_transaction_instructions(&next_transaction, &funded);
    assert_eq!(retry.program_result, TransactionProgramResult::Success);
    let account = &retry
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == vector)
        .unwrap()
        .1;
    let stored_third = [identity.as_slice(), third.public_key().0.as_slice()].concat();
    assert_eq!(
        account.data,
        expected_advanced_data(next_digest, scheme, bump, &stored_third)
    );
    assert_eq!(account.lamports, rent + 1_000_000);

    // Keep the nonce correct but restore the old key: the second signature
    // must only verify against the key installed by the first rotation.
    let mut wrong_key = funded;
    wrong_key
        .iter_mut()
        .find(|(key, _)| *key == vector)
        .unwrap()
        .1
        .data[65..]
        .copy_from_slice(&first.public_key().0);
    let rejected = mollusk.process_transaction_instructions(&next_transaction, &wrong_key);
    assert_eq!(
        rejected.program_result,
        TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
    );
}

#[test]
fn rotate_rejects_malformed_and_unchanged_keys() {
    let directory = tempfile::tempdir().unwrap();
    let mut signer =
        Signer::<xmss::SecretKey>::create(directory.path().join("signer.key")).unwrap();
    let public_key = signer.public_key().0;
    let identity = pda_seed_from_identity(&public_key);
    let (vector, bump) = find_vector_pda(&XMSS, &identity);
    let stored = [identity.as_slice(), public_key.as_slice()].concat();
    let mollusk = mollusk(&XMSS);
    let accounts = [(
        vector,
        build_vector_account(
            NONCE,
            &XMSS,
            bump,
            mollusk.sysvars.rent.minimum_balance(XMSS.account_len()),
            &stored,
        ),
    )];
    for key in [vec![0; 40], vec![0; 42], public_key.to_vec()] {
        let mut rotate = create_rotate_subinstruction(&XMSS, &identity, &public_key);
        rotate.data.truncate(1);
        rotate.data.extend_from_slice(&key);
        let passthrough = create_passthrough_instruction(&XMSS, &identity, &[rotate]);
        let digest = advance_vector_digest_with_fee_payer(
            &XMSS,
            &NONCE,
            &identity,
            &[],
            std::slice::from_ref(&passthrough),
            None,
        );
        let signature = signer.sign(&digest).unwrap();
        let advance = create_advance_instruction(&XMSS, &identity, &signature.0);
        let result = mollusk.process_transaction_instructions(&[advance, passthrough], &accounts);
        assert_eq!(
            result.program_result,
            TransactionProgramResult::Failure(1, ProgramError::InvalidInstructionData)
        );
        assert_eq!(result.resulting_accounts, accounts);
    }
}
