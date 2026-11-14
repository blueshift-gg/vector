//! Full transaction execution: stable PDA, current-key authority and rollback.

use mollusk_svm::result::types::TransactionProgramResult;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_winternitz::hazmat::{self, OneTime, SigningKey};
use solana_xmss as xmss;
use vector_signer_sdk::{
    advance_message, create_close_subinstruction, create_multi_advance_instruction,
    create_passthrough_instruction, create_rotating_advance_instruction,
    create_withdraw_subinstruction, find_vector_pda, rotating_advance_vector_digest, signer_digest,
    AdvanceSigner, Scheme, VectorError, NEVER_EXPIRES, WINTERNITZ, XMSS,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, process_transaction, xmss_stored, NONCE,
};

#[test]
fn winternitz_rotates_without_moving_the_account() {
    round_trip::<hazmat::SecretKey>(&WINTERNITZ, |signature| signature.as_bytes().to_vec());
}

#[test]
fn xmss_rotates_without_moving_the_account() {
    round_trip::<xmss::hazmat::SecretKey>(&XMSS, |signature| signature.as_bytes().to_vec());
}

fn round_trip<K: OneTime>(scheme: &Scheme, wire: fn(K::Signature) -> Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let mut first = SigningKey::<K>::create(directory.path().join("first.key")).unwrap();
    let mut second = SigningKey::<K>::create(directory.path().join("second.key")).unwrap();
    let third = SigningKey::<K>::create(directory.path().join("third.key")).unwrap();
    // The first key names the account for good.
    let identity = first.verifying_key().as_ref().to_vec();
    let (vector, _) = find_vector_pda(scheme, &identity);
    // XMSS also stores its leaf counter, which a new key starts again.
    let store = |key: &[u8]| match scheme.id == XMSS.id {
        true => xmss_stored(key, 0),
        false => key.to_vec(),
    };
    let stored = store(&identity);
    let mollusk = mollusk();
    let rent = mollusk.sysvars.rent.minimum_balance(scheme.account_len);
    let receiver = Address::new_unique();
    let accounts = vec![
        (
            vector,
            build_vector_account(NONCE, scheme, &identity, rent + 5_000_000, &stored),
        ),
        (receiver, Account::new(1_000_000, 0, &Address::default())),
    ];
    let withdraw = create_withdraw_subinstruction(scheme, &identity, &receiver, 3_000_000);
    let passthrough = create_passthrough_instruction(scheme, &identity, &[withdraw]);
    // The key changes in the `Advance`; the CPI still signs as the same
    // account.
    let next_key = second.verifying_key().as_ref().to_vec();
    let digest = rotating_advance_vector_digest(
        scheme,
        &NONCE,
        &identity,
        &next_key,
        &[],
        std::slice::from_ref(&passthrough),
        None,
    );
    let signature = wire(first.sign(&crate::common::signed_hash(&digest)).unwrap());
    let advance = create_rotating_advance_instruction(scheme, &identity, &next_key, &signature);

    // Without an `Advance`, nothing rotates and nothing moves.
    let result = process_transaction(&mollusk, &[&passthrough], &accounts, &[]);
    assert_eq!(
        result.program_result,
        TransactionProgramResult::Failure(0, VectorError::NotAdvanced.into())
    );
    assert_eq!(result.resulting_accounts, accounts);
    // The signature covers the next key: another one does not verify.
    let changed = create_rotating_advance_instruction(
        scheme,
        &identity,
        third.verifying_key().as_ref(),
        &signature,
    );
    let result = process_transaction(&mollusk, &[&changed, &passthrough], &accounts, &[]);
    assert_eq!(
        result.program_result,
        TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
    );
    assert_eq!(result.resulting_accounts, accounts);

    let transaction = [advance, passthrough];
    let result = process_transaction(
        &mollusk,
        &transaction.iter().collect::<Vec<_>>(),
        &accounts,
        &[],
    );
    assert_eq!(result.program_result, TransactionProgramResult::Success);
    let rotated = result.resulting_accounts;
    let stored_second = store(second.verifying_key().as_ref());
    let account = &rotated.iter().find(|(key, _)| *key == vector).unwrap().1;
    assert_eq!(
        account.data,
        expected_advanced_data(digest, scheme, &identity, &stored_second)
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

    let replay = process_transaction(
        &mollusk,
        &transaction.iter().collect::<Vec<_>>(),
        &rotated,
        &[],
    );
    assert_eq!(
        replay.program_result,
        TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
    );
    assert_eq!(replay.resulting_accounts, rotated);

    // The next key signs exactly once. A failed action must roll back both
    // the new key and nonce, allowing these exact bytes to be retried.
    // More than the account holds.
    let withdraw = create_withdraw_subinstruction(scheme, &identity, &receiver, rent + 3_000_000);
    let passthrough = create_passthrough_instruction(scheme, &identity, &[withdraw]);
    let next_key = third.verifying_key().as_ref().to_vec();
    let next_digest = rotating_advance_vector_digest(
        scheme,
        &digest,
        &identity,
        &next_key,
        &[],
        std::slice::from_ref(&passthrough),
        None,
    );
    let next_signature = wire(
        second
            .sign(&crate::common::signed_hash(&next_digest))
            .unwrap(),
    );
    let next_transaction = [
        create_rotating_advance_instruction(scheme, &identity, &next_key, &next_signature),
        passthrough,
    ];
    let failed = process_transaction(
        &mollusk,
        &next_transaction.iter().collect::<Vec<_>>(),
        &rotated,
        &[],
    );
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
        .lamports += rent + 2_000_000;
    let retry = process_transaction(
        &mollusk,
        &next_transaction.iter().collect::<Vec<_>>(),
        &funded,
        &[],
    );
    assert_eq!(retry.program_result, TransactionProgramResult::Success);
    let account = &retry
        .resulting_accounts
        .iter()
        .find(|(key, _)| *key == vector)
        .unwrap()
        .1;
    let stored_third = store(third.verifying_key().as_ref());
    assert_eq!(
        account.data,
        expected_advanced_data(next_digest, scheme, &identity, &stored_third)
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
        .data[76..76 + identity.len()]
        .copy_from_slice(first.verifying_key().as_ref());
    let rejected = process_transaction(
        &mollusk,
        &next_transaction.iter().collect::<Vec<_>>(),
        &wrong_key,
        &[],
    );
    assert_eq!(
        rejected.program_result,
        TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
    );
}

/// Fills with a fixed stream: these keys are for tests only.
pub(crate) fn fill(
    state: &mut u64,
) -> impl FnMut(&mut [u8]) -> Result<(), solana_winternitz::SigningError> + '_ {
    move |bytes| {
        for byte in bytes {
            *state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (*state >> 56) as u8;
        }
        Ok(())
    }
}

#[test]
fn winternitz_key_signs_once() {
    let mut state = 1;
    let key = hazmat::SecretKey::generate(fill(&mut state)).unwrap();
    let next = hazmat::SecretKey::generate(fill(&mut state)).unwrap();
    let identity = key.verifying_key().to_bytes();
    let next_key = next.verifying_key().to_bytes();
    let (vector, _) = find_vector_pda(&WINTERNITZ, &identity);
    let mollusk = mollusk();
    let rent = mollusk.sysvars.rent.minimum_balance(WINTERNITZ.account_len);
    let accounts = [(
        vector,
        build_vector_account(NONCE, &WINTERNITZ, &identity, rent, &identity),
    )];
    let mut send = |next_key: &[u8]| {
        let digest = rotating_advance_vector_digest(
            &WINTERNITZ,
            &NONCE,
            &identity,
            next_key,
            &[],
            &[],
            None,
        );
        let signature = key
            .sign_at(0, &crate::common::signed_hash(&digest), fill(&mut state))
            .unwrap();
        let advance = create_rotating_advance_instruction(
            &WINTERNITZ,
            &identity,
            next_key,
            signature.as_bytes(),
        );
        let result = process_transaction(&mollusk, &[&advance], &accounts, &[]);
        (result.program_result, result.resulting_accounts, digest)
    };

    // Keeping the key would let it sign again.
    let (result, resulting, _) = send(&identity);
    assert_eq!(
        result,
        TransactionProgramResult::Failure(0, VectorError::KeyReused.into())
    );
    assert_eq!(resulting, accounts);

    // A co-signer needs nothing but its `Advance`: the key is replaced there.
    let (result, resulting, digest) = send(&next_key);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(
        resulting[0].1.data,
        expected_advanced_data(digest, &WINTERNITZ, &identity, &next_key)
    );

    // Listed twice in one `Advance`, the account is advanced twice: the
    // second signature must be by the key the first stored, so the key
    // cannot sign two digests.
    let signer = AdvanceSigner {
        next_key: &next_key,
        ..AdvanceSigner::new(&WINTERNITZ, &identity)
    };
    let message = advance_message(NEVER_EXPIRES, &[signer, signer], &[], &[], None);
    let first = signer_digest(&message, &NONCE, &vector, &next_key);
    let second = signer_digest(&message, &first, &vector, &next_key);
    let first = key
        .sign_at(0, &crate::common::signed_hash(&first), fill(&mut state))
        .unwrap();
    let second = key
        .sign_at(0, &crate::common::signed_hash(&second), fill(&mut state))
        .unwrap();
    let twice = create_multi_advance_instruction(
        NEVER_EXPIRES,
        &[(signer, first.as_bytes()), (signer, second.as_bytes())],
    );
    let result = process_transaction(&mollusk, &[&twice], &accounts, &[]);
    assert_eq!(
        result.program_result,
        TransactionProgramResult::Failure(0, ProgramError::MissingRequiredSignature)
    );
    assert_eq!(result.resulting_accounts, accounts);
}

#[test]
fn xmss_leaf_signs_once_and_the_last_leaf_must_rotate() {
    let mut state = 2;
    let key = xmss::hazmat::SecretKey::generate(fill(&mut state)).unwrap();
    let next = xmss::hazmat::SecretKey::generate(fill(&mut state)).unwrap();
    let identity = key.verifying_key().to_bytes();
    let (vector, _) = find_vector_pda(&XMSS, &identity);
    let mollusk = mollusk();
    let rent = mollusk.sysvars.rent.minimum_balance(XMSS.account_len);
    let account = |next_leaf| {
        let stored = xmss_stored(&identity, next_leaf);
        [(
            vector,
            build_vector_account(NONCE, &XMSS, &identity, rent, &stored),
        )]
    };
    let mut send = |next_leaf, leaf, next_key: &[u8]| {
        let digest =
            rotating_advance_vector_digest(&XMSS, &NONCE, &identity, next_key, &[], &[], None);
        let signature = key
            .sign_at(leaf, &crate::common::signed_hash(&digest), fill(&mut state))
            .unwrap();
        let advance =
            create_rotating_advance_instruction(&XMSS, &identity, next_key, signature.as_bytes());
        let result = process_transaction(&mollusk, &[&advance], &account(next_leaf), &[]);
        (
            result.program_result,
            result.resulting_accounts[0].1.data.clone(),
            digest,
        )
    };
    let next_key = next.verifying_key().to_bytes();

    // A leaf below the counter has signed already, whatever the nonce says.
    let (result, data, _) = send(5, 4, &identity);
    assert_eq!(
        result,
        TransactionProgramResult::Failure(0, VectorError::LeafUsed.into())
    );
    assert_eq!(data, account(5)[0].1.data);
    // Keeping the key moves the counter past the leaf.
    let (result, data, digest) = send(5, 5, &identity);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(
        data,
        expected_advanced_data(digest, &XMSS, &identity, &xmss_stored(&identity, 6))
    );

    // After the last leaf the key cannot sign again: it must be replaced.
    let last = xmss::LEAVES - 1;
    let (result, ..) = send(last, last, &identity);
    assert_eq!(
        result,
        TransactionProgramResult::Failure(0, VectorError::TreeExhausted.into())
    );
    let (result, data, digest) = send(last, last, &next_key);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(
        data,
        expected_advanced_data(digest, &XMSS, &identity, &xmss_stored(&next_key, 0))
    );
}

/// Offline, a rotated account is checked against the key it holds now, not
/// the one that named it.
#[test]
fn a_rotated_key_verifies_against_the_key_the_account_holds_now() {
    use vector_signer_sdk::{verify_advance, AdvanceEntry, SignerNonce, VerifyError};

    let directory = tempfile::tempdir().unwrap();
    let first = SigningKey::<hazmat::SecretKey>::create(directory.path().join("1.key")).unwrap();
    let mut second =
        SigningKey::<hazmat::SecretKey>::create(directory.path().join("2.key")).unwrap();
    let third = SigningKey::<hazmat::SecretKey>::create(directory.path().join("3.key")).unwrap();
    let identity = first.verifying_key().as_ref().to_vec();
    let current = second.verifying_key().as_ref().to_vec();
    let next_key = third.verifying_key().as_ref().to_vec();
    let (vector, _) = find_vector_pda(&WINTERNITZ, &identity);

    // The account was rotated to `second`; `second` signs, naming `third`.
    let signer = AdvanceSigner {
        next_key: &next_key,
        ..AdvanceSigner::new(&WINTERNITZ, &identity)
    };
    let message = advance_message(NEVER_EXPIRES, &[signer], &[], &[], None);
    let digest = signer_digest(&message, &NONCE, &vector, &next_key);
    let signature = second
        .sign(&crate::common::signed_hash(&digest))
        .unwrap()
        .as_bytes()
        .to_vec();

    let mut entry = AdvanceEntry::new(signer, SignerNonce::Vector(NONCE), &signature);
    assert_eq!(
        verify_advance(NEVER_EXPIRES, &[entry], &[], &[], None, None),
        Err(VerifyError::SignatureInvalid)
    );
    entry.current_key = Some(&current);
    assert_eq!(
        verify_advance(NEVER_EXPIRES, &[entry], &[], &[], None, None).unwrap(),
        [digest]
    );
}

#[test]
fn winternitz_account_never_closes() {
    never_closes::<hazmat::SecretKey>(&WINTERNITZ, |signature| signature.as_bytes().to_vec());
}

#[test]
fn xmss_account_never_closes() {
    never_closes::<xmss::hazmat::SecretKey>(&XMSS, |signature| signature.as_bytes().to_vec());
}

/// Its address is its first key's: created again, it would start over at
/// that key, which has signed. So neither `Close` nor a `Withdraw` of every
/// lamport is allowed; a `Withdraw` down to rent-exemption is.
fn never_closes<K: OneTime>(scheme: &Scheme, wire: fn(K::Signature) -> Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let mollusk = mollusk();
    let lamports = mollusk.sysvars.rent.minimum_balance(scheme.account_len) + 5_000_000;
    let receiver = Address::new_unique();
    let next = SigningKey::<K>::create(directory.path().join("next.key")).unwrap();
    let next_key = next.verifying_key().as_ref().to_vec();

    // Each attempt signs with a key of its own, over an account of its own,
    // so no one-time key signs twice.
    let attempt = |name: &str, action: fn(&Scheme, &[u8], &Address, u64) -> Instruction| {
        let mut key = SigningKey::<K>::create(directory.path().join(name)).unwrap();
        let identity = key.verifying_key().as_ref().to_vec();
        let (vector, _) = find_vector_pda(scheme, &identity);
        let stored = match scheme.id == XMSS.id {
            true => xmss_stored(&identity, 0),
            false => identity.clone(),
        };
        let account = build_vector_account(NONCE, scheme, &identity, lamports, &stored);
        let passthrough = create_passthrough_instruction(
            scheme,
            &identity,
            &[action(scheme, &identity, &receiver, lamports)],
        );
        let digest = rotating_advance_vector_digest(
            scheme,
            &NONCE,
            &identity,
            &next_key,
            &[],
            std::slice::from_ref(&passthrough),
            None,
        );
        let signature = wire(key.sign(&crate::common::signed_hash(&digest)).unwrap());
        let advance = create_rotating_advance_instruction(scheme, &identity, &next_key, &signature);
        process_transaction(
            &mollusk,
            &[&advance, &passthrough],
            &[
                (vector, account),
                (receiver, Account::new(1_000_000, 0, &Address::default())),
            ],
            &[],
        )
        .program_result
    };

    let refused = TransactionProgramResult::Failure(1, VectorError::KeyRotates.into());
    assert_eq!(
        attempt("close.key", |scheme, identity, receiver, _| {
            create_close_subinstruction(scheme, identity, receiver)
        }),
        refused
    );
    assert_eq!(
        attempt("all.key", |scheme, identity, receiver, lamports| {
            create_withdraw_subinstruction(scheme, identity, receiver, lamports)
        }),
        refused
    );
    assert_eq!(
        attempt("rent.key", |scheme, identity, receiver, _| {
            create_withdraw_subinstruction(scheme, identity, receiver, 5_000_000)
        }),
        TransactionProgramResult::Success
    );
}
