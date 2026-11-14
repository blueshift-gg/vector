//! One-time authorization through Vector's existing handlers.

use mollusk_svm::{
    program::keyed_account_for_system_program,
    result::{types::TransactionProgramResult, Check},
};
use solana_account::Account;
use solana_address::Address;
use solana_program_error::ProgramError;
use solana_winternitz::{hazmat, winternitz};
use vector_core::{
    create_close_subinstruction, create_initialize_winternitz, create_passthrough_instruction,
    create_rotating_advance_instruction, create_withdraw_subinstruction, find_vector_pda,
    rotating_advance_vector_digest, PROGRAM_ID, WINTERNITZ,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, process_transaction, NONCE,
};

#[test]
fn initialize_and_client_encoding() {
    let mollusk = mollusk();
    let public_key = core::array::from_fn(|i| i as u8);
    let identity = public_key;
    let (vector, bump) = find_vector_pda(&WINTERNITZ, &identity);
    // Shared with sdk/ts/test/winternitz.test.ts.
    assert_eq!(
        vector.to_string(),
        "Er2fQZXAf3ZoVHiDQAgJGReN5qUz2oh6t8qfU3GGSb9Y"
    );
    assert_eq!(bump, 255);
    let receiver = Address::new_from_array([9; 32]);
    let close = create_close_subinstruction(&WINTERNITZ, &identity, &receiver);
    let passthrough = create_passthrough_instruction(&WINTERNITZ, &identity, &[close]);
    assert_eq!(
        rotating_advance_vector_digest(
            &WINTERNITZ,
            &NONCE,
            &identity,
            &[7; 41],
            &[],
            &[passthrough],
            None
        ),
        [
            201, 203, 181, 138, 16, 59, 180, 221, 210, 98, 110, 141, 148, 45, 26, 188, 75, 114, 36,
            19, 246, 169, 180, 125, 184, 245, 98, 211, 60, 123, 81, 22
        ],
    );

    let (system, system_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();
    let accounts = [
        (payer, Account::new(1_000_000_000, 0, &system)),
        (vector, Account::default()),
        (system, system_account),
    ];
    let initialize = create_initialize_winternitz(&payer, &public_key);
    let result = mollusk.process_and_validate_instruction(
        &initialize,
        &accounts,
        &[
            Check::success(),
            Check::account(&vector)
                .owner(&PROGRAM_ID)
                .space(WINTERNITZ.account_len)
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
    assert_eq!(stored[72..76], [WINTERNITZ.id, bump, system_bump, 0]);
    assert_eq!(&stored[76..], &public_key);

    // A key of another length has another address, and the scheme refuses it.
    for length in [40, 42] {
        let key = vec![0; length];
        let (address, _) = Address::find_program_address(
            &[b"vector", &[WINTERNITZ.id], &vector_core::vector_seed(&key)],
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
}

#[test]
fn signature_binds_withdrawal_and_rejects_replay() {
    let directory = tempfile::tempdir().unwrap();
    let mut signer = winternitz::SigningKey::create(directory.path().join("signer.key")).unwrap();
    let public_key = signer.verifying_key().to_bytes();
    let identity = public_key;
    let stored = public_key.to_vec();
    let mollusk = mollusk();
    let (vector, _) = find_vector_pda(&WINTERNITZ, &identity);
    let lamports = mollusk.sysvars.rent.minimum_balance(WINTERNITZ.account_len) + 5_000_000;
    let account = build_vector_account(NONCE, &WINTERNITZ, &identity, lamports, &stored);
    let receiver = Address::new_unique();
    let other = Address::new_unique();
    let withdraw = create_withdraw_subinstruction(&WINTERNITZ, &identity, &receiver, 5_000_000);
    let passthrough = create_passthrough_instruction(&WINTERNITZ, &identity, &[withdraw]);
    let next_key = [7; 41];
    let digest = rotating_advance_vector_digest(
        &WINTERNITZ,
        &NONCE,
        &identity,
        &next_key,
        &[],
        std::slice::from_ref(&passthrough),
        None,
    );
    let signature = signer
        .sign(&crate::common::signed_hash(&digest))
        .unwrap()
        .to_bytes();
    let advance =
        create_rotating_advance_instruction(&WINTERNITZ, &identity, &next_key, &signature);
    let expected = expected_advanced_data(digest, &WINTERNITZ, &identity, &next_key);

    let other_withdraw = create_withdraw_subinstruction(&WINTERNITZ, &identity, &other, 5_000_000);
    let changed_action = create_passthrough_instruction(&WINTERNITZ, &identity, &[other_withdraw]);
    let mut tampered = signature;
    tampered[winternitz::SIGNATURE_LEN - 1] ^= 1;
    let mut wrong_key = account.clone();
    wrong_key.data[76] ^= 1;
    let mut advanced = account.clone();
    advanced.data = expected.clone();

    // Reuse the one signature across adversarial inputs, never sign twice.
    for (bytes, state, action, error) in [
        (
            signature.as_slice(),
            account.clone(),
            changed_action,
            ProgramError::MissingRequiredSignature,
        ),
        (
            tampered.as_slice(),
            account.clone(),
            passthrough.clone(),
            ProgramError::MissingRequiredSignature,
        ),
        (
            &signature[..winternitz::SIGNATURE_LEN - 1],
            account.clone(),
            passthrough.clone(),
            ProgramError::InvalidInstructionData,
        ),
        (
            signature.as_slice(),
            wrong_key,
            passthrough.clone(),
            ProgramError::MissingRequiredSignature,
        ),
        (
            signature.as_slice(),
            advanced,
            passthrough.clone(),
            ProgramError::MissingRequiredSignature,
        ),
    ] {
        // The builder refuses a short signature, so cut it from the data.
        let mut padded = bytes.to_vec();
        padded.resize(WINTERNITZ.signature_len, 0);
        let mut invalid =
            create_rotating_advance_instruction(&WINTERNITZ, &identity, &next_key, &padded);
        invalid
            .data
            .truncate(invalid.data.len() - (WINTERNITZ.signature_len - bytes.len()));
        process_transaction(
            &mollusk,
            &[&invalid, &action],
            &[
                (vector, state.clone()),
                (receiver, Account::new(1_000_000, 0, &Address::default())),
                (other, Account::new(1_000_000, 0, &Address::default())),
            ],
            &[
                Check::err(error),
                Check::account(&vector).data(&state.data).build(),
            ],
        );
    }

    let result = process_transaction(
        &mollusk,
        &[&advance, &passthrough],
        &[
            (vector, account),
            (receiver, Account::new(1_000_000, 0, &Address::default())),
        ],
        &[
            Check::success(),
            Check::account(&vector).data(&expected).build(),
            Check::account(&vector)
                .lamports(lamports - 5_000_000)
                .build(),
            Check::account(&receiver).lamports(6_000_000).build(),
        ],
    );
    println!(
        "winternitz advance + withdraw: {} CUs",
        result.compute_units_consumed
    );
}

/// Signs the advance of `account` (at `nonce`) with `key`, naming `next_key`,
/// and runs it. Returns the result, the account afterwards and the new nonce.
fn advance_with(
    key: &hazmat::winternitz::SecretKey,
    state: &mut u64,
    identity: &[u8],
    account: &Account,
    nonce: &[u8; 32],
    next_key: &[u8],
) -> (TransactionProgramResult, Account, [u8; 32]) {
    let digest =
        rotating_advance_vector_digest(&WINTERNITZ, nonce, identity, next_key, &[], &[], None);
    let signature = key
        .sign_at(
            0,
            &crate::common::signed_hash(&digest),
            crate::rotation::fill(state),
        )
        .unwrap();
    let advance =
        create_rotating_advance_instruction(&WINTERNITZ, identity, next_key, signature.as_bytes());
    // The account is named by the first key, whichever key it holds now.
    let (vector, _) = find_vector_pda(&WINTERNITZ, identity);
    let result = process_transaction(&mollusk(), &[&advance], &[(vector, account.clone())], &[]);
    let after = result.resulting_accounts[0].1.clone();
    (result.program_result, after, digest)
}

/// Known limitation: the program only checks that the next key differs from
/// the current one, so A -> B -> A is accepted and A signs again. The signer
/// must never rotate back to a key it has used.
#[test]
fn rotating_back_to_an_old_key_is_accepted_and_the_signer_must_prevent_it() {
    let mut state = 5;
    let a = hazmat::winternitz::SecretKey::generate(crate::rotation::fill(&mut state)).unwrap();
    let b = hazmat::winternitz::SecretKey::generate(crate::rotation::fill(&mut state)).unwrap();
    let a_key = a.verifying_key().to_bytes();
    let b_key = b.verifying_key().to_bytes();
    let rent = mollusk()
        .sysvars
        .rent
        .minimum_balance(WINTERNITZ.account_len);
    let account = build_vector_account(NONCE, &WINTERNITZ, &a_key, rent, &a_key);

    let (result, account, nonce) = advance_with(&a, &mut state, &a_key, &account, &NONCE, &b_key);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(account.data[76..], b_key);
    let (result, account, nonce) = advance_with(&b, &mut state, &a_key, &account, &nonce, &a_key);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(account.data[76..], a_key);
    // A, which signed once already, is the current key again and signs a
    // second time, naming B.
    let (result, account, _) = advance_with(&a, &mut state, &a_key, &account, &nonce, &b_key);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(account.data[76..], b_key);
}

/// A `next_key` or signature of the wrong length is refused.
#[test]
fn wrong_length_next_key_or_signature_is_refused() {
    let mut state = 6;
    let key = hazmat::winternitz::SecretKey::generate(crate::rotation::fill(&mut state)).unwrap();
    let identity = key.verifying_key().to_bytes();
    let next_key = [7; 41];
    let mollusk = mollusk();
    let (vector, _) = find_vector_pda(&WINTERNITZ, &identity);
    let rent = mollusk.sysvars.rent.minimum_balance(WINTERNITZ.account_len);
    let account = build_vector_account(NONCE, &WINTERNITZ, &identity, rent, &identity);
    let digest =
        rotating_advance_vector_digest(&WINTERNITZ, &NONCE, &identity, &next_key, &[], &[], None);
    let signature = key
        .sign_at(
            0,
            &crate::common::signed_hash(&digest),
            crate::rotation::fill(&mut state),
        )
        .unwrap();
    let advance = create_rotating_advance_instruction(
        &WINTERNITZ,
        &identity,
        &next_key,
        signature.as_bytes(),
    );
    // `[discriminator, valid_until, next_key, signature]`
    let key_end = 9 + WINTERNITZ.next_key_len;
    // Too short a key or signature does not parse. Too long ones leave bytes
    // over, which are refused after the signature is checked; the extra bytes
    // are part of what is signed, so that fails first.
    for (edit, error) in [
        (0, ProgramError::InvalidInstructionData),
        (1, ProgramError::MissingRequiredSignature),
        (2, ProgramError::InvalidInstructionData),
        (3, ProgramError::MissingRequiredSignature),
    ] {
        let mut invalid = advance.clone();
        match edit {
            0 => drop(invalid.data.remove(key_end - 1)),
            1 => invalid.data.insert(key_end, 0),
            2 => drop(invalid.data.pop()),
            _ => invalid.data.push(0),
        }
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
