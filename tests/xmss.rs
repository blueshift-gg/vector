//! Exercise the linked XMSS verifier through Vector's SBF authorization flow.

use mollusk_svm::result::types::TransactionProgramResult;
use mollusk_svm::{program::keyed_account_for_system_program, result::Check};
use solana_account::Account;
use solana_address::Address;
use solana_program_error::ProgramError;
use solana_winternitz::{hazmat, xmss};
use vector_core::{
    create_initialize_xmss, create_passthrough_instruction, create_rotating_advance_instruction,
    create_withdraw_subinstruction, find_vector_pda, rotating_advance_vector_digest, VectorError,
    PROGRAM_ID, XMSS,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, process_transaction, xmss_stored, NONCE,
};

#[test]
fn initialize_checks_key_length_and_pda() {
    let mollusk = mollusk();
    let public_key = core::array::from_fn(|i| i as u8);
    let identity = public_key;
    let (system, system_account) = keyed_account_for_system_program();
    let payer = Address::new_unique();
    let (vector, bump) = find_vector_pda(&XMSS, &identity);
    // Shared with sdk/ts/test/xmss.test.ts.
    assert_eq!(
        vector.to_string(),
        "4kd7ArVtukusWaCpQgEZsqabWcnQbB4KjjwYnHVExk7c"
    );
    assert_eq!(bump, 255);
    let receiver = Address::new_from_array([9; 32]);
    let withdraw = create_withdraw_subinstruction(&XMSS, &identity, &receiver, 1234);
    let passthrough = create_passthrough_instruction(&XMSS, &identity, &[withdraw]);
    assert_eq!(
        rotating_advance_vector_digest(
            &XMSS,
            &NONCE,
            &identity,
            &[7; 41],
            &[],
            &[passthrough],
            None
        ),
        [
            29, 105, 205, 166, 164, 7, 39, 200, 172, 179, 152, 231, 49, 141, 198, 123, 174, 2, 190,
            22, 183, 150, 212, 200, 3, 26, 203, 187, 226, 46, 153, 168
        ],
    );
    let accounts = [
        (payer, Account::new(1_000_000_000, 0, &system)),
        (vector, Account::default()),
        (system, system_account),
    ];
    let initialize = create_initialize_xmss(&payer, &public_key);
    let result = mollusk.process_and_validate_instruction(
        &initialize,
        &accounts,
        &[
            Check::success(),
            Check::account(&vector)
                .owner(&PROGRAM_ID)
                .space(XMSS.account_len)
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
    assert_eq!(stored[72..76], [XMSS.id, bump, system_bump, 0]);
    assert_eq!(&stored[76..], &xmss_stored(&public_key, 0));

    // A key of another length has another address, and the scheme refuses it.
    for length in [40, 42] {
        let key = vec![0; length];
        let (address, _) = Address::find_program_address(
            &[b"vector", &[XMSS.id], &vector_core::vector_seed(&key)],
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
    let mut wrong_pda = initialize;
    let other = Address::new_unique();
    wrong_pda.accounts[1].pubkey = other;
    let mut wrong_accounts = accounts;
    wrong_accounts[1].0 = other;
    mollusk.process_and_validate_instruction(
        &wrong_pda,
        &wrong_accounts,
        &[Check::err(ProgramError::InvalidSeeds)],
    );
}

#[test]
fn advance_rejects_replay_wrong_key_and_malformed_signatures() {
    let directory = tempfile::tempdir().unwrap();
    let mut signer = xmss::SigningKey::create(directory.path().join("signer.key")).unwrap();
    let public_key = signer.verifying_key().to_bytes();
    let identity = public_key;
    let stored = xmss_stored(&public_key, 0);
    let mollusk = mollusk();
    let (vector, _) = find_vector_pda(&XMSS, &identity);
    let account = build_vector_account(
        NONCE,
        &XMSS,
        &identity,
        mollusk.sysvars.rent.minimum_balance(XMSS.account_len),
        &stored,
    );
    // The same key next keeps it.
    let digest =
        rotating_advance_vector_digest(&XMSS, &NONCE, &identity, &identity, &[], &[], None);
    let signature = signer.sign(&crate::common::signed_hash(&digest)).unwrap();
    let advance =
        create_rotating_advance_instruction(&XMSS, &identity, &identity, signature.as_bytes());
    // Leaf 0 signed, so leaf 1 is the lowest that may sign next.
    let expected = expected_advanced_data(digest, &XMSS, &identity, &xmss_stored(&public_key, 1));
    let result = mollusk.process_and_validate_instruction_chain(
        &[(
            &advance,
            &[
                Check::success(),
                Check::account(&vector).data(&expected).build(),
            ],
        )],
        &[(vector, account.clone())],
    );
    println!("xmss advance: {} CUs", result.compute_units_consumed);

    // Its leaf has signed, so the same signature cannot land again.
    let mut advanced = account.clone();
    advanced.data = expected.clone();
    mollusk.process_and_validate_instruction_chain(
        &[(
            &advance,
            &[
                Check::err(VectorError::LeafUsed.into()),
                Check::account(&vector).data(&expected).build(),
            ],
        )],
        &[(vector, advanced)],
    );

    // The nonce, the key, and the leaf counter's high byte.
    for (offset, error) in [
        (0, ProgramError::MissingRequiredSignature),
        (76, ProgramError::MissingRequiredSignature),
        (account.data.len() - 1, VectorError::LeafUsed.into()),
    ] {
        let mut changed = account.clone();
        changed.data[offset] ^= 1;
        mollusk.process_and_validate_instruction_chain(
            &[(
                &advance,
                &[
                    Check::err(error),
                    Check::account(&vector).data(&changed.data).build(),
                ],
            )],
            &[(vector, changed.clone())],
        );
    }

    let mut tampered = signature.to_bytes();
    tampered[xmss::SIGNATURE_LEN - 1] ^= 1;
    let mut out_of_range = signature.to_bytes();
    out_of_range[..4].copy_from_slice(&xmss::LEAVES.to_be_bytes());
    for (bytes, error) in [
        (tampered.as_slice(), ProgramError::MissingRequiredSignature),
        (
            out_of_range.as_slice(),
            ProgramError::MissingRequiredSignature,
        ),
        (
            &signature.as_bytes()[..xmss::SIGNATURE_LEN - 1],
            ProgramError::InvalidInstructionData,
        ),
    ] {
        // The builder refuses a short signature, so cut it from the data.
        let mut padded = bytes.to_vec();
        padded.resize(XMSS.signature_len, 0);
        let mut invalid = create_rotating_advance_instruction(&XMSS, &identity, &identity, &padded);
        invalid
            .data
            .truncate(invalid.data.len() - (XMSS.signature_len - bytes.len()));
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

#[test]
fn advance_binds_and_authorizes_withdrawal() {
    let directory = tempfile::tempdir().unwrap();
    let mut signer = xmss::SigningKey::create(directory.path().join("signer.key")).unwrap();
    let public_key = signer.verifying_key().to_bytes();
    let identity = public_key;
    let stored = xmss_stored(&public_key, 0);
    // Abandoned authorizations spend leaves even when no transaction lands.
    signer.sign(&[0; 32]).unwrap();

    let mollusk = mollusk();
    let (vector, _) = find_vector_pda(&XMSS, &identity);
    let rent = mollusk.sysvars.rent.minimum_balance(XMSS.account_len);
    let account = build_vector_account(NONCE, &XMSS, &identity, rent + 5_000_000, &stored);
    let receiver = Address::new_unique();
    let accounts = [
        (vector, account.clone()),
        (receiver, Account::new(1_000_000, 0, &Address::default())),
    ];
    let withdraw = create_withdraw_subinstruction(&XMSS, &identity, &receiver, 3_000_000);
    let passthrough = create_passthrough_instruction(&XMSS, &identity, &[withdraw]);
    let digest = rotating_advance_vector_digest(
        &XMSS,
        &NONCE,
        &identity,
        &identity,
        &[],
        std::slice::from_ref(&passthrough),
        None,
    );
    let signature = signer.sign(&crate::common::signed_hash(&digest)).unwrap();
    assert_eq!(signature.leaf(), 1);
    let advance =
        create_rotating_advance_instruction(&XMSS, &identity, &identity, signature.as_bytes());

    // The signature must bind the downstream action, not just the nonce.
    let changed_withdraw = create_withdraw_subinstruction(&XMSS, &identity, &receiver, 4_000_000);
    let changed = create_passthrough_instruction(&XMSS, &identity, &[changed_withdraw]);
    process_transaction(
        &mollusk,
        &[&advance, &changed],
        &accounts,
        &[
            Check::err(ProgramError::MissingRequiredSignature),
            Check::account(&vector).data(&account.data).build(),
        ],
    );

    // Leaf 0 was abandoned and leaf 1 signed: a signer may skip leaves.
    let expected = expected_advanced_data(digest, &XMSS, &identity, &xmss_stored(&public_key, 2));
    process_transaction(
        &mollusk,
        &[&advance, &passthrough],
        &accounts,
        &[
            Check::success(),
            Check::account(&vector).data(&expected).build(),
            Check::account(&vector).lamports(rent + 2_000_000).build(),
            Check::account(&receiver).lamports(4_000_000).build(),
        ],
    );
}

/// Signs `leaf` of `key` over the advance of `account` (at `nonce`) naming
/// `next_key`, and runs it. Returns the result and the account afterwards.
fn advance_at(
    key: &hazmat::xmss::SecretKey,
    state: &mut u64,
    identity: &[u8],
    leaf: u32,
    account: &Account,
    nonce: &[u8; 32],
    next_key: &[u8],
) -> (TransactionProgramResult, Account, [u8; 32]) {
    let digest = rotating_advance_vector_digest(&XMSS, nonce, identity, next_key, &[], &[], None);
    let signature = key
        .sign_at(
            leaf,
            &crate::common::signed_hash(&digest),
            crate::rotation::fill(state),
        )
        .unwrap();
    let advance =
        create_rotating_advance_instruction(&XMSS, identity, next_key, signature.as_bytes());
    // The account is named by the first key, whichever key it holds now.
    let (vector, _) = find_vector_pda(&XMSS, identity);
    let result = process_transaction(&mollusk(), &[&advance], &[(vector, account.clone())], &[]);
    let after = result.resulting_accounts[0].1.clone();
    (result.program_result, after, digest)
}

/// Known limitation: the program only checks that the next key differs from
/// the current one, so A -> B -> A is accepted and A's leaf counter starts
/// again at 0. A's used leaves can sign a second time; the signer must never
/// rotate back to a key it has used.
#[test]
fn rotating_back_to_an_old_key_reopens_its_leaves_and_the_signer_must_prevent_it() {
    let mut state = 3;
    let a = hazmat::xmss::SecretKey::generate(crate::rotation::fill(&mut state)).unwrap();
    let b = hazmat::xmss::SecretKey::generate(crate::rotation::fill(&mut state)).unwrap();
    let a_key = a.verifying_key().to_bytes();
    let b_key = b.verifying_key().to_bytes();
    let rent = mollusk().sysvars.rent.minimum_balance(XMSS.account_len);
    let account = build_vector_account(NONCE, &XMSS, &a_key, rent, &xmss_stored(&a_key, 0));

    // A signs leaf 0, naming B.
    let (result, account, nonce) = advance_at(&a, &mut state, &a_key, 0, &account, &NONCE, &b_key);
    assert_eq!(result, TransactionProgramResult::Success);
    // B signs leaf 0, naming A again: accepted.
    let (result, account, nonce) = advance_at(&b, &mut state, &a_key, 0, &account, &nonce, &a_key);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(account.data[76..], xmss_stored(&a_key, 0));
    // Leaf 0 of A signs again: it is open once more.
    let (result, account, nonce) = advance_at(&a, &mut state, &a_key, 0, &account, &nonce, &a_key);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(account.data[76..], xmss_stored(&a_key, 1));
    // Only now is leaf 0 used up again.
    let (result, after, _) = advance_at(&a, &mut state, &a_key, 0, &account, &nonce, &a_key);
    assert_eq!(
        result,
        TransactionProgramResult::Failure(0, VectorError::LeafUsed.into())
    );
    assert_eq!(after, account);
}

#[test]
fn skipped_leaves_may_sign_but_never_a_lower_one() {
    let mut state = 4;
    let key = hazmat::xmss::SecretKey::generate(crate::rotation::fill(&mut state)).unwrap();
    let identity = key.verifying_key().to_bytes();
    let rent = mollusk().sysvars.rent.minimum_balance(XMSS.account_len);
    let account = build_vector_account(NONCE, &XMSS, &identity, rent, &xmss_stored(&identity, 0));

    // Leaf 5 first, with the counter at 0.
    let (result, account, nonce) =
        advance_at(&key, &mut state, &identity, 5, &account, &NONCE, &identity);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(account.data[76..], xmss_stored(&identity, 6));
    // Leaf 3 was skipped and is gone for good.
    let (result, after, _) =
        advance_at(&key, &mut state, &identity, 3, &account, &nonce, &identity);
    assert_eq!(
        result,
        TransactionProgramResult::Failure(0, VectorError::LeafUsed.into())
    );
    assert_eq!(after, account);
    // Leaf 6 is the lowest open leaf.
    let (result, account, _) =
        advance_at(&key, &mut state, &identity, 6, &account, &nonce, &identity);
    assert_eq!(result, TransactionProgramResult::Success);
    assert_eq!(account.data[76..], xmss_stored(&identity, 7));
}

#[test]
fn tampered_signature_fields_are_rejected_and_leave_the_account_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let mut signer = xmss::SigningKey::create(directory.path().join("signer.key")).unwrap();
    let identity = signer.verifying_key().to_bytes();
    let mollusk = mollusk();
    let (vector, _) = find_vector_pda(&XMSS, &identity);
    let rent = mollusk.sysvars.rent.minimum_balance(XMSS.account_len);
    // Leaf 0 is abandoned, so the counter is 1 and the signature is leaf 1.
    signer.sign(&[0; 32]).unwrap();
    let account = build_vector_account(NONCE, &XMSS, &identity, rent, &xmss_stored(&identity, 1));
    let digest =
        rotating_advance_vector_digest(&XMSS, &NONCE, &identity, &identity, &[], &[], None);
    let signature = signer
        .sign(&crate::common::signed_hash(&digest))
        .unwrap()
        .to_bytes();
    assert_eq!(signature[..4], 1u32.to_be_bytes());

    // The leaf is a big-endian u32 first, then the 21-byte salt, then the
    // chains, then the authentication path.
    for (offset, error) in [
        // Leaf 1 -> 0: below the counter.
        (3, VectorError::LeafUsed.into()),
        // Leaf 1 -> 3: above the counter, but not the leaf that signed.
        (3 + 0x100, ProgramError::MissingRequiredSignature),
        // Leaf 1 -> 2^24 + 1 and 257: out of the tree.
        (0, ProgramError::MissingRequiredSignature),
        (2, ProgramError::MissingRequiredSignature),
        // The salt.
        (4, ProgramError::MissingRequiredSignature),
        (24, ProgramError::MissingRequiredSignature),
        // The first and the last byte of the authentication path.
        (
            xmss::SIGNATURE_LEN - 8 * 23,
            ProgramError::MissingRequiredSignature,
        ),
        (
            xmss::SIGNATURE_LEN - 1,
            ProgramError::MissingRequiredSignature,
        ),
    ] {
        let mut tampered = signature;
        match offset {
            // Leaf 1 -> 3 by changing its low byte.
            0x103 => tampered[3] ^= 2,
            _ => tampered[offset] ^= 1,
        }
        let advance = create_rotating_advance_instruction(&XMSS, &identity, &identity, &tampered);
        mollusk.process_and_validate_instruction_chain(
            &[(
                &advance,
                &[
                    Check::err(error),
                    Check::account(&vector).data(&account.data).build(),
                ],
            )],
            &[(vector, account.clone())],
        );
    }
}

/// A `next_key` or signature of the wrong length is refused before anything
/// is verified.
#[test]
fn wrong_length_next_key_or_signature_is_invalid_instruction_data() {
    let directory = tempfile::tempdir().unwrap();
    let mut signer = xmss::SigningKey::create(directory.path().join("signer.key")).unwrap();
    let identity = signer.verifying_key().to_bytes();
    let mollusk = mollusk();
    let (vector, _) = find_vector_pda(&XMSS, &identity);
    let rent = mollusk.sysvars.rent.minimum_balance(XMSS.account_len);
    let account = build_vector_account(NONCE, &XMSS, &identity, rent, &xmss_stored(&identity, 0));
    let digest =
        rotating_advance_vector_digest(&XMSS, &NONCE, &identity, &identity, &[], &[], None);
    let signature = signer.sign(&crate::common::signed_hash(&digest)).unwrap();
    let advance =
        create_rotating_advance_instruction(&XMSS, &identity, &identity, signature.as_bytes());
    // `[discriminator, valid_until, next_key, signature]`
    let key_end = 9 + XMSS.next_key_len;
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
