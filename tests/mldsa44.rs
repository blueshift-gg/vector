//! ML-DSA-44 tests.
//!
//! The identity is the 1,312-byte public key. The account stores it and the
//! key's 20,544-byte expanded form. Registration is three `initialize`
//! (10,240 bytes: key, row 0; 20,480: rows 1, 2; 21,932: row 3, `tr`), all
//! in one transaction.

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer};
use mollusk_svm::{
    program::keyed_account_for_system_program,
    result::{types::TransactionProgramResult, Check},
};
use solana_account::Account;
use solana_address::Address;
use solana_ml_dsa::ml_dsa_44::VerifyingKey;
use solana_program_error::ProgramError;
use vector_core::{
    advance_vector_digest, create_advance_instruction, create_initialize_mldsa44,
    create_passthrough_instruction, create_withdraw_subinstruction, find_system_pda,
    find_vector_pda, verify_advance_signature, AdvanceSigner, MLDSA44,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, process_transaction, run_round_trip_spl,
    NONCE,
};

/// The per-transaction compute cap registration has to fit.
const TRANSACTION_CU_LIMIT: u64 = 1_400_000;

fn keypair() -> ([u8; MLDSA44.identity_len], ml_dsa_44::PrivateKey) {
    let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
    (pk.into_bytes(), sk)
}

fn sign(digest: &[u8; 32], sk: &ml_dsa_44::PrivateKey) -> [u8; MLDSA44.signature_len] {
    sk.try_sign(&vector_core::signed(digest), &[]).unwrap()
}

fn stored_identity(public_key: &[u8; MLDSA44.identity_len]) -> Vec<u8> {
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
    assert_eq!(MLDSA44.account_len, 21_932);
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
    assert_eq!(data[72..76], [MLDSA44.id, bump, system_bump, 0]);
    assert_eq!(&data[76..], &stored_identity(&pk)[..]);

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
            // Not complete: no account of the program is a vector account
            // unless it is as long as its scheme says.
            mollusk_svm::result::ProgramResult::Failure(ProgramError::InvalidAccountData)
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
        mollusk.sysvars.rent.minimum_balance(MLDSA44.account_len),
        &stored,
    );

    let digest = advance_vector_digest(&MLDSA44, &NONCE, &pk, &[], &[], None);
    let signature = sign(&digest, &sk);
    assert_eq!(
        verify_advance_signature(
            AdvanceSigner::new(&MLDSA44, &pk),
            &NONCE,
            &[],
            &[],
            None,
            &signature
        ),
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
    let wrong_context = sk
        .try_sign(&vector_core::signed(&digest), b"another protocol")
        .unwrap();
    let mut tampered = signature;
    tampered[100] ^= 1;
    for invalid in [tampered, wrong_context] {
        assert_eq!(
            verify_advance_signature(
                AdvanceSigner::new(&MLDSA44, &pk),
                &NONCE,
                &[],
                &[],
                None,
                &invalid
            ),
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
    let pk = [0x44; MLDSA44.identity_len];
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
            241, 93, 190, 173, 130, 226, 43, 101, 34, 114, 115, 217, 165, 19, 221, 182, 239, 113,
            139, 121, 213, 211, 119, 70, 227, 77, 172, 53, 164, 34, 211, 90
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

/// Signature regions: `c_tilde`, `z`, and the hint block (80 indices, then
/// one cumulative count per polynomial).
const Z_START: usize = 32;
const HINT_START: usize = 2336;
const HINT_COUNTS: usize = 2416;

/// An account at `NONCE` and the digest an empty advance on it signs.
struct Rejection {
    mollusk: mollusk_svm::Mollusk,
    pk: [u8; MLDSA44.identity_len],
    sk: ml_dsa_44::PrivateKey,
    vector: Address,
    account: Account,
    digest: [u8; 32],
}

impl Rejection {
    fn new() -> Self {
        let mut mollusk = mollusk();
        mollusk.compute_budget.compute_unit_limit = 400_000;
        let (pk, sk) = keypair();
        let (vector, _) = find_vector_pda(&MLDSA44, &pk);
        let account = build_vector_account(
            NONCE,
            &MLDSA44,
            &pk,
            mollusk.sysvars.rent.minimum_balance(MLDSA44.account_len),
            &stored_identity(&pk),
        );
        let digest = advance_vector_digest(&MLDSA44, &NONCE, &pk, &[], &[], None);
        Self {
            mollusk,
            pk,
            sk,
            vector,
            account,
            digest,
        }
    }

    fn advance(
        &self,
        signature: &[u8; MLDSA44.signature_len],
    ) -> mollusk_svm::result::InstructionResult {
        let ix = create_advance_instruction(&MLDSA44, &self.pk, signature);
        self.mollusk
            .process_instruction(&ix, &[(self.vector, self.account.clone())])
    }

    /// The advance fails and leaves the account as it was.
    fn assert_rejected(&self, signature: &[u8; MLDSA44.signature_len]) {
        let result = self.advance(signature);
        assert_eq!(
            result.program_result,
            mollusk_svm::result::ProgramResult::Failure(ProgramError::MissingRequiredSignature)
        );
        assert_eq!(
            result.resulting_accounts,
            [(self.vector, self.account.clone())]
        );
    }

    /// A signature whose hint block has at least one free index slot.
    fn sign_with_room(&self) -> [u8; MLDSA44.signature_len] {
        loop {
            let signature = sign(&self.digest, &self.sk);
            if signature[HINT_COUNTS + 3] < 80 {
                return signature;
            }
        }
    }
}

#[test]
fn advance_untouched_signature_succeeds() {
    let fixture = Rejection::new();
    let signature = sign(&fixture.digest, &fixture.sk);
    assert_eq!(
        fixture.advance(&signature).program_result,
        mollusk_svm::result::ProgramResult::Success
    );
}

#[test]
fn advance_flipped_bit_in_each_region_fails() {
    let fixture = Rejection::new();
    // c_tilde, the start and end of z, and the hint indices and counts.
    for at in [
        0,
        31,
        Z_START,
        1000,
        HINT_START - 1,
        HINT_START,
        HINT_COUNTS,
        2419,
    ] {
        for bit in [0, 7] {
            let mut signature = sign(&fixture.digest, &fixture.sk);
            signature[at] ^= 1 << bit;
            fixture.assert_rejected(&signature);
        }
    }
}

#[test]
fn advance_signature_over_another_digest_fails() {
    let fixture = Rejection::new();
    fixture.assert_rejected(&sign(&[7; 32], &fixture.sk));
}

#[test]
fn advance_signature_of_another_key_fails() {
    let fixture = Rejection::new();
    let (_, other) = keypair();
    fixture.assert_rejected(&sign(&fixture.digest, &other));
}

#[test]
fn advance_hint_count_above_omega_fails() {
    let fixture = Rejection::new();
    for count in [81, 255] {
        let mut signature = sign(&fixture.digest, &fixture.sk);
        signature[HINT_COUNTS + 3] = count;
        fixture.assert_rejected(&signature);
    }
}

#[test]
fn advance_decreasing_hint_counts_fail() {
    let fixture = Rejection::new();
    // The cumulative count drops from the third polynomial to the last.
    let mut signature = fixture.sign_with_room();
    signature[HINT_COUNTS + 2] = signature[HINT_COUNTS + 3] + 1;
    fixture.assert_rejected(&signature);
}

#[test]
fn advance_nonzero_hint_padding_fails() {
    let fixture = Rejection::new();
    // An index slot after the last counted hint must be zero.
    let mut signature = fixture.sign_with_room();
    let free = HINT_START + signature[HINT_COUNTS + 3] as usize;
    signature[free] = 1;
    fixture.assert_rejected(&signature);
    signature[free] = 0;
    signature[HINT_COUNTS - 1] = 1;
    fixture.assert_rejected(&signature);
}

#[test]
fn initialize_grow_on_complete_account_fails() {
    let mut mollusk = mollusk();
    mollusk.compute_budget.compute_unit_limit = TRANSACTION_CU_LIMIT;
    let (pk, _) = keypair();
    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, _) = find_vector_pda(&MLDSA44, &pk);
    let complete = build_vector_account(
        NONCE,
        &MLDSA44,
        &pk,
        mollusk.sysvars.rent.minimum_balance(MLDSA44.account_len),
        &stored_identity(&pk),
    );
    let accounts = [
        (payer, payer_account),
        (vector, complete),
        (system_program, system_program_account),
    ];
    let register = create_initialize_mldsa44(&payer, &pk);
    // The first call creates the account, which exists; the later ones grow it.
    let first = mollusk.process_instruction(&register[0], &accounts);
    assert_eq!(
        first.program_result,
        mollusk_svm::result::ProgramResult::Failure(ProgramError::AccountAlreadyInitialized)
    );
    assert_eq!(first.resulting_accounts, accounts);
    for grow in &register[1..] {
        let result = mollusk.process_instruction(grow, &accounts);
        assert_eq!(
            result.program_result,
            mollusk_svm::result::ProgramResult::Failure(ProgramError::InvalidAccountData)
        );
        assert_eq!(result.resulting_accounts, accounts);
    }
}

#[test]
fn registration_fills_every_row_and_tr() {
    let mut mollusk = mollusk();
    mollusk.compute_budget.compute_unit_limit = TRANSACTION_CU_LIMIT;
    let (pk, _) = keypair();
    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, _) = find_vector_pda(&MLDSA44, &pk);
    let register = create_initialize_mldsa44(&payer, &pk);
    let result = process_transaction(
        &mollusk,
        &register.iter().collect::<Vec<_>>(),
        &[
            (payer, payer_account),
            (vector, Account::default()),
            (system_program, system_program_account),
        ],
        &[],
    );
    assert_eq!(result.program_result, TransactionProgramResult::Success);
    let data = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == vector)
        .unwrap()
        .1
        .data;

    // After the 76-byte header: the key, four 5,120-byte rows, then `tr`.
    let key = 76..76 + MLDSA44.identity_len;
    assert_eq!(data[key.clone()], pk);
    for row in 0..4 {
        let start = key.end + row * 5120;
        assert!(
            data[start..start + 5120].iter().any(|&b| b != 0),
            "row {row} is empty"
        );
    }
    let tr = &data[data.len() - 64..];
    assert_eq!(key.end + 4 * 5120 + 64, data.len());
    assert!(tr.iter().any(|&b| b != 0));
    // tr = SHAKE256(pk, 64 bytes).
    assert_eq!(
        tr,
        &VerifyingKey::<false>::from_bytes(&pk).public_key_hash()
    );
}
