//! Hawk-512 program tests — three-call registration plus full
//! advance/close/round-trip now that the `hawk512` crate is available as
//! a signer (`solana-hawk512` is still verify-only on-chain).
//!
//! Three-call registration — all three share discriminator `0`, routed by
//! ix shape + vector account state in `programs/hawk512/src/scheme.rs`:
//! 1. `initialize`: commits 32-byte `sha256(wire)`, allocates the ~10 KB
//!    base, prefunds full rent.
//! 2. `store_wire`: verifies `sha256(payload) == stored hash` and stashes
//!    the 1024-byte wire pubkey in the account.
//! 3. `finalize`: resizes to ~18.5 KB and runs `prepare_into` on the
//!    stashed wire (paired with a `set_compute_unit_limit(600_000)` ix so
//!    the per-tx CU budget covers `prepare_into`'s ~410 k draw on the live
//!    validator).
//!
//! The 3-tx split is forced by the 1232-byte tx ceiling: the 1024-byte
//! wire payload can't coexist with the `system_program` meta required by
//! `CreateAccount`, and `finalize`'s heavy CU need can't coexist with the
//! wire payload either. Grief-proof: each step's check (PDA derivation
//! from the hash, sha256 verify in `store_wire`, idempotent `finalize`)
//! means an attacker who squats on any step can't block the legitimate
//! wire owner from completing registration.
//!
//! `advance`/`close`/round-trip exercise the post-prepared account: the
//! stored identity is reconstructed off-chain via
//! `solana_hawk512::Hawk512Pubkey::prepare_into` and signatures are
//! produced by `hawk512::sign` (KAT-validated against the on-chain
//! verifier).

use hawk512::{
    self as hawk, params::PUB_LEN as HAWK_PUB_LEN, xof::RngContext as HawkRngContext, Rng,
};
use mollusk_svm::{program::keyed_account_for_system_program, result::Check};
use solana_account::Account;
use solana_address::Address;
use solana_hawk512::Hawk512Pubkey;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use vector_core::{
    advance_vector_digest, create_advance_instruction, create_close_subinstruction,
    create_hawk512_finalize, create_hawk512_store_wire, create_initialize_hawk512,
    create_passthrough_instruction, create_withdraw_subinstruction, find_vector_pda,
    hawk512_identity, HAWK512, HAWK512_PREPARED_PUBKEY_LEN, HAWK512_WIRE_PUBKEY_LEN,
};

use crate::common::{
    build_vector_account, expected_advanced_data, mollusk, run_round_trip_spl, NONCE,
};

/// A real KAT Hawk-512 wire pubkey (from the `solana-hawk512` reference
/// vectors) — needed so `prepare`'s `prepare_into` decode succeeds. Used by
/// the two-call registration tests, which only need a valid wire pubkey (no
/// secret key); the advance/close tests below generate their own keypair via
/// the `hawk512` signer.
const KAT_PUBKEY: &[u8; HAWK512_WIRE_PUBKEY_LEN] = include_bytes!("fixtures/hawk512_pk.bin");

/// CPI allocation / per-instruction resize cap. `initialize` allocates
/// `min(full, this)` on the first call.
const MAX_PERMITTED_DATA_INCREASE: usize = 10 * 1024;

/// Account offset where the committed `sha256(wire)` lives: right after the
/// 33-byte header.
const HASH_ACCOUNT_OFFSET: usize = 33;

/// `hawk512::Rng` adapter over a continuous `SHAKE256(seed)` squeeze — the
/// same deterministic stream the TS port uses for cross-language KAT
/// reproducibility.
struct SeededRng(HawkRngContext);

impl SeededRng {
    fn new(seed: &[u8]) -> Self {
        Self(HawkRngContext::new(seed))
    }
}

impl Rng for SeededRng {
    fn fill(&mut self, out: &mut [u8]) {
        let v = self.0.random(out.len());
        out.copy_from_slice(&v);
    }
}

/// Generate a deterministic Hawk-512 keypair from a labelled seed. Stable
/// across runs so PDAs are reproducible.
fn hawk_keypair(seed_label: &[u8]) -> (hawk::PublicKey, hawk::SecretKey) {
    let mut rng = SeededRng::new(seed_label);
    hawk::keygen(&mut rng).expect("hawk keygen")
}

/// Reconstruct the on-chain stored identity for a wire pubkey:
/// `sha256(wire)[32] || pad[7] || prepared[18464]`.
fn hawk_stored_identity(wire: &[u8; HAWK_PUB_LEN]) -> Vec<u8> {
    let pk = Hawk512Pubkey::try_from_slice(wire).expect("decode wire");
    let mut prepared = [0u8; HAWK512_PREPARED_PUBKEY_LEN];
    pk.prepare_into(&mut prepared).expect("prepare_into");
    let mut out = Vec::with_capacity(HAWK512.stored_identity_len);
    out.extend_from_slice(&hawk512_identity(wire));
    out.extend_from_slice(&[0u8; 7]);
    out.extend_from_slice(&prepared);
    debug_assert_eq!(out.len(), HAWK512.stored_identity_len);
    out
}

/// Sign one advance with a Hawk secret key; randomness from a labelled seed
/// (signature contents are excluded from the digest, so deterministic-vs-
/// random doesn't affect nonce progression).
fn sign_hawk_advance(
    sk: &hawk::SecretKey,
    nonce: &[u8; 32],
    identity: &[u8],
    pre: &[Instruction],
    post: &[Instruction],
) -> Instruction {
    let digest = advance_vector_digest(&HAWK512, nonce, identity, pre, post);
    let mut rng = SeededRng::new(b"vector-hawk512-sig");
    let sig = hawk::sign(&digest, sk, &mut rng).expect("hawk sign");
    create_advance_instruction(&HAWK512, identity, sig.as_bytes())
}

#[test]
fn first_initialize_commits_hash() {
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

    // Call 1 commits sha256(wire) right after the 33-byte header; the wire
    // pubkey itself doesn't arrive until `store_wire`.
    let acc = result.get_account(&vector).expect("vector account exists");
    let hash_in_account = &acc.data[HASH_ACCOUNT_OFFSET..HASH_ACCOUNT_OFFSET + 32];
    assert_eq!(
        hash_in_account,
        identity.as_slice(),
        "sha256(wire) not committed by call 1"
    );

    println!(
        "hawk512 initialize #1 (base {} B, full {} B): {} CUs",
        base,
        HAWK512.account_len(),
        result.compute_units_consumed
    );
}

#[test]
fn three_call_registration_prepares_account() {
    let mut mollusk = mollusk(&HAWK512);
    mollusk.compute_budget.compute_unit_limit = 1_400_000;
    let identity = hawk512_identity(KAT_PUBKEY);

    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, _bump) = find_vector_pda(&HAWK512, &identity);

    let init_ix = create_initialize_hawk512(&payer, KAT_PUBKEY);
    let store_wire_ix = create_hawk512_store_wire(KAT_PUBKEY);
    let finalize_ix = create_hawk512_finalize(KAT_PUBKEY);
    // 4th call to any registration ix on a fully prepared account fails
    // with `AccountAlreadyInitialized` — callers who hit this almost
    // certainly meant to use `advance` (disc 1) instead.
    let finalize_again_ix = create_hawk512_finalize(KAT_PUBKEY);

    let accounts = vec![
        (payer, payer_account),
        (vector, Account::default()),
        (system_program, system_program_account),
    ];

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&init_ix, &[Check::success()]),       // commit hash + allocate
            (&store_wire_ix, &[Check::success()]), // verify + stash wire
            (&finalize_ix, &[Check::success()]),   // resize + prepare_into
            (
                &finalize_again_ix,
                &[Check::err(ProgramError::AccountAlreadyInitialized)],
            ),
        ],
        &accounts,
    );

    let acc = result.get_account(&vector).expect("vector account exists");
    assert_eq!(acc.data.len(), HAWK512.account_len());
    // Prepared blob lives at header(33) + hash(32) + pad(7) = 72.
    let prepared = &acc.data[33 + 32 + 7..];
    assert_eq!(prepared.len(), HAWK512_PREPARED_PUBKEY_LEN);
    assert!(
        prepared.iter().any(|&b| b != 0),
        "prepared pubkey region still zero after finalize"
    );
    println!(
        "hawk512 init+store_wire+finalize+already-initialized: {} CUs",
        result.compute_units_consumed
    );
}

#[test]
fn store_wire_rejects_mismatched_key() {
    // Init commits sha256(KAT_PUBKEY); driving store_wire with a *different*
    // wire pubkey must fail the `sha256(payload) == committed` check inside
    // the on-chain handler. This is the key-binding that makes the 3-tx
    // flow grief-proof: an attacker who races to init can neither block nor
    // corrupt the stashed wire, because the wire bytes themselves must
    // hash to the committed PDA-seed.
    let mut mollusk = mollusk(&HAWK512);
    mollusk.compute_budget.compute_unit_limit = 1_400_000;
    let identity = hawk512_identity(KAT_PUBKEY);

    let (system_program, system_program_account) = keyed_account_for_system_program();
    let (payer, payer_account) = (
        Address::new_unique(),
        Account::new(1_000_000_000, 0, &system_program),
    );
    let (vector, _bump) = find_vector_pda(&HAWK512, &identity);

    let init_ix = create_initialize_hawk512(&payer, KAT_PUBKEY);
    // Build a store_wire ix targeting the legitimate PDA but with a
    // garbage wire payload. The handler will compute sha256(payload),
    // see it doesn't match the commit, and reject.
    let mut wrong_wire = *KAT_PUBKEY;
    wrong_wire[0] ^= 0xff;
    let wrong_store_wire_ix = {
        // Mirror `create_hawk512_store_wire` but with the wrong wire bytes
        // at the legitimate PDA (so we exercise the hash check, not the
        // PDA-mismatch path). All three registration steps share disc 0;
        // the dispatcher routes by ix shape + vector data length, and a
        // 1-meta ix with non-empty payload on a base-allocated account is
        // store_wire.
        use solana_instruction::AccountMeta;
        let mut data = Vec::with_capacity(1 + HAWK512_WIRE_PUBKEY_LEN);
        data.push(0u8); // INITIALIZE_DISCRIMINATOR (shared across steps)
        data.extend_from_slice(&wrong_wire);
        Instruction {
            program_id: HAWK512.program_id,
            accounts: vec![AccountMeta::new(vector, false)],
            data,
        }
    };

    let accounts = vec![
        (payer, payer_account),
        (vector, Account::default()),
        (system_program, system_program_account),
    ];

    mollusk.process_and_validate_instruction_chain(
        &[
            (&init_ix, &[Check::success()]),
            (
                &wrong_store_wire_ix,
                &[Check::err(ProgramError::InvalidInstructionData)],
            ),
        ],
        &accounts,
    );
}

#[test]
fn advance_empty() {
    let mut mollusk = mollusk(&HAWK512);
    // Hawk advance budget — verify_with_prepared is the cost driver.
    mollusk.compute_budget.compute_unit_limit = 1_400_000;

    let (pk, sk) = hawk_keypair(b"vector-hawk512-test-key");
    let wire: &[u8; HAWK_PUB_LEN] = pk.as_bytes();
    let identity = hawk512_identity(wire);
    let stored = hawk_stored_identity(wire);

    let (vector, bump) = find_vector_pda(&HAWK512, &identity);
    let vector_account = build_vector_account(
        NONCE,
        &HAWK512,
        bump,
        mollusk.sysvars.rent.minimum_balance(HAWK512.account_len()),
        &stored,
    );

    let advance_ix = sign_hawk_advance(&sk, &NONCE, &identity, &[], &[]);
    let next_nonce = advance_vector_digest(&HAWK512, &NONCE, &identity, &[], &[]);
    let expected_vector_data = expected_advanced_data(next_nonce, &HAWK512, bump, &stored);

    let result = mollusk.process_and_validate_instruction_chain(
        &[(
            &advance_ix,
            &[
                Check::success(),
                Check::account(&vector).data(&expected_vector_data).build(),
            ],
        )],
        &[(vector, vector_account)],
    );
    println!("hawk512 advance: {} CUs", result.compute_units_consumed);
}

#[test]
fn advance_round_trips_spl_mint_authority() {
    let (pk, sk) = hawk_keypair(b"vector-hawk512-test-key");
    let wire: &[u8; HAWK_PUB_LEN] = pk.as_bytes();
    let identity = hawk512_identity(wire);
    let stored = hawk_stored_identity(wire);
    run_round_trip_spl(&HAWK512, &identity, &stored, |nonce, pre, post| {
        sign_hawk_advance(&sk, nonce, &identity, pre, post)
    });
}

#[test]
fn close_via_advance() {
    let mut mollusk = mollusk(&HAWK512);
    mollusk.compute_budget.compute_unit_limit = 1_400_000;

    let (pk, sk) = hawk_keypair(b"vector-hawk512-test-key");
    let wire: &[u8; HAWK_PUB_LEN] = pk.as_bytes();
    let identity = hawk512_identity(wire);
    let stored = hawk_stored_identity(wire);

    let vector_lamports = mollusk.sysvars.rent.minimum_balance(HAWK512.account_len());
    let (vector, bump) = find_vector_pda(&HAWK512, &identity);
    let vector_account = build_vector_account(NONCE, &HAWK512, bump, vector_lamports, &stored);

    let eoa_starting_lamports = 10_000_000_000_u64;
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(eoa_starting_lamports, 0, &Address::default()),
    );

    let close_sub = create_close_subinstruction(&HAWK512, &identity, &eoa);
    let passthrough_ix = create_passthrough_instruction(&HAWK512, &identity, &[close_sub]);
    let advance_ix = sign_hawk_advance(
        &sk,
        &NONCE,
        &identity,
        &[],
        std::slice::from_ref(&passthrough_ix),
    );

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
        &[(vector, vector_account), (eoa, eoa_account)],
    );
}

#[test]
fn withdraw_via_advance() {
    let mut mollusk = mollusk(&HAWK512);
    mollusk.compute_budget.compute_unit_limit = 1_400_000;

    let (pk, sk) = hawk_keypair(b"vector-hawk512-test-key");
    let wire: &[u8; HAWK_PUB_LEN] = pk.as_bytes();
    let identity = hawk512_identity(wire);
    let stored = hawk_stored_identity(wire);

    let rent_min = mollusk.sysvars.rent.minimum_balance(HAWK512.account_len());
    let starting_vector_lamports = rent_min + 5_000_000;
    let withdraw_amount = 3_000_000u64;

    let (vector, bump) = find_vector_pda(&HAWK512, &identity);
    let vector_account =
        build_vector_account(NONCE, &HAWK512, bump, starting_vector_lamports, &stored);

    let eoa_starting_lamports = 10_000_000_000_u64;
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(eoa_starting_lamports, 0, &Address::default()),
    );

    let withdraw_sub = create_withdraw_subinstruction(&HAWK512, &identity, &eoa, withdraw_amount);
    let passthrough_ix = create_passthrough_instruction(&HAWK512, &identity, &[withdraw_sub]);
    let advance_ix = sign_hawk_advance(
        &sk,
        &NONCE,
        &identity,
        &[],
        std::slice::from_ref(&passthrough_ix),
    );

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
        &[(vector, vector_account), (eoa, eoa_account)],
    );
}
