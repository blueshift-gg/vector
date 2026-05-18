//! Shared constants and helpers used by every program's test module.

use mollusk_svm::{result::Check, Mollusk};
use mollusk_svm_programs_token::token::{self, keyed_account};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_program_option::COption;
use solana_program_pack::Pack;
use spl_token_interface::{
    instruction::{mint_to, set_authority, AuthorityType},
    state::{Account as TokenAccount, AccountState, Mint},
};
use vector_core::{advance_vector_digest, find_vector_pda, Scheme, VectorAccount, ED25519,
    EIP191, FALCON512, HAWK512, SECP256K1};

/// Initial nonce used for advance/close digests across the suite.
pub const NONCE: [u8; 32] = [0xff; 32];

/// Test secp256k1 private key (`32 zero bytes || 0x01`). Shared by every
/// secp256k1-based program test module.
pub const SECP256K1_PRIVKEY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
];

/// Path (sans `.so`) to a program's built ELF, keyed off its program ID.
fn program_path(scheme: &Scheme) -> &'static str {
    match scheme.program_id {
        id if id == ED25519.program_id => "../target/deploy/vector_ed25519",
        id if id == EIP191.program_id => "../target/deploy/vector_eip191",
        id if id == FALCON512.program_id => "../target/deploy/vector_falcon512",
        id if id == HAWK512.program_id => "../target/deploy/vector_hawk512",
        id if id == SECP256K1.program_id => "../target/deploy/vector_secp256k1",
        _ => panic!("unknown scheme program id"),
    }
}

/// Construct a freshly-loaded `Mollusk` instance pointed at the program ELF
/// for `scheme`.
pub fn mollusk(scheme: &Scheme) -> Mollusk {
    Mollusk::new(&scheme.program_id, program_path(scheme))
}

/// Build a fully-populated vector account. `stored_identity` is the on-chain
/// identity blob (length `scheme.stored_identity_len`) appended after the
/// 33-byte header.
pub fn build_vector_account(
    nonce: [u8; 32],
    scheme: &Scheme,
    bump: u8,
    lamports: u64,
    stored_identity: &[u8],
) -> Account {
    assert_eq!(stored_identity.len(), scheme.stored_identity_len);
    let mut data = Vec::with_capacity(scheme.account_len());
    data.extend_from_slice(&VectorAccount { nonce, bump }.header_bytes());
    data.extend_from_slice(stored_identity);
    Account {
        lamports,
        data,
        owner: scheme.program_id,
        executable: false,
        rent_epoch: 0,
    }
}

/// Expected on-chain account data after a successful advance: the 33-byte
/// header with `nonce = next_nonce` followed by the unchanged identity.
pub fn expected_advanced_data(
    next_nonce: [u8; 32],
    scheme: &Scheme,
    bump: u8,
    stored_identity: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(scheme.account_len());
    out.extend_from_slice(
        &VectorAccount {
            nonce: next_nonce,
            bump,
        }
        .header_bytes(),
    );
    out.extend_from_slice(stored_identity);
    out
}

/// Drive the SPL mint-authority round-trip flow against any program.
///
/// `identity` is the client identity (PDA seed + digest input;
/// `scheme.identity_len`); `stored_identity` is what the account holds
/// (`scheme.stored_identity_len`) — these differ only for Falcon.
/// `sign_advance` returns a ready-to-submit `advance` `Instruction` given the
/// canonical `(nonce, sub_ixs, pre_ixs, post_ixs)`.
pub fn run_round_trip_spl<F>(
    scheme: &Scheme,
    identity: &[u8],
    stored_identity: &[u8],
    sign_advance: F,
) where
    F: Fn(&[u8; 32], &[Instruction], &[Instruction], &[Instruction]) -> Instruction,
{
    let mut mollusk = mollusk(scheme);
    token::add_program(&mut mollusk);
    mollusk.compute_budget.compute_unit_limit = 1_400_000;

    let (token_program, token_program_account) = keyed_account();
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(1_0000_000_000, 0, &Address::default()),
    );

    let (vector, bump) = find_vector_pda(scheme, identity);
    let vector_account = build_vector_account(
        NONCE,
        scheme,
        bump,
        mollusk
            .sysvars
            .rent
            .minimum_balance(scheme.account_len()),
        stored_identity,
    );

    let (mint, mint_account) = (
        Address::new_unique(),
        token::create_account_for_mint(Mint {
            mint_authority: COption::Some(vector),
            supply: 0,
            decimals: 6,
            is_initialized: true,
            freeze_authority: COption::None,
        }),
    );

    let (destination, destination_account) = (
        Address::new_unique(),
        token::create_account_for_token_account(TokenAccount {
            mint,
            owner: Address::new_unique(),
            amount: 0,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        }),
    );

    let pda_to_eoa_ix = set_authority(
        &token::ID,
        &mint,
        Some(&eoa),
        AuthorityType::MintTokens,
        &vector,
        &[],
    )
    .unwrap();
    let mint_to_ix = mint_to(&token::ID, &mint, &destination, &eoa, &[], 10_000).unwrap();
    let eoa_to_pda_ix = set_authority(
        &token::ID,
        &mint,
        Some(&vector),
        AuthorityType::MintTokens,
        &eoa,
        &[],
    )
    .unwrap();

    let advance_ix = sign_advance(
        &NONCE,
        &[pda_to_eoa_ix.clone()],
        &[],
        &[mint_to_ix.clone(), eoa_to_pda_ix.clone()],
    );

    let next_nonce = advance_vector_digest(
        scheme,
        &NONCE,
        identity,
        &[pda_to_eoa_ix],
        &[],
        &[mint_to_ix.clone(), eoa_to_pda_ix.clone()],
    );

    let expected_vector_data = expected_advanced_data(next_nonce, scheme, bump, stored_identity);

    let accounts = vec![
        (vector, vector_account),
        (token_program, token_program_account),
        (mint, mint_account),
        (destination, destination_account),
        (eoa, eoa_account),
    ];

    let mut expected_mint_data = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::Some(vector),
            supply: 10_000,
            decimals: 6,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut expected_mint_data,
    )
    .unwrap();

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (
                &advance_ix,
                &[
                    Check::success(),
                    Check::account(&vector).data(&expected_vector_data).build(),
                ],
            ),
            (&mint_to_ix, &[Check::success()]),
            (
                &eoa_to_pda_ix,
                &[
                    Check::success(),
                    Check::account(&mint).data(&expected_mint_data).build(),
                ],
            ),
        ],
        &accounts,
    );
    println!(
        "{} spl-round-trip: {} CUs",
        scheme.program_id, result.compute_units_consumed
    );
}
