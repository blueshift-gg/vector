//! Shared constants and helpers used by every program's test module.

use mollusk_svm::{
    result::{types::TransactionResult, Check},
    Mollusk,
};
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
use vector_core::{
    advance_vector_digest, create_passthrough_instruction, find_vector_pda, Scheme, VectorAccount,
    PROGRAM_ID,
};

/// Initial nonce used for advance/close digests across the suite.
pub const NONCE: [u8; 32] = [0xff; 32];

/// Test secp256k1 private key (`32 zero bytes || 0x01`). Shared by every
/// secp256k1-based program test module.
pub const SECP256K1_PRIVKEY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Construct a freshly-loaded `Mollusk` instance with the program's ELF.
pub fn mollusk() -> Mollusk {
    Mollusk::new(&PROGRAM_ID, "../target/deploy/vector")
}

/// Run `instructions` as one transaction and check its result. The
/// instructions sysvar then holds all of them with message-level flags, as
/// on a cluster; Mollusk's instruction chains give each instruction a sysvar
/// of its own. The fee payer is an account of none of the instructions and
/// is left out of the resulting accounts.
pub fn process_transaction(
    mollusk: &Mollusk,
    instructions: &[&Instruction],
    accounts: &[(Address, Account)],
    checks: &[Check],
) -> TransactionResult {
    let instructions: Vec<Instruction> = instructions.iter().map(|&ix| ix.clone()).collect();
    let payer = Address::new_unique();
    let mut accounts = accounts.to_vec();
    accounts.push((payer, Account::new(10_000_000_000, 0, &Address::default())));
    let mut result = mollusk.process_and_validate_transaction_instructions(
        &instructions,
        &accounts,
        checks,
        Some(&payer),
    );
    result.resulting_accounts.retain(|(key, _)| *key != payer);
    result
}

/// Build a fully-populated vector account. `stored_identity` is the on-chain
/// identity blob (length `scheme.stored_identity_len`) appended after the
/// 34-byte header.
pub fn build_vector_account(
    nonce: [u8; 32],
    scheme: &Scheme,
    bump: u8,
    lamports: u64,
    stored_identity: &[u8],
) -> Account {
    assert_eq!(stored_identity.len(), scheme.stored_identity_len);
    let mut data = Vec::with_capacity(scheme.account_len());
    data.extend_from_slice(
        &VectorAccount {
            nonce,
            scheme: scheme.id,
            bump,
        }
        .header_bytes(),
    );
    data.extend_from_slice(stored_identity);
    Account {
        lamports,
        data,
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

/// Expected on-chain account data after a successful advance: the 34-byte
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
            scheme: scheme.id,
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
///
/// `sign_advance(nonce, pre, post)` returns just the `advance`
/// `Instruction` signed over the canonical digest. Sub-instruction CPIs
/// (the mint-authority handoff here) live in a separate `passthrough`
/// ix that this helper builds and threads through `post`, so the closure
/// stays signer-only.
pub fn run_round_trip_spl<F>(
    scheme: &Scheme,
    identity: &[u8],
    stored_identity: &[u8],
    sign_advance: F,
) where
    F: Fn(&[u8; 32], &[Instruction], &[Instruction]) -> Instruction,
{
    let mut mollusk = mollusk();
    token::add_program(&mut mollusk);
    mollusk.compute_budget.compute_unit_limit = 1_400_000;

    let (token_program, token_program_account) = keyed_account();
    let (eoa, eoa_account) = (
        Address::new_unique(),
        Account::new(10_000_000_000, 0, &Address::default()),
    );

    let (vector, bump) = find_vector_pda(scheme, identity);
    let vector_account = build_vector_account(
        NONCE,
        scheme,
        bump,
        mollusk.sysvars.rent.minimum_balance(scheme.account_len()),
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

    // Build the passthrough that runs the mint-authority handoff CPI
    // under vector_pda's signer seeds. Order in the tx is
    // `[advance, passthrough, mint_to, eoa_to_pda]`; advance's digest
    // commits to all three post-instructions.
    let passthrough_ix = create_passthrough_instruction(scheme, identity, &[pda_to_eoa_ix]);
    let post_ixs = [
        passthrough_ix.clone(),
        mint_to_ix.clone(),
        eoa_to_pda_ix.clone(),
    ];
    let advance_ix = sign_advance(&NONCE, &[], &post_ixs);

    let next_nonce = advance_vector_digest(scheme, &NONCE, identity, &[], &post_ixs);

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

    let result = process_transaction(
        &mollusk,
        &[&advance_ix, &passthrough_ix, &mint_to_ix, &eoa_to_pda_ix],
        &accounts,
        &[
            Check::success(),
            Check::account(&vector).data(&expected_vector_data).build(),
            Check::account(&mint).data(&expected_mint_data).build(),
        ],
    );
    println!(
        "scheme {} spl-round-trip: {} CUs",
        scheme.id, result.compute_units_consumed
    );
}
