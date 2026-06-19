//! Fund-in-PDA migration flow.
//!
//! Ports the TS SDK wallet.ts / migrate.ts builders byte-for-byte.
//! No `spl-token` or `spl-associated-token-account` crates are used to avoid
//! pulling a conflicting `solana-program` version.

use solana_address::{address, Address};
use solana_instruction::{AccountMeta, Instruction};

// ── Program IDs ──────────────────────────────────────────────────────────────

/// SPL Token program address (legacy Token program).
pub const TOKEN_PROGRAM_ID: Address = address!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/// SPL Token-2022 program address.
pub const TOKEN_2022_PROGRAM_ID: Address = address!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Associated Token Account program address.
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Address =
    address!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// Solana System Program address.
pub const SYSTEM_PROGRAM_ID: Address = address!("11111111111111111111111111111111");

// ── ATA derivation ───────────────────────────────────────────────────────────

/// Derive the associated token address for `(mint, owner, token_program)`.
///
/// Seeds: `[owner, token_program, mint]` under `ASSOCIATED_TOKEN_PROGRAM_ID`.
pub fn associated_token_address(
    mint: &Address,
    owner: &Address,
    token_program: &Address,
) -> Address {
    let owner_bytes = owner.to_bytes();
    let tp_bytes = token_program.to_bytes();
    let mint_bytes = mint.to_bytes();
    Address::find_program_address(
        &[&owner_bytes, &tp_bytes, &mint_bytes],
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    )
    .0
}

// ── System-transfer helpers ───────────────────────────────────────────────────

/// System `Transfer` instruction: `payer → pda`, lamports funded by payer.
///
/// Data layout: `[tag: u32 LE = 2][lamports: u64 LE]` (12 bytes).
pub fn create_fund_wallet_instruction(
    payer: &Address,
    pda: &Address,
    lamports: u64,
) -> Instruction {
    system_transfer(payer, true, pda, lamports)
}

/// System `Transfer` instruction: `old_wallet → pda`, signed by old_wallet.
///
/// Identical wire layout to [`create_fund_wallet_instruction`].
pub fn create_migrate_sol_instruction(
    old_wallet: &Address,
    pda: &Address,
    lamports: u64,
) -> Instruction {
    system_transfer(old_wallet, true, pda, lamports)
}

/// Shared System Program transfer builder.
fn system_transfer(from: &Address, from_signer: bool, to: &Address, lamports: u64) -> Instruction {
    let mut data = [0u8; 12];
    data[0..4].copy_from_slice(&2u32.to_le_bytes()); // tag = 2 (Transfer)
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*from, from_signer),
            AccountMeta::new(*to, false),
        ],
        data: data.to_vec(),
    }
}

// ── ATA Create instruction ────────────────────────────────────────────────────

/// Create the ATA for `(pda, mint, token_program)`, funded by `payer`.
///
/// Program: `ASSOCIATED_TOKEN_PROGRAM_ID`, data: `[]`.
/// Account order:
///   `[payer(signer,writable), ata(writable), pda(readonly),
///     mint(readonly), SYSTEM(readonly), token_program(readonly)]`
pub fn create_pda_ata_instruction(
    payer: &Address,
    pda: &Address,
    mint: &Address,
    token_program: &Address,
) -> Instruction {
    let ata = associated_token_address(mint, pda, token_program);
    Instruction {
        program_id: ASSOCIATED_TOKEN_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(*pda, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(*token_program, false),
        ],
        data: vec![],
    }
}

// ── SPL Token instructions ────────────────────────────────────────────────────

/// SPL `Transfer` instruction (discriminator = 3).
///
/// Data layout: `[3u8][amount: u64 LE]` (9 bytes).
/// Accounts: `[source(writable), destination(writable), authority(signer,readonly)]`.
pub fn create_spl_transfer_ix(
    source: &Address,
    destination: &Address,
    authority: &Address,
    amount: u64,
    token_program: &Address,
) -> Instruction {
    let mut data = [0u8; 9];
    data[0] = 3u8;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data: data.to_vec(),
    }
}

/// SPL `SetAuthority` instruction (discriminator = 6).
///
/// Data layout: `[6u8][authority_type: u8][1u8 (COption::Some)][new_authority: 32 bytes]`
/// (35 bytes total).
/// Accounts: `[account(writable), current_authority(signer,readonly)]`.
/// Use `authority_type = 2` for `AccountOwner`.
pub fn create_token_authority_reassignment(
    account: &Address,
    current_authority: &Address,
    new_authority_pda: &Address,
    authority_type: u8,
    token_program: &Address,
) -> Instruction {
    let mut data = [0u8; 35];
    data[0] = 6u8;
    data[1] = authority_type;
    data[2] = 1u8; // COption::Some
    data[3..35].copy_from_slice(&new_authority_pda.to_bytes());
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*current_authority, true),
        ],
        data: data.to_vec(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use solana_address::address;
    const A: Address = address!("11111111111111111111111111111111");
    #[test]
    fn fund_sol_is_system_transfer() {
        let ix = create_fund_wallet_instruction(&A, &A, 5);
        assert_eq!(ix.program_id, SYSTEM_PROGRAM_ID);
        assert_eq!(&ix.data[0..4], &2u32.to_le_bytes());
        assert_eq!(&ix.data[4..12], &5u64.to_le_bytes());
    }
    #[test]
    fn spl_transfer_layout() {
        let ix = create_spl_transfer_ix(&A, &A, &A, 50, &TOKEN_PROGRAM_ID);
        assert_eq!(ix.data[0], 3);
        assert_eq!(&ix.data[1..9], &50u64.to_le_bytes());
        assert_eq!(ix.accounts.len(), 3);
        assert!(ix.accounts[2].is_signer); // authority signs
    }
    #[test]
    fn ata_is_deterministic_and_offcurve() {
        let mint = address!("EvFUfisEScFuZSqDXagC17m3bpP32B74dseMHtzQ5TNb");
        let a = associated_token_address(&mint, &A, &TOKEN_PROGRAM_ID);
        assert_eq!(a, associated_token_address(&mint, &A, &TOKEN_PROGRAM_ID));
        assert_ne!(a, A);
    }
    #[test]
    fn set_authority_layout() {
        let ix = create_token_authority_reassignment(&A, &A, &A, 2, &TOKEN_PROGRAM_ID);
        assert_eq!(ix.data[0], 6);
        assert_eq!(ix.data[1], 2);
        assert_eq!(ix.data[2], 1);
        assert_eq!(ix.data.len(), 35);
    }
}
