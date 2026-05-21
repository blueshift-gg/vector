//! Generic instruction builders, scheme-independent. Per-scheme convenience
//! wrappers (e.g. `create_initialize_ed25519`) live in [`crate::schemes`].

use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::scheme::{
    find_vector_pda, Scheme, ADVANCE_DISCRIMINATOR, CLOSE_DISCRIMINATOR, INITIALIZE_DISCRIMINATOR,
    INSTRUCTIONS_SYSVAR_ID, PASSTHROUGH_DISCRIMINATOR, SYSTEM_PROGRAM_ID, WITHDRAW_DISCRIMINATOR,
};

/// Build an `initialize` instruction. `init_payload`'s shape is
/// scheme-defined; there is no scheme byte (the program ID identifies it).
///
/// Accounts: `[payer, vector_pda, system_program]`. `system_program` is
/// required — Solana resolves the pinocchio `CreateAccount` CPI by looking
/// up System in the parent program's account_infos (built-in programs are
/// NOT auto-loaded for CPI dispatch).
///
/// Data: `[INITIALIZE_DISCRIMINATOR, ...init_payload]`.
pub fn create_initialize_instruction(
    payer: &Address,
    scheme: &Scheme,
    identity: &[u8],
    init_payload: &[u8],
) -> Instruction {
    assert_eq!(
        identity.len(),
        scheme.identity_len,
        "identity length mismatch",
    );
    let (vector, _bump) = find_vector_pda(scheme, identity);

    let mut data = Vec::with_capacity(1 + init_payload.len());
    data.push(INITIALIZE_DISCRIMINATOR);
    data.extend_from_slice(init_payload);

    Instruction {
        program_id: scheme.program_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(vector, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Build an `advance` instruction — verify the signature and install the
/// digest as the next nonce. No CPI passthrough; pair with
/// [`create_passthrough_instruction`] in the same tx for that.
///
/// Accounts: `[vector_pda(writable), instructions_sysvar]`.
/// Data: `[ADVANCE_DISCRIMINATOR, ...signature]`.
pub fn create_advance_instruction(
    scheme: &Scheme,
    identity: &[u8],
    advance_vector_signature: &[u8],
) -> Instruction {
    let (vector_pda, _bump) = find_vector_pda(scheme, identity);
    let mut data = Vec::with_capacity(1 + advance_vector_signature.len());
    data.push(ADVANCE_DISCRIMINATOR);
    data.extend_from_slice(advance_vector_signature);
    Instruction {
        program_id: scheme.program_id,
        accounts: vec![
            AccountMeta::new(vector_pda, false),
            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),
        ],
        data,
    }
}

/// Build a `passthrough` instruction — replay a batch of CPIs under the
/// vector PDA's signer seeds. Must be paired with a sibling
/// [`create_advance_instruction`] earlier in the same transaction: the
/// on-chain handler scans the instructions sysvar and refuses if it
/// can't find a prior `advance` for the same vector PDA. The sibling
/// advance's signature digest commits to the entire sysvar buffer (minus
/// the sig bytes), so this passthrough's data + account layout are
/// authenticated end-to-end without a second signature here.
///
/// Accounts: `[vector_pda(writable), instructions_sysvar, sub_ix_program,
/// ...sub_ix accounts...]` repeated per sub-instruction.
/// Data: `[PASSTHROUGH_DISCRIMINATOR, num_ixs(u8),
/// {num_accounts(u8), data_len(u16 LE), data}...]`.
pub fn create_passthrough_instruction(
    scheme: &Scheme,
    identity: &[u8],
    instructions: &[Instruction],
) -> Instruction {
    assert!(
        instructions.len() <= u8::MAX as usize,
        "too many sub-instructions (max {})",
        u8::MAX,
    );

    let (vector_pda, _bump) = find_vector_pda(scheme, identity);

    let flattened_accounts: usize = instructions.iter().map(|ix| 1 + ix.accounts.len()).sum();
    let mut accounts = Vec::with_capacity(2 + flattened_accounts);
    accounts.push(AccountMeta::new(vector_pda, false));
    accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false));
    for ix in instructions {
        accounts.push(AccountMeta::new_readonly(ix.program_id, false));
        accounts.extend(ix.accounts.iter().cloned());
    }

    let payload_len: usize = 1
        + 1
        + instructions
            .iter()
            .map(|ix| 1 + 2 + ix.data.len())
            .sum::<usize>();
    let mut data = Vec::with_capacity(payload_len);
    data.push(PASSTHROUGH_DISCRIMINATOR);
    data.push(instructions.len() as u8);
    for ix in instructions {
        assert!(
            ix.accounts.len() <= u8::MAX as usize,
            "sub-instruction has too many accounts (max {})",
            u8::MAX,
        );
        assert!(
            ix.data.len() <= u16::MAX as usize,
            "sub-instruction data is too long (max {} bytes)",
            u16::MAX,
        );
        data.push(ix.accounts.len() as u8);
        data.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
        data.extend_from_slice(&ix.data);
    }
    debug_assert_eq!(data.len(), payload_len);

    Instruction {
        program_id: scheme.program_id,
        accounts,
        data,
    }
}

/// Build a `close` sub-instruction for inclusion in a
/// [`create_passthrough_instruction`] payload. Direct top-level invocation
/// fails the `vector.is_signer()` gate.
pub fn create_close_subinstruction(
    scheme: &Scheme,
    identity: &[u8],
    close_to: &Address,
) -> Instruction {
    let (vector_pda, _bump) = find_vector_pda(scheme, identity);
    Instruction {
        program_id: scheme.program_id,
        accounts: vec![
            AccountMeta::new(vector_pda, false),
            AccountMeta::new(*close_to, false),
        ],
        data: vec![CLOSE_DISCRIMINATOR],
    }
}

/// Build a `withdraw` sub-instruction for inclusion in a
/// [`create_passthrough_instruction`] payload. Same authorisation model as
/// [`create_close_subinstruction`].
pub fn create_withdraw_subinstruction(
    scheme: &Scheme,
    identity: &[u8],
    receiver: &Address,
    lamports: u64,
) -> Instruction {
    let (vector_pda, _bump) = find_vector_pda(scheme, identity);
    let mut data = Vec::with_capacity(1 + 8);
    data.push(WITHDRAW_DISCRIMINATOR);
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: scheme.program_id,
        accounts: vec![
            AccountMeta::new(vector_pda, false),
            AccountMeta::new(*receiver, false),
        ],
        data,
    }
}
