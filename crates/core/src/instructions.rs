//! Generic instruction builders, scheme-independent. Per-scheme convenience
//! wrappers (e.g. `create_initialize_ed25519`) live in [`crate::schemes`].

use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::scheme::{
    find_vector_pda, Scheme, ADVANCE_DISCRIMINATOR, CLOSE_DISCRIMINATOR,
    INITIALIZE_DISCRIMINATOR, INSTRUCTIONS_SYSVAR_ID, SYSTEM_PROGRAM_ID,
    WITHDRAW_DISCRIMINATOR,
};

/// Build an `initialize` instruction. `init_payload`'s shape is
/// scheme-defined; there is no scheme byte (the program ID identifies it).
///
/// Accounts: `[payer, vector_pda, system_program]`.
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

/// Build an `advance` instruction wrapping `instructions` as a CPI
/// passthrough payload signed by the vector PDA.
pub fn create_advance_instruction(
    scheme: &Scheme,
    identity: &[u8],
    advance_vector_signature: &[u8],
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

    let sig_len = advance_vector_signature.len();
    let payload_len: usize = 1
        + sig_len
        + 1
        + instructions
            .iter()
            .map(|ix| 1 + 2 + ix.data.len())
            .sum::<usize>();
    let mut data = Vec::with_capacity(payload_len);
    data.push(ADVANCE_DISCRIMINATOR);
    data.extend_from_slice(advance_vector_signature);
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

/// Build a `close` instruction suitable for use as a sub-instruction inside
/// an `advance` payload.
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

/// Build a `withdraw` instruction suitable for use as a sub-instruction.
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
