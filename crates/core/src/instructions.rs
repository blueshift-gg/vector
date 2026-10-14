//! Instruction builders for every scheme. Each scheme's own helpers, such as
//! `create_initialize_ed25519`, are in [`crate::schemes`].

use pinocchio::account::MAX_PERMITTED_DATA_INCREASE;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::scheme::{
    find_vector_pda, Scheme, ADVANCE_DISCRIMINATOR, CLOSE_DISCRIMINATOR, INITIALIZE_DISCRIMINATOR,
    INSTRUCTIONS_SYSVAR_ID, PASSTHROUGH_DISCRIMINATOR, PROGRAM_ID, SYSTEM_PROGRAM_ID,
    WITHDRAW_DISCRIMINATOR,
};

/// Build an `initialize` instruction for `identity`, the key the account is
/// created with.
///
/// Accounts: `[payer, vector_pda, system_program]`. The program creates the
/// account through the System program, so it has to be passed.
///
/// Data: `[INITIALIZE_DISCRIMINATOR, scheme, ...identity]`.
pub fn create_initialize_instruction(
    payer: &Address,
    scheme: &Scheme,
    identity: &[u8],
) -> Instruction {
    assert_eq!(
        identity.len(),
        scheme.identity_len,
        "identity length mismatch",
    );
    let (vector, _bump) = find_vector_pda(scheme, identity);

    let mut data = vec![INITIALIZE_DISCRIMINATOR, scheme.id];
    data.extend_from_slice(identity);

    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(vector, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Every `initialize` that creates the account for `identity`: the first
/// carries the key, and each later one grows the account by what one
/// instruction can allocate until it is complete. One instruction for every
/// scheme but ML-DSA-44, which takes three. They fit one transaction.
pub fn create_initialize_instructions(
    payer: &Address,
    scheme: &Scheme,
    identity: &[u8],
) -> Vec<Instruction> {
    let first = create_initialize_instruction(payer, scheme, identity);
    let mut grow = first.clone();
    grow.data.truncate(1);
    let calls = scheme.account_len().div_ceil(MAX_PERMITTED_DATA_INCREASE);
    std::iter::once(first)
        .chain(std::iter::repeat_n(grow, calls - 1))
        .collect()
}

/// Build an `advance` for one signer. It verifies the signature and moves the
/// nonce; pair it with [`create_passthrough_instruction`] to act.
pub fn create_advance_instruction(
    scheme: &Scheme,
    identity: &[u8],
    advance_vector_signature: &[u8],
) -> Instruction {
    create_multi_advance_instruction(&[(scheme, identity, advance_vector_signature)])
}

/// Build an `advance` for several signers, each a `(scheme, identity,
/// signature)`. Every signer signs its own
/// [`signer_digest`](crate::signer_digest) of the one
/// [`advance_message`](crate::advance_message).
///
/// Accounts: `[vector_pda(writable)..., instructions_sysvar]`. Data:
/// `[ADVANCE_DISCRIMINATOR, signature...]`.
pub fn create_multi_advance_instruction(signers: &[(&Scheme, &[u8], &[u8])]) -> Instruction {
    let mut accounts = Vec::with_capacity(signers.len() + 1);
    let mut data = vec![ADVANCE_DISCRIMINATOR];
    for (scheme, identity, _) in signers {
        accounts.push(AccountMeta::new(find_vector_pda(scheme, identity).0, false));
    }
    accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false));
    for (_, _, signature) in signers {
        data.extend_from_slice(signature);
    }
    Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    }
}

/// Build a `passthrough` instruction: run `instructions` as the vector
/// account, which signs each of them. It needs an `advance` for the same
/// account earlier in the transaction ([`create_advance_instruction`]). That
/// advance's signature covers the whole transaction, this instruction
/// included, so there is no second signature here.
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
    assert_eq!(
        scheme.next_key_len, 0,
        "this scheme's key rotates: use create_rotating_passthrough_instruction",
    );
    passthrough_instruction(scheme, identity, instructions)
}

/// [`create_passthrough_instruction`] for Winternitz and XMSS, whose key
/// rotates. `next_public_key` is the key that signs the next transaction; it
/// follows the discriminator and is covered by the signature like the rest.
/// Persist that signer before authorizing this instruction. `identity` stays
/// the first key.
///
/// A Winternitz key signs once, so it must be replaced every time. An XMSS
/// key may be kept with `None` until its tree runs out.
pub fn create_rotating_passthrough_instruction(
    scheme: &Scheme,
    identity: &[u8],
    next_public_key: Option<&[u8]>,
    instructions: &[Instruction],
) -> Instruction {
    assert_ne!(scheme.next_key_len, 0, "this scheme's key does not rotate");
    let mut prefix = Vec::new();
    if scheme.next_key_optional {
        prefix.push(next_public_key.is_some() as u8);
    } else {
        assert!(next_public_key.is_some(), "this scheme's key signs once");
    }
    if let Some(key) = next_public_key {
        assert_eq!(key.len(), scheme.next_key_len, "next key length mismatch");
        prefix.extend_from_slice(key);
    }
    let mut instruction = passthrough_instruction(scheme, identity, instructions);
    instruction.data.splice(1..1, prefix);
    instruction
}

fn passthrough_instruction(
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
        accounts.extend(ix.accounts.iter().cloned().map(|mut meta| {
            // The PDA receives its signer privilege during CPI.
            meta.is_signer &= meta.pubkey != vector_pda;
            meta
        }));
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
        program_id: PROGRAM_ID,
        accounts,
        data,
    }
}

/// Build a `close` instruction to run inside a
/// [`create_passthrough_instruction`]. On its own it fails: only a
/// passthrough makes the vector account a signer.
pub fn create_close_subinstruction(
    scheme: &Scheme,
    identity: &[u8],
    close_to: &Address,
) -> Instruction {
    let (vector_pda, _bump) = find_vector_pda(scheme, identity);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(vector_pda, false),
            AccountMeta::new(*close_to, false),
        ],
        data: vec![CLOSE_DISCRIMINATOR],
    }
}

/// Build a `withdraw` instruction to run inside a
/// [`create_passthrough_instruction`], like [`create_close_subinstruction`].
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
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(vector_pda, false),
            AccountMeta::new(*receiver, false),
        ],
        data,
    }
}
