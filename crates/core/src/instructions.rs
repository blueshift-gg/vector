//! Instruction builders for every scheme. Each scheme's own helpers, such as
//! `create_initialize_ed25519`, are in [`crate::schemes`].

use pinocchio::account::MAX_PERMITTED_DATA_INCREASE;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::scheme::{
    find_system_pda, find_vector_pda, Scheme, ADVANCE_DISCRIMINATOR, CLOSE_DISCRIMINATOR,
    INITIALIZE_DISCRIMINATOR, INSTRUCTIONS_SYSVAR_ID, PASSTHROUGH_DISCRIMINATOR, PROGRAM_ID,
    SYSTEM_PROGRAM_ID, WITHDRAW_DISCRIMINATOR,
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
    let calls = scheme.account_len.div_ceil(MAX_PERMITTED_DATA_INCREASE);
    std::iter::once(first)
        .chain(std::iter::repeat_n(grow, calls - 1))
        .collect()
}

/// One signer of an `advance`: its account, and for a scheme whose key
/// rotates (Winternitz, XMSS), the key that signs next.
#[derive(Clone, Copy, Debug)]
pub struct AdvanceSigner<'a> {
    pub scheme: &'a Scheme,
    /// The key the account was created with.
    pub identity: &'a [u8],
    /// The key that signs next; empty for a scheme whose key never changes.
    pub next_key: &'a [u8],
}

impl<'a> AdvanceSigner<'a> {
    /// A signer whose key never changes.
    pub fn new(scheme: &'a Scheme, identity: &'a [u8]) -> Self {
        Self {
            scheme,
            identity,
            next_key: &[],
        }
    }
}

/// Build an `advance` for one signer, whose key never changes. It verifies
/// the signature and moves the nonce; pair it with
/// [`create_passthrough_instruction`] to act.
pub fn create_advance_instruction(
    scheme: &Scheme,
    identity: &[u8],
    advance_vector_signature: &[u8],
) -> Instruction {
    create_multi_advance_instruction(&[(
        AdvanceSigner::new(scheme, identity),
        advance_vector_signature,
    )])
}

/// [`create_advance_instruction`] for Winternitz and XMSS, whose key
/// rotates: `next_key` is the key that signs next, and the signature covers
/// it (see [`rotating_advance_vector_digest`](crate::rotating_advance_vector_digest)).
/// Persist that signer before authorizing this instruction.
pub fn create_rotating_advance_instruction(
    scheme: &Scheme,
    identity: &[u8],
    next_key: &[u8],
    advance_vector_signature: &[u8],
) -> Instruction {
    let signer = AdvanceSigner {
        scheme,
        identity,
        next_key,
    };
    create_multi_advance_instruction(&[(signer, advance_vector_signature)])
}

/// Build an `advance` for several signers, each with its signature. Every
/// signer signs its own
/// [`signer_digest`](crate::signer_digest) of the one
/// [`advance_message`](crate::advance_message).
///
/// Accounts: `[vector_pda(writable)..., instructions_sysvar]`. Data:
/// `[ADVANCE_DISCRIMINATOR, {next_key, signature}...]`.
pub fn create_multi_advance_instruction(signers: &[(AdvanceSigner, &[u8])]) -> Instruction {
    let mut accounts = Vec::with_capacity(signers.len() + 1);
    let mut data = vec![ADVANCE_DISCRIMINATOR];
    for (signer, signature) in signers {
        assert_eq!(
            signer.next_key.len(),
            signer.scheme.next_key_len,
            "next key length mismatch"
        );
        let (vector, _) = find_vector_pda(signer.scheme, signer.identity);
        accounts.push(AccountMeta::new(vector, false));
        data.extend_from_slice(signer.next_key);
        data.extend_from_slice(signature);
    }
    accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false));
    Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    }
}

/// Who a passthrough signs as: a vector account, or its system PDA
/// ([`find_system_pda`]) for what only a system account can do, such as a
/// System `Transfer`.
#[derive(Clone, Copy, Debug)]
pub struct PassthroughSigner<'a> {
    pub scheme: &'a Scheme,
    /// The key the account was created with.
    pub identity: &'a [u8],
    /// Sign as the account's system PDA instead of the account.
    pub system: bool,
}

impl<'a> PassthroughSigner<'a> {
    /// The vector account signs.
    pub fn vector(scheme: &'a Scheme, identity: &'a [u8]) -> Self {
        Self {
            scheme,
            identity,
            system: false,
        }
    }

    /// The account's system PDA signs.
    pub fn system(scheme: &'a Scheme, identity: &'a [u8]) -> Self {
        Self {
            scheme,
            identity,
            system: true,
        }
    }
}

/// Build a `passthrough` instruction: run `instructions` as the vector
/// account, which signs each of them. It needs an `advance` listing the same
/// account earlier in the transaction ([`create_advance_instruction`]). That
/// advance's signature covers the whole transaction, this instruction
/// included, so there is no second signature here.
pub fn create_passthrough_instruction(
    scheme: &Scheme,
    identity: &[u8],
    instructions: &[Instruction],
) -> Instruction {
    create_multi_passthrough_instruction(
        &[PassthroughSigner::vector(scheme, identity)],
        instructions,
    )
}

/// [`create_passthrough_instruction`], signing as the account's system PDA
/// instead of the account.
pub fn create_system_passthrough_instruction(
    scheme: &Scheme,
    identity: &[u8],
    instructions: &[Instruction],
) -> Instruction {
    create_multi_passthrough_instruction(
        &[PassthroughSigner::system(scheme, identity)],
        instructions,
    )
}

/// Build a `passthrough` for several signers, each a vector account or its
/// system PDA. The transaction's first `advance` must come earlier and list
/// every one of the accounts.
///
/// Accounts: `[instructions_sysvar, vector_pda..., sub_ix_program,
/// ...sub_ix accounts...]` repeated per sub-instruction.
/// Data: `[PASSTHROUGH_DISCRIMINATOR, num_signers(u8), system(u8)...,
/// num_ixs(u8), {num_accounts(u8), data_len(u16 LE), data}...]`.
pub fn create_multi_passthrough_instruction(
    signers: &[PassthroughSigner],
    instructions: &[Instruction],
) -> Instruction {
    assert!(
        signers.len() <= u8::MAX as usize,
        "too many signers (max {})",
        u8::MAX,
    );
    assert!(
        instructions.len() <= u8::MAX as usize,
        "too many sub-instructions (max {})",
        u8::MAX,
    );

    let mut accounts = vec![AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false)];
    let mut data = vec![PASSTHROUGH_DISCRIMINATOR, signers.len() as u8];
    let mut addresses = Vec::with_capacity(signers.len());
    for signer in signers {
        let (vector, _) = find_vector_pda(signer.scheme, signer.identity);
        accounts.push(AccountMeta::new_readonly(vector, false));
        data.push(signer.system as u8);
        addresses.push(if signer.system {
            find_system_pda(&vector).0
        } else {
            vector
        });
    }

    for ix in instructions {
        accounts.push(AccountMeta::new_readonly(ix.program_id, false));
        accounts.extend(ix.accounts.iter().cloned().map(|mut meta| {
            // The program gives the signers their signature during CPI.
            meta.is_signer &= !addresses.contains(&meta.pubkey);
            meta
        }));
    }

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
