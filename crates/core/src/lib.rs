//! Off-chain helpers for constructing vector program instructions and
//! computing the digests the on-chain program will verify.
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use solana_address::{address, Address};
use solana_instruction::{AccountMeta, BorrowedAccountMeta, BorrowedInstruction, Instruction};
use solana_instructions_sysvar::construct_instructions_data;

/// On-chain program ID. Must match `declare_id!` in
/// `programs/vector-program/src/lib.rs`.
pub const VECTOR_PROGRAM_ID: Address = address!("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV");

pub const SYSTEM_PROGRAM_ID: Address = address!("11111111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR_ID: Address = address!("Sysvar1nstructions1111111111111111111111111");

pub const INITIALIZE_DISCRIMINATOR: u8 = 0;
pub const ADVANCE_DISCRIMINATOR: u8 = 1;
pub const CLOSE_DISCRIMINATOR: u8 = 2;

pub const SIGNATURE_LEN: usize = 64;

pub const VECTOR_PDA_SEED: &[u8] = b"vector";

/// Derive the canonical `(vector_pda, bump)` for the given Ed25519 address.
#[inline]
pub fn find_vector_pda(address: &Address) -> (Address, u8) {
    Address::find_program_address(&[VECTOR_PDA_SEED, address.as_ref()], &VECTOR_PROGRAM_ID)
}

/// Host-side mirror of the on-chain `VectorAccount` layout:
/// `seed (32) || address (32) || bump (1)`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorAccount {
    pub seed: [u8; 32],
    pub address: Address,
    pub bump: u8,
}

impl VectorAccount {
    pub const LEN: usize = 65;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];
        bytes[..32].copy_from_slice(&self.seed);
        bytes[32..64].copy_from_slice(&self.address.to_bytes());
        bytes[64] = self.bump;
        bytes
    }

    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Self {
        let mut seed = [0u8; 32];
        let mut address = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        address.copy_from_slice(&bytes[32..64]);
        VectorAccount {
            seed,
            address: address.into(),
            bump: bytes[64],
        }
    }
}

/// Build an `initialize` instruction creating a new vector account at the
/// canonical PDA for `address`. The seed is derived on-chain from the
/// SlotHashes sysvar.
///
/// Accounts: `[payer, vector_pda, system_program]`.
/// Data: `[discriminator, address (32)]`.
pub fn create_initialize_instruction(payer: &Address, address: &Address) -> Instruction {
    let (vector, _bump) = find_vector_pda(address);

    let mut data = Vec::with_capacity(1 + 32);
    data.push(INITIALIZE_DISCRIMINATOR);
    data.extend_from_slice(&address.to_bytes());

    Instruction {
        program_id: VECTOR_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(vector, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Build an `advance` instruction wrapping `instructions` as a CPI passthrough
/// payload signed by the vector PDA.
///
/// Outer accounts: `[vector_pda, instructions_sysvar, ...flattened CPI accounts]`.
/// Each sub-instruction contributes its `program_id` followed by its account
/// metas, in order, without deduplication.
///
/// Data layout:
///
/// ```text
/// [0]       discriminator = ADVANCE_DISCRIMINATOR
/// [1..65]   advance_vector_signature
/// [65]      num_instructions (u8)
/// for each instruction:
///   u8  num_accounts
///   u16 data_len (little endian)
///   [u8; data_len] instruction_data
/// ```
///
/// # Panics
///
/// If more than 255 sub-instructions are supplied, any sub-instruction has
/// more than 255 accounts, or any sub-instruction's data exceeds 65535 bytes.
pub fn create_advance_instruction(
    address: &Address,
    advance_vector_signature: &[u8; SIGNATURE_LEN],
    instructions: &[Instruction],
) -> Instruction {
    assert!(
        instructions.len() <= u8::MAX as usize,
        "too many sub-instructions (max {})",
        u8::MAX,
    );

    let (vector_pda, _bump) = find_vector_pda(address);

    let flattened_accounts: usize = instructions.iter().map(|ix| 1 + ix.accounts.len()).sum();
    let mut accounts = Vec::with_capacity(2 + flattened_accounts);
    accounts.push(AccountMeta::new(vector_pda, false));
    accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false));
    for ix in instructions {
        accounts.push(AccountMeta::new_readonly(ix.program_id, false));
        accounts.extend(ix.accounts.iter().cloned());
    }

    let payload_len: usize = 1
        + SIGNATURE_LEN
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
        program_id: VECTOR_PROGRAM_ID,
        accounts,
        data,
    }
}

/// Compute the canonical `advance_vector_digest` the client must sign over.
///
/// `digest = SHA256(pre || seed || address || post)`, where `pre` and `post`
/// span the entire instructions sysvar buffer minus advance's 64-byte
/// signature region. The signer therefore commits to every top-level
/// instruction in the hosting transaction. The same digest doubles as the
/// next on-chain seed.
pub fn advance_vector_digest(
    seed: &[u8; 32],
    address: &Address,
    sub_instructions: &[Instruction],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> [u8; 32] {
    let placeholder = [0u8; SIGNATURE_LEN];
    let advance_ix = create_advance_instruction(address, &placeholder, sub_instructions);
    vector_digest(
        &advance_ix,
        pre_instructions.len(),
        seed,
        address,
        pre_instructions,
        post_instructions,
    )
}

/// Sign the canonical `advance_vector_digest` and return a ready-to-submit
/// advance instruction. The vector address is derived from `signing_key`.
pub fn sign_advance_instruction(
    signing_key: &SigningKey,
    seed: &[u8; 32],
    sub_instructions: &[Instruction],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> Instruction {
    let address: Address = signing_key.verifying_key().to_bytes().into();
    let digest = advance_vector_digest(
        seed,
        &address,
        sub_instructions,
        pre_instructions,
        post_instructions,
    );
    let advance_vector_signature: [u8; SIGNATURE_LEN] = signing_key.sign(&digest).to_bytes();
    create_advance_instruction(&address, &advance_vector_signature, sub_instructions)
}

/// Build a `close` instruction draining the vector PDA into `close_to`.
///
/// Shares advance's signature scheme; only the discriminator differs.
///
/// Accounts: `[vector_pda, instructions_sysvar, close_to]`.
/// Data: `[CLOSE_DISCRIMINATOR, close_vector_signature (64)]`.
pub fn create_close_instruction(
    address: &Address,
    close_vector_signature: &[u8; SIGNATURE_LEN],
    close_to: &Address,
) -> Instruction {
    let (vector_pda, _bump) = find_vector_pda(address);

    let mut data = Vec::with_capacity(1 + SIGNATURE_LEN);
    data.push(CLOSE_DISCRIMINATOR);
    data.extend_from_slice(close_vector_signature);

    Instruction {
        program_id: VECTOR_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(vector_pda, false),
            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),
            AccountMeta::new(*close_to, false),
        ],
        data,
    }
}

/// Compute the canonical `close_vector_digest`. Mirrors
/// [`advance_vector_digest`] — only the embedded discriminator (2 vs. 1)
/// differs.
pub fn close_vector_digest(
    seed: &[u8; 32],
    address: &Address,
    close_to: &Address,
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> [u8; 32] {
    let placeholder = [0u8; SIGNATURE_LEN];
    let close_ix = create_close_instruction(address, &placeholder, close_to);
    vector_digest(
        &close_ix,
        pre_instructions.len(),
        seed,
        address,
        pre_instructions,
        post_instructions,
    )
}

/// Sign the canonical `close_vector_digest` and return a ready-to-submit
/// close instruction. The vector address is derived from `signing_key`.
pub fn sign_close_instruction(
    signing_key: &SigningKey,
    seed: &[u8; 32],
    close_to: &Address,
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> Instruction {
    let address: Address = signing_key.verifying_key().to_bytes().into();
    let digest = close_vector_digest(
        seed,
        &address,
        close_to,
        pre_instructions,
        post_instructions,
    );
    let close_vector_signature: [u8; SIGNATURE_LEN] = signing_key.sign(&digest).to_bytes();
    create_close_instruction(&address, &close_vector_signature, close_to)
}

/// Shared digest computation for any vector instruction whose data starts
/// with `[discriminator (1), signature (64), ...]`. Builds the full
/// transaction-order instruction list, serializes the sysvar via
/// `construct_instructions_data`, locates the target instruction's signature
/// hole, and hashes
/// `buffer[..sig_start] || seed || address || buffer[sig_end..]`.
fn vector_digest(
    target_ix: &Instruction,
    target_index: usize,
    seed: &[u8; 32],
    address: &Address,
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> [u8; 32] {
    let mut all_ixs: Vec<&Instruction> =
        Vec::with_capacity(pre_instructions.len() + 1 + post_instructions.len());
    all_ixs.extend(pre_instructions.iter());
    all_ixs.push(target_ix);
    all_ixs.extend(post_instructions.iter());

    let borrowed_ixs: Vec<BorrowedInstruction> = all_ixs
        .iter()
        .map(|ix| {
            let accounts = ix
                .accounts
                .iter()
                .map(|meta| BorrowedAccountMeta {
                    pubkey: &meta.pubkey,
                    is_signer: meta.is_signer,
                    is_writable: meta.is_writable,
                })
                .collect();
            BorrowedInstruction {
                program_id: &ix.program_id,
                accounts,
                data: &ix.data,
            }
        })
        .collect();
    let buffer = construct_instructions_data(&borrowed_ixs);

    // Header: num_instructions (u16) + one offset u16 per instruction.
    let ix_offset_pos = 2 + 2 * target_index;
    let ix_offset = u16::from_le_bytes(
        buffer[ix_offset_pos..ix_offset_pos + 2]
            .try_into()
            .expect("vector buffer header truncated"),
    ) as usize;

    // Region: num_accounts (u16) + 33 * N metas + 32-byte program id +
    // u16 data_len + data. Signature sits right after the 1-byte discriminator.
    let num_accounts = target_ix.accounts.len();
    let sig_start = ix_offset + 2 + 33 * num_accounts + 32 + 2 + 1;
    let sig_end = sig_start + SIGNATURE_LEN;

    debug_assert!(sig_end + 2 <= buffer.len());

    let mut hasher = Sha256::new();
    hasher.update(&buffer[..sig_start]);
    hasher.update(seed);
    hasher.update(address.to_bytes());
    hasher.update(&buffer[sig_end..]);
    hasher.finalize().into()
}
