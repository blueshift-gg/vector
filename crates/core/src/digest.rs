//! The canonical `advance` digest the client signs and the on-chain program
//! recomputes from the instructions sysvar.

use sha2::{Digest as Sha2Digest, Sha256};
use solana_instruction::{BorrowedAccountMeta, BorrowedInstruction, Instruction};
use solana_instructions_sysvar::construct_instructions_data;

use crate::instructions::create_advance_instruction;
use crate::scheme::Scheme;

/// Compute the canonical `advance_vector_digest` the client must sign over.
///
/// `digest = SHA256(pre || nonce || identity || post)`, where `pre` and
/// `post` span the entire instructions sysvar buffer minus the scheme's
/// signature region.
pub fn advance_vector_digest(
    scheme: &Scheme,
    nonce: &[u8; 32],
    identity: &[u8],
    sub_instructions: &[Instruction],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> [u8; 32] {
    let sig_len = scheme.signature_len;
    let placeholder = vec![0u8; sig_len];
    let advance_ix =
        create_advance_instruction(scheme, identity, &placeholder, sub_instructions);
    vector_digest(
        &advance_ix,
        pre_instructions.len(),
        sig_len,
        nonce,
        identity,
        pre_instructions,
        post_instructions,
    )
}

/// Shared digest computation for any vector instruction whose data starts
/// with `[discriminator (1), signature (sig_len), ...]`. Hashes
/// `buffer[..sig_start] || nonce || identity || buffer[sig_end..]`.
fn vector_digest(
    target_ix: &Instruction,
    target_index: usize,
    sig_len: usize,
    nonce: &[u8; 32],
    identity: &[u8],
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
    // u16 data_len + data. Signature sits right after the 1-byte
    // discriminator.
    let num_accounts = target_ix.accounts.len();
    let sig_start = ix_offset + 2 + 33 * num_accounts + 32 + 2 + 1;
    let sig_end = sig_start + sig_len;

    debug_assert!(sig_end + 2 <= buffer.len());

    let mut hasher = Sha256::new();
    hasher.update(&buffer[..sig_start]);
    hasher.update(nonce);
    hasher.update(identity);
    hasher.update(&buffer[sig_end..]);
    hasher.finalize().into()
}
