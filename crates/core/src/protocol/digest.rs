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
/// signature region inside the `advance` ix.
///
/// Callers pass the full ix layout via `pre_instructions` /
/// `post_instructions` — the advance ix is inserted at `pre.len()`. Any
/// sibling `passthrough` ix authorising CPIs under the vector PDA's signer
/// seeds is just another pre/post ix; the on-chain `passthrough` handler
/// scans the sysvar to pair with this `advance`, and the digest commits
/// to all of it.
pub fn advance_vector_digest(
    scheme: &Scheme,
    nonce: &[u8; 32],
    identity: &[u8],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> [u8; 32] {
    let sig_len = scheme.signature_len;
    let placeholder = vec![0u8; sig_len];
    let advance_ix = create_advance_instruction(scheme, identity, &placeholder);

    let mut all_owned: Vec<Instruction> =
        Vec::with_capacity(pre_instructions.len() + 1 + post_instructions.len());
    all_owned.extend(pre_instructions.iter().cloned());
    let advance_index = all_owned.len();
    all_owned.push(advance_ix);
    all_owned.extend(post_instructions.iter().cloned());

    vector_digest(advance_index, sig_len, nonce, identity, &all_owned)
        .expect("signing layout is well-formed")
}

/// Shared digest computation for any vector instruction whose data starts
/// with `[discriminator (1), signature (sig_len), ...]`. Hashes
/// `buffer[..sig_start] || nonce || identity || buffer[sig_end..]`.
///
/// This is the FAITHFUL digest: the signature region is carved from the
/// REAL instruction at `target_index` using its actual `accounts.len()`,
/// so it commits to exactly the bytes in hand (not a reconstruction).
///
/// Returns `None` instead of panicking on any out-of-bounds / malformed
/// buffer, so it is safe to call on hostile artifact bytes at the
/// ingestion boundary.
pub(crate) fn vector_digest(
    target_index: usize,
    sig_len: usize,
    nonce: &[u8; 32],
    identity: &[u8],
    all_ixs: &[Instruction],
) -> Option<[u8; 32]> {
    let target_ix = all_ixs.get(target_index)?;
    let num_accounts = target_ix.accounts.len();

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
    let ix_offset_pos = 2usize.checked_add(2usize.checked_mul(target_index)?)?;
    let ix_offset = u16::from_le_bytes(
        buffer
            .get(ix_offset_pos..ix_offset_pos.checked_add(2)?)?
            .try_into()
            .ok()?,
    ) as usize;

    // Region: num_accounts (u16) + 33 * N metas + 32-byte program id +
    // u16 data_len + data. Signature sits right after the 1-byte
    // discriminator.
    let sig_start = ix_offset
        .checked_add(2)?
        .checked_add(33usize.checked_mul(num_accounts)?)?
        .checked_add(32)?
        .checked_add(2)?
        .checked_add(1)?;
    let sig_end = sig_start.checked_add(sig_len)?;

    if sig_start > buffer.len() || sig_end > buffer.len() {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(&buffer[..sig_start]);
    hasher.update(nonce);
    hasher.update(identity);
    hasher.update(&buffer[sig_end..]);
    Some(hasher.finalize().into())
}
