//! The canonical `advance` digest the client signs and the on-chain program
//! recomputes from the instructions sysvar.

use std::collections::HashMap;

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::Address;
use solana_instruction::{BorrowedAccountMeta, BorrowedInstruction, Instruction};
use solana_instructions_sysvar::construct_instructions_data;

use crate::instructions::create_advance_instruction;
use crate::scheme::Scheme;

/// Promote instruction-level account flags to message-level flags, matching
/// what the Solana runtime writes into the live instructions sysvar: each
/// unique account's `is_signer`/`is_writable` are OR-ed across every
/// top-level instruction, and the transaction's fee payer (always a writable
/// signer at the message level) is folded in when supplied.
///
/// Mirrors `promoteToMessageFlags` in `sdk/ts/src/digest.ts`.
fn promote_to_message_flags(instructions: &mut [Instruction], fee_payer: Option<&Address>) {
    let mut flags: HashMap<Address, (bool, bool)> = HashMap::new();
    if let Some(payer) = fee_payer {
        flags.insert(*payer, (true, true));
    }
    for ix in instructions.iter() {
        for meta in &ix.accounts {
            let entry = flags.entry(meta.pubkey).or_insert((false, false));
            entry.0 |= meta.is_signer;
            entry.1 |= meta.is_writable;
        }
    }
    for ix in instructions.iter_mut() {
        for meta in &mut ix.accounts {
            let (is_signer, is_writable) = flags[&meta.pubkey];
            meta.is_signer = is_signer;
            meta.is_writable = is_writable;
        }
    }
}

/// Compute the canonical `advance_vector_digest` the client must sign over,
/// **exactly as the on-chain program recomputes it from the live
/// instructions sysvar**. This is the mirror of `advanceVectorDigest` in
/// `sdk/ts/src/digest.ts`.
///
/// `digest = SHA256(pre || nonce || identity || post)`, where `pre` and
/// `post` span the entire instructions sysvar buffer minus the scheme's
/// signature region inside the `advance` ix.
///
/// Two runtime behaviours are reproduced before hashing:
///
/// 1. **Message-level flag promotion** — the live sysvar serializes each
///    account's *message-level* `is_signer`/`is_writable` (OR-ed across all
///    top-level instructions), not the per-instruction flags. `fee_payer`,
///    when supplied, participates in this promotion only (it is always a
///    writable signer at the message level): the digest is independent of
///    the fee payer **unless** the fee payer's key appears among the
///    committed instructions' accounts, in which case promotion folds it in.
/// 2. **Sysvar index footer** — the buffer's trailing two bytes hold the
///    runtime's `current_instruction_index`, i.e. the advance's own index
///    (`pre_instructions.len()`), not zero.
///
/// Callers pass the full ix layout via `pre_instructions` /
/// `post_instructions` — the advance ix is inserted at `pre.len()`. Any
/// sibling `passthrough` ix authorising CPIs under the vector PDA's signer
/// seeds is just another pre/post ix; the on-chain `passthrough` handler
/// scans the sysvar to pair with this `advance`, and the digest commits
/// to all of it.
pub fn advance_vector_digest_with_fee_payer(
    scheme: &Scheme,
    nonce: &[u8; 32],
    identity: &[u8],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
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

    promote_to_message_flags(&mut all_owned, fee_payer);

    vector_digest(advance_index, sig_len, nonce, identity, &all_owned)
}

/// [`advance_vector_digest_with_fee_payer`] **without** message-level flag
/// promotion: account flags are hashed exactly as supplied (the sysvar index
/// footer is still patched to the advance's index).
///
/// On a real cluster the live sysvar always carries message-level flags, so
/// prefer [`advance_vector_digest_with_fee_payer`] unless either (a) the
/// supplied flags are already message-consistent, or (b) you are targeting a
/// harness that serializes instruction flags verbatim into the sysvar (e.g.
/// mollusk). When every account's flags agree across the transaction's
/// instructions and the fee payer appears in none of them, the two functions
/// return the same digest.
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
}

/// Shared digest computation for any vector instruction whose data starts
/// with `[discriminator (1), signature (sig_len), ...]`. Hashes
/// `buffer[..sig_start] || nonce || identity || buffer[sig_end..]` over the
/// reconstructed sysvar buffer with its `current_instruction_index` footer
/// patched to `target_index` (what the runtime stores before executing the
/// target instruction — `construct_instructions_data` leaves it zeroed).
fn vector_digest(
    target_index: usize,
    sig_len: usize,
    nonce: &[u8; 32],
    identity: &[u8],
    all_ixs: &[Instruction],
) -> [u8; 32] {
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
    let mut buffer = construct_instructions_data(&borrowed_ixs);

    // Patch the trailing `current_instruction_index` footer to the target's
    // index. The on-chain program hashes the live sysvar, whose footer the
    // runtime sets to the executing instruction's index; the constructed
    // buffer leaves it zeroed, which only matches when the advance is the
    // transaction's first instruction.
    let len = buffer.len();
    buffer[len - 2..].copy_from_slice(&(target_index as u16).to_le_bytes());

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
    let num_accounts = all_ixs[target_index].accounts.len();
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
