//! The canonical `advance` digest the client signs and the on-chain program
//! recomputes from the instructions sysvar.

use std::collections::HashMap;

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::Address;
use solana_instruction::{BorrowedAccountMeta, BorrowedInstruction, Instruction};
use solana_instructions_sysvar::construct_instructions_data;

use crate::instructions::create_multi_advance_instruction;
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

/// The message every signer of one `advance` approves, **exactly as the
/// on-chain program recomputes it from the live instructions sysvar**: the
/// SHA-256 of the sysvar with the signatures cut off the end of the advance's
/// data. Mirrors `advanceMessage` in `sdk/ts/src/digest.ts`.
///
/// `signers` are the advance's `(scheme, identity)` pairs, in order. The
/// advance is inserted at `pre_instructions.len()`; a sibling `passthrough`
/// is just another pre/post instruction, and the message covers all of it.
///
/// Two runtime behaviours are reproduced before hashing:
///
/// 1. **Message-level flag promotion** — the live sysvar serializes each
///    account's *message-level* `is_signer`/`is_writable` (OR-ed across all
///    top-level instructions), not the per-instruction flags. `fee_payer`,
///    when supplied, participates in this promotion only (it is always a
///    writable signer at the message level): the message is independent of
///    the fee payer **unless** the fee payer's key appears among the
///    committed instructions' accounts, in which case promotion folds it in.
/// 2. **Sysvar index footer** — the buffer's trailing two bytes hold the
///    runtime's `current_instruction_index`, i.e. the advance's own index
///    (`pre_instructions.len()`), not zero.
pub fn advance_message(
    signers: &[(&Scheme, &[u8])],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
) -> [u8; 32] {
    let placeholders: Vec<Vec<u8>> = signers
        .iter()
        .map(|(scheme, _)| vec![0; scheme.signature_len])
        .collect();
    let signed: Vec<_> = signers
        .iter()
        .zip(&placeholders)
        .map(|(&(scheme, identity), signature)| (scheme, identity, signature.as_slice()))
        .collect();

    let mut all: Vec<Instruction> = pre_instructions.to_vec();
    let advance_index = all.len();
    all.push(create_multi_advance_instruction(&signed));
    all.extend_from_slice(post_instructions);
    promote_to_message_flags(&mut all, fee_payer);

    let borrowed: Vec<BorrowedInstruction> = all
        .iter()
        .map(|ix| BorrowedInstruction {
            program_id: &ix.program_id,
            accounts: ix
                .accounts
                .iter()
                .map(|meta| BorrowedAccountMeta {
                    pubkey: &meta.pubkey,
                    is_signer: meta.is_signer,
                    is_writable: meta.is_writable,
                })
                .collect(),
            data: &ix.data,
        })
        .collect();
    let mut buffer = construct_instructions_data(&borrowed);

    // The runtime sets the footer to the executing instruction's index; the
    // constructed buffer leaves it zeroed.
    let len = buffer.len();
    buffer[len - 2..].copy_from_slice(&(advance_index as u16).to_le_bytes());

    // Header: num_instructions (u16) + one offset u16 per instruction.
    // Region: num_accounts (u16) + 33 * N metas + 32-byte program id +
    // u16 data_len + data. The signatures follow the discriminator and one
    // scheme byte per signer, and run to the end of the data.
    let offset_pos = 2 + 2 * advance_index;
    let offset = u16::from_le_bytes([buffer[offset_pos], buffer[offset_pos + 1]]) as usize;
    let advance = &all[advance_index];
    let data_start = offset + 2 + 33 * advance.accounts.len() + 32 + 2;
    let signatures_start = data_start + 1 + signers.len();
    let data_end = data_start + advance.data.len();

    let mut hasher = Sha256::new();
    hasher.update(&buffer[..signatures_start]);
    hasher.update(&buffer[data_end..]);
    hasher.finalize().into()
}

/// What one signer signs: `SHA256(message || nonce || identity)`, with
/// `message` from [`advance_message`]. The message is shared by every signer
/// of the advance; the nonce and identity make the digest this signer's own.
/// It is also the account's next nonce. Mirrors `signerDigest` in
/// `sdk/ts/src/digest.ts`.
pub fn signer_digest(message: &[u8; 32], nonce: &[u8; 32], identity: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.update(nonce);
    hasher.update(identity);
    hasher.finalize().into()
}

/// [`signer_digest`] for an advance with one signer. Mirrors
/// `advanceVectorDigest` in `sdk/ts/src/digest.ts`.
pub fn advance_vector_digest_with_fee_payer(
    scheme: &Scheme,
    nonce: &[u8; 32],
    identity: &[u8],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
) -> [u8; 32] {
    let message = advance_message(
        &[(scheme, identity)],
        pre_instructions,
        post_instructions,
        fee_payer,
    );
    signer_digest(&message, nonce, identity)
}

/// [`advance_vector_digest_with_fee_payer`] for a fee payer that is not among
/// the committed instructions' accounts, where it has no effect on the
/// digest. Mirrors `advanceVectorDigest` without `feePayer` in
/// `sdk/ts/src/digest.ts`.
pub fn advance_vector_digest(
    scheme: &Scheme,
    nonce: &[u8; 32],
    identity: &[u8],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
) -> [u8; 32] {
    advance_vector_digest_with_fee_payer(
        scheme,
        nonce,
        identity,
        pre_instructions,
        post_instructions,
        None,
    )
}

/// The digest a pre-signed revocation commits to: [`advance_vector_digest`]
/// with empty pre/post instructions. The resulting advance is an inert
/// transition — landing it only installs the next nonce, orphaning every
/// signature pre-signed against `nonce` (a kill-switch).
///
/// This digest commits to the instructions sysvar of the broadcasting
/// transaction, so a pre-signed revocation must be broadcast as a
/// transaction containing ONLY the advance instruction. ed25519 / eip191 /
/// secp256k1 inert advances fit the default compute budget (~13k / ~26k /
/// ~72k CUs); for Falcon-512, sign via the advance signer with a
/// compute-budget pre-instruction committed at sign time (its ~184k CU
/// verify leaves no headroom under the 200k default).
pub fn revocation_digest(scheme: &Scheme, nonce: &[u8; 32], identity: &[u8]) -> [u8; 32] {
    advance_vector_digest(scheme, nonce, identity, &[], &[])
}
