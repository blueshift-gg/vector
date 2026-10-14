//! What a vector account signs: a digest of the transaction, which the
//! program recomputes from the instructions sysvar.

use std::collections::HashMap;

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::Address;
use solana_instruction::{BorrowedAccountMeta, BorrowedInstruction, Instruction};
use solana_instructions_sysvar::construct_instructions_data;

use crate::instructions::{create_multi_advance_instruction, AdvanceSigner};
use crate::scheme::{find_vector_pda, Scheme};

/// Set each account's flags to what the runtime writes in the instructions
/// sysvar: signer or writable if any instruction says so, and the fee payer
/// always both.
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

/// The message every signer of one advance approves: the SHA-256 of the
/// instructions sysvar without the advance's signatures.
///
/// `signers` are the advance's, in order. The advance goes after
/// `pre_instructions`. A passthrough is one of the pre or post instructions,
/// so the message covers it.
///
/// `fee_payer` is as in [`advance_vector_digest`].
pub fn advance_message(
    signers: &[AdvanceSigner],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
) -> [u8; 32] {
    let placeholders: Vec<Vec<u8>> = signers
        .iter()
        .map(|signer| vec![0; signer.scheme.signature_len])
        .collect();
    let signed: Vec<_> = signers
        .iter()
        .zip(&placeholders)
        .map(|(&signer, signature)| (signer, signature.as_slice()))
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
    // u16 data_len + data. The signatures are the end of the data.
    let offset_pos = 2 + 2 * advance_index;
    let offset = u16::from_le_bytes([buffer[offset_pos], buffer[offset_pos + 1]]) as usize;
    let advance = &all[advance_index];
    let data_end = offset + 2 + 33 * advance.accounts.len() + 32 + 2 + advance.data.len();
    let signatures_len: usize = placeholders.iter().map(Vec::len).sum();

    let mut hasher = Sha256::new();
    hasher.update(&buffer[..data_end - signatures_len]);
    hasher.update(&buffer[data_end..]);
    hasher.finalize().into()
}

/// What one signer signs, and the account's next nonce: `SHA256(message ||
/// nonce || vector)`, with `message` from [`advance_message`] and `vector`
/// the signer's account address.
pub fn signer_digest(message: &[u8; 32], nonce: &[u8; 32], vector: &Address) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.update(nonce);
    hasher.update(vector);
    hasher.finalize().into()
}

/// [`signer_digest`] for an advance with one signer, whose key never
/// changes.
///
/// Pass `fee_payer` when it is also an account of one of the instructions:
/// the runtime then marks it a writable signer there, and the digest covers
/// that flag.
pub fn advance_vector_digest(
    scheme: &Scheme,
    nonce: &[u8; 32],
    identity: &[u8],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
) -> [u8; 32] {
    rotating_advance_vector_digest(
        scheme,
        nonce,
        identity,
        &[],
        pre_instructions,
        post_instructions,
        fee_payer,
    )
}

/// [`advance_vector_digest`] for Winternitz and XMSS, whose key rotates.
/// `next_key` is the key that signs next: a Winternitz key must change every
/// time, an XMSS key may stay until its tree runs out. `identity` stays the
/// first key.
pub fn rotating_advance_vector_digest(
    scheme: &Scheme,
    nonce: &[u8; 32],
    identity: &[u8],
    next_key: &[u8],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
) -> [u8; 32] {
    let signer = AdvanceSigner {
        scheme,
        identity,
        next_key,
    };
    let message = advance_message(&[signer], pre_instructions, post_instructions, fee_payer);
    signer_digest(&message, nonce, &find_vector_pda(scheme, identity).0)
}

/// The digest of an advance with nothing around it. Landing that advance only
/// moves the nonce, which cancels everything signed against the old one. It
/// must be the only instruction of its transaction.
pub fn revocation_digest(scheme: &Scheme, nonce: &[u8; 32], identity: &[u8]) -> [u8; 32] {
    advance_vector_digest(scheme, nonce, identity, &[], &[], None)
}
