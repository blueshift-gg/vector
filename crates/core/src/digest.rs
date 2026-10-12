//! What a vector account signs: a digest of the transaction, which the
//! program recomputes from the instructions sysvar.

use std::collections::HashMap;

use sha2::{Digest as Sha2Digest, Sha256};
use solana_address::Address;
use solana_instruction::{BorrowedAccountMeta, BorrowedInstruction, Instruction};
use solana_instructions_sysvar::construct_instructions_data;

use crate::instructions::create_multi_advance_instruction;
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
/// `signers` are the advance's `(scheme, identity)` pairs, in order. The
/// advance goes after `pre_instructions`. A passthrough is one of the pre or
/// post instructions, so the message covers it.
///
/// `fee_payer` only matters when it is also an account of one of the
/// instructions: the sysvar then shows it as a writable signer there.
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
    // u16 data_len + data. The signatures are the data after the
    // discriminator.
    let offset_pos = 2 + 2 * advance_index;
    let offset = u16::from_le_bytes([buffer[offset_pos], buffer[offset_pos + 1]]) as usize;
    let advance = &all[advance_index];
    let data_start = offset + 2 + 33 * advance.accounts.len() + 32 + 2;
    let signatures_start = data_start + 1;
    let data_end = data_start + advance.data.len();

    let mut hasher = Sha256::new();
    hasher.update(&buffer[..signatures_start]);
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

/// [`signer_digest`] for an advance with one signer.
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
    signer_digest(&message, nonce, &find_vector_pda(scheme, identity).0)
}

/// [`advance_vector_digest_with_fee_payer`] without a fee payer: use it when
/// the fee payer is not an account of any instruction.
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

/// The digest of an advance with nothing around it. Landing that advance only
/// moves the nonce, which cancels everything signed against the old one. It
/// must be the only instruction of its transaction.
pub fn revocation_digest(scheme: &Scheme, nonce: &[u8; 32], identity: &[u8]) -> [u8; 32] {
    advance_vector_digest(scheme, nonce, identity, &[], &[])
}
