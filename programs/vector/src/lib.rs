//! Vector — one program for every signing scheme.
//!
//! Instruction data starts with a discriminator. `0`–`4` are the shared
//! instructions in [`vector_common`]; a scheme may add its own after those
//! (`Rotate` for Winternitz and XMSS, `Expand` for ML-DSA-44).
//!
//! The first account is a vector account, and its header says which
//! [`SigningScheme`] from [`schemes`] handles it. `Initialize` (`0`) has no
//! account yet, so the scheme is the byte after its discriminator. `Advance`
//! (`1`) takes several accounts: see [`advance`].
#![no_std]

use pinocchio::{
    entrypoint, error::ProgramError, nostd_panic_handler, AccountView, Address, ProgramResult,
};
use solana_address::declare_id;
use vector_common::{
    advance_message, dispatch, SigningScheme, VectorAccount, ADVANCE_DISCRIMINATOR,
};

pub mod schemes;
use schemes::{
    ed25519::Ed25519, eip191::Secp256k1Eip191, falcon512::Falcon512, mldsa44::MlDsa44,
    secp256k1::Secp256k1Ecdsa, winternitz::Winternitz, xmss::Xmss,
};

entrypoint!(process_instruction);
nostd_panic_handler!();

declare_id!("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV");

const INITIALIZE_DISCRIMINATOR: u8 = 0;

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let [discriminator, data @ ..] = instruction_data else {
        return Err(ProgramError::InvalidInstructionData);
    };
    match *discriminator {
        ADVANCE_DISCRIMINATOR => advance(program_id, accounts, data),
        // There is no account yet, so the instruction names the scheme.
        INITIALIZE_DISCRIMINATOR => {
            let [scheme, payload @ ..] = data else {
                return Err(ProgramError::InvalidInstructionData);
            };
            route(
                *scheme,
                program_id,
                accounts,
                INITIALIZE_DISCRIMINATOR,
                payload,
            )
        }
        // Everything else acts on a vector account, which says its scheme.
        discriminator => {
            let [vector, ..] = &*accounts else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            let scheme = VectorAccount::scheme(vector, program_id)?;
            route(scheme, program_id, accounts, discriminator, data)
        }
    }
}

/// Run one instruction as `scheme`.
fn route(
    scheme: u8,
    program_id: &Address,
    accounts: &mut [AccountView],
    discriminator: u8,
    data: &[u8],
) -> ProgramResult {
    match scheme {
        Ed25519::ID => dispatch::<Ed25519>(program_id, accounts, discriminator, data),
        Secp256k1Eip191::ID => {
            dispatch::<Secp256k1Eip191>(program_id, accounts, discriminator, data)
        }
        Secp256k1Ecdsa::ID => dispatch::<Secp256k1Ecdsa>(program_id, accounts, discriminator, data),
        Falcon512::ID => dispatch::<Falcon512>(program_id, accounts, discriminator, data),
        MlDsa44::ID => dispatch::<MlDsa44>(program_id, accounts, discriminator, data),
        Winternitz::ID => dispatch::<Winternitz>(program_id, accounts, discriminator, data),
        Xmss::ID => dispatch::<Xmss>(program_id, accounts, discriminator, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Verify one signature per account and install each account's next nonce.
/// Every signer signs the same message: the whole transaction with the
/// signatures cut out. `Advance` runs no CPI — pair it with `Passthrough`.
///
/// Instruction data, after the discriminator: one signature per account, in
/// order, each of its account's scheme's length.
///
/// Accounts:
/// 0..n. `[writable]` vector PDAs, one per signer
/// n.    `[]`         instructions sysvar
fn advance(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [vectors @ .., instructions_sysvar] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if vectors.is_empty() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let message = advance_message(instructions_sysvar)?;

    use vector_common::advance as verify;
    let mut signatures = data;
    for vector in vectors {
        signatures = match VectorAccount::scheme(vector, program_id)? {
            Ed25519::ID => verify::<Ed25519>(vector, &message, signatures),
            Secp256k1Eip191::ID => verify::<Secp256k1Eip191>(vector, &message, signatures),
            Secp256k1Ecdsa::ID => verify::<Secp256k1Ecdsa>(vector, &message, signatures),
            Falcon512::ID => verify::<Falcon512>(vector, &message, signatures),
            MlDsa44::ID => verify::<MlDsa44>(vector, &message, signatures),
            Winternitz::ID => verify::<Winternitz>(vector, &message, signatures),
            Xmss::ID => verify::<Xmss>(vector, &message, signatures),
            _ => Err(ProgramError::InvalidAccountData),
        }?;
    }
    // The cut-out tail must be signatures and nothing else.
    if !signatures.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(())
}
