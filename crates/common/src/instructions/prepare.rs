use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult, Resize};

use crate::scheme::SigningScheme;
use crate::state::VectorAccount;

/// Round two of a two-step registration (Hawk-512). Run after
/// [`initialize`](super::initialize::process) created the base account and
/// stored the cheap `sha256(wire)` prefix: re-supply the wire pubkey, grow
/// the account to full size, and write the heavy region (Hawk's ~18 KB
/// prepared pubkey) in place.
///
/// Permissionless and idempotent. There is no signature: authorisation is
/// purely [`SigningScheme::prepare`]'s `sha256(payload) == identity[..32]`
/// binding, so a caller can only finish registering the key already
/// committed by `initialize`, never bind a different one. The owner check
/// here is the *only* phase/owner check in the codebase — single-step
/// programs never reach it.
///
/// Accounts: same shape as `initialize` (`[payer, vector, system]`) so the
/// client can submit the *identical* instruction twice; payer/system are
/// unused here.
pub fn process<S: SigningScheme>(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let [_payer, vector, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Only an account this program already created (via `initialize`, which
    // enforced the canonical PDA) can be program-owned, so ownership is the
    // integrity anchor; `S::prepare` then binds the payload to the committed
    // hash.
    if !vector.owned_by(program_id) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    if instruction_data.len() != S::INIT_PAYLOAD_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let full_len = VectorAccount::account_len::<S>();
    if vector.data_len() >= full_len {
        // Already fully registered — idempotent no-op.
        return Ok(());
    }

    // Grow the base allocation to full size (capped at
    // `MAX_PERMITTED_DATA_INCREASE` per instruction; the base chunk is sized
    // so one resize completes it), then fill the heavy region.
    vector.resize(full_len)?;
    let mut data = vector.try_borrow_mut()?;
    let (_, identity_out) = data.split_at_mut(VectorAccount::HEADER_LEN);
    S::prepare(instruction_data, &mut identity_out[..S::IDENTITY_LEN])
}
