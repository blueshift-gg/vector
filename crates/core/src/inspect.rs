//! Offline inspection + verification of [`Artifact`]s — decode intent and
//! check signatures without a chain connection.
use crate::protocol::encoding::ADVANCE_DISCRIMINATOR;
use crate::scheme::{SchemeMeta, Verifier};
use crate::vector::Artifact;

/// Error returned by [`verify_artifact`] when the artifact cannot be verified.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The artifact's `program_id` is not a scheme compiled into this build.
    #[error("artifact program id is not a supported (compiled-in) scheme")]
    UnsupportedProgram,
    /// The advance instruction, account list, or field lengths are not canonical.
    #[error("artifact is malformed: bad advance instruction, layout, or field length")]
    Malformed,
}

/// Verify the artifact's signature against the digest computed over the
/// REAL instruction layout in hand (not a normalized reconstruction).
///
/// Before verifying, the advance ix is asserted to be the canonical shape
/// and bound to the correct PDA + instructions sysvar: a mutated account
/// list, an advance pointing at the wrong PDA, or trailing bytes after the
/// signature all yield `Err(Malformed)`. This restores the "offline verify
/// == will run on chain" guarantee. Dispatch covers only the compiled-in
/// schemes (feature-gated). Tampered sig => Ok(false); unknown program =>
/// Err(UnsupportedProgram); hostile/malformed bytes => Err(Malformed)
/// (never a panic).
pub fn verify_artifact(a: &Artifact) -> Result<bool, VerifyError> {
    let adv = a
        .instructions
        .get(a.advance_index)
        .ok_or(VerifyError::Malformed)?;
    if adv.data.first() != Some(&ADVANCE_DISCRIMINATOR) {
        return Err(VerifyError::Malformed);
    }

    macro_rules! dispatch {
        ($($feat:literal => $ty:path),* $(,)?) => {{
            $(
                #[cfg(feature = $feat)]
                {
                    if a.program_id == <$ty as SchemeMeta>::PROGRAM_ID {
                        let adv = &a.instructions[a.advance_index];
                        let scheme = <$ty as SchemeMeta>::descriptor();
                        if a.identity.len() != <$ty as SchemeMeta>::IDENTITY_LEN {
                            return Err(VerifyError::Malformed);
                        }
                        if adv.program_id != a.program_id {
                            return Err(VerifyError::Malformed);
                        }
                        if adv.data.len() != 1 + <$ty as SchemeMeta>::SIGNATURE_LEN {
                            return Err(VerifyError::Malformed);
                        }
                        let pda = crate::protocol::pda::find_vector_pda(&scheme, &a.identity).0;
                        if adv.accounts.len() != 2
                            || adv.accounts[0].pubkey != pda
                            || adv.accounts[1].pubkey
                                != crate::protocol::encoding::INSTRUCTIONS_SYSVAR_ID
                        {
                            return Err(VerifyError::Malformed);
                        }
                        let signature = &adv.data[1..];
                        // FAITHFUL digest over the REAL instruction layout
                        // (not a reconstruction):
                        let digest = crate::protocol::digest::vector_digest(
                            a.advance_index,
                            <$ty as SchemeMeta>::SIGNATURE_LEN,
                            &a.nonce,
                            &a.identity,
                            &a.instructions,
                        )
                        .ok_or(VerifyError::Malformed)?;
                        return Ok(<$ty as Verifier>::verify(
                            &a.identity,
                            a.public_key.as_deref(),
                            &digest,
                            signature,
                        ));
                    }
                }
            )*
        }};
    }

    dispatch!(
        "ed25519" => crate::schemes::ed25519::Ed25519,
        "secp256k1" => crate::schemes::secp256k1::Secp256k1,
        "eip191" => crate::schemes::eip191::Eip191,
        "falcon512" => crate::schemes::falcon512::Falcon512,
        "hawk512" => crate::schemes::hawk512::Hawk512,
    );

    Err(VerifyError::UnsupportedProgram)
}

// ── Human-readable inspection ────────────────────────────────────────────────

use crate::protocol::encoding::{
    CLOSE_DISCRIMINATOR, PASSTHROUGH_DISCRIMINATOR, WITHDRAW_DISCRIMINATOR,
};
use solana_address::{address, Address};
use solana_instruction::Instruction;

const SYSTEM_PROGRAM_ID: Address = address!("11111111111111111111111111111111");
const COMPUTE_BUDGET_ID: Address = address!("ComputeBudget111111111111111111111111111111");

fn hex8(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

fn short_addr(a: &Address) -> String {
    let s = a.to_string();
    let chars: Vec<char> = s.chars().collect();
    if chars.len() > 8 {
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[chars.len() - 4..].iter().collect();
        format!("{}…{}", prefix, suffix)
    } else {
        s
    }
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

fn read_u64_le(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
}

/// Summarize a single instruction into a human-readable line.
fn summarize_ix(ix: &Instruction, program_id: &Address) -> String {
    let pid = &ix.program_id;
    let data = ix.data.as_slice();

    // Vector advance instruction — label it; nonce→next_nonce context lives in review()
    if pid == program_id && data.first() == Some(&ADVANCE_DISCRIMINATOR) {
        return format!(
            "advance {}: sig {}B",
            short_addr(program_id),
            data.len().saturating_sub(1)
        );
    }

    // Vector passthrough instruction
    if pid == program_id && data.first() == Some(&PASSTHROUGH_DISCRIMINATOR) {
        let n = data.get(1).copied().unwrap_or(0);
        // Try to decode sub-instructions and label them
        let mut labels: Vec<String> = Vec::new();
        let mut d_off: usize = 2;
        for _ in 0..n {
            let num_accounts = match data.get(d_off) {
                Some(&v) => v as usize,
                None => break,
            };
            let data_len = match read_u16_le(data, d_off + 1) {
                Some(v) => v as usize,
                None => break,
            };
            let sub_data = data.get(d_off + 3..d_off + 3 + data_len).unwrap_or(&[]);
            let label = if num_accounts == 0 && !sub_data.is_empty() {
                format!("sub-ix({}B)", sub_data.len())
            } else {
                match sub_data.first() {
                    Some(&WITHDRAW_DISCRIMINATOR) => {
                        let lamports = read_u64_le(sub_data, 1).unwrap_or(0);
                        format!("withdraw {} lamports", lamports)
                    }
                    Some(&CLOSE_DISCRIMINATOR) => "close".to_string(),
                    _ => format!("sub-ix({}B)", sub_data.len()),
                }
            };
            labels.push(label);
            d_off += 3 + data_len;
        }
        if labels.is_empty() {
            return format!("passthrough: {} sub-instruction(s)", n);
        }
        return format!(
            "passthrough: {} sub-instruction(s) [{}]",
            n,
            labels.join(", ")
        );
    }

    // System Program transfer (instruction tag 2 = transfer, data = [2, 0,0,0,0, lamports(8)])
    // Actually System transfer: discriminant is u32 LE = 2, so bytes [2,0,0,0] then lamports u64
    if pid == &SYSTEM_PROGRAM_ID {
        if let Some(tag) = read_u32_le(data, 0) {
            if tag == 2 && data.len() >= 12 && ix.accounts.len() >= 2 {
                let lamports = read_u64_le(data, 4).unwrap_or(0);
                let from = short_addr(&ix.accounts[0].pubkey);
                let to = short_addr(&ix.accounts[1].pubkey);
                return format!("System transfer {} lamports {} → {}", lamports, from, to);
            }
        }
        let raw_hex = hex8(data);
        return format!("raw {}: {}…", short_addr(pid), raw_hex);
    }

    // ComputeBudget SetComputeUnitLimit (tag 2, data = [2, units_le(4)])
    if pid == &COMPUTE_BUDGET_ID {
        if data.first() == Some(&2u8) && data.len() >= 5 {
            let units = read_u32_le(data, 1).unwrap_or(0);
            return format!("compute budget: set unit limit {}", units);
        }
        let raw_hex = hex8(data);
        return format!("raw {}: {}…", short_addr(pid), raw_hex);
    }

    // Unknown / raw
    let raw_hex = hex8(data);
    format!("raw {}: {}…", short_addr(pid), raw_hex)
}

/// One line per instruction. Known instructions are decoded; unknown ones
/// render as `"raw <programId>: <first 8 hex bytes of data>…"`.
pub fn summarize(a: &Artifact) -> Vec<String> {
    a.instructions
        .iter()
        .map(|ix| summarize_ix(ix, &a.program_id))
        .collect()
}

/// A deterministic multi-line block for human sign-off.
pub fn review(a: &Artifact) -> String {
    let mut lines = vec!["VECTOR ARTIFACT".to_string()];
    lines.push(format!("program: {}", a.program_id));
    lines.push(format!("identity: {}…", hex8(&a.identity)));
    lines.push(format!(
        "nonce: {}… → {}…",
        hex8(&a.nonce),
        hex8(&a.next_nonce)
    ));
    lines.push(match a.fee_payer {
        Some(ref fp) => format!("fee payer: {}", fp),
        None => "fee payer: none".to_string(),
    });
    lines.push("instructions:".to_string());
    for line in summarize(a) {
        lines.push(format!("  - {}", line));
    }
    lines.join("\n")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::schemes::ed25519::Ed25519;
    use crate::vector::{Op, Vector};
    #[test]
    fn verify_accepts_genuine_rejects_tampered() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let art = v.authorize(&[0u8; 32], Op::Inert);
        assert!(verify_artifact(&art).unwrap());
        let mut bad = art.clone();
        bad.instructions[0].data[5] ^= 1; // corrupt a signature byte (in the advance data)
        assert!(!verify_artifact(&bad).unwrap());
    }
    #[test]
    fn unknown_program_is_error() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let mut art = v.authorize(&[0u8; 32], Op::Inert);
        art.program_id = solana_address::address!("11111111111111111111111111111111");
        assert!(verify_artifact(&art).is_err());
    }
    #[test]
    fn summarize_nonempty_for_inert() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let art = v.authorize(&[0u8; 32], Op::Inert);
        assert!(!summarize(&art).is_empty());
    }
    #[test]
    fn rejects_mutated_advance_accounts() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let mut art = v.authorize(&[0u8; 32], Op::Inert);
        // append a bogus extra account to the advance ix -> no longer canonical shape
        art.instructions[0]
            .accounts
            .push(solana_instruction::AccountMeta::new_readonly(
                solana_address::address!("11111111111111111111111111111111"),
                false,
            ));
        assert!(matches!(verify_artifact(&art), Err(VerifyError::Malformed)));
    }
    #[test]
    fn rejects_advance_pointing_at_wrong_pda() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let mut art = v.authorize(&[0u8; 32], Op::Inert);
        art.instructions[0].accounts[0] = solana_instruction::AccountMeta::new(
            solana_address::address!("11111111111111111111111111111111"),
            false,
        );
        assert!(matches!(verify_artifact(&art), Err(VerifyError::Malformed)));
    }
    #[test]
    fn rejects_trailing_bytes_on_advance() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let mut art = v.authorize(&[0u8; 32], Op::Inert);
        art.instructions[0].data.push(0xab); // extra byte after the signature
        assert!(matches!(verify_artifact(&art), Err(VerifyError::Malformed)));
    }
    #[test]
    fn genuine_still_verifies_after_hardening() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let art = v.authorize(&[0u8; 32], Op::Inert);
        assert!(verify_artifact(&art).unwrap());
        // and a withdraw (has a passthrough post-ix) still verifies
        let art2 = v.withdraw(
            &[0u8; 32],
            &solana_address::address!("11111111111111111111111111111111"),
            1,
        );
        assert!(verify_artifact(&art2).unwrap());
    }
}
