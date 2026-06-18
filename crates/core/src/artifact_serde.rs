//! Deterministic JSON wire for [`Artifact`], byte-compatible with the TS SDK.
use crate::vector::Artifact;
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use std::str::FromStr;

fn hex_enc(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn hex_dec(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[derive(Serialize, Deserialize)]
struct WireKey {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
    #[serde(rename = "isWritable")]
    is_writable: bool,
}

#[derive(Serialize, Deserialize)]
struct WireIx {
    #[serde(rename = "programId")]
    program_id: String,
    keys: Vec<WireKey>,
    data: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Wire {
    program_id: String,
    identity: String,
    nonce: String,
    next_nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    advance_index: usize,
    instructions: Vec<WireIx>,
}

/// Deterministic JSON for transport. Equal artifacts → equal bytes.
pub fn serialize_artifact(a: &Artifact) -> String {
    let w = Wire {
        program_id: a.program_id.to_string(),
        identity: hex_enc(&a.identity),
        nonce: hex_enc(&a.nonce),
        next_nonce: hex_enc(&a.next_nonce),
        fee_payer: a.fee_payer.map(|f| f.to_string()),
        public_key: a.public_key.as_ref().map(|p| hex_enc(p)),
        advance_index: a.advance_index,
        instructions: a
            .instructions
            .iter()
            .map(|ix| WireIx {
                program_id: ix.program_id.to_string(),
                keys: ix
                    .accounts
                    .iter()
                    .map(|m| WireKey {
                        pubkey: m.pubkey.to_string(),
                        is_signer: m.is_signer,
                        is_writable: m.is_writable,
                    })
                    .collect(),
                data: hex_enc(&ix.data),
            })
            .collect(),
    };
    serde_json::to_string(&w).expect("serialize artifact")
}

/// Rebuild an [`Artifact`] from [`serialize_artifact`] output.
pub fn deserialize_artifact(json: &str) -> Result<Artifact, String> {
    let w: Wire = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let addr = |s: &str| Address::from_str(s).map_err(|_| format!("bad address {s}"));
    Ok(Artifact {
        program_id: addr(&w.program_id)?,
        identity: hex_dec(&w.identity).ok_or("bad identity hex")?,
        nonce: hex_dec(&w.nonce)
            .and_then(|v| v.try_into().ok())
            .ok_or("bad nonce")?,
        next_nonce: hex_dec(&w.next_nonce)
            .and_then(|v| v.try_into().ok())
            .ok_or("bad next_nonce")?,
        fee_payer: w.fee_payer.map(|s| addr(&s)).transpose()?,
        public_key: w
            .public_key
            .map(|s| hex_dec(&s).ok_or("bad publicKey hex".to_string()))
            .transpose()?,
        advance_index: w.advance_index,
        instructions: w
            .instructions
            .into_iter()
            .map(|ix| {
                Ok::<_, String>(Instruction {
                    program_id: addr(&ix.program_id)?,
                    accounts: ix
                        .keys
                        .into_iter()
                        .map(|k| {
                            Ok::<_, String>(AccountMeta {
                                pubkey: addr(&k.pubkey)?,
                                is_signer: k.is_signer,
                                is_writable: k.is_writable,
                            })
                        })
                        .collect::<Result<_, _>>()?,
                    data: hex_dec(&ix.data).ok_or("bad ix data hex")?,
                })
            })
            .collect::<Result<_, _>>()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::Artifact;
    use solana_address::address;
    use solana_instruction::{AccountMeta, Instruction};

    #[test]
    fn json_roundtrip_and_optional_omitted() {
        let a = Artifact {
            program_id: address!("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV"),
            identity: vec![1, 2, 3],
            nonce: [4u8; 32],
            next_nonce: [5u8; 32],
            fee_payer: None,
            public_key: None,
            advance_index: 0,
            instructions: vec![Instruction {
                program_id: address!("11111111111111111111111111111111"),
                accounts: vec![AccountMeta::new(
                    address!("11111111111111111111111111111111"),
                    true,
                )],
                data: vec![9, 9],
            }],
        };
        let json = serialize_artifact(&a);
        assert!(!json.contains("feePayer")); // None omitted, matches TS
        assert!(json.contains("\"advanceIndex\":0"));
        assert!(json.contains("\"keys\"")); // TS uses `keys`, not `accounts`
        let b = deserialize_artifact(&json).unwrap();
        assert_eq!(b.nonce, a.nonce);
        assert_eq!(b.instructions[0].data, a.instructions[0].data);
    }
}
