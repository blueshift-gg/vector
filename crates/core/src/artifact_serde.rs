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

/// Why an artifact JSON failed to decode.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeserializeError {
    /// The outer JSON is malformed or has an unexpected structure.
    #[error("invalid artifact JSON: {0}")]
    Json(String),
    /// A field that must contain a lowercase hex string has invalid hex.
    #[error("invalid hex in field `{0}`")]
    Hex(&'static str),
    /// A field that must contain a base58 Solana address failed to parse.
    #[error("invalid base58 address: `{0}`")]
    Address(String),
    /// A decoded byte buffer has the wrong length for its field.
    #[error("field `{0}` has the wrong byte length")]
    Length(&'static str),
}

/// Rebuild an [`Artifact`] from [`serialize_artifact`] output.
pub fn deserialize_artifact(json: &str) -> Result<Artifact, DeserializeError> {
    let w: Wire = serde_json::from_str(json).map_err(|e| DeserializeError::Json(e.to_string()))?;
    let addr = |s: &str| Address::from_str(s).map_err(|_| DeserializeError::Address(s.to_string()));
    Ok(Artifact {
        program_id: addr(&w.program_id)?,
        identity: hex_dec(&w.identity).ok_or(DeserializeError::Hex("identity"))?,
        nonce: hex_dec(&w.nonce)
            .ok_or(DeserializeError::Hex("nonce"))?
            .try_into()
            .map_err(|_| DeserializeError::Length("nonce"))?,
        next_nonce: hex_dec(&w.next_nonce)
            .ok_or(DeserializeError::Hex("nextNonce"))?
            .try_into()
            .map_err(|_| DeserializeError::Length("nextNonce"))?,
        fee_payer: w.fee_payer.map(|s| addr(&s)).transpose()?,
        public_key: w
            .public_key
            .map(|s| hex_dec(&s).ok_or(DeserializeError::Hex("publicKey")))
            .transpose()?,
        advance_index: w.advance_index,
        instructions: w
            .instructions
            .into_iter()
            .map(|ix| {
                Ok::<_, DeserializeError>(Instruction {
                    program_id: addr(&ix.program_id)?,
                    accounts: ix
                        .keys
                        .into_iter()
                        .map(|k| {
                            Ok::<_, DeserializeError>(AccountMeta {
                                pubkey: addr(&k.pubkey)?,
                                is_signer: k.is_signer,
                                is_writable: k.is_writable,
                            })
                        })
                        .collect::<Result<_, _>>()?,
                    data: hex_dec(&ix.data).ok_or(DeserializeError::Hex("data"))?,
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

    /// Build a minimal valid Artifact for serde tests.
    fn minimal_artifact() -> Artifact {
        Artifact {
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
        }
    }

    #[test]
    fn json_roundtrip_and_optional_omitted() {
        let a = minimal_artifact();
        let json = serialize_artifact(&a);
        assert!(!json.contains("feePayer")); // None omitted, matches TS
        assert!(json.contains("\"advanceIndex\":0"));
        assert!(json.contains("\"keys\"")); // TS uses `keys`, not `accounts`
        let b = deserialize_artifact(&json).unwrap();
        assert_eq!(b.nonce, a.nonce);
        assert_eq!(b.instructions[0].data, a.instructions[0].data);
    }

    // ── Robustness / adversarial deserialization tests ───────────────────────

    #[test]
    fn rejects_invalid_json() {
        assert!(matches!(
            deserialize_artifact("{not valid json"),
            Err(DeserializeError::Json(_))
        ));
    }

    #[test]
    fn rejects_bad_hex_identity() {
        // Start from a valid artifact JSON; replace the identity hex value with non-hex.
        // identity is checked AFTER programId (which is valid base58), so we get Hex.
        let json = serialize_artifact(&minimal_artifact());
        // The identity field value in the JSON is a hex string like "010203".
        // Replace it with a clearly non-hex sentinel. Use a JSON-safe replacement:
        // "identity":"010203" -> "identity":"ZZZZZZ"
        let identity_hex = hex_enc(&minimal_artifact().identity);
        let corrupted = json.replace(
            &format!("\"identity\":\"{}\"", identity_hex),
            "\"identity\":\"ZZZZZZ\"",
        );
        assert!(
            corrupted != json,
            "replacement did not find the identity field"
        );
        assert!(matches!(
            deserialize_artifact(&corrupted),
            Err(DeserializeError::Hex("identity"))
        ));
    }

    #[test]
    fn rejects_wrong_length_nonce() {
        // Valid hex but only 2 bytes instead of 32 => Length error for "nonce".
        // nonce is checked after identity (valid hex), so we must also have identity valid.
        let json = serialize_artifact(&minimal_artifact());
        let nonce_hex = hex_enc(&[4u8; 32]); // 64-char hex for [4u8;32]
        let corrupted = json.replace(
            &format!("\"nonce\":\"{}\"", nonce_hex),
            "\"nonce\":\"0102\"", // valid hex, but only 2 bytes
        );
        assert!(
            corrupted != json,
            "replacement did not find the nonce field"
        );
        assert!(matches!(
            deserialize_artifact(&corrupted),
            Err(DeserializeError::Length("nonce"))
        ));
    }

    #[test]
    fn rejects_bad_base58_program_id() {
        // programId is the FIRST address checked, so an invalid base58 there
        // immediately yields Address(_).
        let json = serialize_artifact(&minimal_artifact());
        // Replace the program id string value with an invalid base58 (contains '0').
        let corrupted = json.replace(
            "\"programId\":\"vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV\"",
            "\"programId\":\"not-a-valid-base58-address!!!\"",
        );
        assert!(
            corrupted != json,
            "replacement did not find the programId field"
        );
        assert!(matches!(
            deserialize_artifact(&corrupted),
            Err(DeserializeError::Address(_))
        ));
    }

    #[test]
    fn empty_instructions_is_ok() {
        // An artifact with zero instructions must deserialize without panic.
        let a = Artifact {
            instructions: vec![],
            ..minimal_artifact()
        };
        let json = serialize_artifact(&a);
        let result = deserialize_artifact(&json);
        assert!(
            result.is_ok(),
            "expected Ok for empty instructions, got {result:?}"
        );
        assert_eq!(result.unwrap().instructions.len(), 0);
    }
}
