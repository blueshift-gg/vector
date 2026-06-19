//! Online (RPC) CLI handlers: nonce, scan, advance.
use crate::scheme_arg::SchemeArg;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer as _;
use std::str::FromStr;
use vector_client::read::VectorClient;
use vector_client::scan::{MigrationReport, ScanOptions};
use vector_core::{Artifact, Ed25519, Eip191, Hawk512, Op, Registration, Secp256k1, Vector};

fn addr(s: &str) -> Result<Address, String> {
    Address::from_str(s).map_err(|_| format!("bad address: {s}"))
}

/// Parse a 64-char hex string into a 32-byte seed.
///
/// Used by `advance` to load the Vector scheme key (the offline signer) from
/// `--signer-seed`, kept independent from the fee-payer key file.
pub fn parse_seed_hex(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!(
            "seed must be 64 hex chars (32 bytes), got {}",
            s.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| format!("bad hex: {e}"))?;
    }
    Ok(out)
}

/// Load a Solana keypair JSON file (array of 64 u8) into a Keypair.
fn load_fee_payer(path: &str) -> Result<Keypair, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let bytes: Vec<u8> =
        serde_json::from_str(&raw).map_err(|e| format!("parse keypair json: {e}"))?;
    Keypair::try_from(&bytes[..]).map_err(|e| format!("keypair from bytes: {e}"))
}

pub async fn nonce(url: &str, pda: &str) -> Result<(), String> {
    let client = VectorClient::new(url);
    let n = client.nonce(&addr(pda)?).await.map_err(|e| e.to_string())?;
    println!(
        "{}",
        n.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    Ok(())
}

pub async fn scan(url: &str, owner: &str, pda: &str) -> Result<(), String> {
    let client = VectorClient::new(url);
    let report: MigrationReport = client
        .scan_migration(&ScanOptions {
            owner: addr(owner)?,
            pda: addr(pda)?,
            mints: vec![],
            accounts: vec![],
            dust_lamports: 0,
        })
        .await
        .map_err(|e| e.to_string())?;
    println!("complete: {}", report.complete);
    for item in &report.unmigrated {
        println!(
            "  UNMIGRATED {:?} {} {}",
            item.kind,
            item.address,
            item.detail.clone().unwrap_or_default()
        );
    }
    Ok(())
}

/// Read the current nonce and produce a signed artifact (inert, or a withdraw
/// if `to`+`lamports` are given). Generic so every scheme shares this path.
async fn make_artifact<S: Registration>(
    client: &VectorClient,
    v: Vector<S>,
    to: Option<Address>,
    lamports: Option<u64>,
) -> Result<Artifact, String> {
    let n = client.nonce(&v.pda()).await.map_err(|e| e.to_string())?;
    Ok(match (to, lamports) {
        (Some(t), Some(l)) => v.withdraw(&n, &t, l),
        (None, None) => v.authorize(&n, Op::Inert),
        _ => return Err("--to and --lamports must be given together".into()),
    })
}

pub async fn advance(
    url: &str,
    keypair: &str,
    signer_seed: &str,
    scheme: SchemeArg,
    to: Option<String>,
    lamports: Option<u64>,
) -> Result<(), String> {
    let client = VectorClient::new(url);
    // The Vector scheme key (the offline/air-gapped signer) and the fee payer
    // (a separate hot key that pays for and broadcasts the tx) are INDEPENDENT
    // — that separation is the whole point of Vector. `--signer-seed` is the
    // scheme key as 64 hex chars; `--keypair` is the fee payer's JSON key file,
    // which only pays + signs the transaction and is never the scheme key.
    // Falcon has no seed-based keygen and is unsupported via the CLI.
    let seed = parse_seed_hex(signer_seed)?; // the Vector scheme key (offline signer)
    let fee_payer = load_fee_payer(keypair)?;
    let fp_addr = Address::from(fee_payer.pubkey().to_bytes());
    let to_addr = to.as_deref().map(addr).transpose()?;
    let art = match scheme {
        SchemeArg::Ed25519 => {
            make_artifact(
                &client,
                Vector::with_fee_payer(Ed25519::from_seed(&seed), fp_addr),
                to_addr,
                lamports,
            )
            .await?
        }
        SchemeArg::Secp256k1 => {
            make_artifact(
                &client,
                Vector::with_fee_payer(Secp256k1::from_seed(&seed), fp_addr),
                to_addr,
                lamports,
            )
            .await?
        }
        SchemeArg::Eip191 => {
            make_artifact(
                &client,
                Vector::with_fee_payer(Eip191::from_seed(&seed), fp_addr),
                to_addr,
                lamports,
            )
            .await?
        }
        SchemeArg::Hawk512 => {
            make_artifact(
                &client,
                Vector::with_fee_payer(Hawk512::from_seed(&seed), fp_addr),
                to_addr,
                lamports,
            )
            .await?
        }
        SchemeArg::Falcon512 => return Err(
            "falcon512 advance is not supported via the CLI (no seed-based keygen); use the SDK"
                .into(),
        ),
    };
    let sig = client
        .send_artifact(&art, &fee_payer)
        .await
        .map_err(|e| e.to_string())?;
    println!("{sig}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_seed_hex_ok() {
        let s = "00".repeat(32);
        assert_eq!(parse_seed_hex(&s).unwrap(), [0u8; 32]);
    }
    #[test]
    fn parse_seed_hex_rejects_wrong_len() {
        assert!(parse_seed_hex("00").is_err());
    }
}
