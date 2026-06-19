//! On-chain integration tests for the Vector fund-in-PDA flow.
//!
//! All tests are `#[ignore]`d.  They require a running `solana-test-validator`
//! with the Vector programs deployed.
//!
//! # How to run
//!
//! 1. Build all programs:
//!    ```bash
//!    cargo build-sbf
//!    ```
//! 2. Start the local validator (deploys the programs):
//!    ```bash
//!    bun run validator
//!    ```
//! 3. Run the ignored integration tests:
//!    ```bash
//!    cargo test -p vector-client --features ed25519 --test onchain -- --ignored
//!    ```

#![cfg(feature = "ed25519")]

use solana_address::Address;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use vector_client::{
    migrate::create_fund_wallet_instruction,
    read::VectorClient,
    scan::{ScanOptions, ScanStatus},
};
use vector_core::{Ed25519, Vector};

const RPC: &str = "http://127.0.0.1:8899";

/// Seed for the Vector signing identity (mirrors `KEY` from the TS test).
const KEY: [u8; 32] = {
    let mut k = [0u8; 32];
    k[31] = 0x51;
    k
};

/// Helper: airdrop `lamports` to `pubkey` and confirm via `confirm_transaction`.
async fn airdrop_and_confirm(
    client: &VectorClient,
    pubkey: &Address,
    lamports: u64,
) -> Result<(), String> {
    // bridge Address -> Pubkey (same type via bytes, explicit for clarity)
    let key = Address::from(pubkey.to_bytes());
    let sig: Signature = client
        .rpc
        .request_airdrop(&key, lamports)
        .await
        .map_err(|e| e.to_string())?;
    // Poll until confirmed.
    for _ in 0..30 {
        let ok = client
            .rpc
            .confirm_transaction(&sig)
            .await
            .map_err(|e| e.to_string())?;
        if ok {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err("airdrop not confirmed within 15 s".into())
}

/// Helper: build and send a plain (non-artifact) transaction signed by `payer`.
async fn send_plain_tx(
    client: &VectorClient,
    instructions: &[solana_instruction::Instruction],
    payer: &Keypair,
) -> Result<Signature, String> {
    let payer_addr = Address::from(payer.pubkey().to_bytes());

    // Bridge RPC blockhash (solana-hash 3.x) -> tx blockhash (solana-hash 4.x)
    let rpc_bh = client
        .rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| e.to_string())?;
    let blockhash = Hash::new_from_array(rpc_bh.to_bytes());

    let tx =
        Transaction::new_signed_with_payer(instructions, Some(&payer_addr), &[payer], blockhash);

    client
        .rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| e.to_string())
}

/// Verify that the Vector PDA can hold SOL and spend it via an offline-signed
/// artifact (withdraw sub-instruction).
///
/// Flow mirrors `wallet.test.ts` → "PDA holds SOL and spends it via an
/// offline-signed artifact":
///
/// 1. Airdrop 1 SOL to the fee payer.
/// 2. Initialize the Vector account + fund it with 5_000_000 lamports.
/// 3. Read the PDA balance and the current nonce.
/// 4. Build a `withdraw(1_000)` artifact, broadcast it.
/// 5. Assert the PDA balance dropped by exactly 1_000 lamports.
/// 6. Assert the on-chain nonce advanced to `art.next_nonce`.
#[tokio::test]
#[ignore]
async fn fund_in_pda_holds_and_spends_sol() -> Result<(), String> {
    let client = VectorClient::new(RPC);
    let payer = Keypair::new();
    let payer_addr = Address::from(payer.pubkey().to_bytes());

    // 1. Airdrop 1 SOL to the fee payer.
    airdrop_and_confirm(&client, &payer_addr, 1_000_000_000).await?;

    // 2. Build the Vector identity with the fee payer set.
    let v = Vector::with_fee_payer(Ed25519::from_seed(&KEY), payer_addr);

    // Initialize the PDA account and fund it with 5_000_000 lamports in one tx.
    let init_ix = v.initialize(&payer_addr);
    let fund_ix = create_fund_wallet_instruction(&payer_addr, &v.pda(), 5_000_000);
    send_plain_tx(&client, &[init_ix, fund_ix], &payer).await?;

    // 3. Read PDA balance before the withdrawal.
    let pda_key = Address::from(v.pda().to_bytes());
    let balance_before: u64 = client
        .rpc
        .get_balance(&pda_key)
        .await
        .map_err(|e| e.to_string())?;

    let nonce = client.nonce(&v.pda()).await?;

    // 4. Build a withdraw artifact and send it.
    let art = v.withdraw(&nonce, &payer_addr, 1_000);
    client.send_artifact(&art, &payer).await?;

    // 5. Assert PDA balance dropped by exactly 1_000 lamports.
    let balance_after: u64 = client
        .rpc
        .get_balance(&pda_key)
        .await
        .map_err(|e| e.to_string())?;
    let drop = balance_before
        .checked_sub(balance_after)
        .ok_or("balance increased unexpectedly")?;
    if drop != 1_000 {
        return Err(format!(
            "expected PDA balance to drop by 1_000 lamports, got {drop}"
        ));
    }

    // 6. Assert the on-chain nonce advanced to art.next_nonce.
    let new_nonce = client.nonce(&v.pda()).await?;
    if new_nonce != art.next_nonce {
        return Err(format!(
            "nonce mismatch: on-chain {new_nonce:?} != artifact next_nonce {:?}",
            art.next_nonce
        ));
    }

    Ok(())
}

/// Verify that `scan_migration` correctly flags a freshly-funded keypair as
/// having un-migrated SOL.
///
/// Flow mirrors `wallet.test.ts` → "scanMigration runs against real RPC and
/// flags the old key's SOL":
///
/// 1. Airdrop to a fresh `old` keypair.
/// 2. Run `scan_migration` with `dust_lamports: 0`.
/// 3. Assert `report.complete == false`.
/// 4. Assert at least one `Sol`-kind item is `Unmigrated`.
#[tokio::test]
#[ignore]
async fn scan_flags_funded_old_key() -> Result<(), String> {
    let client = VectorClient::new(RPC);
    let old = Keypair::new();
    let old_addr = Address::from(old.pubkey().to_bytes());

    // Airdrop so the old key has a non-zero SOL balance.
    airdrop_and_confirm(&client, &old_addr, 500_000_000).await?;

    // Build a Vector identity (no fee payer needed for scan).
    let v = Vector::new(Ed25519::from_seed(&KEY));

    let report = client
        .scan_migration(&ScanOptions {
            owner: old_addr,
            pda: v.pda(),
            mints: vec![],
            accounts: vec![],
            dust_lamports: 0,
        })
        .await?;

    if report.complete {
        return Err("expected report.complete == false for a funded old key".into());
    }

    let has_unmigrated_sol = report.items.iter().any(|item| {
        item.kind == vector_client::scan::ScanKind::Sol && item.status == ScanStatus::Unmigrated
    });
    if !has_unmigrated_sol {
        return Err("expected at least one Sol/Unmigrated item in the scan report".into());
    }

    Ok(())
}
