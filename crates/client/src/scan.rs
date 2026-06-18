//! Migration scanner — audit everything an old keypair authority still controls
//! vs. the target Vector PDA.
//!
//! Ports the TS SDK `scan.ts` `scanMigration` faithfully:
//!   1. native SOL balance,
//!   2. SPL + Token-2022 accounts owned by the old key,
//!   3. stake accounts where the old key is staker (offset 12) or withdraw
//!      authority (offset 44),
//!   4. declared mints — mint authority (COption @0/@4) + freeze (@46/@50),
//!   5. declared generic accounts — 32-byte authority at a given offset.
//!
//! The pure report aggregation ([`MigrationReport::from_items`]) is unit-tested
//! offline; the RPC-driven discovery ([`crate::read::VectorClient::scan_migration`])
//! is exercised live in task B6.
//!
//! # Pubkey / Address bridge
//!
//! The RPC client methods take `&solana_pubkey::Pubkey` (a 3.0.0 shim over the
//! workspace `solana-address 2.6.0`) and the RPC `TokenAccountsFilter` /
//! `get_program_ui_accounts_with_config` program argument is the same `Pubkey`.
//! We bridge each `Address` through bytes (`Address::from(a.to_bytes())`) — the
//! identical pattern `read.rs` uses — so no extra dependency or `From` impl is
//! needed. `RpcKeyedAccount.pubkey` and `(Pubkey, UiAccount)` come back from RPC;
//! the `Pubkey` is rendered to base58 with `.to_string()`.

use std::collections::HashSet;

use solana_address::Address;
use solana_rpc_client_api::config::{
    RpcAccountInfoConfig, RpcProgramAccountsConfig, UiDataSliceConfig,
};
use solana_rpc_client_api::filter::{Memcmp, RpcFilterType};
use solana_rpc_client_api::request::TokenAccountsFilter;

use crate::migrate::{TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID};
use crate::read::VectorClient;

/// `Stake11111111111111111111111111111111111111`.
pub const STAKE_PROGRAM_ID: Address =
    solana_address::address!("Stake11111111111111111111111111111111111111");

/// What kind of authority/asset an audited item represents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanKind {
    Sol,
    Token,
    Token2022,
    Stake,
    MintAuthority,
    FreezeAuthority,
    Account,
}

/// Whether an item has been migrated off the old authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanStatus {
    Migrated,
    Unmigrated,
}

/// One audited item: an account the old authority did or did not migrate.
#[derive(Clone, Debug)]
pub struct ScanItem {
    pub kind: ScanKind,
    /// Base58 address of the controlled account (or the old wallet, for SOL).
    pub address: String,
    pub status: ScanStatus,
    pub detail: Option<String>,
}

/// Full migration audit for one `owner` → `pda` pair.
#[derive(Clone, Debug)]
pub struct MigrationReport {
    pub owner: String,
    pub pda: String,
    /// True iff nothing controllable remains on the old authority.
    pub complete: bool,
    pub items: Vec<ScanItem>,
    /// Convenience: just the items still on the old key — your to-do list.
    pub unmigrated: Vec<ScanItem>,
}

impl MigrationReport {
    /// Aggregate `items` into a report: `complete` iff no item is `Unmigrated`.
    pub fn from_items(owner: String, pda: String, items: Vec<ScanItem>) -> Self {
        let unmigrated: Vec<ScanItem> = items
            .iter()
            .filter(|i| i.status == ScanStatus::Unmigrated)
            .cloned()
            .collect();
        Self {
            complete: unmigrated.is_empty(),
            owner,
            pda,
            items,
            unmigrated,
        }
    }
}

/// A generic account to audit: verify the 32-byte authority at `authority_offset`.
#[derive(Clone, Debug)]
pub struct DeclaredAccount {
    pub address: Address,
    pub authority_offset: usize,
    pub kind: Option<ScanKind>,
    pub label: Option<String>,
}

/// Options driving a [`VectorClient::scan_migration`] run.
#[derive(Clone, Debug, Default)]
pub struct ScanOptions {
    /// The old keypair authority being migrated away from.
    pub owner: Address,
    /// The target Vector PDA the authority should now point at.
    pub pda: Address,
    /// Mints to check (mint + freeze authority) — not discoverable by authority.
    pub mints: Vec<Address>,
    /// Generic accounts: verify the 32-byte authority at `authority_offset`.
    pub accounts: Vec<DeclaredAccount>,
    /// SOL balance (lamports) at/below which `owner` counts as drained.
    pub dust_lamports: u64,
}

/// Read a base58 pubkey out of `data` at `offset` (`offset..offset+32`).
/// Returns `None` if the slice would run past the end of `data`.
fn pubkey_at(data: &[u8], offset: usize) -> Option<String> {
    let end = offset.checked_add(32)?;
    if data.len() < end {
        return None;
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[offset..end]);
    Some(Address::from(bytes).to_string())
}

impl VectorClient {
    /// Audit the migration of `opts.owner` → `opts.pda`. `complete` is true iff
    /// nothing controllable remains on `owner`. Run it, migrate
    /// `report.unmigrated`, re-run until complete.
    pub async fn scan_migration(&self, opts: &ScanOptions) -> Result<MigrationReport, String> {
        let owner = opts.owner.to_string();
        let pda = opts.pda.to_string();
        let mut items: Vec<ScanItem> = Vec::new();

        // bridge: Address (workspace 2.6.0) -> the Pubkey the RPC client expects.
        let owner_key = Address::from(opts.owner.to_bytes());

        // 1. Native SOL.
        let balance = self
            .rpc
            .get_balance(&owner_key)
            .await
            .map_err(|e| e.to_string())?;
        if balance > opts.dust_lamports {
            items.push(ScanItem {
                kind: ScanKind::Sol,
                address: owner.clone(),
                status: ScanStatus::Unmigrated,
                detail: Some(format!("{balance} lamports still on the old key")),
            });
        } else {
            items.push(ScanItem {
                kind: ScanKind::Sol,
                address: owner.clone(),
                status: ScanStatus::Migrated,
                detail: None,
            });
        }

        // 2. SPL + Token-2022 accounts owned by the old key.
        for (program_id, kind) in [
            (TOKEN_PROGRAM_ID, ScanKind::Token),
            (TOKEN_2022_PROGRAM_ID, ScanKind::Token2022),
        ] {
            let prog_key = Address::from(program_id.to_bytes());
            let res = self
                .rpc
                .get_token_accounts_by_owner(&owner_key, TokenAccountsFilter::ProgramId(prog_key))
                .await
                .map_err(|e| e.to_string())?;
            for keyed in res {
                items.push(ScanItem {
                    kind: kind.clone(),
                    address: keyed.pubkey,
                    status: ScanStatus::Unmigrated,
                    detail: Some("token account still owned by the old key".into()),
                });
            }
        }

        // 3. Stake accounts where the old key is staker or withdraw authority.
        let stake_program = Address::from(STAKE_PROGRAM_ID.to_bytes());
        let mut seen_stake: HashSet<String> = HashSet::new();
        for (offset, role) in [
            (12usize, "stake authority"),
            (44usize, "withdraw authority"),
        ] {
            let config = RpcProgramAccountsConfig {
                filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_base58_encoded(
                    offset,
                    &opts.owner.to_bytes(),
                ))]),
                account_config: RpcAccountInfoConfig {
                    // zero-length data slice: we only need the addresses.
                    data_slice: Some(UiDataSliceConfig {
                        offset: 0,
                        length: 0,
                    }),
                    ..Default::default()
                },
                ..Default::default()
            };
            // `get_program_accounts_with_config` is deprecated in 3.1.14 in
            // favour of the `_ui_` variant; we only need the addresses (the data
            // slice is zero-length), so the `UiAccount` payload is discarded and
            // the semantics are identical.
            let accts = self
                .rpc
                .get_program_ui_accounts_with_config(&stake_program, config)
                .await
                .map_err(|e| e.to_string())?;
            for (pubkey, _account) in accts {
                let addr = pubkey.to_string();
                if !seen_stake.insert(addr.clone()) {
                    continue;
                }
                items.push(ScanItem {
                    kind: ScanKind::Stake,
                    address: addr,
                    status: ScanStatus::Unmigrated,
                    detail: Some(format!("old key is the {role}")),
                });
            }
        }

        // 4. Declared mints — mint authority (COption @0/@4) + freeze (@46/@50).
        for mint in &opts.mints {
            let mint_key = Address::from(mint.to_bytes());
            let account = match self.rpc.get_account(&mint_key).await {
                Ok(a) => a,
                Err(_) => continue,
            };
            let data = account.data;
            if data.first() == Some(&1) {
                if let Some(auth) = pubkey_at(&data, 4) {
                    let migrated = auth == pda;
                    items.push(ScanItem {
                        kind: ScanKind::MintAuthority,
                        address: mint.to_string(),
                        status: if migrated {
                            ScanStatus::Migrated
                        } else {
                            ScanStatus::Unmigrated
                        },
                        detail: if migrated {
                            None
                        } else {
                            Some(format!("mint authority is {auth}"))
                        },
                    });
                }
            }
            if data.len() >= 82 && data[46] == 1 {
                if let Some(auth) = pubkey_at(&data, 50) {
                    let migrated = auth == pda;
                    items.push(ScanItem {
                        kind: ScanKind::FreezeAuthority,
                        address: mint.to_string(),
                        status: if migrated {
                            ScanStatus::Migrated
                        } else {
                            ScanStatus::Unmigrated
                        },
                        detail: if migrated {
                            None
                        } else {
                            Some(format!("freeze authority is {auth}"))
                        },
                    });
                }
            }
        }

        // 5. Declared generic accounts — authority at a given offset.
        for a in &opts.accounts {
            let acc_key = Address::from(a.address.to_bytes());
            let account = match self.rpc.get_account(&acc_key).await {
                Ok(acc) => acc,
                Err(_) => continue,
            };
            let auth = match pubkey_at(&account.data, a.authority_offset) {
                Some(auth) => auth,
                None => continue,
            };
            let migrated = auth == pda;
            let label = a
                .label
                .as_ref()
                .map(|l| format!("{l}: "))
                .unwrap_or_default();
            items.push(ScanItem {
                kind: a.kind.clone().unwrap_or(ScanKind::Account),
                address: a.address.to_string(),
                status: if migrated {
                    ScanStatus::Migrated
                } else {
                    ScanStatus::Unmigrated
                },
                detail: Some(if migrated {
                    format!("{label}authority is the PDA")
                } else {
                    format!("{label}authority is {auth}")
                }),
            });
        }

        Ok(MigrationReport::from_items(owner, pda, items))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn item(status: ScanStatus) -> ScanItem {
        ScanItem {
            kind: ScanKind::Sol,
            address: "x".into(),
            status,
            detail: None,
        }
    }
    #[test]
    fn incomplete_when_unmigrated_present() {
        let r =
            MigrationReport::from_items("o".into(), "p".into(), vec![item(ScanStatus::Unmigrated)]);
        assert!(!r.complete);
        assert_eq!(r.unmigrated.len(), 1);
    }
    #[test]
    fn complete_when_all_migrated() {
        let r =
            MigrationReport::from_items("o".into(), "p".into(), vec![item(ScanStatus::Migrated)]);
        assert!(r.complete);
        assert!(r.unmigrated.is_empty());
    }
}
