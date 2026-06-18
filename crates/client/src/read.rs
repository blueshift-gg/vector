//! Read Vector account state over async RPC.
//!
//! # Pubkey / Address type note
//!
//! `solana-rpc-client 3.1` declares a dependency on `solana-pubkey 3.0.0`.
//! That crate is a thin shim: `pub use solana_address::Address as Pubkey` where
//! it pulls in `solana-address 1.1.0`, which itself re-exports
//! `solana-address 2.6.0` (the same version the workspace pins).
//! Cargo resolves all three to the single `solana-address 2.6.0` node, so the
//! concrete Rust type is identical.  We still convert through bytes
//! (`pda.to_bytes()` → `[u8; 32]` → `solana_address::Address::from(bytes)`)
//! for explicitness and to silence any potential "different re-export path"
//! lint; no extra dependencies are needed.

use solana_address::Address;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use vector_core::VectorAccount;

/// Async client for reading Vector accounts.
pub struct VectorClient {
    pub rpc: RpcClient,
}

impl VectorClient {
    /// Create a new client targeting `url` (e.g. `"https://api.mainnet-beta.solana.com"`).
    pub fn new(url: impl ToString) -> Self {
        Self {
            rpc: RpcClient::new(url.to_string()),
        }
    }

    /// Current 32-byte nonce from the PDA's account header.
    pub async fn nonce(&self, pda: &Address) -> Result<[u8; 32], String> {
        let header = self.read_header(pda).await?;
        Ok(header.nonce)
    }

    /// Full account header (nonce + bump).
    pub async fn status(&self, pda: &Address) -> Result<VectorAccount, String> {
        self.read_header(pda).await
    }

    /// Internal: fetch raw account data and decode the 33-byte header.
    ///
    /// `get_account_data` expects a `&solana_pubkey::Pubkey` (solana-pubkey
    /// 3.0.0), which is `solana_address::Address` re-exported through a 1.1.0
    /// shim but ultimately the same `solana-address 2.6.0` concrete type.
    /// We convert through bytes to make the identity explicit.
    async fn read_header(&self, pda: &Address) -> Result<VectorAccount, String> {
        // bytes conversion: pda (Address 2.6.0) → [u8;32] → Address 2.6.0
        // passed as the Pubkey the RPC client expects.
        let rpc_key = Address::from(pda.to_bytes());
        let data = self
            .rpc
            .get_account_data(&rpc_key)
            .await
            .map_err(|e| e.to_string())?;
        if data.len() < VectorAccount::HEADER_LEN {
            return Err("account too small for vector header".into());
        }
        let mut h = [0u8; VectorAccount::HEADER_LEN];
        h.copy_from_slice(&data[..VectorAccount::HEADER_LEN]);
        Ok(VectorAccount::from_header_bytes(&h))
    }
}

#[cfg(test)]
mod tests {
    use vector_core::VectorAccount;

    #[test]
    fn header_roundtrips() {
        let acct = VectorAccount {
            nonce: [3u8; 32],
            bump: 254,
        };
        let bytes = acct.header_bytes();
        let back = VectorAccount::from_header_bytes(&bytes);
        assert_eq!(back.nonce, [3u8; 32]);
        assert_eq!(back.bump, 254);
    }
}
