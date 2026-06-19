//! Typed errors for the Vector RPC client.
use solana_rpc_client_api::client_error::Error as RpcError;

/// Error type returned by [`crate::read::VectorClient`] operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// An underlying Solana RPC call failed.
    #[error("rpc error: {0}")]
    Rpc(#[from] RpcError),
    /// The fetched account is smaller than the 33-byte Vector header.
    #[error("account is too small for a vector header: {have} bytes (need {need})")]
    AccountTooSmall {
        /// Actual byte length of the account data.
        have: usize,
        /// Minimum byte length required.
        need: usize,
    },
    /// An artifact JSON blob failed to deserialize.
    #[error("artifact decode: {0}")]
    Decode(#[from] vector_core::DeserializeError),
    /// A catch-all error with a human-readable message.
    #[error("{0}")]
    Other(String),
}
