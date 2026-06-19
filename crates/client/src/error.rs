//! Typed errors for the Vector RPC client.
use solana_rpc_client_api::client_error::Error as RpcError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("rpc error: {0}")]
    Rpc(#[from] RpcError),
    #[error("account is too small for a vector header: {have} bytes (need {need})")]
    AccountTooSmall { have: usize, need: usize },
    #[error("artifact decode: {0}")]
    Decode(#[from] vector_core::DeserializeError),
    #[error("{0}")]
    Other(String),
}
