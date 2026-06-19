//! Async RPC client, fund-in-PDA migration, and the migration scanner for Vector.
//! Builds on the offline `vector-core` SDK.
pub mod error;
pub mod migrate;
pub mod read;
pub mod scan;
pub mod send;

pub use error::*;
