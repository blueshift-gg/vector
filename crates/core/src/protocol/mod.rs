//! Protocol primitives shared with the on-chain programs: the advance
//! [`digest`], PDA derivation ([`pda`]), and on-chain [`encoding`] constants
//! + account header.

pub mod digest;
pub mod encoding;
pub mod pda;
pub use digest::*;
pub use encoding::*;
pub use pda::*;
