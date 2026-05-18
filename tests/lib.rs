//! Mollusk-SBF integration tests for the per-scheme Vector programs. One
//! module per program; shared helpers live in [`common`].

#[cfg(test)]
mod common;

#[cfg(test)]
mod ed25519;

#[cfg(test)]
mod eip191;

#[cfg(test)]
mod falcon512;

#[cfg(test)]
mod hawk512;

#[cfg(test)]
mod secp256k1;
