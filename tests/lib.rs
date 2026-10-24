//! Mollusk-SBF integration tests for the Vector program. One module per
//! scheme; shared helpers live in [`common`].

#[cfg(test)]
mod common;

#[cfg(test)]
mod ed25519;

#[cfg(test)]
mod eip191;

#[cfg(test)]
mod falcon512;

#[cfg(test)]
mod mldsa44;

#[cfg(test)]
mod secp256k1;

#[cfg(test)]
mod xmss;

#[cfg(test)]
mod winternitz;

#[cfg(test)]
mod rotation;

#[cfg(test)]
mod schemes;

#[cfg(test)]
mod multi;

#[cfg(test)]
mod passthrough;

#[cfg(test)]
mod nonce;

#[cfg(test)]
mod blueshift_nonce;
