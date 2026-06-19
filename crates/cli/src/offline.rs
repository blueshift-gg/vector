//! Offline (no-RPC) CLI handlers: decode, review, and verify artifacts.
use vector_core::{
    deserialize_artifact, review as review_artifact, summarize, verify_artifact, Artifact,
};

fn load(path: &str) -> Result<Artifact, String> {
    let json = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    deserialize_artifact(&json)
}

/// Decoded one-line-per-instruction summary.
pub fn inspect(path: &str) -> Result<Vec<String>, String> {
    Ok(summarize(&load(path)?))
}

/// Human-readable sign-off block.
pub fn review(path: &str) -> Result<String, String> {
    Ok(review_artifact(&load(path)?))
}

/// Offline signature check: Ok(true) valid, Ok(false) invalid.
pub fn verify(path: &str) -> Result<bool, String> {
    verify_artifact(&load(path)?).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vector_core::{serialize_artifact, Ed25519, Op, Vector};

    fn write_tmp(json: &str, name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("vector_cli_test_{name}.json"));
        std::fs::write(&p, json).unwrap();
        p
    }

    #[test]
    fn verify_ok_for_genuine_artifact() {
        let art = Vector::new(Ed25519::from_seed(&[1u8; 32])).authorize(&[0u8; 32], Op::Inert);
        let path = write_tmp(&serialize_artifact(&art), "ok");
        assert!(verify(path.to_str().unwrap()).unwrap()); // true = valid
    }

    #[test]
    fn verify_false_for_tampered_artifact() {
        let mut art = Vector::new(Ed25519::from_seed(&[1u8; 32])).authorize(&[0u8; 32], Op::Inert);
        art.instructions[0].data[5] ^= 1;
        let path = write_tmp(&serialize_artifact(&art), "bad");
        assert!(!verify(path.to_str().unwrap()).unwrap()); // false = invalid
    }

    #[test]
    fn inspect_nonempty() {
        let art = Vector::new(Ed25519::from_seed(&[1u8; 32])).authorize(&[0u8; 32], Op::Inert);
        let path = write_tmp(&serialize_artifact(&art), "inspect");
        assert!(!inspect(path.to_str().unwrap()).unwrap().is_empty());
    }
}
