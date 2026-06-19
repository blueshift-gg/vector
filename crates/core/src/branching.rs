//! SDK-only sub-account lanes: deterministic child seeds via HKDF-SHA256,
//! byte-compatible with the TS SDK's `deriveLaneSeed`.
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

/// Domain-separation salt (matches TS `LANE_KDF_SALT`).
const LANE_KDF_SALT: &[u8] = b"vector-lane-kdf-v1";

/// HKDF-SHA256 (RFC 5869).
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut ext = HmacSha256::new_from_slice(salt).expect("hmac key");
    ext.update(ikm);
    let prk = ext.finalize().into_bytes();
    let mut okm = Vec::with_capacity(length);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < length {
        let mut h = HmacSha256::new_from_slice(&prk).expect("hmac key");
        h.update(&t);
        h.update(info);
        h.update(&[counter]);
        t = h.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&t);
        counter += 1;
    }
    okm.truncate(length);
    okm
}

/// 32-byte child seed for sub-account `index` of `scheme_name`, from a 32-byte
/// master secret. Matches TS `deriveLaneSeed(master, scheme_name, index)`.
pub fn derive_lane_seed(master: &[u8], scheme_name: &str, index: u32) -> [u8; 32] {
    let info = format!("vector-lane:{scheme_name}:{index}");
    let okm = hkdf_sha256(master, LANE_KDF_SALT, info.as_bytes(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    #[test]
    fn matches_ts_golden_vectors() {
        let m = [7u8; 32];
        assert_eq!(
            hex(&derive_lane_seed(&m, "ed25519", 0)),
            "b58e0fdca6efeed5fa5105e7bdeff18ac28dc65dd9cc976c0cdd8c368249400d"
        );
        assert_eq!(
            hex(&derive_lane_seed(&m, "secp256k1", 0)),
            "dd9f3c78743855ba4f0ec3e6795daa8b925bbf255a41392e3f47593e79b8be94"
        );
        assert_eq!(
            hex(&derive_lane_seed(&m, "eip191", 0)),
            "da5da64424fa4ecba7f8155abc1bcacf30fb1fbef00a28bdb8ca31f2e923172e"
        );
    }
    #[test]
    fn deterministic_and_distinct() {
        let m = [9u8; 32];
        assert_eq!(
            derive_lane_seed(&m, "ed25519", 0),
            derive_lane_seed(&m, "ed25519", 0)
        );
        assert_ne!(
            derive_lane_seed(&m, "ed25519", 0),
            derive_lane_seed(&m, "ed25519", 1)
        );
        assert_ne!(
            derive_lane_seed(&m, "ed25519", 0),
            derive_lane_seed(&m, "secp256k1", 0)
        ); // scheme domain-sep
    }
}
