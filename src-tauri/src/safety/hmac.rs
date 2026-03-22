use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

/// Compute HMAC-SHA256 of `data` using `secret`, returning hex-encoded string.
pub fn compute_hmac(secret: &str, data: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, data);
    hex::encode(tag.as_ref())
}

/// Verify that `expected_hex` matches the HMAC-SHA256 of `data` using `secret`.
///
/// Uses constant-time comparison via the `ring` crate.
pub fn verify_hmac(secret: &str, data: &[u8], expected_hex: &str) -> bool {
    let expected_bytes = match hex::decode(expected_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    hmac::verify(&key, data, &expected_bytes).is_ok()
}

/// Generate a cryptographically secure random secret: 16 random bytes encoded
/// as 32 hex characters.
pub fn generate_secret() -> String {
    let rng = SystemRandom::new();
    let mut buf = [0u8; 16];
    rng.fill(&mut buf)
        .expect("system random number generator failed");
    hex::encode(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_verify_roundtrip() {
        let secret = "test-secret-key";
        let data = b"some important data";
        let mac = compute_hmac(secret, data);
        assert!(verify_hmac(secret, data, &mac));
    }

    #[test]
    fn test_verify_wrong_data() {
        let secret = "test-secret-key";
        let mac = compute_hmac(secret, b"original data");
        assert!(!verify_hmac(secret, b"tampered data", &mac));
    }

    #[test]
    fn test_verify_wrong_secret() {
        let secret = "correct-secret";
        let data = b"some data";
        let mac = compute_hmac(secret, data);
        assert!(!verify_hmac("wrong-secret", data, &mac));
    }

    #[test]
    fn test_verify_invalid_hex() {
        assert!(!verify_hmac("secret", b"data", "not-valid-hex!!!"));
    }

    #[test]
    fn test_verify_wrong_length() {
        assert!(!verify_hmac("secret", b"data", "aabb"));
    }

    #[test]
    fn test_generate_secret_length() {
        let s = generate_secret();
        assert_eq!(s.len(), 32, "secret should be 32 hex chars");
    }

    #[test]
    fn test_generate_secret_is_hex() {
        let s = generate_secret();
        assert!(
            s.chars().all(|c| c.is_ascii_hexdigit()),
            "secret should only contain hex digits"
        );
    }

    #[test]
    fn test_generate_secret_uniqueness() {
        let s1 = generate_secret();
        let s2 = generate_secret();
        assert_ne!(s1, s2, "two generated secrets should differ");
    }

    #[test]
    fn test_hmac_deterministic() {
        let secret = "deterministic-key";
        let data = b"deterministic data";
        let mac1 = compute_hmac(secret, data);
        let mac2 = compute_hmac(secret, data);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_output_is_hex() {
        let mac = compute_hmac("key", b"data");
        assert!(mac.chars().all(|c| c.is_ascii_hexdigit()));
        // HMAC-SHA256 produces 32 bytes = 64 hex chars
        assert_eq!(mac.len(), 64);
    }
}
