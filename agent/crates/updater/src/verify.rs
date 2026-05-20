//! SHA-256 + Ed25519 verification for downloaded binaries.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Computes lowercase hex SHA-256 of the file at `path`.
pub fn sha256_hex(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Verifies that the file at `path` has the expected SHA-256.
pub fn check_sha256(path: &Path, expected_hex: &str) -> Result<()> {
    let actual = sha256_hex(path)?;
    if actual.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        bail!(
            "sha256 mismatch: expected {}, got {}",
            expected_hex,
            actual
        )
    }
}

/// Verifies an Ed25519 signature over the file at `path`.
///
/// `signature_hex` is the hex-encoded 64-byte signature.
/// `pubkey` is the 32-byte raw Ed25519 public key.
///
/// Uses strict verification (no malleability — see `verify_strict`).
pub fn check_signature(path: &Path, signature_hex: &str, pubkey: &[u8; 32]) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;

    let sig_bytes = hex::decode(signature_hex.trim()).context("decode signature hex")?;
    if sig_bytes.len() != 64 {
        bail!("signature must be 64 bytes, got {}", sig_bytes.len());
    }
    let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());

    let verifying = VerifyingKey::from_bytes(pubkey).context("parse public key")?;
    verifying
        .verify_strict(&bytes, &sig)
        .context("signature does not verify against release key")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::RngCore;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(content: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        f
    }

    fn new_signing_key() -> SigningKey {
        // Skip the `rand_core` feature gate on ed25519-dalek by seeding by hand.
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn sha256_of_known_input() {
        let f = write_temp(b"hello");
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            sha256_hex(f.path()).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn check_sha256_match() {
        let f = write_temp(b"hello");
        check_sha256(
            f.path(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        .unwrap();
    }

    #[test]
    fn check_sha256_match_case_insensitive() {
        let f = write_temp(b"hello");
        check_sha256(
            f.path(),
            "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824",
        )
        .unwrap();
    }

    #[test]
    fn check_sha256_mismatch() {
        let f = write_temp(b"hello");
        assert!(check_sha256(f.path(), "0000000000000000000000000000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn signature_verifies_with_correct_key() {
        let signing = new_signing_key();
        let pubkey: [u8; 32] = signing.verifying_key().to_bytes();

        let f = write_temp(b"some binary content");
        let bytes = std::fs::read(f.path()).unwrap();
        let sig = signing.sign(&bytes);
        let sig_hex = hex::encode(sig.to_bytes());

        check_signature(f.path(), &sig_hex, &pubkey).unwrap();
    }

    #[test]
    fn signature_rejected_with_wrong_key() {
        let signer = new_signing_key();
        let attacker = new_signing_key();

        let f = write_temp(b"binary content");
        let bytes = std::fs::read(f.path()).unwrap();
        let sig = signer.sign(&bytes);
        let sig_hex = hex::encode(sig.to_bytes());

        let attacker_pubkey: [u8; 32] = attacker.verifying_key().to_bytes();
        assert!(check_signature(f.path(), &sig_hex, &attacker_pubkey).is_err());
    }

    #[test]
    fn signature_rejected_on_tampered_file() {
        let signing = new_signing_key();
        let pubkey: [u8; 32] = signing.verifying_key().to_bytes();

        let f1 = write_temp(b"original content");
        let original_bytes = std::fs::read(f1.path()).unwrap();
        let sig = signing.sign(&original_bytes);
        let sig_hex = hex::encode(sig.to_bytes());

        let f2 = write_temp(b"tampered content");
        assert!(check_signature(f2.path(), &sig_hex, &pubkey).is_err());
    }

    #[test]
    fn signature_rejected_for_wrong_length() {
        let f = write_temp(b"x");
        let pubkey = [0u8; 32];
        assert!(check_signature(f.path(), "abcd", &pubkey).is_err());
    }

    #[test]
    fn signature_rejected_for_bad_hex() {
        let f = write_temp(b"x");
        let pubkey = [0u8; 32];
        assert!(check_signature(f.path(), "not hex!", &pubkey).is_err());
    }
}
