use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::{Path, PathBuf};

/// Trait for key storage backends.
pub trait KeyStore {
    fn generate_and_store(&self) -> Result<()>;
    fn sign(&self, data: &[u8]) -> Result<String>;
    fn public_key_base64(&self) -> Result<String>;
    fn exists(&self) -> bool;
}

/// File-based key store. Stores Ed25519 secret key as raw bytes.
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn load_signing_key(&self) -> Result<SigningKey> {
        let bytes = fs::read(&self.path).context("Failed to read key file")?;
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key file length"))?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }
}

impl KeyStore for FileKeyStore {
    fn generate_and_store(&self) -> Result<()> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let key_bytes = signing_key.to_bytes();

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context("Failed to create key directory")?;
        }

        fs::write(&self.path, key_bytes).context("Failed to write key file")?;

        // Set file permissions to 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&self.path, perms).context("Failed to set key file permissions")?;
        }

        Ok(())
    }

    fn sign(&self, data: &[u8]) -> Result<String> {
        let signing_key = self.load_signing_key()?;
        let signature = signing_key.sign(data);
        Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    fn public_key_base64(&self) -> Result<String> {
        let signing_key = self.load_signing_key()?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Ok(base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes()))
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }
}

/// Generate a keypair and return (signing_key_bytes, public_key_base64).
pub fn generate_keypair() -> (Vec<u8>, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes());
    (signing_key.to_bytes().to_vec(), pub_b64)
}

/// Sign data with a raw signing key and return base64 signature.
pub fn sign_with_key(key_bytes: &[u8; 32], data: &[u8]) -> String {
    let signing_key = SigningKey::from_bytes(key_bytes);
    let signature = signing_key.sign(data);
    base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
}

/// Get the key file path within a config directory.
pub fn key_path_in(config_dir: &Path) -> PathBuf {
    config_dir.join("agent.key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use tempfile::tempdir;

    #[test]
    fn generate_sign_verify() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");
        let store = FileKeyStore::new(&key_path);

        store.generate_and_store().unwrap();
        assert!(store.exists());

        let data = b"hello world";
        let sig_b64 = store.sign(data).unwrap();
        let pub_b64 = store.public_key_base64().unwrap();

        // Verify the signature
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        let pub_bytes = base64::engine::general_purpose::STANDARD
            .decode(&pub_b64)
            .unwrap();

        let pub_key_arr: [u8; 32] = pub_bytes.try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pub_key_arr).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn different_data_different_signatures() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");
        let store = FileKeyStore::new(&key_path);
        store.generate_and_store().unwrap();

        let sig1 = store.sign(b"data one").unwrap();
        let sig2 = store.sign(b"data two").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sign_with_key_fn() {
        let (key_bytes, pub_b64) = generate_keypair();
        let key_arr: [u8; 32] = key_bytes.try_into().unwrap();
        let sig_b64 = sign_with_key(&key_arr, b"test data");

        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(&sig_b64).unwrap();
        let pub_bytes = base64::engine::general_purpose::STANDARD.decode(&pub_b64).unwrap();
        let pub_arr: [u8; 32] = pub_bytes.try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pub_arr).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        assert!(verifying_key.verify(b"test data", &signature).is_ok());
    }

    #[test]
    fn generate_keypair_produces_valid_key() {
        let (key_bytes, pub_b64) = generate_keypair();
        assert_eq!(key_bytes.len(), 32);
        let pub_bytes = base64::engine::general_purpose::STANDARD.decode(&pub_b64).unwrap();
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn sign_with_wrong_key_fails_verify() {
        let (key_bytes, _) = generate_keypair();
        let (_, other_pub_b64) = generate_keypair();

        let key_arr: [u8; 32] = key_bytes.try_into().unwrap();
        let sig_b64 = sign_with_key(&key_arr, b"test data");

        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(&sig_b64).unwrap();
        let other_pub_bytes = base64::engine::general_purpose::STANDARD.decode(&other_pub_b64).unwrap();
        let other_pub_arr: [u8; 32] = other_pub_bytes.try_into().unwrap();
        let other_key = VerifyingKey::from_bytes(&other_pub_arr).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        assert!(other_key.verify(b"test data", &signature).is_err());
    }

    #[test]
    fn nonexistent_key_file() {
        let store = FileKeyStore::new("/tmp/nonexistent_open_attest_test_key");
        assert!(!store.exists());
        assert!(store.sign(b"data").is_err());
        assert!(store.public_key_base64().is_err());
    }

    #[test]
    fn public_key_base64_is_valid() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");
        let store = FileKeyStore::new(&key_path);
        store.generate_and_store().unwrap();

        let pub_b64 = store.public_key_base64().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&pub_b64)
            .unwrap();
        assert_eq!(decoded.len(), 32); // Ed25519 public key is 32 bytes
    }
}
