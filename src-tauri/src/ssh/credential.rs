use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SERVICE_NAME: &str = "traffic-rules";
const HMAC_SERVICE_NAME: &str = "traffic-rules-hmac";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Credential stored in the OS keychain for a remote host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Credential {
    /// SSH password authentication.
    Password { username: String, password: String },
    /// Path to an SSH private key, optionally with a passphrase.
    KeyFile {
        username: String,
        key_path: String,
        passphrase: Option<String>,
    },
    /// Use the SSH agent (no stored secret needed beyond username).
    Agent { username: String },
}

impl Credential {
    pub fn username(&self) -> &str {
        match self {
            Credential::Password { username, .. } => username,
            Credential::KeyFile { username, .. } => username,
            Credential::Agent { username } => username,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("credential not found for host: {0}")]
    NotFound(String),
    #[error("failed to serialize credential: {0}")]
    Serialization(String),
    #[error("failed to deserialize credential: {0}")]
    Deserialization(String),
}

// ---------------------------------------------------------------------------
// CredentialStore
// ---------------------------------------------------------------------------

/// OS keychain wrapper using the `keyring` crate.
///
/// Service name: `"traffic-rules"`. Account: `host_id`.
/// HMAC secrets use service `"traffic-rules-hmac"`.
pub struct CredentialStore {
    _private: (),
}

impl CredentialStore {
    /// Create a new credential store. This does not open any keychain
    /// connection eagerly — the keyring crate connects on each operation.
    pub fn new() -> Result<Self, CredentialError> {
        Ok(Self { _private: () })
    }

    /// Store a credential for the given host.
    pub fn store(&self, host_id: &str, credential: &Credential) -> Result<(), CredentialError> {
        let json = serde_json::to_string(credential)
            .map_err(|e| CredentialError::Serialization(e.to_string()))?;
        let entry = keyring::Entry::new(SERVICE_NAME, host_id)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;
        entry
            .set_password(&json)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;
        Ok(())
    }

    /// Retrieve a credential for the given host.
    pub fn retrieve(&self, host_id: &str) -> Result<Credential, CredentialError> {
        let entry = keyring::Entry::new(SERVICE_NAME, host_id)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;
        let json = entry
            .get_password()
            .map_err(|e| match e {
                keyring::Error::NoEntry => CredentialError::NotFound(host_id.to_string()),
                other => CredentialError::Keyring(other.to_string()),
            })?;
        let cred: Credential = serde_json::from_str(&json)
            .map_err(|e| CredentialError::Deserialization(e.to_string()))?;
        Ok(cred)
    }

    /// Delete a credential for the given host.
    pub fn delete(&self, host_id: &str) -> Result<(), CredentialError> {
        let entry = keyring::Entry::new(SERVICE_NAME, host_id)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;
        entry
            .delete_credential()
            .map_err(|e| match e {
                keyring::Error::NoEntry => CredentialError::NotFound(host_id.to_string()),
                other => CredentialError::Keyring(other.to_string()),
            })?;
        Ok(())
    }

    /// Store an HMAC secret for the given host in the keychain.
    pub fn store_hmac_secret(
        &self,
        host_id: &str,
        secret: &str,
    ) -> Result<(), CredentialError> {
        let entry = keyring::Entry::new(HMAC_SERVICE_NAME, host_id)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;
        entry
            .set_password(secret)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;
        Ok(())
    }

    /// Retrieve the HMAC secret for the given host from the keychain.
    pub fn retrieve_hmac_secret(&self, host_id: &str) -> Result<String, CredentialError> {
        let entry = keyring::Entry::new(HMAC_SERVICE_NAME, host_id)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;
        entry
            .get_password()
            .map_err(|e| match e {
                keyring::Error::NoEntry => CredentialError::NotFound(host_id.to_string()),
                other => CredentialError::Keyring(other.to_string()),
            })
    }
}
