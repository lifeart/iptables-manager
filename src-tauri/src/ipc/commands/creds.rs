use crate::ipc::errors::IpcError;

/// Store a credential in the OS keychain for the given host.
#[tauri::command]
pub async fn cred_store(
    host_id: String,
    credential: serde_json::Value,
) -> Result<(), IpcError> {
    let store = crate::ssh::credential::CredentialStore::new().map_err(|e| {
        IpcError::CommandFailed {
            stderr: format!("credential store error: {}", e),
            exit_code: 1,
            explanation: None,
        }
    })?;

    let cred: crate::ssh::credential::Credential =
        serde_json::from_value(credential).map_err(|e| IpcError::CommandFailed {
            stderr: format!("invalid credential payload: {}", e),
            exit_code: 1,
            explanation: None,
        })?;

    store.store(&host_id, &cred).map_err(|e| IpcError::CommandFailed {
        stderr: format!("failed to store credential: {}", e),
        exit_code: 1,
        explanation: None,
    })?;

    Ok(())
}

/// Delete a credential from the OS keychain for the given host.
#[tauri::command]
pub async fn cred_delete(
    host_id: String,
) -> Result<(), IpcError> {
    let store = crate::ssh::credential::CredentialStore::new().map_err(|e| {
        IpcError::CommandFailed {
            stderr: format!("credential store error: {}", e),
            exit_code: 1,
            explanation: None,
        }
    })?;

    match store.delete(&host_id) {
        Ok(()) => Ok(()),
        Err(crate::ssh::credential::CredentialError::NotFound(_)) => Ok(()),
        Err(e) => Err(IpcError::CommandFailed {
            stderr: format!("failed to delete credential: {}", e),
            exit_code: 1,
            explanation: None,
        }),
    }
}
