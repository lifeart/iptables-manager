use thiserror::Error;

use crate::safety::hmac::generate_secret;
use crate::ssh::command::build_command;
use crate::ssh::credential::CredentialStore;
use crate::ssh::executor::{CommandExecutor, CommandOutput};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const APP_DIR: &str = "/var/lib/traffic-rules";
const SNAPSHOTS_DIR: &str = "/var/lib/traffic-rules/snapshots";
const REVERT_SCRIPT_PATH: &str = "/var/lib/traffic-rules/revert.sh";
const EXPIRE_SCRIPT_PATH: &str = "/var/lib/traffic-rules/expire-rule.sh";
const HMAC_SECRET_PATH: &str = "/var/lib/traffic-rules/.hmac_secret";

const REVERT_SCRIPT: &str = include_str!("../../scripts/revert.sh");
const EXPIRE_SCRIPT: &str = include_str!("../../scripts/expire-rule.sh");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ProvisionResult {
    pub success: bool,
    pub hmac_secret_stored: bool,
    pub sudo_verified: bool,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ProvisionError {
    #[error("failed to create directory: {0}")]
    DirectoryCreation(String),
    #[error("failed to write file {path}: {reason}")]
    FileWrite { path: String, reason: String },
    #[error("failed to set permissions on {path}: {reason}")]
    Permissions { path: String, reason: String },
    #[error("sudo access denied for {command}: {stderr}")]
    SudoDenied { command: String, stderr: String },
    #[error("command execution failed: {0}")]
    Exec(String),
    #[error("credential store error: {0}")]
    CredentialStore(String),
}

// ---------------------------------------------------------------------------
// Provision logic
// ---------------------------------------------------------------------------

/// Provision a remote host for traffic-rules management.
///
/// Steps:
/// 1. Create `/var/lib/traffic-rules/snapshots/` with correct permissions
/// 2. Write `revert.sh` and `expire-rule.sh` scripts
/// 3. Generate HMAC secret, write to remote `.hmac_secret` file
/// 4. Store HMAC secret in local keychain
/// 5. Verify sudo access for iptables-save, iptables-restore, ipset
pub async fn provision_host(
    executor: &dyn CommandExecutor,
    host_id: &str,
    cred_store: &CredentialStore,
) -> Result<ProvisionResult, ProvisionError> {
    // 1. Create app directory and snapshots subdirectory
    create_directories(executor).await?;

    // 2. Write scripts
    write_script(executor, REVERT_SCRIPT_PATH, REVERT_SCRIPT, "0755").await?;
    write_script(executor, EXPIRE_SCRIPT_PATH, EXPIRE_SCRIPT, "0755").await?;

    // 3. Generate and deploy HMAC secret
    let secret = generate_secret();
    write_secret(executor, HMAC_SECRET_PATH, &secret).await?;

    // 4. Store HMAC secret in local keychain
    cred_store
        .store_hmac_secret(host_id, &secret)
        .map_err(|e| ProvisionError::CredentialStore(e.to_string()))?;

    // 5. Verify sudo access for required commands
    verify_sudo_access(executor).await?;

    Ok(ProvisionResult {
        success: true,
        hmac_secret_stored: true,
        sudo_verified: true,
    })
}

/// Create the app directory structure with proper permissions.
async fn create_directories(executor: &dyn CommandExecutor) -> Result<(), ProvisionError> {
    let cmd = build_command("sudo", &["mkdir", "-p", SNAPSHOTS_DIR]);
    let output = executor
        .exec(&cmd)
        .await
        .map_err(|e| ProvisionError::Exec(e.to_string()))?;
    check_exit(&output, "mkdir -p")?;

    let cmd = build_command("sudo", &["chmod", "0700", APP_DIR]);
    let output = executor
        .exec(&cmd)
        .await
        .map_err(|e| ProvisionError::Exec(e.to_string()))?;
    check_exit_perm(&output, APP_DIR)?;

    Ok(())
}

/// Write a script to the remote host via stdin (avoids shell escaping of content).
async fn write_script(
    executor: &dyn CommandExecutor,
    path: &str,
    content: &str,
    mode: &str,
) -> Result<(), ProvisionError> {
    // Use tee to write via stdin — content never passes through shell
    let write_cmd = build_command("sudo", &["tee", path]);
    let output = executor
        .exec_with_stdin(&write_cmd, content.as_bytes())
        .await
        .map_err(|e| ProvisionError::Exec(e.to_string()))?;
    if output.exit_code != 0 {
        return Err(ProvisionError::FileWrite {
            path: path.to_string(),
            reason: output.stderr,
        });
    }

    let chmod_cmd = build_command("sudo", &["chmod", mode, path]);
    let output = executor
        .exec(&chmod_cmd)
        .await
        .map_err(|e| ProvisionError::Exec(e.to_string()))?;
    check_exit_perm(&output, path)?;

    Ok(())
}

/// Write the HMAC secret file with restrictive permissions.
async fn write_secret(
    executor: &dyn CommandExecutor,
    path: &str,
    secret: &str,
) -> Result<(), ProvisionError> {
    let write_cmd = build_command("sudo", &["tee", path]);
    let output = executor
        .exec_with_stdin(&write_cmd, secret.as_bytes())
        .await
        .map_err(|e| ProvisionError::Exec(e.to_string()))?;
    if output.exit_code != 0 {
        return Err(ProvisionError::FileWrite {
            path: path.to_string(),
            reason: output.stderr,
        });
    }

    let chmod_cmd = build_command("sudo", &["chmod", "0600", path]);
    let output = executor
        .exec(&chmod_cmd)
        .await
        .map_err(|e| ProvisionError::Exec(e.to_string()))?;
    check_exit_perm(&output, path)?;

    Ok(())
}

/// Verify sudo access for iptables-save, iptables-restore, and ipset.
async fn verify_sudo_access(executor: &dyn CommandExecutor) -> Result<(), ProvisionError> {
    let commands = ["iptables-save", "iptables-restore", "ipset"];
    for cmd_name in &commands {
        let cmd = build_command("sudo", &["-n", cmd_name, "--help"]);
        let output = executor
            .exec(&cmd)
            .await
            .map_err(|e| ProvisionError::Exec(e.to_string()))?;
        // Exit code 0 or 1 are both acceptable — we just need sudo to not reject us.
        // Exit code 1 from --help is fine for ipset. A "permission denied" from
        // sudo will give a specific stderr message. Use case-insensitive
        // matching since error messages vary across sudo versions and locales.
        let stderr_lower = output.stderr.to_lowercase();
        if stderr_lower.contains("permission denied")
            || stderr_lower.contains("not allowed")
            || stderr_lower.contains("a password is required")
            || output.exit_code > 1
        {
            return Err(ProvisionError::SudoDenied {
                command: cmd_name.to_string(),
                stderr: output.stderr,
            });
        }
    }
    Ok(())
}

fn check_exit(output: &CommandOutput, context: &str) -> Result<(), ProvisionError> {
    if output.exit_code != 0 {
        return Err(ProvisionError::DirectoryCreation(format!(
            "{}: {}",
            context, output.stderr
        )));
    }
    Ok(())
}

fn check_exit_perm(output: &CommandOutput, path: &str) -> Result<(), ProvisionError> {
    if output.exit_code != 0 {
        return Err(ProvisionError::Permissions {
            path: path.to_string(),
            reason: output.stderr.clone(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::executor::{CommandOutput, ExecError};
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// Mock executor that records commands and returns configurable responses.
    struct MockExecutor {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl MockExecutor {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CommandExecutor for MockExecutor {
        async fn exec(&self, command: &str) -> Result<CommandOutput, ExecError> {
            self.calls.lock().unwrap().push(command.to_string());
            Ok(CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            })
        }

        async fn exec_with_stdin(
            &self,
            command: &str,
            _stdin: &[u8],
        ) -> Result<CommandOutput, ExecError> {
            self.calls.lock().unwrap().push(command.to_string());
            Ok(CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            })
        }
    }

    #[tokio::test]
    async fn test_create_directories() {
        let executor = MockExecutor::new();
        create_directories(&executor).await.unwrap();

        let calls = executor.calls();
        assert!(calls.iter().any(|c| c.contains("mkdir") && c.contains("/var/lib/traffic-rules/snapshots")));
        assert!(calls.iter().any(|c| c.contains("chmod") && c.contains("0700")));
    }

    #[tokio::test]
    async fn test_write_script() {
        let executor = MockExecutor::new();
        write_script(&executor, "/tmp/test.sh", "#!/bin/bash\necho hi", "0755")
            .await
            .unwrap();

        let calls = executor.calls();
        assert!(calls.iter().any(|c| c.contains("tee") && c.contains("/tmp/test.sh")));
        assert!(calls.iter().any(|c| c.contains("chmod") && c.contains("0755")));
    }
}
