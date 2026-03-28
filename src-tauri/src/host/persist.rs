use tracing::warn;
use thiserror::Error;

use crate::ssh::command::build_command;
use crate::ssh::executor::{CommandExecutor, ExecError};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PersistError {
    #[error("command execution error: {0}")]
    Exec(#[from] ExecError),
    #[error("persistence failed for {distro}: {reason}")]
    Failed { distro: String, reason: String },
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Save iptables rules persistently using the distro-appropriate method.
///
/// `distro_family` should be one of: `"debian"`, `"rhel"`, `"arch"`,
/// `"alpine"`, or `"other"`.
pub async fn save_rules_persistently(
    executor: &dyn CommandExecutor,
    distro_family: &str,
) -> Result<(), PersistError> {
    match distro_family {
        "debian" => save_debian(executor).await,
        "rhel" => save_rhel(executor).await,
        "arch" => save_arch(executor).await,
        "alpine" => save_alpine(executor).await,
        _ => save_manual_fallback(executor).await,
    }
}

// ---------------------------------------------------------------------------
// Distro-specific implementations
// ---------------------------------------------------------------------------

/// Debian/Ubuntu: use netfilter-persistent
async fn save_debian(executor: &dyn CommandExecutor) -> Result<(), PersistError> {
    let cmd = build_command("sudo", &["netfilter-persistent", "save"]);
    let output = executor.exec(&cmd).await?;

    if output.exit_code != 0 {
        // Fallback: direct iptables-save
        return save_to_file(
            executor,
            "/etc/iptables/rules.v4",
            "/etc/iptables/rules.v6",
        )
        .await;
    }

    Ok(())
}

/// RHEL/CentOS/Fedora: use iptables-services or direct save
async fn save_rhel(executor: &dyn CommandExecutor) -> Result<(), PersistError> {
    // Try `service iptables save` first (iptables-services package)
    let cmd = build_command("sudo", &["service", "iptables", "save"]);
    let output = executor.exec(&cmd).await?;

    if output.exit_code != 0 {
        // Fallback: direct iptables-save to sysconfig
        return save_to_file(
            executor,
            "/etc/sysconfig/iptables",
            "/etc/sysconfig/ip6tables",
        )
        .await;
    }

    Ok(())
}

/// Arch Linux: save to /etc/iptables/iptables.rules
async fn save_arch(executor: &dyn CommandExecutor) -> Result<(), PersistError> {
    save_to_file(
        executor,
        "/etc/iptables/iptables.rules",
        "/etc/iptables/ip6tables.rules",
    )
    .await
}

/// Alpine Linux: use rc-service
async fn save_alpine(executor: &dyn CommandExecutor) -> Result<(), PersistError> {
    let cmd = build_command("sudo", &["rc-service", "iptables", "save"]);
    let output = executor.exec(&cmd).await?;

    if output.exit_code != 0 {
        return Err(PersistError::Failed {
            distro: "alpine".to_string(),
            reason: format!("rc-service iptables save failed: {}", output.stderr.trim()),
        });
    }

    Ok(())
}

/// Manual fallback: iptables-save piped to a standard location
async fn save_manual_fallback(executor: &dyn CommandExecutor) -> Result<(), PersistError> {
    save_to_file(executor, "/etc/iptables.rules", "/etc/ip6tables.rules").await
}

/// Helper: dump iptables-save output to a file via sudo tee
async fn save_to_file(
    executor: &dyn CommandExecutor,
    v4_path: &str,
    v6_path: &str,
) -> Result<(), PersistError> {
    // Save IPv4 rules
    let v4_cmd = format!("sudo iptables-save | sudo tee {}", shell_words::quote(v4_path));
    let output = executor.exec(&v4_cmd).await?;
    if output.exit_code != 0 {
        return Err(PersistError::Failed {
            distro: "manual".to_string(),
            reason: format!("failed to save v4 rules to {}: {}", v4_path, output.stderr.trim()),
        });
    }

    // Save IPv6 rules (best effort — ip6tables may not be available)
    let v6_cmd = format!(
        "sudo ip6tables-save | sudo tee {}",
        shell_words::quote(v6_path)
    );
    // Ignore errors for IPv6 — host may not have ip6tables
    if let Err(e) = executor.exec(&v6_cmd).await {
        warn!("Failed to save IPv6 rules (non-fatal): {}", e);
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

    struct MockExecutor {
        responses: Vec<(String, CommandOutput)>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl MockExecutor {
        fn new(responses: Vec<(&str, i32, &str, &str)>) -> Self {
            Self {
                responses: responses
                    .into_iter()
                    .map(|(pattern, exit_code, stdout, stderr)| {
                        (
                            pattern.to_string(),
                            CommandOutput {
                                stdout: stdout.to_string(),
                                stderr: stderr.to_string(),
                                exit_code,
                            },
                        )
                    })
                    .collect(),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn find_response(&self, command: &str) -> CommandOutput {
            for (pattern, output) in &self.responses {
                if command.contains(pattern) {
                    return output.clone();
                }
            }
            CommandOutput {
                stdout: String::new(),
                stderr: "not found".to_string(),
                exit_code: 1,
            }
        }
    }

    #[async_trait]
    impl CommandExecutor for MockExecutor {
        async fn exec(&self, command: &str) -> Result<CommandOutput, ExecError> {
            self.calls.lock().unwrap().push(command.to_string());
            Ok(self.find_response(command))
        }

        async fn exec_with_stdin(
            &self,
            command: &str,
            _stdin: &[u8],
        ) -> Result<CommandOutput, ExecError> {
            self.calls.lock().unwrap().push(command.to_string());
            Ok(self.find_response(command))
        }
    }

    #[tokio::test]
    async fn test_save_debian_success() {
        let executor = MockExecutor::new(vec![
            ("netfilter-persistent", 0, "", ""),
        ]);
        let result = save_rules_persistently(&executor, "debian").await;
        assert!(result.is_ok());
        let calls = executor.calls.lock().unwrap();
        assert!(calls.iter().any(|c| c.contains("netfilter-persistent")));
    }

    #[tokio::test]
    async fn test_save_rhel_success() {
        let executor = MockExecutor::new(vec![
            ("service iptables save", 0, "", ""),
        ]);
        let result = save_rules_persistently(&executor, "rhel").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_save_alpine_failure() {
        let executor = MockExecutor::new(vec![
            ("rc-service", 1, "", "service not found"),
        ]);
        let result = save_rules_persistently(&executor, "alpine").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("alpine"));
    }

    #[tokio::test]
    async fn test_save_manual_fallback() {
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, "# Generated\n*filter\nCOMMIT\n", ""),
        ]);
        let result = save_rules_persistently(&executor, "other").await;
        assert!(result.is_ok());
    }
}
