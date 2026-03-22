use thiserror::Error;

use crate::iptables::types::AddressFamily;
use crate::ssh::command::build_command;
use crate::ssh::executor::{CommandExecutor, ExecError};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum IpsetError {
    #[error("command execution error: {0}")]
    Exec(#[from] ExecError),
    #[error("ipset operation failed: {0}")]
    OperationFailed(String),
    #[error("ipset not available on remote host")]
    NotAvailable,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new ipset with the given name and address family.
///
/// Creates a `hash:net` set. For IPv4, uses `family inet`; for IPv6, `family inet6`.
/// For `AddressFamily::Both`, creates two sets: `{name}` (inet) and `{name}-v6` (inet6).
pub async fn create_ipset(
    executor: &dyn CommandExecutor,
    name: &str,
    family: &AddressFamily,
) -> Result<(), IpsetError> {
    match family {
        AddressFamily::V4 => {
            create_single_ipset(executor, name, "inet").await
        }
        AddressFamily::V6 => {
            create_single_ipset(executor, name, "inet6").await
        }
        AddressFamily::Both => {
            create_single_ipset(executor, name, "inet").await?;
            let v6_name = format!("{}-v6", name);
            create_single_ipset(executor, &v6_name, "inet6").await
        }
    }
}

/// Sync an ipset's entries using atomic swap.
///
/// Process:
/// 1. Create a temporary set with the same type
/// 2. Bulk-add all entries via `ipset restore` (stdin)
/// 3. Swap the temp set with the real set
/// 4. Destroy the temp set
///
/// This ensures zero downtime during updates.
pub async fn sync_ipset(
    executor: &dyn CommandExecutor,
    name: &str,
    entries: &[String],
    family: &AddressFamily,
) -> Result<(), IpsetError> {
    let inet_family = match family {
        AddressFamily::V4 => "inet",
        AddressFamily::V6 => "inet6",
        AddressFamily::Both => {
            // Split entries into v4 and v6, sync both
            let (v4_entries, v6_entries) = split_entries_by_family(entries);
            sync_single_ipset(executor, name, &v4_entries, "inet").await?;
            let v6_name = format!("{}-v6", name);
            sync_single_ipset(executor, &v6_name, &v6_entries, "inet6").await?;
            return Ok(());
        }
    };

    sync_single_ipset(executor, name, entries, inet_family).await
}

/// Delete an ipset and its v6 companion if it exists.
pub async fn delete_ipset(
    executor: &dyn CommandExecutor,
    name: &str,
) -> Result<(), IpsetError> {
    // Delete primary set
    delete_single_ipset(executor, name).await?;

    // Try deleting v6 companion (best-effort, may not exist)
    let v6_name = format!("{}-v6", name);
    let _ = delete_single_ipset(executor, &v6_name).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async fn create_single_ipset(
    executor: &dyn CommandExecutor,
    name: &str,
    inet_family: &str,
) -> Result<(), IpsetError> {
    let cmd = build_command(
        "sudo",
        &["ipset", "create", name, "hash:net", "family", inet_family, "-exist"],
    );
    let output = executor.exec(&cmd).await?;
    if output.exit_code != 0 {
        return Err(IpsetError::OperationFailed(format!(
            "create {} failed: {}",
            name,
            output.stderr.trim()
        )));
    }
    Ok(())
}

async fn sync_single_ipset(
    executor: &dyn CommandExecutor,
    name: &str,
    entries: &[String],
    inet_family: &str,
) -> Result<(), IpsetError> {
    let tmp_name = format!("{}-tmp", name);

    // 1. Create temp set (with -exist to handle leftover from a previous failed sync)
    let create_cmd = build_command(
        "sudo",
        &["ipset", "create", &tmp_name, "hash:net", "family", inet_family, "-exist"],
    );
    let output = executor.exec(&create_cmd).await?;
    if output.exit_code != 0 {
        return Err(IpsetError::OperationFailed(format!(
            "create temp set failed: {}",
            output.stderr.trim()
        )));
    }

    // Flush the temp set in case it already existed with stale entries
    let flush_cmd = build_command("sudo", &["ipset", "flush", &tmp_name]);
    let _ = executor.exec(&flush_cmd).await;

    // 2. Bulk-add entries via ipset restore (stdin)
    if !entries.is_empty() {
        let restore_data: String = entries
            .iter()
            .map(|e| format!("add {} {}", tmp_name, e))
            .collect::<Vec<_>>()
            .join("\n");

        let restore_cmd = build_command("sudo", &["ipset", "restore"]);
        let output = executor
            .exec_with_stdin(&restore_cmd, restore_data.as_bytes())
            .await?;
        if output.exit_code != 0 {
            // Clean up temp set
            let destroy_cmd = build_command("sudo", &["ipset", "destroy", &tmp_name]);
            let _ = executor.exec(&destroy_cmd).await;
            return Err(IpsetError::OperationFailed(format!(
                "bulk add to temp set failed: {}",
                output.stderr.trim()
            )));
        }
    }

    // 3. Atomic swap
    let swap_cmd = build_command("sudo", &["ipset", "swap", name, &tmp_name]);
    let output = executor.exec(&swap_cmd).await?;
    if output.exit_code != 0 {
        // Clean up temp set
        let destroy_cmd = build_command("sudo", &["ipset", "destroy", &tmp_name]);
        let _ = executor.exec(&destroy_cmd).await;
        return Err(IpsetError::OperationFailed(format!(
            "swap failed: {}",
            output.stderr.trim()
        )));
    }

    // 4. Destroy temp set (now contains old data)
    let destroy_cmd = build_command("sudo", &["ipset", "destroy", &tmp_name]);
    let output = executor.exec(&destroy_cmd).await?;
    if output.exit_code != 0 {
        // Non-fatal — the swap succeeded
        tracing::warn!("failed to destroy temp ipset {}: {}", tmp_name, output.stderr.trim());
    }

    Ok(())
}

async fn delete_single_ipset(
    executor: &dyn CommandExecutor,
    name: &str,
) -> Result<(), IpsetError> {
    // Flush first to remove all entries (required before destroy if set is in use)
    let flush_cmd = build_command("sudo", &["ipset", "flush", name]);
    let _ = executor.exec(&flush_cmd).await;

    let cmd = build_command("sudo", &["ipset", "destroy", name]);
    let output = executor.exec(&cmd).await?;
    if output.exit_code != 0 {
        return Err(IpsetError::OperationFailed(format!(
            "destroy {} failed: {}",
            name,
            output.stderr.trim()
        )));
    }
    Ok(())
}

/// Split entries into IPv4 and IPv6 based on address format.
fn split_entries_by_family(entries: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for entry in entries {
        if entry.contains(':') {
            v6.push(entry.clone());
        } else {
            v4.push(entry.clone());
        }
    }

    (v4, v6)
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

        fn get_calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
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
    async fn test_create_ipset_v4() {
        let executor = MockExecutor::new(vec![
            ("ipset create", 0, "", ""),
        ]);
        let result = create_ipset(&executor, "TR-blocklist", &AddressFamily::V4).await;
        assert!(result.is_ok());
        let calls = executor.get_calls();
        assert!(calls[0].contains("hash:net"));
        assert!(calls[0].contains("family inet"));
    }

    #[tokio::test]
    async fn test_create_ipset_v6() {
        let executor = MockExecutor::new(vec![
            ("ipset create", 0, "", ""),
        ]);
        let result = create_ipset(&executor, "TR-blocklist", &AddressFamily::V6).await;
        assert!(result.is_ok());
        let calls = executor.get_calls();
        assert!(calls[0].contains("family inet6"));
    }

    #[tokio::test]
    async fn test_create_ipset_both() {
        let executor = MockExecutor::new(vec![
            ("ipset create", 0, "", ""),
        ]);
        let result = create_ipset(&executor, "TR-blocklist", &AddressFamily::Both).await;
        assert!(result.is_ok());
        let calls = executor.get_calls();
        assert_eq!(calls.len(), 2);
    }

    #[tokio::test]
    async fn test_sync_ipset() {
        let executor = MockExecutor::new(vec![
            ("ipset create", 0, "", ""),
            ("ipset restore", 0, "", ""),
            ("ipset swap", 0, "", ""),
            ("ipset destroy", 0, "", ""),
        ]);
        let entries = vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()];
        let result = sync_ipset(&executor, "TR-blocklist", &entries, &AddressFamily::V4).await;
        assert!(result.is_ok());

        let calls = executor.get_calls();
        // Should create temp, restore, swap, destroy
        assert!(calls.iter().any(|c| c.contains("create") && c.contains("-tmp")));
        assert!(calls.iter().any(|c| c.contains("restore")));
        assert!(calls.iter().any(|c| c.contains("swap")));
        assert!(calls.iter().any(|c| c.contains("destroy")));
    }

    #[tokio::test]
    async fn test_delete_ipset() {
        let executor = MockExecutor::new(vec![
            ("ipset flush", 0, "", ""),
            ("ipset destroy", 0, "", ""),
        ]);
        let result = delete_ipset(&executor, "TR-blocklist").await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_split_entries_by_family() {
        let entries = vec![
            "10.0.0.0/8".to_string(),
            "192.168.0.0/16".to_string(),
            "2001:db8::/32".to_string(),
            "fd00::/8".to_string(),
        ];
        let (v4, v6) = split_entries_by_family(&entries);
        assert_eq!(v4.len(), 2);
        assert_eq!(v6.len(), 2);
        assert!(v4.contains(&"10.0.0.0/8".to_string()));
        assert!(v6.contains(&"2001:db8::/32".to_string()));
    }
}
