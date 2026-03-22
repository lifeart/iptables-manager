use thiserror::Error;

use crate::ssh::command::build_command;
use crate::ssh::executor::{CommandExecutor, ExecError};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SysctlError {
    #[error("command execution error: {0}")]
    Exec(#[from] ExecError),
    #[error("sysctl operation failed: {0}")]
    Failed(String),
    #[error("invalid sysctl key: {0}")]
    InvalidKey(String),
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SYSCTL_CONF_PATH: &str = "/etc/sysctl.d/99-traffic-rules.conf";

/// Allowed sysctl keys (whitelist for safety).
const ALLOWED_KEYS: &[&str] = &[
    "net.ipv4.ip_forward",
    "net.ipv6.conf.all.forwarding",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.all.log_martians",
    "net.netfilter.nf_conntrack_max",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Set a sysctl value on the remote host.
///
/// If `persistent` is true, also writes the setting to
/// `/etc/sysctl.d/99-traffic-rules.conf` so it survives reboots.
pub async fn set_sysctl(
    executor: &dyn CommandExecutor,
    key: &str,
    value: &str,
    persistent: bool,
) -> Result<(), SysctlError> {
    validate_key(key)?;
    validate_value(value)?;

    // Apply immediately
    let setting = format!("{}={}", key, value);
    let cmd = build_command("sudo", &["sysctl", "-w", &setting]);
    let output = executor.exec(&cmd).await?;
    if output.exit_code != 0 {
        return Err(SysctlError::Failed(format!(
            "sysctl -w failed: {}",
            output.stderr.trim()
        )));
    }

    // Persist if requested
    if persistent {
        persist_sysctl(executor, key, value).await?;
    }

    Ok(())
}

/// Get a sysctl value from the remote host.
pub async fn get_sysctl(
    executor: &dyn CommandExecutor,
    key: &str,
) -> Result<String, SysctlError> {
    validate_key(key)?;

    let cmd = build_command("sudo", &["sysctl", "-n", key]);
    let output = executor.exec(&cmd).await?;
    if output.exit_code != 0 {
        return Err(SysctlError::Failed(format!(
            "sysctl -n {} failed: {}",
            key,
            output.stderr.trim()
        )));
    }

    Ok(output.stdout.trim().to_string())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn validate_key(key: &str) -> Result<(), SysctlError> {
    if !ALLOWED_KEYS.contains(&key) {
        return Err(SysctlError::InvalidKey(format!(
            "{} is not in the allowed sysctl keys list",
            key
        )));
    }
    // Extra safety: ensure no shell metacharacters
    if key.contains(';')
        || key.contains('|')
        || key.contains('&')
        || key.contains('`')
        || key.contains('$')
        || key.contains('\n')
    {
        return Err(SysctlError::InvalidKey(
            "key contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<(), SysctlError> {
    // Only allow numeric values and simple strings
    if value.contains(';')
        || value.contains('|')
        || value.contains('&')
        || value.contains('`')
        || value.contains('$')
        || value.contains('\n')
    {
        return Err(SysctlError::Failed(
            "value contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

/// Persist a sysctl setting to the Traffic Rules conf file.
///
/// Reads the existing file, updates or adds the key, and writes back.
async fn persist_sysctl(
    executor: &dyn CommandExecutor,
    key: &str,
    value: &str,
) -> Result<(), SysctlError> {
    // Read existing file (may not exist)
    let cat_cmd = build_command("cat", &[SYSCTL_CONF_PATH]);
    let existing = match executor.exec(&cat_cmd).await {
        Ok(o) if o.exit_code == 0 => o.stdout,
        _ => String::new(),
    };

    // Update or add the key
    let new_content = update_sysctl_conf(&existing, key, value);

    // Write back via sudo tee
    let tee_cmd = build_command("sudo", &["tee", SYSCTL_CONF_PATH]);
    let output = executor
        .exec_with_stdin(&tee_cmd, new_content.as_bytes())
        .await?;
    if output.exit_code != 0 {
        return Err(SysctlError::Failed(format!(
            "failed to write {}: {}",
            SYSCTL_CONF_PATH,
            output.stderr.trim()
        )));
    }

    Ok(())
}

/// Update or add a sysctl key=value in the conf file content.
fn update_sysctl_conf(existing: &str, key: &str, value: &str) -> String {
    let target_prefix = format!("{} ", key);
    let target_prefix_eq = format!("{}=", key);
    let new_line = format!("{} = {}", key, value);
    let mut found = false;
    let mut lines: Vec<String> = Vec::new();

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(&target_prefix) || trimmed.starts_with(&target_prefix_eq) {
            lines.push(new_line.clone());
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }

    if !found {
        if !lines.is_empty() && !lines.last().map_or(true, |l| l.is_empty()) {
            // Don't add extra blank line if file already ends with one
        }
        lines.push(new_line);
    }

    let mut result = lines.join("\n");
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result
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

    #[test]
    fn test_validate_key_allowed() {
        assert!(validate_key("net.ipv4.ip_forward").is_ok());
        assert!(validate_key("net.ipv6.conf.all.forwarding").is_ok());
    }

    #[test]
    fn test_validate_key_disallowed() {
        assert!(validate_key("net.some.random.key").is_err());
    }

    #[test]
    fn test_validate_key_injection() {
        // Even if it matched an allowed key prefix, shell chars are rejected
        assert!(validate_key("net.ipv4.ip_forward;rm -rf /").is_err());
    }

    #[test]
    fn test_update_sysctl_conf_new() {
        let result = update_sysctl_conf("", "net.ipv4.ip_forward", "1");
        assert_eq!(result, "net.ipv4.ip_forward = 1\n");
    }

    #[test]
    fn test_update_sysctl_conf_existing() {
        let existing = "net.ipv4.ip_forward = 0\nnet.ipv4.conf.all.rp_filter = 1\n";
        let result = update_sysctl_conf(existing, "net.ipv4.ip_forward", "1");
        assert!(result.contains("net.ipv4.ip_forward = 1"));
        assert!(result.contains("net.ipv4.conf.all.rp_filter = 1"));
        // Should not duplicate
        assert_eq!(result.matches("ip_forward").count(), 1);
    }

    #[test]
    fn test_update_sysctl_conf_add_to_existing() {
        let existing = "net.ipv4.conf.all.rp_filter = 1\n";
        let result = update_sysctl_conf(existing, "net.ipv4.ip_forward", "1");
        assert!(result.contains("net.ipv4.conf.all.rp_filter = 1"));
        assert!(result.contains("net.ipv4.ip_forward = 1"));
    }

    #[tokio::test]
    async fn test_get_sysctl() {
        let executor = MockExecutor::new(vec![
            ("sysctl", 0, "1\n", ""),
        ]);
        let result = get_sysctl(&executor, "net.ipv4.ip_forward").await;
        assert_eq!(result.unwrap(), "1");
    }

    #[tokio::test]
    async fn test_set_sysctl_no_persist() {
        let executor = MockExecutor::new(vec![
            ("sysctl -w", 0, "net.ipv4.ip_forward = 1\n", ""),
        ]);
        let result =
            set_sysctl(&executor, "net.ipv4.ip_forward", "1", false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_set_sysctl_invalid_key() {
        let executor = MockExecutor::new(vec![]);
        let result =
            set_sysctl(&executor, "invalid.key", "1", false).await;
        assert!(result.is_err());
    }
}
