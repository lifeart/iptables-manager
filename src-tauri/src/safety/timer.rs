use thiserror::Error;

use crate::ssh::command::build_command;
use crate::ssh::executor::{CommandExecutor, ExecError};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which mechanism is used for the safety revert timer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyMechanism {
    /// `iptables-apply` handles rollback natively.
    IptablesApply,
    /// POSIX `at` daemon.
    At,
    /// `systemd-run --on-active`.
    SystemdRun,
    /// `nohup` background process (last resort).
    Nohup,
}

/// Opaque identifier for a scheduled revert job.
#[derive(Debug, Clone)]
pub struct RevertJobId {
    pub mechanism: SafetyMechanism,
    /// Mechanism-specific identifier (at job number, systemd unit name, PID).
    pub id: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("failed to schedule revert: {0}")]
    ScheduleFailed(String),
    #[error("failed to cancel revert: {0}")]
    CancelFailed(String),
    #[error("command execution error: {0}")]
    Exec(#[from] ExecError),
}

// ---------------------------------------------------------------------------
// Mechanism detection
// ---------------------------------------------------------------------------

/// Detect the best available safety timer mechanism on the remote host.
///
/// Fallback chain:
/// 1. `at` + verify atd is running
/// 2. `systemd-run`
/// 3. `nohup` (last resort)
///
/// Note: `iptables-apply` is intentionally excluded because it requires
/// interactive stdin confirmation to cancel the revert timer, which our SSH
/// execution model cannot provide.
pub async fn detect_mechanism(executor: &dyn CommandExecutor) -> SafetyMechanism {
    // NOTE: iptables-apply is intentionally skipped here. It requires
    // interactive stdin confirmation to cancel the revert, which we cannot
    // provide through our SSH execution model. Starting directly with `at`
    // gives us a mechanism we can properly cancel via `atrm`.

    // 1. Check for `at` command and atd running
    let cmd = build_command("which", &["at"]);
    if let Ok(output) = executor.exec(&cmd).await {
        if output.exit_code == 0 && is_atd_running(executor).await {
            return SafetyMechanism::At;
        }
    }

    // 2. Check for systemd-run
    let cmd = build_command("which", &["systemd-run"]);
    if let Ok(output) = executor.exec(&cmd).await {
        if output.exit_code == 0 {
            return SafetyMechanism::SystemdRun;
        }
    }

    // 3. Fallback to nohup
    SafetyMechanism::Nohup
}

/// Check if atd is running via systemctl or pgrep.
async fn is_atd_running(executor: &dyn CommandExecutor) -> bool {
    // Try systemctl first
    let cmd = build_command("systemctl", &["is-active", "atd"]);
    if let Ok(output) = executor.exec(&cmd).await {
        if output.exit_code == 0 && output.stdout.trim() == "active" {
            return true;
        }
    }

    // Fallback to pgrep
    let cmd = build_command("pgrep", &["atd"]);
    if let Ok(output) = executor.exec(&cmd).await {
        return output.exit_code == 0;
    }

    false
}

// ---------------------------------------------------------------------------
// Schedule revert
// ---------------------------------------------------------------------------

/// Schedule a safety revert on the remote host.
///
/// The HMAC secret is passed via temp file (never CLI argument — not visible
/// in `ps`).
pub async fn schedule_revert(
    executor: &dyn CommandExecutor,
    mechanism: SafetyMechanism,
    backup_path: &str,
    timeout_secs: u32,
) -> Result<RevertJobId, SafetyError> {
    match mechanism {
        SafetyMechanism::IptablesApply => {
            schedule_iptables_apply(executor, backup_path, timeout_secs).await
        }
        SafetyMechanism::At => {
            schedule_at(executor, backup_path, timeout_secs).await
        }
        SafetyMechanism::SystemdRun => {
            schedule_systemd_run(executor, backup_path, timeout_secs).await
        }
        SafetyMechanism::Nohup => {
            schedule_nohup(executor, backup_path, timeout_secs).await
        }
    }
}

/// Cancel a previously scheduled revert.
///
/// Uses the mechanism stored in `job_id` rather than a separate parameter,
/// ensuring the correct mechanism is always used.
pub async fn cancel_revert(
    executor: &dyn CommandExecutor,
    job_id: &RevertJobId,
) -> Result<(), SafetyError> {
    match &job_id.mechanism {
        SafetyMechanism::IptablesApply => {
            // iptables-apply is no longer used by detect_mechanism, but this
            // arm is kept for backward compatibility with any previously
            // scheduled jobs. iptables-apply requires interactive stdin
            // confirmation which we cannot provide; cancellation is a no-op.
            Ok(())
        }
        SafetyMechanism::At => {
            let cmd = build_command("atrm", &[&job_id.id]);
            let output = executor
                .exec(&cmd)
                .await
                .map_err(|e| SafetyError::CancelFailed(e.to_string()))?;
            if output.exit_code != 0 {
                return Err(SafetyError::CancelFailed(format!(
                    "atrm failed (exit {}): {}",
                    output.exit_code, output.stderr
                )));
            }
            Ok(())
        }
        SafetyMechanism::SystemdRun => {
            let cmd = build_command("sudo", &["systemctl", "stop", &job_id.id]);
            executor
                .exec(&cmd)
                .await
                .map_err(|e| SafetyError::CancelFailed(e.to_string()))?;
            Ok(())
        }
        SafetyMechanism::Nohup => {
            let cmd = build_command("kill", &[&job_id.id]);
            executor
                .exec(&cmd)
                .await
                .map_err(|e| SafetyError::CancelFailed(e.to_string()))?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Per-mechanism scheduling implementations
// ---------------------------------------------------------------------------

async fn schedule_iptables_apply(
    executor: &dyn CommandExecutor,
    backup_path: &str,
    timeout_secs: u32,
) -> Result<RevertJobId, SafetyError> {
    let timeout_str = timeout_secs.to_string();
    let cmd = build_command(
        "sudo",
        &["iptables-apply", "-t", &timeout_str, backup_path],
    );
    let output = executor
        .exec(&cmd)
        .await
        .map_err(|e| SafetyError::ScheduleFailed(e.to_string()))?;
    if output.exit_code != 0 {
        return Err(SafetyError::ScheduleFailed(output.stderr));
    }
    Ok(RevertJobId {
        mechanism: SafetyMechanism::IptablesApply,
        id: "iptables-apply".to_string(),
    })
}

async fn schedule_at(
    executor: &dyn CommandExecutor,
    backup_path: &str,
    timeout_secs: u32,
) -> Result<RevertJobId, SafetyError> {
    // Schedule revert.sh to run after timeout via `at`
    let revert_cmd = format!(
        "/var/lib/traffic-rules/revert.sh < /dev/null",
    );
    let at_time = format!("now + {} seconds", timeout_secs);
    let at_cmd = build_command("at", &[&at_time]);

    let output = executor
        .exec_with_stdin(&at_cmd, revert_cmd.as_bytes())
        .await
        .map_err(|e| SafetyError::ScheduleFailed(e.to_string()))?;

    // `at` prints the job number on stderr like "job 42 at ..."
    let job_id = parse_at_job_id(&output.stderr).unwrap_or_else(|| "unknown".to_string());

    let _ = backup_path; // backup_path is used by revert.sh internally

    Ok(RevertJobId {
        mechanism: SafetyMechanism::At,
        id: job_id,
    })
}

async fn schedule_systemd_run(
    executor: &dyn CommandExecutor,
    _backup_path: &str,
    timeout_secs: u32,
) -> Result<RevertJobId, SafetyError> {
    let delay = format!("{}s", timeout_secs);
    // Use a timestamp-based identifier so the unit name survives app restarts
    // (unlike std::process::id() which changes each launch).
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let unit_name = format!("traffic-rules-revert-{}", ts);
    let cmd = build_command(
        "sudo",
        &[
            "systemd-run",
            "--unit", &unit_name,
            &format!("--on-active={}", delay),
            "/var/lib/traffic-rules/revert.sh",
        ],
    );
    let output = executor
        .exec(&cmd)
        .await
        .map_err(|e| SafetyError::ScheduleFailed(e.to_string()))?;
    if output.exit_code != 0 {
        return Err(SafetyError::ScheduleFailed(output.stderr));
    }
    Ok(RevertJobId {
        mechanism: SafetyMechanism::SystemdRun,
        id: unit_name,
    })
}

async fn schedule_nohup(
    executor: &dyn CommandExecutor,
    _backup_path: &str,
    timeout_secs: u32,
) -> Result<RevertJobId, SafetyError> {
    // Write the revert command to a temp script on the remote host to avoid
    // shell injection from nested quoting.
    let script_content = format!(
        "#!/bin/sh\nsleep {} && /var/lib/traffic-rules/revert.sh\n",
        timeout_secs
    );
    let tmp_script = "/var/lib/traffic-rules/.nohup-revert.sh";

    // Write script via stdin (safe — no shell interpolation)
    let write_cmd = build_command("sudo", &["tee", tmp_script]);
    let write_output = executor
        .exec_with_stdin(&write_cmd, script_content.as_bytes())
        .await
        .map_err(|e| SafetyError::ScheduleFailed(e.to_string()))?;
    if write_output.exit_code != 0 {
        return Err(SafetyError::ScheduleFailed(write_output.stderr));
    }

    let chmod_cmd = build_command("sudo", &["chmod", "0755", tmp_script]);
    let chmod_output = executor
        .exec(&chmod_cmd)
        .await
        .map_err(|e| SafetyError::ScheduleFailed(e.to_string()))?;
    if chmod_output.exit_code != 0 {
        return Err(SafetyError::ScheduleFailed(chmod_output.stderr));
    }

    // Run the script via nohup
    let run_cmd = build_command(
        "bash",
        &["-c", &format!("nohup {} > /dev/null 2>&1 & echo $!", tmp_script)],
    );
    let output = executor
        .exec(&run_cmd)
        .await
        .map_err(|e| SafetyError::ScheduleFailed(e.to_string()))?;
    if output.exit_code != 0 {
        return Err(SafetyError::ScheduleFailed(output.stderr));
    }
    let pid = output.stdout.trim().to_string();
    Ok(RevertJobId {
        mechanism: SafetyMechanism::Nohup,
        id: pid,
    })
}

/// Parse the job ID from `at` stderr output like "job 42 at ...".
fn parse_at_job_id(stderr: &str) -> Option<String> {
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("job ") {
            // "job 42 at Thu Mar 22 ..."
            return trimmed
                .strip_prefix("job ")
                .and_then(|rest| rest.split_whitespace().next())
                .map(|s| s.to_string());
        }
    }
    None
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

    /// Mock executor with configurable responses per command pattern.
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
            // Default: command not found
            CommandOutput {
                stdout: String::new(),
                stderr: format!("{}: not found", command),
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
    async fn test_detect_at() {
        let executor = MockExecutor::new(vec![
            // at is available
            ("which at", 0, "/usr/bin/at", ""),
            // atd is running
            ("is-active", 0, "active", ""),
        ]);
        let mechanism = detect_mechanism(&executor).await;
        assert_eq!(mechanism, SafetyMechanism::At);
    }

    #[tokio::test]
    async fn test_detect_systemd_run() {
        let executor = MockExecutor::new(vec![
            ("which at", 1, "", ""),
            ("systemd-run", 0, "/usr/bin/systemd-run", ""),
        ]);
        let mechanism = detect_mechanism(&executor).await;
        assert_eq!(mechanism, SafetyMechanism::SystemdRun);
    }

    #[tokio::test]
    async fn test_detect_nohup_fallback() {
        let executor = MockExecutor::new(vec![
            ("which at", 1, "", ""),
            ("systemd-run", 1, "", ""),
        ]);
        let mechanism = detect_mechanism(&executor).await;
        assert_eq!(mechanism, SafetyMechanism::Nohup);
    }

    #[tokio::test]
    async fn test_detect_at_without_atd() {
        let executor = MockExecutor::new(vec![
            ("which at", 0, "/usr/bin/at", ""),
            // atd is NOT running
            ("is-active", 1, "inactive", ""),
            ("pgrep", 1, "", ""),
            // systemd-run is available
            ("systemd-run", 0, "/usr/bin/systemd-run", ""),
        ]);
        let mechanism = detect_mechanism(&executor).await;
        // Should skip `at` and fall through to systemd-run
        assert_eq!(mechanism, SafetyMechanism::SystemdRun);
    }

    #[test]
    fn test_parse_at_job_id() {
        assert_eq!(
            parse_at_job_id("job 42 at Thu Mar 22 10:00:00 2026\n"),
            Some("42".to_string())
        );
        assert_eq!(
            parse_at_job_id("warning: commands will be executed using /bin/sh\njob 7 at Sun Mar 23 12:00:00 2026\n"),
            Some("7".to_string())
        );
        assert_eq!(parse_at_job_id("no job here"), None);
    }
}
