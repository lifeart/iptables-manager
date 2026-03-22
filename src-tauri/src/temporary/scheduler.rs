use thiserror::Error;

use crate::safety::timer::SafetyMechanism;
use crate::ssh::command::build_command;
use crate::ssh::executor::{CommandExecutor, ExecError};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A scheduled rule expiry on a remote host.
#[derive(Debug, Clone)]
pub struct ScheduledExpiry {
    pub rule_id: String,
    pub host_id: String,
    pub expires_at: u64,
    pub remote_job_id: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ScheduleError {
    #[error("failed to schedule expiry: {0}")]
    ScheduleFailed(String),
    #[error("failed to cancel expiry: {0}")]
    CancelFailed(String),
    #[error("command execution error: {0}")]
    Exec(#[from] ExecError),
}

// ---------------------------------------------------------------------------
// Schedule expiry
// ---------------------------------------------------------------------------

/// Schedule a rule expiry on the remote host.
///
/// Uses the same fallback chain as the safety timer (at -> systemd-run -> nohup).
/// The expiry command does content-based delete:
///   `sudo iptables -w 5 -D TR-INPUT <rule_spec_args>`
pub async fn schedule_expiry(
    executor: &dyn CommandExecutor,
    mechanism: SafetyMechanism,
    rule_id: &str,
    rule_spec_args: &str,
    expires_at: u64,
) -> Result<ScheduledExpiry, ScheduleError> {
    let delete_cmd = format!("sudo iptables -w 5 -D TR-INPUT {}", rule_spec_args);
    let host_id = String::new(); // Caller sets this after

    let remote_job_id = match mechanism {
        SafetyMechanism::At => {
            schedule_expiry_at(executor, &delete_cmd, expires_at).await?
        }
        SafetyMechanism::SystemdRun => {
            schedule_expiry_systemd(executor, &delete_cmd, expires_at).await?
        }
        SafetyMechanism::Nohup => {
            schedule_expiry_nohup(executor, &delete_cmd, expires_at).await?
        }
        SafetyMechanism::IptablesApply => {
            // IptablesApply is not applicable for rule expiry; fall back to nohup
            schedule_expiry_nohup(executor, &delete_cmd, expires_at).await?
        }
    };

    Ok(ScheduledExpiry {
        rule_id: rule_id.to_string(),
        host_id,
        expires_at,
        remote_job_id,
    })
}

/// Cancel a previously scheduled rule expiry.
pub async fn cancel_expiry(
    executor: &dyn CommandExecutor,
    mechanism: SafetyMechanism,
    job: &ScheduledExpiry,
) -> Result<(), ScheduleError> {
    match mechanism {
        SafetyMechanism::At => {
            let cmd = build_command("atrm", &[&job.remote_job_id]);
            let output = executor
                .exec(&cmd)
                .await
                .map_err(|e| ScheduleError::CancelFailed(e.to_string()))?;
            if output.exit_code != 0 {
                return Err(ScheduleError::CancelFailed(format!(
                    "atrm failed (exit {}): {}",
                    output.exit_code, output.stderr
                )));
            }
        }
        SafetyMechanism::SystemdRun => {
            let cmd = build_command("sudo", &["systemctl", "stop", &job.remote_job_id]);
            executor
                .exec(&cmd)
                .await
                .map_err(|e| ScheduleError::CancelFailed(e.to_string()))?;
        }
        SafetyMechanism::Nohup => {
            let cmd = build_command("kill", &[&job.remote_job_id]);
            executor
                .exec(&cmd)
                .await
                .map_err(|e| ScheduleError::CancelFailed(e.to_string()))?;
        }
        SafetyMechanism::IptablesApply => {
            // No-op, same as safety timer
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-mechanism scheduling
// ---------------------------------------------------------------------------

async fn schedule_expiry_at(
    executor: &dyn CommandExecutor,
    delete_cmd: &str,
    expires_at: u64,
) -> Result<String, ScheduleError> {
    // Convert expires_at to an `at` time specification.
    // We use the epoch timestamp format with date conversion.
    let at_time_cmd = format!("date -d @{} '+%H:%M %Y-%m-%d'", expires_at);
    let time_output = executor
        .exec(&at_time_cmd)
        .await
        .map_err(|e| ScheduleError::ScheduleFailed(e.to_string()))?;

    let at_time = time_output.stdout.trim().to_string();
    if at_time.is_empty() {
        return Err(ScheduleError::ScheduleFailed(
            "failed to compute at time".to_string(),
        ));
    }

    let at_cmd = build_command("at", &[&at_time]);
    let output = executor
        .exec_with_stdin(&at_cmd, delete_cmd.as_bytes())
        .await
        .map_err(|e| ScheduleError::ScheduleFailed(e.to_string()))?;

    let job_id = parse_at_job_id(&output.stderr).unwrap_or_else(|| "unknown".to_string());
    Ok(job_id)
}

async fn schedule_expiry_systemd(
    executor: &dyn CommandExecutor,
    delete_cmd: &str,
    expires_at: u64,
) -> Result<String, ScheduleError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let delay_secs = if expires_at > now {
        expires_at - now
    } else {
        1 // Execute immediately if already past
    };

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let unit_name = format!("traffic-rules-expire-{}", ts);
    let delay = format!("{}s", delay_secs);

    let cmd = build_command(
        "sudo",
        &[
            "systemd-run",
            "--unit",
            &unit_name,
            &format!("--on-active={}", delay),
            "bash",
            "-c",
            delete_cmd,
        ],
    );

    let output = executor
        .exec(&cmd)
        .await
        .map_err(|e| ScheduleError::ScheduleFailed(e.to_string()))?;

    if output.exit_code != 0 {
        return Err(ScheduleError::ScheduleFailed(output.stderr));
    }

    Ok(unit_name)
}

async fn schedule_expiry_nohup(
    executor: &dyn CommandExecutor,
    delete_cmd: &str,
    expires_at: u64,
) -> Result<String, ScheduleError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let delay_secs = if expires_at > now {
        expires_at - now
    } else {
        0
    };

    // Write a temp script to avoid shell quoting issues
    let script_content = format!(
        "#!/bin/sh\nsleep {} && {}\n",
        delay_secs, delete_cmd
    );
    let tmp_script = "/var/lib/traffic-rules/.nohup-expire.sh";

    let write_cmd = build_command("sudo", &["tee", tmp_script]);
    let write_output = executor
        .exec_with_stdin(&write_cmd, script_content.as_bytes())
        .await
        .map_err(|e| ScheduleError::ScheduleFailed(e.to_string()))?;
    if write_output.exit_code != 0 {
        return Err(ScheduleError::ScheduleFailed(write_output.stderr));
    }

    let chmod_cmd = build_command("sudo", &["chmod", "0755", tmp_script]);
    let chmod_output = executor
        .exec(&chmod_cmd)
        .await
        .map_err(|e| ScheduleError::ScheduleFailed(e.to_string()))?;
    if chmod_output.exit_code != 0 {
        return Err(ScheduleError::ScheduleFailed(chmod_output.stderr));
    }

    let run_cmd = build_command(
        "bash",
        &[
            "-c",
            &format!("nohup {} > /dev/null 2>&1 & echo $!", tmp_script),
        ],
    );
    let output = executor
        .exec(&run_cmd)
        .await
        .map_err(|e| ScheduleError::ScheduleFailed(e.to_string()))?;
    if output.exit_code != 0 {
        return Err(ScheduleError::ScheduleFailed(output.stderr));
    }

    let pid = output.stdout.trim().to_string();
    Ok(pid)
}

/// Parse the job ID from `at` stderr output like "job 42 at ...".
fn parse_at_job_id(stderr: &str) -> Option<String> {
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("job ") {
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

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn find_response(&self, command: &str) -> CommandOutput {
            for (pattern, output) in &self.responses {
                if command.contains(pattern) {
                    return output.clone();
                }
            }
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
    async fn test_schedule_expiry_at() {
        let executor = MockExecutor::new(vec![
            ("date", 0, "10:30 2026-03-22", ""),
            ("at", 0, "", "job 99 at Sun Mar 22 10:30:00 2026\n"),
        ]);

        let result = schedule_expiry(
            &executor,
            SafetyMechanism::At,
            "rule-1",
            "-p tcp --dport 8080 -j ACCEPT",
            1742644200, // some future timestamp
        )
        .await
        .unwrap();

        assert_eq!(result.rule_id, "rule-1");
        assert_eq!(result.remote_job_id, "99");
        assert_eq!(result.expires_at, 1742644200);

        let calls = executor.calls();
        assert!(calls.iter().any(|c| c.contains("date")));
        assert!(calls.iter().any(|c| c.contains("at")));
    }

    #[tokio::test]
    async fn test_schedule_expiry_systemd() {
        let executor = MockExecutor::new(vec![
            ("systemd-run", 0, "", ""),
        ]);

        let result = schedule_expiry(
            &executor,
            SafetyMechanism::SystemdRun,
            "rule-2",
            "-p tcp --dport 443 -j ACCEPT",
            u64::MAX / 2,
        )
        .await
        .unwrap();

        assert_eq!(result.rule_id, "rule-2");
        assert!(result.remote_job_id.starts_with("traffic-rules-expire-"));

        let calls = executor.calls();
        assert!(calls.iter().any(|c| c.contains("systemd-run")));
        // Verify the delete command is in the systemd-run invocation
        assert!(calls.iter().any(|c| c.contains("iptables") && c.contains("-D TR-INPUT")));
    }

    #[tokio::test]
    async fn test_schedule_expiry_nohup() {
        let executor = MockExecutor::new(vec![
            ("tee", 0, "", ""),
            ("chmod", 0, "", ""),
            ("nohup", 0, "12345", ""),
        ]);

        let result = schedule_expiry(
            &executor,
            SafetyMechanism::Nohup,
            "rule-3",
            "-p udp --dport 53 -j ACCEPT",
            u64::MAX / 2,
        )
        .await
        .unwrap();

        assert_eq!(result.rule_id, "rule-3");
        assert_eq!(result.remote_job_id, "12345");

        let calls = executor.calls();
        assert!(calls.iter().any(|c| c.contains("tee")));
        assert!(calls.iter().any(|c| c.contains("chmod")));
        assert!(calls.iter().any(|c| c.contains("nohup")));
    }

    #[tokio::test]
    async fn test_cancel_expiry_at() {
        let executor = MockExecutor::new(vec![
            ("atrm", 0, "", ""),
        ]);

        let job = ScheduledExpiry {
            rule_id: "rule-1".to_string(),
            host_id: "host-1".to_string(),
            expires_at: 1742644200,
            remote_job_id: "99".to_string(),
        };

        cancel_expiry(&executor, SafetyMechanism::At, &job)
            .await
            .unwrap();

        let calls = executor.calls();
        assert!(calls.iter().any(|c| c.contains("atrm") && c.contains("99")));
    }

    #[tokio::test]
    async fn test_cancel_expiry_systemd() {
        let executor = MockExecutor::new(vec![
            ("systemctl", 0, "", ""),
        ]);

        let job = ScheduledExpiry {
            rule_id: "rule-2".to_string(),
            host_id: "host-1".to_string(),
            expires_at: 1742644200,
            remote_job_id: "traffic-rules-expire-123".to_string(),
        };

        cancel_expiry(&executor, SafetyMechanism::SystemdRun, &job)
            .await
            .unwrap();

        let calls = executor.calls();
        assert!(calls
            .iter()
            .any(|c| c.contains("systemctl") && c.contains("traffic-rules-expire-123")));
    }

    #[tokio::test]
    async fn test_cancel_expiry_nohup() {
        let executor = MockExecutor::new(vec![
            ("kill", 0, "", ""),
        ]);

        let job = ScheduledExpiry {
            rule_id: "rule-3".to_string(),
            host_id: "host-1".to_string(),
            expires_at: 1742644200,
            remote_job_id: "12345".to_string(),
        };

        cancel_expiry(&executor, SafetyMechanism::Nohup, &job)
            .await
            .unwrap();

        let calls = executor.calls();
        assert!(calls
            .iter()
            .any(|c| c.contains("kill") && c.contains("12345")));
    }

    #[tokio::test]
    async fn test_cancel_expiry_at_failure() {
        let executor = MockExecutor::new(vec![
            ("atrm", 1, "", "cannot find job"),
        ]);

        let job = ScheduledExpiry {
            rule_id: "rule-1".to_string(),
            host_id: "host-1".to_string(),
            expires_at: 1742644200,
            remote_job_id: "99".to_string(),
        };

        let result = cancel_expiry(&executor, SafetyMechanism::At, &job).await;
        assert!(matches!(result, Err(ScheduleError::CancelFailed(_))));
    }

    #[tokio::test]
    async fn test_schedule_expiry_at_date_failure() {
        let executor = MockExecutor::new(vec![
            ("date", 0, "", ""), // empty stdout
        ]);

        let result = schedule_expiry(
            &executor,
            SafetyMechanism::At,
            "rule-1",
            "-p tcp --dport 80 -j ACCEPT",
            1742644200,
        )
        .await;

        assert!(matches!(result, Err(ScheduleError::ScheduleFailed(_))));
    }

    #[test]
    fn test_parse_at_job_id_valid() {
        assert_eq!(
            parse_at_job_id("job 42 at Thu Mar 22 10:00:00 2026\n"),
            Some("42".to_string())
        );
    }

    #[test]
    fn test_parse_at_job_id_with_warning() {
        assert_eq!(
            parse_at_job_id("warning: will use /bin/sh\njob 7 at Sun Mar 23 12:00:00 2026\n"),
            Some("7".to_string())
        );
    }

    #[test]
    fn test_parse_at_job_id_none() {
        assert_eq!(parse_at_job_id("no match here"), None);
    }

    #[tokio::test]
    async fn test_schedule_expiry_iptables_apply_falls_back_to_nohup() {
        let executor = MockExecutor::new(vec![
            ("tee", 0, "", ""),
            ("chmod", 0, "", ""),
            ("nohup", 0, "9999", ""),
        ]);

        let result = schedule_expiry(
            &executor,
            SafetyMechanism::IptablesApply,
            "rule-4",
            "-p tcp --dport 22 -j ACCEPT",
            u64::MAX / 2,
        )
        .await
        .unwrap();

        assert_eq!(result.rule_id, "rule-4");
        assert_eq!(result.remote_job_id, "9999");
    }

    #[tokio::test]
    async fn test_cancel_expiry_iptables_apply_is_noop() {
        let executor = MockExecutor::new(vec![]);

        let job = ScheduledExpiry {
            rule_id: "rule-4".to_string(),
            host_id: "host-1".to_string(),
            expires_at: 1742644200,
            remote_job_id: "".to_string(),
        };

        cancel_expiry(&executor, SafetyMechanism::IptablesApply, &job)
            .await
            .unwrap();
    }
}
