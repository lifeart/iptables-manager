use serde::Serialize;
use tracing::warn;

use crate::ssh::executor::{CommandExecutor, CommandOutput, ExecError};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct LockHolder {
    pub pid: u32,
    pub process_name: String,
}

#[derive(Debug)]
pub enum LockError {
    Exec(ExecError),
    Exhausted {
        holder: Option<LockHolder>,
        attempts: u32,
    },
}

impl From<ExecError> for LockError {
    fn from(e: ExecError) -> Self {
        LockError::Exec(e)
    }
}

// ---------------------------------------------------------------------------
// Lock contention detection
// ---------------------------------------------------------------------------

fn is_lock_contention(output: &CommandOutput) -> bool {
    if output.exit_code == 4 {
        return true;
    }
    let stderr_lower = output.stderr.to_lowercase();
    stderr_lower.contains("xtables lock")
        || stderr_lower.contains("resource temporarily unavailable")
}

/// Detect the process currently holding the xtables lock, if any.
pub async fn detect_lock_holder(executor: &dyn CommandExecutor) -> Option<LockHolder> {
    // Get PID(s) holding the lock file
    let fuser_output = executor
        .exec("fuser /run/xtables.lock 2>/dev/null")
        .await
        .ok()?;

    if fuser_output.exit_code != 0 || fuser_output.stdout.trim().is_empty() {
        return None;
    }

    // Parse first PID from output (fuser may return "   1234  5678")
    let pid: u32 = fuser_output
        .stdout
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;

    // Get process name for that PID
    let ps_cmd = format!("ps -p {} -o comm= 2>/dev/null", pid);
    let ps_output = executor.exec(&ps_cmd).await.ok()?;

    if ps_output.exit_code != 0 || ps_output.stdout.trim().is_empty() {
        return None;
    }

    Some(LockHolder {
        pid,
        process_name: ps_output.stdout.trim().to_string(),
    })
}

// ---------------------------------------------------------------------------
// Retry with exponential backoff
// ---------------------------------------------------------------------------

/// Execute a command with automatic retry on xtables lock contention.
///
/// If `stdin` is `Some`, the command is executed with stdin data piped in.
/// Retries up to `max_retries` times with exponential backoff (1s, 2s, 4s, ...).
/// Only lock-contention errors trigger retries — other failures are returned
/// immediately.
pub async fn execute_with_lock_retry(
    executor: &dyn CommandExecutor,
    command: &str,
    stdin: Option<&[u8]>,
    max_retries: u32,
) -> Result<CommandOutput, LockError> {
    for attempt in 0..max_retries {
        let result = match stdin {
            Some(data) => executor.exec_with_stdin(command, data).await,
            None => executor.exec(command).await,
        };

        match result {
            Ok(output) => {
                if !is_lock_contention(&output) {
                    return Ok(output);
                }
                // Lock contention — prepare to retry
                let holder = detect_lock_holder(executor).await;
                warn!(
                    attempt = attempt + 1,
                    max_retries,
                    holder_pid = holder.as_ref().map(|h| h.pid),
                    holder_process = holder.as_ref().map(|h| h.process_name.as_str()),
                    "xtables lock contention, retrying"
                );

                let backoff_secs = 1u64 << attempt; // 1, 2, 4, ...
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
            }
            Err(e) => {
                return Err(LockError::Exec(e));
            }
        }
    }

    // All retries exhausted
    let holder = detect_lock_holder(executor).await;
    Err(LockError::Exhausted {
        holder,
        attempts: max_retries,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::executor::{CommandOutput, ExecError};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    /// A mock executor that returns sequential responses for the same command.
    /// Each call pops the next response from the queue.
    struct SequentialMockExecutor {
        responses: Mutex<Vec<Result<CommandOutput, ExecError>>>,
        calls: Mutex<Vec<String>>,
    }

    impl SequentialMockExecutor {
        fn new(responses: Vec<Result<CommandOutput, ExecError>>) -> Self {
            Self {
                responses: Mutex::new(responses),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn get_calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CommandExecutor for SequentialMockExecutor {
        async fn exec(&self, command: &str) -> Result<CommandOutput, ExecError> {
            self.calls.lock().unwrap().push(command.to_string());
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: "no more mock responses".to_string(),
                    exit_code: 1,
                })
            } else {
                responses.remove(0)
            }
        }

        async fn exec_with_stdin(
            &self,
            command: &str,
            _stdin: &[u8],
        ) -> Result<CommandOutput, ExecError> {
            self.calls.lock().unwrap().push(command.to_string());
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: "no more mock responses".to_string(),
                    exit_code: 1,
                })
            } else {
                responses.remove(0)
            }
        }
    }

    fn lock_error_output() -> CommandOutput {
        CommandOutput {
            stdout: String::new(),
            stderr: "Another app is currently holding the xtables lock".to_string(),
            exit_code: 4,
        }
    }

    fn success_output() -> CommandOutput {
        CommandOutput {
            stdout: "OK".to_string(),
            stderr: String::new(),
            exit_code: 0,
        }
    }

    fn normal_error_output() -> CommandOutput {
        CommandOutput {
            stdout: String::new(),
            stderr: "iptables: Bad rule".to_string(),
            exit_code: 1,
        }
    }

    #[tokio::test]
    async fn test_lock_retry_succeeds_second_attempt() {
        let executor = SequentialMockExecutor::new(vec![
            // First call: lock contention
            Ok(lock_error_output()),
            // fuser call for detect_lock_holder (returns nothing)
            Ok(CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 1,
            }),
            // Second call: success
            Ok(success_output()),
        ]);

        let result = execute_with_lock_retry(&executor, "sudo iptables-restore", None, 3).await;
        assert!(result.is_ok(), "should succeed on second attempt");
        assert_eq!(result.unwrap().stdout, "OK");
    }

    #[tokio::test]
    async fn test_lock_retry_exhausted() {
        let executor = SequentialMockExecutor::new(vec![
            // Attempt 1: lock contention
            Ok(lock_error_output()),
            // fuser for detect after attempt 1
            Ok(CommandOutput { stdout: String::new(), stderr: String::new(), exit_code: 1 }),
            // Attempt 2: lock contention
            Ok(lock_error_output()),
            // fuser for detect after attempt 2
            Ok(CommandOutput { stdout: String::new(), stderr: String::new(), exit_code: 1 }),
            // Final detect_lock_holder after exhaustion
            Ok(CommandOutput { stdout: String::new(), stderr: String::new(), exit_code: 1 }),
        ]);

        let result = execute_with_lock_retry(&executor, "sudo iptables-restore", None, 2).await;
        assert!(result.is_err(), "should be exhausted");
        match result.unwrap_err() {
            LockError::Exhausted { holder, attempts } => {
                assert_eq!(attempts, 2);
                assert!(holder.is_none());
            }
            other => panic!("expected Exhausted, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_detect_lock_holder_with_pid() {
        let executor = SequentialMockExecutor::new(vec![
            // fuser output
            Ok(CommandOutput {
                stdout: "  1234  ".to_string(),
                stderr: String::new(),
                exit_code: 0,
            }),
            // ps output
            Ok(CommandOutput {
                stdout: "fail2ban-server\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            }),
        ]);

        let holder = detect_lock_holder(&executor).await;
        assert!(holder.is_some());
        let holder = holder.unwrap();
        assert_eq!(holder.pid, 1234);
        assert_eq!(holder.process_name, "fail2ban-server");
    }

    #[tokio::test]
    async fn test_not_lock_error_no_retry() {
        let executor = SequentialMockExecutor::new(vec![
            // First (and only) call: non-lock error
            Ok(normal_error_output()),
        ]);

        let result = execute_with_lock_retry(&executor, "sudo iptables-restore", None, 3).await;
        // Should return immediately with the error output (not retry)
        assert!(result.is_ok(), "non-lock error should still return Ok(CommandOutput)");
        let output = result.unwrap();
        assert_eq!(output.exit_code, 1);
        assert!(output.stderr.contains("Bad rule"));

        // Verify only one call was made (no retries)
        let calls = executor.get_calls();
        assert_eq!(calls.len(), 1, "should not retry on non-lock errors");
    }

    #[tokio::test]
    async fn test_lock_retry_with_stdin() {
        let executor = SequentialMockExecutor::new(vec![
            // First call: lock contention
            Ok(lock_error_output()),
            // fuser for detect
            Ok(CommandOutput { stdout: String::new(), stderr: String::new(), exit_code: 1 }),
            // Second call: success
            Ok(success_output()),
        ]);

        let result = execute_with_lock_retry(
            &executor,
            "sudo iptables-restore",
            Some(b"*filter\nCOMMIT\n"),
            3,
        )
        .await;
        assert!(result.is_ok(), "should succeed with stdin on retry");
    }

    #[test]
    fn test_is_lock_contention_exit_code_4() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 4,
        };
        assert!(is_lock_contention(&output));
    }

    #[test]
    fn test_is_lock_contention_xtables_lock_message() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: "Another app is currently holding the xtables lock".to_string(),
            exit_code: 1,
        };
        assert!(is_lock_contention(&output));
    }

    #[test]
    fn test_is_lock_contention_resource_unavailable() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: "Resource temporarily unavailable".to_string(),
            exit_code: 11,
        };
        assert!(is_lock_contention(&output));
    }

    #[test]
    fn test_is_not_lock_contention() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: "iptables: Bad rule".to_string(),
            exit_code: 1,
        };
        assert!(!is_lock_contention(&output));
    }
}
