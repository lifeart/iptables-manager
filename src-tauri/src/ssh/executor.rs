use async_trait::async_trait;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Execution errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ExecError {
    #[error("SSH connection lost: {0}")]
    ConnectionLost(String),
    #[error("command timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
    #[error("transport error: {0}")]
    Transport(String),
}

// ---------------------------------------------------------------------------
// Command output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

// ---------------------------------------------------------------------------
// CommandExecutor trait
// ---------------------------------------------------------------------------

/// Abstraction over SSH command execution for testability.
///
/// All functions that would execute SSH commands accept a `&dyn CommandExecutor`
/// instead of a concrete SSH session. This enables unit testing with mock
/// executors.
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Execute a command string on the remote host and return its output.
    async fn exec(&self, command: &str) -> Result<CommandOutput, ExecError>;

    /// Execute a command string, piping `stdin` data to its standard input.
    async fn exec_with_stdin(
        &self,
        command: &str,
        stdin: &[u8],
    ) -> Result<CommandOutput, ExecError>;
}
