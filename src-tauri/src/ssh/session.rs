use crate::ssh::executor::CommandExecutor;

// ---------------------------------------------------------------------------
// SshSession — wrapper around a CommandExecutor with metadata
// ---------------------------------------------------------------------------

pub struct SshSession {
    executor: Box<dyn CommandExecutor>,
    host_id: String,
    connected_at: std::time::Instant,
    management_ip: Option<String>,
}

impl SshSession {
    /// Create a new session wrapping the given executor.
    pub fn new(executor: Box<dyn CommandExecutor>, host_id: String) -> Self {
        Self {
            executor,
            host_id,
            connected_at: std::time::Instant::now(),
            management_ip: None,
        }
    }

    /// Access the underlying command executor.
    pub fn executor(&self) -> &dyn CommandExecutor {
        self.executor.as_ref()
    }

    /// The host identifier this session belongs to.
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    /// The management IP discovered for this host, if any.
    pub fn management_ip(&self) -> Option<&str> {
        self.management_ip.as_deref()
    }

    /// Set the management IP for this host.
    pub fn set_management_ip(&mut self, ip: String) {
        self.management_ip = Some(ip);
    }

    /// How long this session has been connected.
    pub fn uptime(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::executor::{CommandOutput, ExecError};
    use async_trait::async_trait;

    struct MockExecutor;

    #[async_trait]
    impl CommandExecutor for MockExecutor {
        async fn exec(&self, _command: &str) -> Result<CommandOutput, ExecError> {
            Ok(CommandOutput {
                stdout: "mock".to_string(),
                stderr: String::new(),
                exit_code: 0,
            })
        }

        async fn exec_with_stdin(
            &self,
            _command: &str,
            _stdin: &[u8],
        ) -> Result<CommandOutput, ExecError> {
            Ok(CommandOutput {
                stdout: "mock".to_string(),
                stderr: String::new(),
                exit_code: 0,
            })
        }
    }

    #[test]
    fn test_new_session() {
        let session = SshSession::new(Box::new(MockExecutor), "host-1".to_string());
        assert_eq!(session.host_id(), "host-1");
        assert!(session.management_ip().is_none());
    }

    #[test]
    fn test_set_management_ip() {
        let mut session = SshSession::new(Box::new(MockExecutor), "host-1".to_string());
        session.set_management_ip("10.0.0.1".to_string());
        assert_eq!(session.management_ip(), Some("10.0.0.1"));
    }

    #[test]
    fn test_uptime_is_non_negative() {
        let session = SshSession::new(Box::new(MockExecutor), "host-1".to_string());
        // uptime should be very small but non-negative
        assert!(session.uptime().as_secs() < 5);
    }

    #[tokio::test]
    async fn test_executor_accessible() {
        let session = SshSession::new(Box::new(MockExecutor), "host-1".to_string());
        let output = session.executor().exec("echo hi").await.unwrap();
        assert_eq!(output.stdout, "mock");
        assert_eq!(output.exit_code, 0);
    }
}
