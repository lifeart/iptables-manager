use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock, Semaphore, OwnedSemaphorePermit};
use tokio_util::sync::CancellationToken;

use crate::ssh::executor::{CommandExecutor, CommandOutput, ExecError};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// SSH connection configuration for a remote host.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub key_path: Option<String>,
    pub jump_host: Option<JumpHost>,
}

/// Jump host (ProxyJump) configuration.
#[derive(Debug, Clone)]
pub struct JumpHost {
    pub hostname: String,
    pub port: u16,
    pub username: String,
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// Connection status for a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("already connected: {0}")]
    AlreadyConnected(String),
}

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("host not connected: {0}")]
    NotConnected(String),
    #[error("pool is shut down")]
    Shutdown,
}

// ---------------------------------------------------------------------------
// SshTransport trait
// ---------------------------------------------------------------------------

/// Abstraction over the SSH transport layer so tests can mock connections.
#[async_trait]
pub trait SshTransport: Send + Sync {
    async fn connect(
        &self,
        config: &ConnectionConfig,
    ) -> Result<Box<dyn CommandExecutor>, ConnectError>;
}

// ---------------------------------------------------------------------------
// ApplyLockGuard
// ---------------------------------------------------------------------------

/// RAII guard for per-host apply locks.
pub struct ApplyLockGuard {
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

// ---------------------------------------------------------------------------
// ManagedSession
// ---------------------------------------------------------------------------

struct ManagedSession {
    host_id: String,
    config: ConnectionConfig,
    executor: Box<dyn CommandExecutor>,
    concurrency: Arc<Semaphore>,
    cancel: CancellationToken,
    connected: std::sync::atomic::AtomicBool,
}

// ---------------------------------------------------------------------------
// ConnectionPool
// ---------------------------------------------------------------------------

pub struct ConnectionPool {
    sessions: RwLock<HashMap<String, Arc<ManagedSession>>>,
    apply_locks: DashMap<String, Arc<Mutex<()>>>,
    max_concurrent_per_host: usize,
    transport: Box<dyn SshTransport>,
    is_shutdown: std::sync::atomic::AtomicBool,
}

impl ConnectionPool {
    /// Create a new connection pool with the given transport.
    pub fn new(transport: Box<dyn SshTransport>) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            apply_locks: DashMap::new(),
            max_concurrent_per_host: 3,
            transport,
            is_shutdown: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create a pool with a custom concurrency limit per host.
    pub fn with_concurrency(transport: Box<dyn SshTransport>, max_concurrent: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            apply_locks: DashMap::new(),
            max_concurrent_per_host: max_concurrent,
            transport,
            is_shutdown: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Connect to a host, creating a managed session.
    pub async fn connect(
        &self,
        host_id: &str,
        config: ConnectionConfig,
    ) -> Result<(), ConnectError> {
        if self.is_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ConnectError::Transport("pool is shut down".to_string()));
        }

        // Check if already connected
        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(host_id) {
                return Err(ConnectError::AlreadyConnected(host_id.to_string()));
            }
        }

        let executor = self.transport.connect(&config).await?;

        let session = Arc::new(ManagedSession {
            host_id: host_id.to_string(),
            config,
            executor,
            concurrency: Arc::new(Semaphore::new(self.max_concurrent_per_host)),
            cancel: CancellationToken::new(),
            connected: std::sync::atomic::AtomicBool::new(true),
        });

        let mut sessions = self.sessions.write().await;
        sessions.insert(host_id.to_string(), session);

        Ok(())
    }

    /// Disconnect from a host, cancelling background tasks.
    pub async fn disconnect(&self, host_id: &str) -> Result<(), PoolError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .remove(host_id)
            .ok_or_else(|| PoolError::NotConnected(host_id.to_string()))?;

        session
            .connected
            .store(false, std::sync::atomic::Ordering::Relaxed);
        session.cancel.cancel();

        Ok(())
    }

    /// Execute a command on a connected host, respecting the concurrency semaphore.
    pub async fn execute(
        &self,
        host_id: &str,
        command: &str,
    ) -> Result<CommandOutput, ExecError> {
        let session = self.get_session(host_id).await?;
        let _permit = self.acquire_concurrency(&session).await?;
        session.executor.exec(command).await
    }

    /// Execute a command with stdin data on a connected host.
    pub async fn execute_with_stdin(
        &self,
        host_id: &str,
        command: &str,
        stdin: &[u8],
    ) -> Result<CommandOutput, ExecError> {
        let session = self.get_session(host_id).await?;
        let _permit = self.acquire_concurrency(&session).await?;
        session.executor.exec_with_stdin(command, stdin).await
    }

    /// Get the connection status of a host.
    pub fn get_status(&self, host_id: &str) -> ConnectionStatus {
        // Use try_read to avoid blocking; if we can't read, report disconnected
        if let Ok(sessions) = self.sessions.try_read() {
            if let Some(session) = sessions.get(host_id) {
                if session
                    .connected
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    return ConnectionStatus::Connected;
                }
            }
        }
        ConnectionStatus::Disconnected
    }

    /// Acquire the per-host apply lock.
    ///
    /// Only one apply operation may run per host at a time.
    pub async fn acquire_apply_lock(&self, host_id: &str) -> ApplyLockGuard {
        let lock = self
            .apply_locks
            .entry(host_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let guard = lock.lock_owned().await;
        ApplyLockGuard { _guard: guard }
    }

    /// Shut down the pool, disconnecting all hosts.
    pub async fn shutdown(&self) {
        self.is_shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let mut sessions = self.sessions.write().await;
        for (_, session) in sessions.drain() {
            session
                .connected
                .store(false, std::sync::atomic::Ordering::Relaxed);
            session.cancel.cancel();
        }
    }

    // -- helpers --

    async fn get_session(&self, host_id: &str) -> Result<Arc<ManagedSession>, ExecError> {
        let sessions = self.sessions.read().await;
        sessions
            .get(host_id)
            .cloned()
            .ok_or_else(|| ExecError::ConnectionLost(format!("host not connected: {}", host_id)))
    }

    async fn acquire_concurrency(
        &self,
        session: &ManagedSession,
    ) -> Result<OwnedSemaphorePermit, ExecError> {
        session
            .concurrency
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ExecError::ConnectionLost("semaphore closed".to_string()))
    }
}

// ---------------------------------------------------------------------------
// MockTransport for testing
// ---------------------------------------------------------------------------

/// Mock transport that creates MockExecutors returning configurable output.
pub struct MockTransport {
    default_output: CommandOutput,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            default_output: CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        }
    }

    pub fn with_output(output: CommandOutput) -> Self {
        Self {
            default_output: output,
        }
    }
}

#[async_trait]
impl SshTransport for MockTransport {
    async fn connect(
        &self,
        _config: &ConnectionConfig,
    ) -> Result<Box<dyn CommandExecutor>, ConnectError> {
        Ok(Box::new(MockPoolExecutor {
            output: self.default_output.clone(),
        }))
    }
}

/// Simple mock executor used by MockTransport.
struct MockPoolExecutor {
    output: CommandOutput,
}

#[async_trait]
impl CommandExecutor for MockPoolExecutor {
    async fn exec(&self, _command: &str) -> Result<CommandOutput, ExecError> {
        Ok(self.output.clone())
    }

    async fn exec_with_stdin(
        &self,
        _command: &str,
        _stdin: &[u8],
    ) -> Result<CommandOutput, ExecError> {
        Ok(self.output.clone())
    }
}

/// Mock transport that always fails to connect.
pub struct FailingTransport {
    pub message: String,
}

#[async_trait]
impl SshTransport for FailingTransport {
    async fn connect(
        &self,
        _config: &ConnectionConfig,
    ) -> Result<Box<dyn CommandExecutor>, ConnectError> {
        Err(ConnectError::Transport(self.message.clone()))
    }
}

// ---------------------------------------------------------------------------
// OpensshTransport — real SSH transport using the `openssh` crate
// ---------------------------------------------------------------------------

/// Real SSH transport that shells out to the system `ssh` binary via the
/// `openssh` crate.
pub struct OpensshTransport;

#[async_trait]
impl SshTransport for OpensshTransport {
    async fn connect(
        &self,
        config: &ConnectionConfig,
    ) -> Result<Box<dyn CommandExecutor>, ConnectError> {
        use openssh::{KnownHosts, SessionBuilder};

        let mut builder = SessionBuilder::default();
        builder
            .known_hosts_check(KnownHosts::Accept)
            .user(config.username.clone())
            .port(config.port);

        if let Some(ref key_path) = config.key_path {
            // Expand ~ to home directory
            let expanded = if key_path.starts_with("~/") {
                if let Some(home) = dirs_path() {
                    format!("{}/{}", home, &key_path[2..])
                } else {
                    key_path.clone()
                }
            } else {
                key_path.clone()
            };
            builder.keyfile(&expanded);
        }

        if let Some(ref jump) = config.jump_host {
            let jump_dest = format!("{}@{}:{}", jump.username, jump.hostname, jump.port);
            builder.jump_hosts(vec![jump_dest]);
        }

        let session = builder
            .connect(&config.hostname)
            .await
            .map_err(|e| ConnectError::Transport(format!("SSH connection failed: {}", e)))?;

        Ok(Box::new(OpensshExecutor {
            session: Arc::new(session),
        }))
    }
}

/// Helper to get the home directory path.
fn dirs_path() -> Option<String> {
    std::env::var("HOME").ok()
}

/// Command executor backed by a real openssh session.
struct OpensshExecutor {
    session: Arc<openssh::Session>,
}

#[async_trait]
impl CommandExecutor for OpensshExecutor {
    async fn exec(&self, command: &str) -> Result<CommandOutput, ExecError> {
        let output = self
            .session
            .raw_command(command)
            .output()
            .await
            .map_err(|e| ExecError::Transport(format!("SSH exec failed: {}", e)))?;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    async fn exec_with_stdin(
        &self,
        command: &str,
        stdin_data: &[u8],
    ) -> Result<CommandOutput, ExecError> {
        use openssh::Stdio;
        use tokio::io::AsyncWriteExt;

        let mut child = self
            .session
            .raw_command(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .await
            .map_err(|e| ExecError::Transport(format!("SSH spawn failed: {}", e)))?;

        // Write stdin data
        if let Some(mut stdin) = child.stdin().take() {
            stdin
                .write_all(stdin_data)
                .await
                .map_err(|e| ExecError::Transport(format!("stdin write failed: {}", e)))?;
            drop(stdin);
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| ExecError::Transport(format!("SSH wait failed: {}", e)))?;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ConnectionConfig {
        ConnectionConfig {
            hostname: "10.0.0.1".to_string(),
            port: 22,
            username: "root".to_string(),
            key_path: None,
            jump_host: None,
        }
    }

    #[tokio::test]
    async fn test_connect_and_execute() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));
        pool.connect("host-1", test_config()).await.unwrap();

        let output = pool.execute("host-1", "echo hi").await.unwrap();
        assert_eq!(output.exit_code, 0);
    }

    #[tokio::test]
    async fn test_connect_already_connected() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));
        pool.connect("host-1", test_config()).await.unwrap();

        let result = pool.connect("host-1", test_config()).await;
        assert!(matches!(result, Err(ConnectError::AlreadyConnected(_))));
    }

    #[tokio::test]
    async fn test_disconnect() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));
        pool.connect("host-1", test_config()).await.unwrap();

        assert_eq!(pool.get_status("host-1"), ConnectionStatus::Connected);

        pool.disconnect("host-1").await.unwrap();

        assert_eq!(pool.get_status("host-1"), ConnectionStatus::Disconnected);
    }

    #[tokio::test]
    async fn test_disconnect_not_connected() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));
        let result = pool.disconnect("host-1").await;
        assert!(matches!(result, Err(PoolError::NotConnected(_))));
    }

    #[tokio::test]
    async fn test_execute_not_connected() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));
        let result = pool.execute("host-1", "echo hi").await;
        assert!(matches!(result, Err(ExecError::ConnectionLost(_))));
    }

    #[tokio::test]
    async fn test_execute_with_stdin() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));
        pool.connect("host-1", test_config()).await.unwrap();

        let output = pool
            .execute_with_stdin("host-1", "cat", b"hello")
            .await
            .unwrap();
        assert_eq!(output.exit_code, 0);
    }

    #[tokio::test]
    async fn test_status_unknown_host() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));
        assert_eq!(pool.get_status("unknown"), ConnectionStatus::Disconnected);
    }

    #[tokio::test]
    async fn test_apply_lock_serializes() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));

        // Acquire lock
        let guard1 = pool.acquire_apply_lock("host-1").await;

        // Try to acquire same lock from another task — should block
        let pool2 = &pool;
        let handle = tokio::spawn({
            let pool_ref = unsafe {
                // SAFETY: pool lives longer than the spawned task in this test
                &*(pool2 as *const ConnectionPool)
            };
            async move {
                let _guard2 = pool_ref.acquire_apply_lock("host-1").await;
                42
            }
        });

        // Give it a moment, then drop the first guard
        tokio::task::yield_now().await;
        drop(guard1);

        let result = handle.await.unwrap();
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_apply_lock_different_hosts_independent() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));

        let _guard1 = pool.acquire_apply_lock("host-1").await;
        // Different host should not block
        let _guard2 = pool.acquire_apply_lock("host-2").await;
    }

    #[tokio::test]
    async fn test_shutdown() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));
        pool.connect("host-1", test_config()).await.unwrap();
        pool.connect("host-2", test_config()).await.unwrap();

        pool.shutdown().await;

        assert_eq!(pool.get_status("host-1"), ConnectionStatus::Disconnected);
        assert_eq!(pool.get_status("host-2"), ConnectionStatus::Disconnected);

        // New connections should fail
        let result = pool.connect("host-3", test_config()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_transport_failure() {
        let pool = ConnectionPool::new(Box::new(FailingTransport {
            message: "connection refused".to_string(),
        }));

        let result = pool.connect("host-1", test_config()).await;
        assert!(matches!(result, Err(ConnectError::Transport(_))));
    }

    #[tokio::test]
    async fn test_concurrency_limit() {
        let pool = ConnectionPool::with_concurrency(Box::new(MockTransport::new()), 1);
        pool.connect("host-1", test_config()).await.unwrap();

        // With max_concurrent=1, only one command runs at a time.
        // This test verifies it works without deadlocking.
        let output = pool.execute("host-1", "cmd1").await.unwrap();
        assert_eq!(output.exit_code, 0);

        let output = pool.execute("host-1", "cmd2").await.unwrap();
        assert_eq!(output.exit_code, 0);
    }

    #[tokio::test]
    async fn test_custom_output() {
        let output = CommandOutput {
            stdout: "hello world".to_string(),
            stderr: String::new(),
            exit_code: 0,
        };
        let pool = ConnectionPool::new(Box::new(MockTransport::with_output(output)));
        pool.connect("host-1", test_config()).await.unwrap();

        let result = pool.execute("host-1", "echo hello").await.unwrap();
        assert_eq!(result.stdout, "hello world");
    }

    #[tokio::test]
    async fn test_reconnect_after_disconnect() {
        let pool = ConnectionPool::new(Box::new(MockTransport::new()));
        pool.connect("host-1", test_config()).await.unwrap();
        pool.disconnect("host-1").await.unwrap();

        // Should be able to reconnect
        pool.connect("host-1", test_config()).await.unwrap();
        assert_eq!(pool.get_status("host-1"), ConnectionStatus::Connected);
    }
}
