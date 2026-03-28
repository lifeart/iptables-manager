use std::sync::Arc;

use tracing::{debug, warn};

use crate::ipc::errors::IpcError;
use crate::iptables::parser::parse_iptables_save;
use crate::iptables::types::ParsedRuleset;
use crate::ssh::command::build_command;
use crate::ssh::executor::{CommandExecutor, CommandOutput, ExecError};
use crate::ssh::pool::ConnectionPool;

use async_trait::async_trait;

// ---------------------------------------------------------------------------
// PoolProxyExecutor -- adapts ConnectionPool to CommandExecutor trait
// ---------------------------------------------------------------------------

/// Proxy that implements CommandExecutor by delegating to the ConnectionPool.
pub(crate) struct PoolProxyExecutor {
    pub pool: Arc<ConnectionPool>,
    pub host_id: String,
}

#[async_trait]
impl CommandExecutor for PoolProxyExecutor {
    async fn exec(&self, command: &str) -> Result<CommandOutput, ExecError> {
        self.pool.execute(&self.host_id, command).await
    }

    async fn exec_with_stdin(
        &self,
        command: &str,
        stdin: &[u8],
    ) -> Result<CommandOutput, ExecError> {
        self.pool
            .execute_with_stdin(&self.host_id, command, stdin)
            .await
    }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/// Shorthand for the common `IpcError::ConnectionFailed` construction pattern.
pub(crate) fn exec_failed(host_id: &str, reason: impl std::fmt::Display) -> IpcError {
    IpcError::ConnectionFailed {
        host_id: host_id.to_string(),
        reason: reason.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]) & 0x0FFF,
        (u16::from_be_bytes([bytes[8], bytes[9]]) & 0x3FFF) | 0x8000,
        u64::from_be_bytes([0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]])
    )
}

/// Fetch the current iptables ruleset from a remote host, returning
/// the raw `iptables-save` output and the parsed representation.
pub(crate) async fn fetch_current_ruleset(
    executor: &dyn CommandExecutor,
    host_id: &str,
) -> Result<(String, ParsedRuleset), IpcError> {
    let cmd = build_command("sudo", &["iptables-save"]);
    let output = executor.exec(&cmd).await.map_err(|e| {
        exec_failed(host_id, format!("failed to run iptables-save: {}", e))
    })?;

    if output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: output.stderr,
            exit_code: output.exit_code,
        });
    }

    let raw = output.stdout;
    let ruleset = parse_iptables_save(&raw).map_err(|e| IpcError::CommandFailed {
        stderr: format!("failed to parse iptables-save output: {}", e),
        exit_code: 1,
    })?;

    Ok((raw, ruleset))
}

/// Create a backup of the current iptables rules before applying changes.
///
/// Saves filtered rules to `/var/lib/traffic-rules/backup.v4` (and `.v6`),
/// then computes HMAC and writes it to `.hmac` files.
pub(crate) async fn create_pre_apply_backup(
    executor: &dyn CommandExecutor,
    host_id: &str,
) -> Result<(), IpcError> {
    debug!("Creating pre-apply backup for {}", host_id);
    // Fetch current IPv4 rules
    let save_cmd = build_command("sudo", &["iptables-save", "-w", "5"]);
    let save_output = executor.exec(&save_cmd).await.map_err(|e| {
        exec_failed(host_id, format!("failed to run iptables-save for backup: {}", e))
    })?;
    if save_output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: format!("iptables-save for backup failed: {}", save_output.stderr),
            exit_code: save_output.exit_code,
        });
    }

    let filtered_v4 = crate::snapshot::manager::filter_tr_chains(&save_output.stdout);

    // Write backup v4
    let write_cmd = build_command("sudo", &["tee", "/var/lib/traffic-rules/backup.v4"]);
    let write_output = executor
        .exec_with_stdin(&write_cmd, filtered_v4.as_bytes())
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: format!("failed to write backup.v4: {}", e),
            exit_code: 1,
        })?;
    if write_output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: format!("failed to write backup.v4: {}", write_output.stderr),
            exit_code: write_output.exit_code,
        });
    }

    // Fetch current IPv6 rules (optional -- may not be available)
    let save_v6_cmd = build_command("sudo", &["ip6tables-save", "-w", "5"]);
    if let Ok(v6_output) = executor.exec(&save_v6_cmd).await {
        if v6_output.exit_code == 0 {
            let filtered_v6 = crate::snapshot::manager::filter_tr_chains(&v6_output.stdout);
            if !filtered_v6.is_empty() {
                let write_v6_cmd =
                    build_command("sudo", &["tee", "/var/lib/traffic-rules/backup.v6"]);
                if let Err(e) = executor
                    .exec_with_stdin(&write_v6_cmd, filtered_v6.as_bytes())
                    .await
                {
                    warn!("Failed to write backup.v6 (non-fatal): {}", e);
                }
            }
        }
    }

    // Compute and write HMAC for the v4 backup
    let cred_store = crate::ssh::credential::CredentialStore::new().map_err(|e| {
        IpcError::CommandFailed {
            stderr: format!("credential store error: {}", e),
            exit_code: 1,
        }
    })?;

    if let Ok(secret) = cred_store.retrieve_hmac_secret(host_id) {
        let hmac_hex = crate::safety::hmac::compute_hmac(&secret, filtered_v4.as_bytes());
        let hmac_cmd =
            build_command("sudo", &["tee", "/var/lib/traffic-rules/backup.v4.hmac"]);
        if let Err(e) = executor
            .exec_with_stdin(&hmac_cmd, hmac_hex.as_bytes())
            .await
        {
            warn!("Failed to write HMAC file (non-fatal): {}", e);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ssh::executor::{CommandOutput, ExecError};
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Mock executor that records commands and returns configurable responses.
    pub(crate) struct MockExecutor {
        responses: Vec<(String, CommandOutput)>,
        calls: Arc<Mutex<Vec<String>>>,
        stdin_calls: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    }

    impl MockExecutor {
        pub fn new(responses: Vec<(&str, i32, &str, &str)>) -> Self {
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
                stdin_calls: Arc::new(Mutex::new(Vec::new())),
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
                stderr: format!("{}: not found", command),
                exit_code: 1,
            }
        }

        pub fn get_calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        pub fn get_stdin_calls(&self) -> Vec<(String, Vec<u8>)> {
            self.stdin_calls.lock().unwrap().clone()
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
            stdin: &[u8],
        ) -> Result<CommandOutput, ExecError> {
            self.calls.lock().unwrap().push(command.to_string());
            self.stdin_calls
                .lock()
                .unwrap()
                .push((command.to_string(), stdin.to_vec()));
            Ok(self.find_response(command))
        }
    }

    // -- Test: create_pre_apply_backup creates backup before apply --

    #[tokio::test]
    async fn test_create_pre_apply_backup_saves_v4_rules() {
        let iptables_output = r#"*filter
:INPUT ACCEPT [0:0]
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"#;
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, iptables_output, ""),
            ("tee /var/lib/traffic-rules/backup.v4", 0, "", ""),
            ("ip6tables-save", 1, "", "not found"),
        ]);

        let result = create_pre_apply_backup(&executor, "test-host").await;
        assert!(result.is_ok(), "backup should succeed");

        let calls = executor.get_calls();
        assert!(
            calls.iter().any(|c| c.contains("iptables-save")),
            "should call iptables-save"
        );
        assert!(
            calls.iter().any(|c| c.contains("backup.v4")),
            "should write backup.v4"
        );

        let stdin_calls = executor.get_stdin_calls();
        let backup_write = stdin_calls
            .iter()
            .find(|(cmd, _)| cmd.contains("backup.v4") && !cmd.contains("hmac"));
        assert!(backup_write.is_some(), "should write backup data via stdin");
        let backup_content = String::from_utf8_lossy(&backup_write.unwrap().1);
        assert!(
            backup_content.contains("TR-INPUT"),
            "backup should contain TR- chains"
        );
        assert!(
            !backup_content.contains(":INPUT ACCEPT"),
            "backup should not contain built-in chain declarations"
        );
    }

    #[tokio::test]
    async fn test_create_pre_apply_backup_command_order() {
        let iptables_output = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n";
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, iptables_output, ""),
            ("tee", 0, "", ""),
            ("ip6tables-save", 1, "", ""),
        ]);

        let _ = create_pre_apply_backup(&executor, "host1").await;

        let calls = executor.get_calls();
        let save_idx = calls.iter().position(|c| c.contains("iptables-save")).unwrap();
        let tee_idx = calls.iter().position(|c| c.contains("tee")).unwrap();
        assert!(
            save_idx < tee_idx,
            "iptables-save (idx {}) must come before tee write (idx {})",
            save_idx,
            tee_idx
        );
    }

    #[tokio::test]
    async fn test_backup_writes_hmac_when_secret_available() {
        let iptables_output = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n";
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, iptables_output, ""),
            ("ip6tables-save", 1, "", "not found"),
            ("backup.v4.hmac", 0, "", ""),
            ("backup.v4", 0, "", ""),
        ]);

        let cred_store = crate::ssh::credential::CredentialStore::new().unwrap();
        let test_host = "test-hmac-host";
        let test_secret = "abcdef0123456789abcdef0123456789";
        if cred_store
            .store_hmac_secret(test_host, test_secret)
            .is_err()
        {
            eprintln!("Skipping: no keyring backend available in test environment");
            return;
        }

        let result = create_pre_apply_backup(&executor, test_host).await;
        assert!(result.is_ok(), "backup should succeed: {:?}", result);

        let stdin_calls = executor.get_stdin_calls();
        let hmac_write = stdin_calls
            .iter()
            .find(|(cmd, _)| cmd.contains("backup.v4.hmac"));
        assert!(
            hmac_write.is_some(),
            "should write HMAC via tee when secret is available"
        );

        let hmac_content = String::from_utf8_lossy(&hmac_write.unwrap().1);
        assert_eq!(hmac_content.len(), 64, "HMAC should be 64 hex chars");
        assert!(
            hmac_content.chars().all(|c| c.is_ascii_hexdigit()),
            "HMAC should be hex-encoded"
        );

        let filtered = crate::snapshot::manager::filter_tr_chains(iptables_output);
        let expected_hmac =
            crate::safety::hmac::compute_hmac(test_secret, filtered.as_bytes());
        assert_eq!(
            hmac_content, expected_hmac,
            "written HMAC should match computed HMAC"
        );

        if let Ok(entry) = keyring::Entry::new("traffic-rules-hmac", test_host) {
            let _ = entry.delete_credential();
        }
    }

    #[tokio::test]
    async fn test_backup_skips_hmac_when_no_secret() {
        let iptables_output = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 80 -j ACCEPT\nCOMMIT\n";
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, iptables_output, ""),
            ("ip6tables-save", 1, "", "not found"),
            ("backup.v4", 0, "", ""),
        ]);

        let result =
            create_pre_apply_backup(&executor, "nonexistent-host-no-hmac-secret").await;
        assert!(
            result.is_ok(),
            "backup should succeed even without HMAC secret: {:?}",
            result
        );

        let stdin_calls = executor.get_stdin_calls();
        let hmac_write = stdin_calls
            .iter()
            .find(|(cmd, _)| cmd.contains("hmac"));
        assert!(
            hmac_write.is_none(),
            "should NOT write HMAC when no secret is available"
        );
    }

    #[tokio::test]
    async fn test_backup_includes_v6_when_available() {
        let v4_output = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n";
        let v6_output = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 443 -j ACCEPT\nCOMMIT\n";
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, v4_output, ""),
            ("ip6tables-save", 0, v6_output, ""),
            ("backup.v6", 0, "", ""),
            ("backup.v4", 0, "", ""),
        ]);

        let result =
            create_pre_apply_backup(&executor, "host-v6-test").await;
        assert!(result.is_ok(), "backup should succeed: {:?}", result);

        let calls = executor.get_calls();
        assert!(
            calls.iter().any(|c| c.contains("ip6tables-save")),
            "should call ip6tables-save"
        );
        assert!(
            calls.iter().any(|c| c.contains("backup.v6")),
            "should write backup.v6 when v6 rules are available"
        );

        let stdin_calls = executor.get_stdin_calls();
        let v6_write = stdin_calls
            .iter()
            .find(|(cmd, _)| cmd.contains("backup.v6"));
        assert!(v6_write.is_some(), "should write v6 backup data via stdin");
    }

    #[tokio::test]
    async fn test_backup_skips_v6_when_unavailable() {
        let v4_output = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n";
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, v4_output, ""),
            ("ip6tables-save", 1, "", "ip6tables not found"),
            ("backup.v4", 0, "", ""),
        ]);

        let result =
            create_pre_apply_backup(&executor, "host-no-v6").await;
        assert!(
            result.is_ok(),
            "backup should succeed even if ip6tables-save fails: {:?}",
            result
        );

        let stdin_calls = executor.get_stdin_calls();
        let v6_write = stdin_calls
            .iter()
            .find(|(cmd, _)| cmd.contains("backup.v6"));
        assert!(
            v6_write.is_none(),
            "should NOT write backup.v6 when ip6tables-save fails"
        );
    }

    // -------------------------------------------------------------------
    // fetch_current_ruleset tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_fetch_current_ruleset_parses_valid_output() {
        let iptables_output = r#"*filter
:INPUT ACCEPT [100:5000]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [50:2500]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p udp --dport 53 -j DROP
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT
"#;
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, iptables_output, ""),
        ]);

        let result = fetch_current_ruleset(&executor, "test-host").await;
        assert!(result.is_ok(), "should parse valid output: {:?}", result);

        let (raw, ruleset) = result.unwrap();

        // Raw output preserved
        assert_eq!(raw, iptables_output);

        // Tables parsed correctly
        assert!(ruleset.tables.contains_key("filter"), "should have filter table");
        assert!(ruleset.tables.contains_key("nat"), "should have nat table");

        // Chains parsed correctly
        let filter = &ruleset.tables["filter"];
        assert!(filter.chains.contains_key("INPUT"), "filter should have INPUT chain");
        assert!(filter.chains.contains_key("FORWARD"), "filter should have FORWARD chain");
        assert!(filter.chains.contains_key("OUTPUT"), "filter should have OUTPUT chain");

        // Rules parsed correctly
        let input_chain = &filter.chains["INPUT"];
        assert_eq!(input_chain.rules.len(), 3, "INPUT should have 3 rules");
        assert_eq!(
            input_chain.policy.as_deref(),
            Some("ACCEPT"),
            "INPUT policy should be ACCEPT"
        );

        // FORWARD chain policy
        let forward_chain = &filter.chains["FORWARD"];
        assert_eq!(
            forward_chain.policy.as_deref(),
            Some("DROP"),
            "FORWARD policy should be DROP"
        );
    }

    #[tokio::test]
    async fn test_fetch_current_ruleset_returns_error_on_failure() {
        let executor = MockExecutor::new(vec![
            ("iptables-save", 1, "", "iptables: Permission denied"),
        ]);

        let result = fetch_current_ruleset(&executor, "test-host").await;
        assert!(result.is_err(), "should return error on exit code 1");

        match result.unwrap_err() {
            IpcError::CommandFailed { stderr, exit_code } => {
                assert_eq!(exit_code, 1);
                assert!(
                    stderr.contains("Permission denied"),
                    "error should contain stderr message, got: {}",
                    stderr
                );
            }
            other => panic!("expected CommandFailed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_backup_fails_on_iptables_save_failure() {
        let executor = MockExecutor::new(vec![
            ("iptables-save", 1, "", "iptables: command not found"),
        ]);

        let result = create_pre_apply_backup(&executor, "host-broken").await;
        assert!(
            result.is_err(),
            "backup should fail when iptables-save fails"
        );

        let err = result.unwrap_err();
        match err {
            IpcError::CommandFailed { stderr, exit_code } => {
                assert!(
                    stderr.contains("iptables-save"),
                    "error should mention iptables-save, got: {}",
                    stderr
                );
                assert_eq!(exit_code, 1);
            }
            other => panic!("expected CommandFailed, got {:?}", other),
        }
    }
}
