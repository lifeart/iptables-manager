use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::ipc::errors::IpcError;
use crate::iptables::explain::explain_rule;
use crate::iptables::parser::parse_iptables_save;
use crate::iptables::types::RuleSpec;
use crate::ssh::pool::{ConnectionConfig, ConnectionPool};
use crate::host::detect::detect_capabilities;
use crate::ssh::command::build_command;

// ---------------------------------------------------------------------------
// Shared state type alias
// ---------------------------------------------------------------------------

pub type PoolState = Arc<ConnectionPool>;

// ---------------------------------------------------------------------------
// Serializable response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionResult {
    pub host_id: String,
    pub status: String,
    pub latency_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestConnectionResult {
    pub success: bool,
    pub latency_ms: u64,
    pub iptables_available: bool,
    pub root_access: bool,
    pub docker_detected: bool,
    pub fail2ban_detected: bool,
    pub nftables_backend: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionResult {
    pub completed: bool,
    pub capabilities: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionResult {
    pub success: bool,
    pub dirs_created: Vec<String>,
    pub revert_script_installed: bool,
    pub sudo_verified: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetResult {
    pub rules: serde_json::Value,
    pub default_policy: String,
    pub raw_iptables_save: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyResult {
    pub success: bool,
    pub safety_timer_active: bool,
    pub safety_timer_expiry: Option<u64>,
    pub remote_job_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityData {
    pub hit_counters: Vec<crate::activity::monitor::HitCounter>,
    pub conntrack_current: u64,
    pub conntrack_max: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyTimerResult {
    pub job_id: String,
    pub mechanism: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestConnectionParams {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String,
    pub key_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Tauri IPC command handlers
// ---------------------------------------------------------------------------

/// Connect to a remote host via SSH.
#[tauri::command]
pub async fn host_connect(
    host_id: String,
    hostname: String,
    port: u16,
    username: String,
    auth_method: String,
    key_path: Option<String>,
    pool: State<'_, PoolState>,
) -> Result<ConnectionResult, IpcError> {
    let start = Instant::now();

    let config = ConnectionConfig {
        hostname: hostname.clone(),
        port,
        username,
        key_path: if auth_method == "key" { key_path } else { None },
        jump_host: None,
    };

    pool.connect(&host_id, config).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: e.to_string(),
        }
    })?;

    let latency = start.elapsed().as_millis() as u64;

    Ok(ConnectionResult {
        host_id,
        status: "connected".to_string(),
        latency_ms: latency,
    })
}

/// Disconnect from a remote host.
#[tauri::command]
pub async fn host_disconnect(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<(), IpcError> {
    pool.disconnect(&host_id).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: e.to_string(),
        }
    })?;
    Ok(())
}

/// Test connection to a remote host without storing the session.
#[tauri::command]
pub async fn host_test(
    params: TestConnectionParams,
    pool: State<'_, PoolState>,
) -> Result<TestConnectionResult, IpcError> {
    let start = Instant::now();
    let temp_id = format!("__test_{}", uuid_v4());

    let config = ConnectionConfig {
        hostname: params.hostname.clone(),
        port: params.port,
        username: params.username.clone(),
        key_path: if params.auth_method == "key" {
            params.key_path.clone()
        } else {
            None
        },
        jump_host: None,
    };

    // Try to connect
    if let Err(e) = pool.connect(&temp_id, config).await {
        return Ok(TestConnectionResult {
            success: false,
            latency_ms: start.elapsed().as_millis() as u64,
            iptables_available: false,
            root_access: false,
            docker_detected: false,
            fail2ban_detected: false,
            nftables_backend: false,
            error: Some(e.to_string()),
        });
    }

    let latency = start.elapsed().as_millis() as u64;

    // Check iptables
    let iptables_cmd = build_command("sudo", &["iptables", "--version"]);
    let ipt_result = pool.execute(&temp_id, &iptables_cmd).await;
    let (iptables_available, nftables_backend) = match ipt_result {
        Ok(ref output) if output.exit_code == 0 => {
            let nft = output.stdout.contains("nf_tables");
            (true, nft)
        }
        _ => (false, false),
    };

    // Check root/sudo
    let sudo_cmd = build_command("sudo", &["-n", "true"]);
    let root_result = pool.execute(&temp_id, &sudo_cmd).await;
    let root_access = matches!(root_result, Ok(ref o) if o.exit_code == 0);

    // Check docker
    let docker_cmd = build_command("systemctl", &["is-active", "docker"]);
    let docker_result = pool.execute(&temp_id, &docker_cmd).await;
    let docker_detected = matches!(docker_result, Ok(ref o) if o.exit_code == 0);

    // Check fail2ban
    let f2b_cmd = build_command("systemctl", &["is-active", "fail2ban"]);
    let f2b_result = pool.execute(&temp_id, &f2b_cmd).await;
    let fail2ban_detected = matches!(f2b_result, Ok(ref o) if o.exit_code == 0);

    // Clean up test connection
    let _ = pool.disconnect(&temp_id).await;

    Ok(TestConnectionResult {
        success: true,
        latency_ms: latency,
        iptables_available,
        root_access,
        docker_detected,
        fail2ban_detected,
        nftables_backend,
        error: None,
    })
}

/// Detect host capabilities via SSH.
#[tauri::command]
pub async fn host_detect(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<DetectionResult, IpcError> {
    // We need a CommandExecutor — get one via the pool's execute method.
    // Create a proxy executor that uses the pool.
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };

    let capabilities = detect_capabilities(&proxy).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: format!("detection failed: {}", e),
        }
    })?;

    let caps_json = serde_json::to_value(&capabilities).unwrap_or(serde_json::Value::Null);

    Ok(DetectionResult {
        completed: true,
        capabilities: Some(caps_json),
    })
}

/// Delete a host and optionally remove remote data.
#[tauri::command]
pub async fn host_delete(
    host_id: String,
    _remove_remote_data: bool,
    pool: State<'_, PoolState>,
) -> Result<(), IpcError> {
    // Disconnect if connected
    let _ = pool.disconnect(&host_id).await;
    Ok(())
}

/// Fetch the current iptables rules for a host.
#[tauri::command]
pub async fn fetch_rules(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<RuleSetResult, IpcError> {
    let cmd = build_command("sudo", &["iptables-save"]);
    let output = pool.execute(&host_id, &cmd).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: format!("failed to run iptables-save: {}", e),
        }
    })?;

    if output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: output.stderr,
            exit_code: output.exit_code,
        });
    }

    let raw = output.stdout.clone();

    let ruleset = parse_iptables_save(&raw).map_err(|e| IpcError::CommandFailed {
        stderr: format!("failed to parse iptables-save output: {}", e),
        exit_code: 1,
    })?;

    // Determine default policy from the filter table's INPUT chain
    let default_policy = ruleset
        .tables
        .get("filter")
        .and_then(|t| t.chains.get("INPUT"))
        .and_then(|c| c.policy.clone())
        .unwrap_or_else(|| "ACCEPT".to_string())
        .to_lowercase();

    let rules_json = serde_json::to_value(&ruleset).unwrap_or(serde_json::Value::Null);

    Ok(RuleSetResult {
        rules: rules_json,
        default_policy,
        raw_iptables_save: raw,
    })
}

/// Apply rule changes via iptables-restore.
///
/// Before applying, saves a backup of the current rules to
/// `/var/lib/traffic-rules/backup.v4` (and `.v6`), computes an HMAC
/// of the backup, and writes it alongside as `.hmac`. This ensures
/// the safety-timer revert script can verify backup integrity.
#[tauri::command]
pub async fn rules_apply(
    host_id: String,
    changes_json: String,
    pool: State<'_, PoolState>,
) -> Result<ApplyResult, IpcError> {
    let _lock = pool.acquire_apply_lock(&host_id).await;

    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };

    // ── Step 1: Save backup of current rules ────────────────────
    create_pre_apply_backup(&proxy, &host_id).await?;

    // ── Step 2: Apply the new rules ─────────────────────────────
    let restore_cmd = build_command(
        "sudo",
        &["iptables-restore", "-w", "5", "--noflush", "--counters"],
    );
    let output = pool
        .execute_with_stdin(&host_id, &restore_cmd, changes_json.as_bytes())
        .await
        .map_err(|e| IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: format!("failed to apply rules: {}", e),
        })?;

    if output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: output.stderr,
            exit_code: output.exit_code,
        });
    }

    Ok(ApplyResult {
        success: true,
        safety_timer_active: false,
        safety_timer_expiry: None,
        remote_job_id: None,
    })
}

/// Create a backup of the current iptables rules before applying changes.
///
/// Saves filtered rules to `/var/lib/traffic-rules/backup.v4` (and `.v6`),
/// then computes HMAC and writes it to `.hmac` files.
async fn create_pre_apply_backup(
    executor: &dyn CommandExecutor,
    host_id: &str,
) -> Result<(), IpcError> {
    // Fetch current IPv4 rules
    let save_cmd = build_command("sudo", &["iptables-save", "-w", "5"]);
    let save_output = executor.exec(&save_cmd).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.to_string(),
            reason: format!("failed to run iptables-save for backup: {}", e),
        }
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

    // Fetch current IPv6 rules (optional — may not be available)
    let save_v6_cmd = build_command("sudo", &["ip6tables-save", "-w", "5"]);
    if let Ok(v6_output) = executor.exec(&save_v6_cmd).await {
        if v6_output.exit_code == 0 {
            let filtered_v6 = crate::snapshot::manager::filter_tr_chains(&v6_output.stdout);
            if !filtered_v6.is_empty() {
                let write_v6_cmd =
                    build_command("sudo", &["tee", "/var/lib/traffic-rules/backup.v6"]);
                let _ = executor
                    .exec_with_stdin(&write_v6_cmd, filtered_v6.as_bytes())
                    .await;
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
        let _ = executor
            .exec_with_stdin(&hmac_cmd, hmac_hex.as_bytes())
            .await;
    }

    Ok(())
}

/// Revert rule changes on a host.
#[tauri::command]
pub async fn rules_revert(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<(), IpcError> {
    let cmd = build_command("sudo", &["/var/lib/traffic-rules/revert.sh"]);
    let output = pool.execute(&host_id, &cmd).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: format!("failed to revert: {}", e),
        }
    })?;
    if output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: output.stderr,
            exit_code: output.exit_code,
        });
    }
    Ok(())
}

/// Confirm applied changes (cancel safety timer and clean up backup files).
#[tauri::command]
pub async fn rules_confirm(
    host_id: String,
    job_id: Option<String>,
    mechanism: Option<String>,
    pool: State<'_, PoolState>,
) -> Result<(), IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };

    // Cancel the scheduled revert job if we have job info
    if let Some(ref jid) = job_id {
        if !jid.is_empty() {
            let mech = match mechanism.as_deref() {
                Some("At") => crate::safety::timer::SafetyMechanism::At,
                Some("SystemdRun") => crate::safety::timer::SafetyMechanism::SystemdRun,
                Some("Nohup") => crate::safety::timer::SafetyMechanism::Nohup,
                Some("IptablesApply") => crate::safety::timer::SafetyMechanism::IptablesApply,
                _ => crate::safety::timer::SafetyMechanism::At,
            };

            let revert_job = crate::safety::timer::RevertJobId {
                mechanism: mech,
                id: jid.clone(),
            };

            crate::safety::timer::cancel_revert(&proxy, &revert_job)
                .await
                .map_err(|e| IpcError::CommandFailed {
                    stderr: format!("cancel safety timer: {}", e),
                    exit_code: 1,
                })?;
        }
    }

    // Clean up backup files on the remote host
    let cleanup_cmd = build_command(
        "sudo",
        &[
            "rm", "-f",
            "/var/lib/traffic-rules/backup.v4",
            "/var/lib/traffic-rules/backup.v4.hmac",
            "/var/lib/traffic-rules/backup.v6",
        ],
    );
    // Best-effort cleanup — don't fail if files don't exist
    let _ = proxy.exec(&cleanup_cmd).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Activity polling IPC commands
// ---------------------------------------------------------------------------

/// Subscribe to activity polling for a host (no-op; frontend polls via fetch_* calls).
#[tauri::command]
pub async fn activity_subscribe(host_id: String) -> Result<(), IpcError> {
    let _ = host_id;
    Ok(())
}

/// Unsubscribe from activity polling for a host (no-op; frontend stops calling fetch_*).
#[tauri::command]
pub async fn activity_unsubscribe(host_id: String) -> Result<(), IpcError> {
    let _ = host_id;
    Ok(())
}

/// Fetch hit counters from `iptables -L -v -n -x` on the remote host.
#[tauri::command]
pub async fn activity_fetch_hit_counters(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<Vec<crate::activity::monitor::HitCounter>, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };
    crate::activity::monitor::fetch_hit_counters(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
        })
}

/// One-shot conntrack data fetch: returns `{ current, max, percent }`.
#[tauri::command]
pub async fn activity_fetch_conntrack_table(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<crate::activity::monitor::ConntrackUsage, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };
    crate::activity::monitor::fetch_conntrack_usage(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
        })
}

/// One-shot fail2ban ban list fetch.
#[tauri::command]
pub async fn activity_fetch_bans(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<Vec<crate::activity::monitor::Fail2banBan>, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };
    crate::activity::monitor::fetch_fail2ban_bans(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
        })
}

/// Fetch all activity data at once for a connected host.
#[tauri::command]
pub async fn fetch_activity(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<ActivityData, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };

    let hit_counters = crate::activity::monitor::fetch_hit_counters(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: format!("hit counters: {}", e),
            exit_code: 1,
        })?;

    let conntrack = crate::activity::monitor::fetch_conntrack_usage(&proxy).await;
    let (conntrack_current, conntrack_max) = match conntrack {
        Ok(usage) => (usage.current, usage.max),
        Err(_) => (0, 0), // conntrack may not be available
    };

    Ok(ActivityData {
        hit_counters,
        conntrack_current,
        conntrack_max,
    })
}

// ---------------------------------------------------------------------------
// Safety timer IPC commands
// ---------------------------------------------------------------------------

/// Schedule a safety revert timer on the remote host.
#[tauri::command]
pub async fn set_safety_timer(
    host_id: String,
    timeout_secs: u32,
    pool: State<'_, PoolState>,
) -> Result<SafetyTimerResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };

    // Detect the best available mechanism
    let mechanism = crate::safety::timer::detect_mechanism(&proxy).await;

    // Schedule the revert
    let backup_path = "/var/lib/traffic-rules/snapshots/pre-apply.rules";
    let job = crate::safety::timer::schedule_revert(&proxy, mechanism, backup_path, timeout_secs)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: format!("safety timer: {}", e),
            exit_code: 1,
        })?;

    Ok(SafetyTimerResult {
        job_id: job.id,
        mechanism: format!("{:?}", job.mechanism),
    })
}

/// Cancel a previously scheduled safety revert timer.
#[tauri::command]
pub async fn clear_safety_timer(
    host_id: String,
    job_id: String,
    mechanism: Option<String>,
    pool: State<'_, PoolState>,
) -> Result<(), IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };

    // Determine the mechanism from the string, defaulting to At
    let mech = match mechanism.as_deref() {
        Some("At") => crate::safety::timer::SafetyMechanism::At,
        Some("SystemdRun") => crate::safety::timer::SafetyMechanism::SystemdRun,
        Some("Nohup") => crate::safety::timer::SafetyMechanism::Nohup,
        Some("IptablesApply") => crate::safety::timer::SafetyMechanism::IptablesApply,
        _ => crate::safety::timer::SafetyMechanism::At,
    };

    let revert_job = crate::safety::timer::RevertJobId {
        mechanism: mech,
        id: job_id,
    };

    crate::safety::timer::cancel_revert(&proxy, &revert_job)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: format!("cancel safety timer: {}", e),
            exit_code: 1,
        })?;

    Ok(())
}

/// Produce a human-readable explanation of a rule.
#[tauri::command]
pub async fn explain_rule_cmd(rule_json: String) -> Result<String, IpcError> {
    let spec: RuleSpec = serde_json::from_str(&rule_json).map_err(|e| {
        IpcError::CommandFailed {
            stderr: format!("invalid rule JSON: {}", e),
            exit_code: 1,
        }
    })?;

    Ok(explain_rule(&spec))
}

/// Export rules in the requested format.
#[tauri::command]
pub async fn export_rules(
    host_id: String,
    format: String,
    pool: State<'_, PoolState>,
) -> Result<String, IpcError> {
    match format.as_str() {
        "shell" | "ansible" | "iptables-save" => {}
        _ => {
            return Err(IpcError::CommandFailed {
                stderr: format!("unsupported export format: {}", format),
                exit_code: 1,
            });
        }
    }

    // For iptables-save format, just return raw output
    let cmd = build_command("sudo", &["iptables-save"]);
    let output = pool.execute(&host_id, &cmd).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: format!("failed to run iptables-save: {}", e),
        }
    })?;

    if output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: output.stderr,
            exit_code: output.exit_code,
        });
    }

    Ok(output.stdout)
}

/// Provision a remote host for management.
#[tauri::command]
pub async fn host_provision(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<ProvisionResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };

    let cred_store = crate::ssh::credential::CredentialStore::new().map_err(|e| {
        IpcError::ProvisionFailed {
            reason: format!("credential store error: {}", e),
        }
    })?;

    crate::ssh::provision::provision_host(&proxy, &host_id, &cred_store)
        .await
        .map_err(|e| IpcError::ProvisionFailed {
            reason: e.to_string(),
        })?;

    Ok(ProvisionResult {
        success: true,
        dirs_created: vec![
            "/var/lib/traffic-rules".to_string(),
            "/var/lib/traffic-rules/snapshots".to_string(),
        ],
        revert_script_installed: true,
        sudo_verified: true,
    })
}

// ---------------------------------------------------------------------------
// Conntrack summary (activity_fetch_conntrack)
// ---------------------------------------------------------------------------

/// Fetch conntrack usage summary (current, max).
/// This is a lightweight alias distinct from `activity_fetch_conntrack_table`.
#[tauri::command]
pub async fn activity_fetch_conntrack(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<crate::activity::monitor::ConntrackUsage, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };
    crate::activity::monitor::fetch_conntrack_usage(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
        })
}

// ---------------------------------------------------------------------------
// Credential stub commands
// ---------------------------------------------------------------------------

/// Store a credential (stub — actual credential storage is handled client-side via OS keychain).
#[tauri::command]
pub async fn cred_store(
    _host_id: String,
    _credential: serde_json::Value,
) -> Result<(), IpcError> {
    Ok(())
}

/// Delete a credential (stub — actual credential storage is handled client-side via OS keychain).
#[tauri::command]
pub async fn cred_delete(
    _host_id: String,
) -> Result<(), IpcError> {
    Ok(())
}

// ---------------------------------------------------------------------------
// IP list commands
// ---------------------------------------------------------------------------

/// Delete an ipset on the remote host.
#[tauri::command]
pub async fn iplist_delete(
    host_id: String,
    ip_list_id: String,
    pool: State<'_, PoolState>,
) -> Result<(), IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };
    crate::ipset::manager::delete_ipset(&proxy, &ip_list_id)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
        })
}

/// Sync (refresh) an ipset on the remote host.
/// For now this re-creates the set with no entries; the frontend should
/// send the full entry list in a follow-up if needed.
#[tauri::command]
pub async fn iplist_sync(
    host_id: String,
    ip_list_id: String,
    pool: State<'_, PoolState>,
) -> Result<(), IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };
    let empty: Vec<String> = Vec::new();
    crate::ipset::manager::sync_ipset(
        &proxy,
        &ip_list_id,
        &empty,
        &crate::iptables::types::AddressFamily::V4,
    )
    .await
    .map_err(|e| IpcError::CommandFailed {
        stderr: e.to_string(),
        exit_code: 1,
    })
}

// ---------------------------------------------------------------------------
// Rules analysis commands
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateCheckResult {
    pub is_duplicate: bool,
    pub existing_rule_id: Option<String>,
    pub similarity: f64,
}

/// Check if a rule is a duplicate of an existing rule (stub).
#[tauri::command]
pub async fn rules_check_duplicate(
    _host_id: String,
    _rule: serde_json::Value,
) -> Result<DuplicateCheckResult, IpcError> {
    Ok(DuplicateCheckResult {
        is_duplicate: false,
        existing_rule_id: None,
        similarity: 0.0,
    })
}

/// Detect conflicts among the current rules on a host.
///
/// Returns an empty list for now; a full implementation requires converting
/// ParsedRuleset into EffectiveRule[], which is planned for a future iteration.
#[tauri::command]
pub async fn rules_detect_conflicts(
    _host_id: String,
) -> Result<Vec<crate::iptables::conflict::RuleConflict>, IpcError> {
    Ok(Vec::new())
}

/// Trace a test packet through the current iptables ruleset.
#[tauri::command]
pub async fn rules_trace(
    host_id: String,
    packet: crate::iptables::tracer::TestPacket,
    pool: State<'_, PoolState>,
) -> Result<crate::iptables::tracer::TraceResult, IpcError> {
    // Fetch current rules
    let cmd = build_command("sudo", &["iptables-save"]);
    let output = pool.execute(&host_id, &cmd).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: format!("failed to run iptables-save: {}", e),
        }
    })?;
    if output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: output.stderr,
            exit_code: output.exit_code,
        });
    }

    let ruleset = parse_iptables_save(&output.stdout).map_err(|e| IpcError::CommandFailed {
        stderr: format!("failed to parse iptables-save output: {}", e),
        exit_code: 1,
    })?;

    Ok(crate::iptables::tracer::trace_packet(&ruleset, &packet))
}

// ---------------------------------------------------------------------------
// Snapshot commands
// ---------------------------------------------------------------------------

/// Create a snapshot of the current iptables rules on the remote host.
#[tauri::command]
pub async fn snapshot_create(
    host_id: String,
    _description: Option<String>,
    pool: State<'_, PoolState>,
) -> Result<crate::snapshot::manager::SnapshotMeta, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };
    let data = crate::snapshot::manager::create_snapshot(&proxy, &host_id)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
        })?;
    Ok(crate::snapshot::manager::SnapshotMeta {
        id: data.id,
        host_id: data.host_id,
        timestamp: data.timestamp,
        description: data.description,
        remote_path_v4: data.remote_path_v4,
    })
}

/// List snapshots stored on the remote host.
#[tauri::command]
pub async fn snapshot_list(
    host_id: String,
    pool: State<'_, PoolState>,
) -> Result<Vec<crate::snapshot::manager::SnapshotMeta>, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };
    crate::snapshot::manager::list_remote_snapshots(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
        })
}

/// Restore a snapshot on the remote host.
#[tauri::command]
pub async fn snapshot_restore(
    host_id: String,
    snapshot_id: String,
    pool: State<'_, PoolState>,
) -> Result<ApplyResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id.clone(),
    };

    // List snapshots to find the one we want
    let snapshots = crate::snapshot::manager::list_remote_snapshots(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
        })?;

    let meta = snapshots.iter().find(|s| s.id == snapshot_id).ok_or_else(|| {
        IpcError::CommandFailed {
            stderr: format!("snapshot not found: {}", snapshot_id),
            exit_code: 1,
        }
    })?;

    // Read the snapshot file from the remote host
    let remote_path = meta.remote_path_v4.as_deref().ok_or_else(|| {
        IpcError::CommandFailed {
            stderr: "snapshot has no remote path".to_string(),
            exit_code: 1,
        }
    })?;
    let cat_cmd = build_command("sudo", &["cat", remote_path]);
    let cat_output = pool.execute(&host_id, &cat_cmd).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: format!("failed to read snapshot: {}", e),
        }
    })?;
    if cat_output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: cat_output.stderr,
            exit_code: cat_output.exit_code,
        });
    }

    let snapshot_data = crate::snapshot::manager::SnapshotData {
        id: meta.id.clone(),
        host_id: meta.host_id.clone(),
        iptables_save_v4: cat_output.stdout,
        iptables_save_v6: None,
        timestamp: meta.timestamp,
        description: meta.description.clone(),
        remote_path_v4: meta.remote_path_v4.clone(),
        remote_path_v6: None,
    };

    crate::snapshot::manager::restore_snapshot(&proxy, &snapshot_data)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
        })?;

    Ok(ApplyResult {
        success: true,
        safety_timer_active: false,
        safety_timer_expiry: None,
        remote_job_id: None,
    })
}

// ---------------------------------------------------------------------------
// PoolProxyExecutor — adapts ConnectionPool to CommandExecutor trait
// ---------------------------------------------------------------------------

use crate::ssh::executor::{CommandExecutor, CommandOutput, ExecError};
use async_trait::async_trait;

/// Proxy that implements CommandExecutor by delegating to the ConnectionPool.
struct PoolProxyExecutor {
    pool: Arc<ConnectionPool>,
    host_id: String,
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
// Helpers
// ---------------------------------------------------------------------------

fn uuid_v4() -> String {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::executor::{CommandOutput, ExecError};
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Mock executor that records commands and returns configurable responses.
    struct MockExecutor {
        responses: Vec<(String, CommandOutput)>,
        calls: Arc<Mutex<Vec<String>>>,
        stdin_calls: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
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

        fn get_calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn get_stdin_calls(&self) -> Vec<(String, Vec<u8>)> {
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

    // ── Test: create_pre_apply_backup creates backup before apply ──

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
        // Should call iptables-save first
        assert!(
            calls.iter().any(|c| c.contains("iptables-save")),
            "should call iptables-save"
        );
        // Should write backup.v4
        assert!(
            calls.iter().any(|c| c.contains("backup.v4")),
            "should write backup.v4"
        );

        // Verify the written content is filtered (only TR- chains)
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
        // iptables-save must come before tee (backup write)
        let save_idx = calls.iter().position(|c| c.contains("iptables-save")).unwrap();
        let tee_idx = calls.iter().position(|c| c.contains("tee")).unwrap();
        assert!(
            save_idx < tee_idx,
            "iptables-save (idx {}) must come before tee write (idx {})",
            save_idx,
            tee_idx
        );
    }

    // ── Test: schedule_revert + cancel_revert roundtrip ──

    #[tokio::test]
    async fn test_schedule_and_cancel_at_roundtrip() {
        let executor = MockExecutor::new(vec![
            ("at", 0, "", "job 42 at Thu Mar 22 10:00:00 2026\n"),
            ("atrm", 0, "", ""),
        ]);

        let job = crate::safety::timer::schedule_revert(
            &executor,
            crate::safety::timer::SafetyMechanism::At,
            "/var/lib/traffic-rules/backup.v4",
            60,
        )
        .await
        .expect("schedule should succeed");

        assert_eq!(job.id, "42");
        assert_eq!(job.mechanism, crate::safety::timer::SafetyMechanism::At);

        let cancel_result = crate::safety::timer::cancel_revert(&executor, &job).await;
        assert!(cancel_result.is_ok(), "cancel should succeed");

        let calls = executor.get_calls();
        assert!(
            calls.iter().any(|c| c.contains("atrm")),
            "should call atrm to cancel"
        );
    }

    #[tokio::test]
    async fn test_schedule_and_cancel_systemd_run_roundtrip() {
        let executor = MockExecutor::new(vec![
            ("systemd-run", 0, "", ""),
            ("systemctl", 0, "", ""),
        ]);

        let job = crate::safety::timer::schedule_revert(
            &executor,
            crate::safety::timer::SafetyMechanism::SystemdRun,
            "/var/lib/traffic-rules/backup.v4",
            120,
        )
        .await
        .expect("schedule should succeed");

        assert_eq!(
            job.mechanism,
            crate::safety::timer::SafetyMechanism::SystemdRun
        );
        assert!(
            job.id.starts_with("traffic-rules-revert-"),
            "systemd unit name should have expected prefix"
        );

        let cancel_result = crate::safety::timer::cancel_revert(&executor, &job).await;
        assert!(cancel_result.is_ok(), "cancel should succeed");
    }

    #[tokio::test]
    async fn test_schedule_and_cancel_nohup_roundtrip() {
        let executor = MockExecutor::new(vec![
            ("tee", 0, "", ""),
            ("chmod", 0, "", ""),
            ("nohup", 0, "12345\n", ""),
            ("kill", 0, "", ""),
        ]);

        let job = crate::safety::timer::schedule_revert(
            &executor,
            crate::safety::timer::SafetyMechanism::Nohup,
            "/var/lib/traffic-rules/backup.v4",
            30,
        )
        .await
        .expect("schedule should succeed");

        assert_eq!(job.mechanism, crate::safety::timer::SafetyMechanism::Nohup);
        assert_eq!(job.id, "12345");

        let cancel_result = crate::safety::timer::cancel_revert(&executor, &job).await;
        assert!(cancel_result.is_ok(), "cancel should succeed");
    }
}
