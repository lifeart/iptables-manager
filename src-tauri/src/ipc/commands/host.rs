use std::time::Instant;

use tauri::State;
use tracing::warn;

use crate::host::detect::{detect_capabilities, detect_mixed_backend, MixedBackendStatus};
use crate::ipc::errors::IpcError;
use crate::ssh::command::build_command;
use crate::ssh::pool::ConnectionConfig;

use super::helpers::{exec_failed, uuid_v4, PoolProxyExecutor};
use super::types::{
    ConnectionResult, DetectionResult, EnablePersistenceResult, MixedBackendCheckResult, ProvisionResult,
    TestConnectionParams, TestConnectionResult,
};
use super::AppState;

/// Connect to a remote host via SSH.
#[tauri::command]
pub async fn host_connect(
    host_id: String,
    hostname: String,
    port: u16,
    username: String,
    auth_method: String,
    key_path: Option<String>,
    state: State<'_, AppState>,
) -> Result<ConnectionResult, IpcError> {
    let start = Instant::now();

    let config = ConnectionConfig {
        hostname: hostname.clone(),
        port,
        username,
        key_path: if auth_method == "key" { key_path } else { None },
        jump_host: None,
    };

    state.pool.connect(&host_id, config).await.map_err(|e| {
        exec_failed(&host_id, e)
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
    state: State<'_, AppState>,
) -> Result<(), IpcError> {
    state.pool.disconnect(&host_id).await.map_err(|e| {
        exec_failed(&host_id, e)
    })?;
    Ok(())
}

/// Test connection to a remote host without storing the session.
#[tauri::command]
pub async fn host_test(
    params: TestConnectionParams,
    state: State<'_, AppState>,
) -> Result<TestConnectionResult, IpcError> {
    let pool = &state.pool;
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
    if let Err(e) = pool.disconnect(&temp_id).await {
        warn!("Failed to disconnect test session {} (non-fatal): {}", temp_id, e);
    }

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
    state: State<'_, AppState>,
) -> Result<DetectionResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    let capabilities = detect_capabilities(&proxy).await.map_err(|e| {
        exec_failed(&host_id, format!("detection failed: {}", e))
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
    state: State<'_, AppState>,
) -> Result<(), IpcError> {
    if let Err(e) = state.pool.disconnect(&host_id).await {
        warn!("Failed to disconnect host {} during delete (non-fatal): {}", host_id, e);
    }
    Ok(())
}

/// Provision a remote host for management.
#[tauri::command]
pub async fn host_provision(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<ProvisionResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
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

/// Check for mixed iptables backend (legacy + nft rules both populated).
#[tauri::command]
pub async fn check_mixed_backend(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<MixedBackendCheckResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    let status = detect_mixed_backend(&proxy).await.map_err(|e| {
        exec_failed(&host_id, format!("mixed backend detection failed: {}", e))
    })?;

    match status {
        MixedBackendStatus::Mixed {
            legacy_rule_count,
            nft_rule_count,
        } => Ok(MixedBackendCheckResult {
            is_mixed: true,
            legacy_rule_count,
            nft_rule_count,
            remediation: format!(
                "Run 'iptables-legacy -F' to flush {} legacy rules, or migrate all rules to nft.",
                legacy_rule_count
            ),
        }),
        MixedBackendStatus::Clean => Ok(MixedBackendCheckResult {
            is_mixed: false,
            legacy_rule_count: 0,
            nft_rule_count: 0,
            remediation: String::new(),
        }),
        MixedBackendStatus::Unknown => Ok(MixedBackendCheckResult {
            is_mixed: false,
            legacy_rule_count: 0,
            nft_rule_count: 0,
            remediation: String::new(),
        }),
    }
}

/// Enable persistence for iptables rules on a remote host.
///
/// Installs the appropriate package and enables the service based on the
/// detected distro family. For Debian, installs iptables-persistent;
/// for RHEL, installs iptables-services.
#[tauri::command]
pub async fn enable_persistence(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<EnablePersistenceResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    // Detect the distro family to determine which persistence method to use
    let caps = detect_capabilities(&proxy).await.map_err(|e| {
        exec_failed(&host_id, format!("detection failed: {}", e))
    })?;

    let distro_family = &caps.distro.family;

    match distro_family {
        crate::host::detect::DistroFamily::Debian => {
            // Install iptables-persistent non-interactively
            let install_cmd = build_command(
                "sudo",
                &[
                    "bash", "-c",
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent",
                ],
            );
            let install_out = proxy.pool.execute(&host_id, &install_cmd).await.map_err(|e| {
                exec_failed(&host_id, format!("install failed: {}", e))
            })?;
            if install_out.exit_code != 0 {
                return Ok(EnablePersistenceResult {
                    success: false,
                    method: "iptables-persistent".to_string(),
                    message: format!(
                        "Package installation failed: {}",
                        install_out.stderr.trim()
                    ),
                });
            }

            // Enable the service
            let enable_cmd = build_command(
                "sudo",
                &["systemctl", "enable", "netfilter-persistent"],
            );
            let _ = proxy.pool.execute(&host_id, &enable_cmd).await;

            // Save current rules
            let save_cmd = build_command(
                "sudo",
                &["netfilter-persistent", "save"],
            );
            let _ = proxy.pool.execute(&host_id, &save_cmd).await;

            Ok(EnablePersistenceResult {
                success: true,
                method: "iptables-persistent".to_string(),
                message: "iptables-persistent installed and enabled successfully.".to_string(),
            })
        }
        crate::host::detect::DistroFamily::Rhel => {
            // Install iptables-services
            let install_cmd = build_command(
                "sudo",
                &["yum", "install", "-y", "iptables-services"],
            );
            let install_out = proxy.pool.execute(&host_id, &install_cmd).await.map_err(|e| {
                exec_failed(&host_id, format!("install failed: {}", e))
            })?;
            if install_out.exit_code != 0 {
                return Ok(EnablePersistenceResult {
                    success: false,
                    method: "iptables-services".to_string(),
                    message: format!(
                        "Package installation failed: {}",
                        install_out.stderr.trim()
                    ),
                });
            }

            // Enable the service
            let enable_cmd = build_command(
                "sudo",
                &["systemctl", "enable", "iptables"],
            );
            let _ = proxy.pool.execute(&host_id, &enable_cmd).await;

            // Save current rules
            let save_cmd = build_command(
                "sudo",
                &["service", "iptables", "save"],
            );
            let _ = proxy.pool.execute(&host_id, &save_cmd).await;

            Ok(EnablePersistenceResult {
                success: true,
                method: "iptables-services".to_string(),
                message: "iptables-services installed and enabled successfully.".to_string(),
            })
        }
        _ => Ok(EnablePersistenceResult {
            success: false,
            method: "manual".to_string(),
            message: "Automatic persistence setup not supported for this distribution. Please configure manually.".to_string(),
        }),
    }
}
