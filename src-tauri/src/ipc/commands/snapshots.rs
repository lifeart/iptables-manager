use tauri::State;

use crate::ipc::errors::IpcError;
use crate::ssh::command::build_command;

use super::helpers::PoolProxyExecutor;
use super::types::ApplyResult;
use super::PoolState;

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
    let rule_count = crate::snapshot::manager::count_rules(&data.iptables_save_v4)
        + data.iptables_save_v6.as_deref().map_or(0, crate::snapshot::manager::count_rules);
    Ok(crate::snapshot::manager::SnapshotMeta {
        id: data.id,
        host_id: data.host_id,
        timestamp: data.timestamp,
        description: data.description,
        rule_count,
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
    let remote_path = format!("/var/lib/traffic-rules/snapshots/{}.v4", meta.id);
    let cat_cmd = build_command("sudo", &["cat", &remote_path]);
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
        remote_path_v4: Some(remote_path),
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
        safety_timer_mechanism: None,
    })
}
