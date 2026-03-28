use tauri::State;
use tracing::debug;

use crate::ipc::errors::IpcError;

use super::helpers::PoolProxyExecutor;
use super::types::ActivityData;
use super::AppState;

/// Subscribe to activity polling for a host (no-op; frontend polls via fetch_* calls).
#[tauri::command]
pub async fn activity_subscribe(host_id: String) -> Result<String, IpcError> {
    debug!("Activity stream started for {}", host_id);
    Ok(format!("stream-{}", host_id))
}

/// Unsubscribe from activity polling for a host (no-op; frontend stops calling fetch_*).
#[tauri::command]
pub async fn activity_unsubscribe(stream_id: String) -> Result<(), IpcError> {
    let _ = stream_id;
    Ok(())
}

/// Fetch hit counters from `iptables -L -v -n -x` on the remote host.
#[tauri::command]
pub async fn activity_fetch_hit_counters(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<crate::activity::monitor::HitCounter>, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };
    crate::activity::monitor::fetch_hit_counters(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
            explanation: None,
        })
}

/// Fetch the full conntrack table as individual entries.
#[tauri::command]
pub async fn activity_fetch_conntrack_table(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<crate::activity::monitor::ConntrackEntry>, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };
    crate::activity::monitor::fetch_conntrack_table(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
            explanation: None,
        })
}

/// One-shot fail2ban ban list fetch.
#[tauri::command]
pub async fn activity_fetch_bans(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<crate::activity::monitor::Fail2banBan>, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };
    crate::activity::monitor::fetch_fail2ban_bans(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
            explanation: None,
        })
}

/// Fetch all activity data at once for a connected host.
#[tauri::command]
pub async fn fetch_activity(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<ActivityData, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    let hit_counters = crate::activity::monitor::fetch_hit_counters(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: format!("hit counters: {}", e),
            exit_code: 1,
            explanation: None,
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

/// Fetch conntrack usage summary (current, max).
/// This is a lightweight alias distinct from `activity_fetch_conntrack_table`.
#[tauri::command]
pub async fn activity_fetch_conntrack(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<crate::activity::monitor::ConntrackUsage, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };
    crate::activity::monitor::fetch_conntrack_usage(&proxy)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
            explanation: None,
        })
}
