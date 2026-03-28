use tauri::State;

use crate::ipc::errors::IpcError;

use super::helpers::PoolProxyExecutor;
use super::AppState;

/// Sync (refresh) an ipset on the remote host.
#[tauri::command]
pub async fn iplist_sync(
    host_id: String,
    ip_list_id: String,
    state: State<'_, AppState>,
) -> Result<(), IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
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

/// Delete an ipset on the remote host.
#[tauri::command]
pub async fn iplist_delete(
    host_id: String,
    ip_list_id: String,
    state: State<'_, AppState>,
) -> Result<(), IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };
    crate::ipset::manager::delete_ipset(&proxy, &ip_list_id)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
        })
}
