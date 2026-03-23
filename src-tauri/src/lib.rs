pub mod ipc;
pub mod ssh;
pub mod iptables;
pub mod ipset;
pub mod safety;
pub mod host;
pub mod snapshot;
pub mod activity;
pub mod export;
pub mod temporary;
pub mod sysctl;

use std::sync::Arc;
use ssh::pool::{ConnectionPool, OpensshTransport};
use ipc::commands::PoolState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Create the connection pool with real SSH transport
    let pool: PoolState = Arc::new(ConnectionPool::new(Box::new(OpensshTransport)));

    tauri::Builder::default()
        .manage(pool)
        .invoke_handler(tauri::generate_handler![
            // Host connection commands
            ipc::commands::host_connect,
            ipc::commands::host_disconnect,
            ipc::commands::host_test,
            ipc::commands::host_detect,
            ipc::commands::host_delete,
            ipc::commands::host_provision,
            // Rules commands
            ipc::commands::fetch_rules,
            ipc::commands::rules_apply,
            ipc::commands::rules_revert,
            ipc::commands::rules_confirm,
            ipc::commands::explain_rule_cmd,
            ipc::commands::export_rules,
            // Activity polling commands
            ipc::commands::activity_subscribe,
            ipc::commands::activity_unsubscribe,
            ipc::commands::fetch_hit_counters,
            ipc::commands::fetch_conntrack_table,
            ipc::commands::fetch_bans,
            ipc::commands::fetch_activity,
            // Safety timer commands
            ipc::commands::set_safety_timer,
            ipc::commands::clear_safety_timer,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
