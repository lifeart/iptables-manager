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
use dashmap::DashMap;
use ssh::pool::{ConnectionPool, OpensshTransport};
use ipc::commands::AppState;
use tracing_subscriber::{fmt, EnvFilter};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize tracing subscriber: DEBUG+ for our crate, respects RUST_LOG overrides
    fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("traffic_rules_lib=debug".parse().unwrap()),
        )
        .with_target(false)
        .compact()
        .init();

    // Create the connection pool with real SSH transport
    let pool = Arc::new(ConnectionPool::new(Box::new(OpensshTransport)));

    // Create drift detection state (in-memory hash store per host)
    let drift = Arc::new(DashMap::new());
    let drift_rulesets = Arc::new(DashMap::new());

    let app_state = AppState { pool, drift, drift_rulesets };

    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            // Host connection commands
            ipc::commands::host_connect,
            ipc::commands::host_disconnect,
            ipc::commands::host_test,
            ipc::commands::host_detect,
            ipc::commands::host_delete,
            ipc::commands::host_provision,
            ipc::commands::check_mixed_backend,
            ipc::commands::enable_persistence,
            // Rules commands
            ipc::commands::fetch_rules,
            ipc::commands::rules_apply,
            ipc::commands::rules_apply_group,
            ipc::commands::rules_preview,
            ipc::commands::rules_revert,
            ipc::commands::rules_confirm,
            ipc::commands::rules_trace,
            ipc::commands::rules_live_trace,
            ipc::commands::rules_check_duplicate,
            ipc::commands::rules_detect_conflicts,
            ipc::commands::explain_rule_cmd,
            ipc::commands::export_rules,
            // Cross-host comparison and import
            ipc::commands::compare_hosts,
            ipc::commands::import_existing_rules,
            // Activity polling commands
            ipc::commands::activity_subscribe,
            ipc::commands::activity_unsubscribe,
            ipc::commands::activity_fetch_hit_counters,
            ipc::commands::activity_fetch_conntrack_table,
            ipc::commands::activity_fetch_conntrack,
            ipc::commands::activity_fetch_bans,
            ipc::commands::fetch_activity,
            // Snapshot commands
            ipc::commands::snapshot_create,
            ipc::commands::snapshot_list,
            ipc::commands::snapshot_restore,
            // IP list commands
            ipc::commands::iplist_sync,
            ipc::commands::iplist_delete,
            // Credential commands
            ipc::commands::cred_store,
            ipc::commands::cred_delete,
            // Safety timer commands
            ipc::commands::set_safety_timer,
            ipc::commands::clear_safety_timer,
            // Drift detection commands
            ipc::commands::check_drift,
            ipc::commands::reset_drift,
            // Ipset optimization commands
            ipc::commands::analyze_ipset_opportunities,
            ipc::commands::convert_to_ipset,
            // Dual-stack divergence
            ipc::commands::check_v4_v6_divergence,
            // Coexistence profile
            ipc::commands::get_coexistence_profile,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
