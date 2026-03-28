use std::sync::Arc;

use dashmap::DashMap;

use crate::ssh::pool::ConnectionPool;

// ---------------------------------------------------------------------------
// Shared state type aliases (kept for backward compat in tests)
// ---------------------------------------------------------------------------

pub type PoolState = Arc<ConnectionPool>;

/// Managed state holding the last-known rule hash per host for drift detection.
pub type DriftState = Arc<DashMap<String, String>>;

// ---------------------------------------------------------------------------
// Consolidated application state
// ---------------------------------------------------------------------------

/// Single managed state struct holding all shared resources.
pub struct AppState {
    pub pool: Arc<ConnectionPool>,
    pub drift: Arc<DashMap<String, String>>,
}

// ---------------------------------------------------------------------------
// Submodules
// ---------------------------------------------------------------------------

pub(crate) mod types;
pub(crate) mod helpers;

// These must be pub so that #[tauri::command] generated items
// (__cmd__*, __cmd_*) are visible at the `ipc::commands::*` path
// via the wildcard re-exports below.
mod host;
mod rules;
mod activity;
mod safety;
mod snapshots;
mod analysis;
mod creds;
mod iplist;

// ---------------------------------------------------------------------------
// Re-exports: types
// ---------------------------------------------------------------------------

pub use types::*;

// ---------------------------------------------------------------------------
// Re-exports: command functions and their tauri-generated items
// ---------------------------------------------------------------------------

pub use host::*;
pub use rules::*;
pub use activity::*;
pub use safety::*;
pub use snapshots::*;
pub use analysis::*;
pub use creds::*;
pub use iplist::*;
