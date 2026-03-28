use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ssh::pool::ConnectionPool;

// ---------------------------------------------------------------------------
// Shared state type aliases
// ---------------------------------------------------------------------------

pub type PoolState = Arc<ConnectionPool>;

/// Managed state holding the last-known rule hash per host for drift detection.
pub type DriftState = Arc<Mutex<HashMap<String, String>>>;

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
