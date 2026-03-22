use serde::Serialize;
use thiserror::Error;

/// Typed IPC errors sent to the frontend.
///
/// Serialized as `{ kind: "VariantName", detail: { ... } }` via serde's
/// internally-tagged enum representation.
#[derive(Debug, Serialize, Error)]
#[serde(tag = "kind", content = "detail")]
pub enum IpcError {
    #[error("connection to {host_id} failed: {reason}")]
    ConnectionFailed { host_id: String, reason: String },

    #[error("authentication failed for {host_id}")]
    AuthFailed { host_id: String },

    #[error("lockout detected: {trace_summary}")]
    LockoutDetected {
        trace_summary: String,
        matched_rule: Option<String>,
    },

    #[error("iptables lock held, retry after {retry_after_ms}ms")]
    IptablesLocked { retry_after_ms: u64 },

    #[error("operation {operation} timed out")]
    Timeout { operation: String },

    #[error("partial apply: {succeeded}/{total} succeeded — {error}")]
    PartialApply {
        succeeded: usize,
        total: usize,
        error: String,
    },

    #[error("disk full at {path}")]
    DiskFull { path: String, available_bytes: u64 },

    #[error("quota exceeded for {store}")]
    QuotaExceeded { store: String },

    #[error("provisioning failed: {reason}")]
    ProvisionFailed { reason: String },

    #[error("command failed (exit {exit_code}): {stderr}")]
    CommandFailed { stderr: String, exit_code: i32 },
}

// Tauri requires `Into<tauri::ipc::InvokeError>` or a manual `Serialize` impl
// for command return types. Since we derive `Serialize`, Tauri can use that.
// But we also need `Into<String>` for older Tauri patterns:
impl From<IpcError> for String {
    fn from(err: IpcError) -> String {
        // Serialize as JSON for the frontend
        serde_json::to_string(&err).unwrap_or_else(|_| err.to_string())
    }
}
