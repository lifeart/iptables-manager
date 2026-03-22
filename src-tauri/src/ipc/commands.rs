use crate::ipc::errors::IpcError;
use crate::iptables::explain::explain_rule;
use crate::iptables::types::RuleSpec;

// ---------------------------------------------------------------------------
// Tauri IPC command handlers
// ---------------------------------------------------------------------------

/// Fetch the current iptables rules for a host.
///
/// In a full implementation, this would look up the SSH session from the
/// connection pool, run `iptables-save`, parse the output, and return
/// the structured ruleset. For now it returns an error indicating the
/// host is not connected.
#[tauri::command]
pub async fn fetch_rules(host_id: String) -> Result<String, IpcError> {
    // TODO: Look up host connection from pool, run iptables-save, parse
    Err(IpcError::ConnectionFailed {
        host_id,
        reason: "not yet connected — call host:connect first".to_string(),
    })
}

/// Produce a human-readable explanation of a rule.
///
/// Accepts a JSON-serialized `RuleSpec` and returns a plain-English
/// explanation string.
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
///
/// Supported formats: `"shell"`, `"ansible"`, `"iptables-save"`.
///
/// In a full implementation, this would fetch the current ruleset for the
/// host and format it. For now it returns a placeholder indicating the
/// host needs to be connected first.
#[tauri::command]
pub async fn export_rules(
    host_id: String,
    format: String,
) -> Result<String, IpcError> {
    // Validate the format parameter
    match format.as_str() {
        "shell" | "ansible" | "iptables-save" => {}
        _ => {
            return Err(IpcError::CommandFailed {
                stderr: format!("unsupported export format: {}", format),
                exit_code: 1,
            });
        }
    }

    // TODO: Look up host connection, fetch rules, export in requested format
    Err(IpcError::ConnectionFailed {
        host_id,
        reason: "not yet connected — call host:connect first".to_string(),
    })
}
