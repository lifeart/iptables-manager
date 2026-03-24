use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ssh::command::build_command;
use crate::ssh::executor::{CommandExecutor, ExecError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SNAPSHOT_DIR: &str = "/var/lib/traffic-rules/snapshots";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("command execution error: {0}")]
    Exec(#[from] ExecError),
    #[error("snapshot not found: {0}")]
    NotFound(String),
    #[error("failed to create snapshot: {0}")]
    CreateFailed(String),
    #[error("failed to restore snapshot: {0}")]
    RestoreFailed(String),
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Full snapshot data including iptables-save content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotData {
    pub id: String,
    pub host_id: String,
    pub iptables_save_v4: String,
    pub iptables_save_v6: Option<String>,
    pub timestamp: u64,
    pub description: Option<String>,
    pub remote_path_v4: Option<String>,
    pub remote_path_v6: Option<String>,
}

/// Lightweight metadata for listing snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub id: String,
    pub host_id: String,
    pub timestamp: u64,
    pub description: Option<String>,
    pub remote_path_v4: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a snapshot of the current iptables rules on the remote host.
///
/// Runs `iptables-save`, filters to TR- chains, and stores both locally
/// (returned in the result) and remotely in the snapshots directory.
pub async fn create_snapshot(
    executor: &dyn CommandExecutor,
    host_id: &str,
) -> Result<SnapshotData, SnapshotError> {
    // Ensure snapshot directory exists
    let mkdir_cmd = build_command("sudo", &["mkdir", "-p", SNAPSHOT_DIR]);
    executor.exec(&mkdir_cmd).await?;

    // Fetch current rules
    let save_cmd = build_command("sudo", &["iptables-save", "-w", "5"]);
    let output = executor.exec(&save_cmd).await?;
    if output.exit_code != 0 {
        return Err(SnapshotError::CreateFailed(format!(
            "iptables-save failed: {}",
            output.stderr.trim()
        )));
    }

    let full_save = output.stdout;
    let filtered_v4 = filter_tr_chains(&full_save);

    // Try IPv6
    let save_v6_cmd = build_command("sudo", &["ip6tables-save", "-w", "5"]);
    let filtered_v6 = match executor.exec(&save_v6_cmd).await {
        Ok(o) if o.exit_code == 0 => {
            let f = filter_tr_chains(&o.stdout);
            if f.is_empty() { None } else { Some(f) }
        }
        _ => None,
    };

    // Generate snapshot ID from millisecond timestamp to avoid collisions
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ts = duration.as_secs();
    let ts_ms = duration.as_millis() as u64;
    let snapshot_id = format!("{}-{}", host_id, ts_ms);

    // Save to remote
    let remote_path_v4 = format!("{}/{}.v4", SNAPSHOT_DIR, snapshot_id);
    let write_cmd = build_command("sudo", &["tee", &remote_path_v4]);
    let write_output = executor
        .exec_with_stdin(&write_cmd, filtered_v4.as_bytes())
        .await?;
    if write_output.exit_code != 0 {
        return Err(SnapshotError::CreateFailed(format!(
            "failed to write snapshot: {}",
            write_output.stderr.trim()
        )));
    }

    // Restrict permissions
    let chmod_cmd = build_command("sudo", &["chmod", "0600", &remote_path_v4]);
    let _ = executor.exec(&chmod_cmd).await;

    let mut remote_path_v6_opt = None;
    if let Some(ref v6_data) = filtered_v6 {
        let path = format!("{}/{}.v6", SNAPSHOT_DIR, snapshot_id);
        let cmd = build_command("sudo", &["tee", &path]);
        let _ = executor.exec_with_stdin(&cmd, v6_data.as_bytes()).await;
        let chmod = build_command("sudo", &["chmod", "0600", &path]);
        let _ = executor.exec(&chmod).await;
        remote_path_v6_opt = Some(path);
    }

    Ok(SnapshotData {
        id: snapshot_id,
        host_id: host_id.to_string(),
        iptables_save_v4: filtered_v4,
        iptables_save_v6: filtered_v6,
        timestamp: ts,
        description: None,
        remote_path_v4: Some(remote_path_v4),
        remote_path_v6: remote_path_v6_opt,
    })
}

/// Restore a snapshot by applying its saved rules via `iptables-restore --noflush`.
pub async fn restore_snapshot(
    executor: &dyn CommandExecutor,
    snapshot: &SnapshotData,
) -> Result<(), SnapshotError> {
    // Restore IPv4
    let restore_cmd = build_command(
        "sudo",
        &["iptables-restore", "-w", "5", "--noflush", "--counters"],
    );
    let output = executor
        .exec_with_stdin(&restore_cmd, snapshot.iptables_save_v4.as_bytes())
        .await?;
    if output.exit_code != 0 {
        return Err(SnapshotError::RestoreFailed(format!(
            "iptables-restore failed: {}",
            output.stderr.trim()
        )));
    }

    // Restore IPv6 if available
    if let Some(ref v6_data) = snapshot.iptables_save_v6 {
        let restore_v6_cmd = build_command(
            "sudo",
            &["ip6tables-restore", "-w", "5", "--noflush", "--counters"],
        );
        let output = executor
            .exec_with_stdin(&restore_v6_cmd, v6_data.as_bytes())
            .await?;
        if output.exit_code != 0 {
            return Err(SnapshotError::RestoreFailed(format!(
                "ip6tables-restore failed: {}",
                output.stderr.trim()
            )));
        }
    }

    Ok(())
}

/// List snapshots stored on the remote host.
pub async fn list_remote_snapshots(
    executor: &dyn CommandExecutor,
) -> Result<Vec<SnapshotMeta>, SnapshotError> {
    let cmd = build_command("ls", &["-1", SNAPSHOT_DIR]);
    let output = match executor.exec(&cmd).await {
        Ok(o) if o.exit_code == 0 => o,
        Ok(o) => {
            // Directory may not exist yet
            if o.stderr.contains("No such file") || o.stderr.contains("cannot access") {
                return Ok(Vec::new());
            }
            return Err(SnapshotError::Exec(ExecError::Transport(o.stderr)));
        }
        Err(e) => return Err(SnapshotError::Exec(e)),
    };

    let mut snapshots = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for line in output.stdout.lines() {
        let filename = line.trim();
        if filename.is_empty() {
            continue;
        }

        // Files are like "host-123-1711100000.v4"
        let base = if let Some(stripped) = filename.strip_suffix(".v4") {
            stripped
        } else if let Some(stripped) = filename.strip_suffix(".v6") {
            stripped
        } else {
            continue;
        };

        if seen_ids.contains(base) {
            continue;
        }
        seen_ids.insert(base.to_string());

        // Extract timestamp from the ID (last component after -)
        let timestamp = base
            .rsplit('-')
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Extract host_id (everything before the last -)
        let host_id = if let Some(idx) = base.rfind('-') {
            base[..idx].to_string()
        } else {
            base.to_string()
        };

        snapshots.push(SnapshotMeta {
            id: base.to_string(),
            host_id,
            timestamp,
            description: None,
            remote_path_v4: Some(format!("{}/{}.v4", SNAPSHOT_DIR, base)),
        });
    }

    // Sort by timestamp descending (newest first)
    snapshots.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Ok(snapshots)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Filter an `iptables-save` output to only include TR- chains.
///
/// Preserves the table structure (*table / COMMIT) but only includes
/// `:TR-*` chain declarations, `-A TR-*` rules, and rules in built-in
/// chains (INPUT/OUTPUT/FORWARD) that jump to a TR- chain.
fn filter_tr_chains(input: &str) -> String {
    let mut out = String::new();
    let mut in_table = false;
    let mut has_tr_content = false;
    let mut table_header = String::new();
    let mut table_lines: Vec<String> = Vec::new();

    /// Built-in chains whose jump-to-TR rules should be preserved.
    const BUILTIN_CHAINS: &[&str] = &["INPUT", "OUTPUT", "FORWARD"];

    /// Flush accumulated table content into the output buffer.
    fn flush_table(
        out: &mut String,
        table_header: &str,
        table_lines: &[String],
        has_tr_content: bool,
    ) {
        if has_tr_content {
            out.push_str(table_header);
            out.push('\n');
            for tl in table_lines {
                out.push_str(tl);
                out.push('\n');
            }
            out.push_str("COMMIT\n");
        }
    }

    for line in input.lines() {
        if line.starts_with('*') {
            // Flush previous table if it had TR content
            flush_table(&mut out, &table_header, &table_lines, has_tr_content);

            table_header = line.to_string();
            table_lines.clear();
            has_tr_content = false;
            in_table = true;
            continue;
        }

        if line == "COMMIT" {
            flush_table(&mut out, &table_header, &table_lines, has_tr_content);
            in_table = false;
            table_lines.clear();
            has_tr_content = false;
            continue;
        }

        if !in_table {
            continue;
        }

        // Chain declarations: ":TR-INPUT - [0:0]"
        if line.starts_with(':') {
            let chain_name = line[1..].split_whitespace().next().unwrap_or("");
            if chain_name.starts_with("TR-") {
                table_lines.push(line.to_string());
                has_tr_content = true;
            }
            continue;
        }

        // Rules: "-A CHAIN ..."
        if line.starts_with("-A ") {
            let chain_name = line[3..].split_whitespace().next().unwrap_or("");
            if chain_name.starts_with("TR-") {
                // Direct TR- chain rule
                table_lines.push(line.to_string());
                has_tr_content = true;
            }
            // NOTE: We deliberately EXCLUDE jump rules from built-in chains
            // (e.g., "-A INPUT -j TR-INPUT"). These are managed by ensure_jump_rules()
            // and including them in the backup causes duplication on --noflush restore.
        }
    }

    // Flush any remaining table (handles input without a final COMMIT)
    flush_table(&mut out, &table_header, &table_lines, has_tr_content);

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_tr_chains() {
        let input = r#"# Generated by iptables-save v1.8.7
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:TR-CONNTRACK - [0:0]
:TR-INPUT - [0:0]
-A INPUT -j TR-CONNTRACK
-A INPUT -j TR-INPUT
-A DOCKER -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j ACCEPT
-A TR-CONNTRACK -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A TR-INPUT -i lo -j ACCEPT
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"#;
        let filtered = filter_tr_chains(input);
        assert!(filtered.contains("*filter"));
        assert!(filtered.contains(":TR-CONNTRACK - [0:0]"));
        assert!(filtered.contains(":TR-INPUT - [0:0]"));
        assert!(filtered.contains("-A TR-CONNTRACK"));
        assert!(filtered.contains("-A TR-INPUT -i lo -j ACCEPT"));
        assert!(filtered.contains("COMMIT"));
        // Should NOT include jump rules from built-in chains — these are managed
        // separately by ensure_jump_rules() and would cause duplication on --noflush restore
        assert!(!filtered.contains("-A INPUT -j TR-CONNTRACK"));
        assert!(!filtered.contains("-A INPUT -j TR-INPUT"));
        // Should NOT contain Docker or built-in chain declarations
        assert!(!filtered.contains(":INPUT"));
        assert!(!filtered.contains(":DOCKER"));
        assert!(!filtered.contains("-A DOCKER"));
    }

    #[test]
    fn test_filter_tr_chains_no_tr() {
        let input = r#"*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"#;
        let filtered = filter_tr_chains(input);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_tr_chains_no_commit() {
        // Input without a final COMMIT — should still be flushed
        let input = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 22 -j ACCEPT\n";
        let filtered = filter_tr_chains(input);
        assert!(filtered.contains("*filter"));
        assert!(filtered.contains("-A TR-INPUT"));
        assert!(filtered.contains("COMMIT"));
    }

    #[test]
    fn test_filter_tr_chains_multiple_tables() {
        let input = r#"*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.1:80
COMMIT
*raw
:TR-CT-HELPERS - [0:0]
-A TR-CT-HELPERS -p tcp --dport 21 -j CT --helper ftp
COMMIT
"#;
        let filtered = filter_tr_chains(input);
        assert!(filtered.contains("*filter"));
        assert!(filtered.contains("-A TR-INPUT"));
        assert!(!filtered.contains("*nat"));
        assert!(!filtered.contains("PREROUTING"));
        assert!(filtered.contains("*raw"));
        assert!(filtered.contains("-A TR-CT-HELPERS"));
    }
}
