use std::collections::HashMap;

use tauri::State;
use tracing::{debug, warn};

use crate::ipc::errors::IpcError;
use crate::iptables::parser::parse_iptables_save;
use crate::iptables::ipset_suggest::{self, IpsetSuggestion};
use crate::ssh::command::build_command;

use super::helpers::{exec_failed, fetch_current_ruleset, PoolProxyExecutor};
use super::types::{CompareHostsResult, ConvertToIpsetResult, DriftCheckResult, ImportExistingRulesResult};
use super::AppState;

/// Compare iptables rules between two connected hosts.
#[tauri::command]
pub async fn compare_hosts(
    host_id_a: String,
    host_id_b: String,
    state: State<'_, AppState>,
) -> Result<CompareHostsResult, IpcError> {
    let proxy_a = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id_a.clone(),
    };
    let proxy_b = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id_b.clone(),
    };

    let (raw_a, _ruleset_a) = fetch_current_ruleset(&proxy_a, &host_id_a).await?;
    let (raw_b, _ruleset_b) = fetch_current_ruleset(&proxy_b, &host_id_b).await?;

    let rules_a = extract_rule_lines(&raw_a);
    let rules_b = extract_rule_lines(&raw_b);

    let set_a: std::collections::HashSet<&str> = rules_a.iter().map(|s| s.as_str()).collect();
    let set_b: std::collections::HashSet<&str> = rules_b.iter().map(|s| s.as_str()).collect();

    let only_in_a: Vec<String> = rules_a.iter().filter(|r| !set_b.contains(r.as_str())).cloned().collect();
    let only_in_b: Vec<String> = rules_b.iter().filter(|r| !set_a.contains(r.as_str())).cloned().collect();
    let identical = set_a.intersection(&set_b).count();
    let different = find_chain_diffs(&raw_a, &raw_b);

    Ok(CompareHostsResult { only_in_a, only_in_b, different, identical })
}

/// Fetch ALL iptables rules from a host (not just TR-managed) and return
/// them as parsed RuleSpecs for the frontend to import.
#[tauri::command]
pub async fn import_existing_rules(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<ImportExistingRulesResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    let (raw, ruleset) = fetch_current_ruleset(&proxy, &host_id).await?;

    let mut non_tr_count = 0usize;
    for table in ruleset.tables.values() {
        for (chain_name, chain_state) in &table.chains {
            if !chain_name.starts_with("TR-") {
                non_tr_count += chain_state.rules.len();
            }
        }
    }

    let rules_json = serde_json::to_value(&ruleset).unwrap_or(serde_json::Value::Null);

    Ok(ImportExistingRulesResult {
        rules: rules_json,
        raw_iptables_save: raw,
        non_tr_rule_count: non_tr_count,
    })
}

/// Analyze a host's iptables rules for ipset optimization opportunities.
#[tauri::command]
pub async fn analyze_ipset_opportunities(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<IpsetSuggestion>, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    let (_raw, ruleset) = fetch_current_ruleset(&proxy, &host_id).await?;
    Ok(ipset_suggest::analyze_ipset_opportunities(&ruleset, 50))
}

/// Create an ipset from an optimization suggestion.
///
/// Creates the ipset and syncs entries. The actual rule replacement
/// (removing N rules, adding 1 ipset rule) must be done manually by the user.
#[tauri::command]
pub async fn convert_to_ipset(
    host_id: String,
    suggestion_json: String,
    state: State<'_, AppState>,
) -> Result<ConvertToIpsetResult, IpcError> {
    let suggestion: IpsetSuggestion = serde_json::from_str(&suggestion_json).map_err(|e| {
        IpcError::CommandFailed {
            stderr: format!("invalid suggestion JSON: {}", e),
            exit_code: 1,
        }
    })?;

    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    // Fetch current ruleset to extract all matching IPs
    let (_raw, ruleset) = fetch_current_ruleset(&proxy, &host_id).await?;

    let mut ips = Vec::new();
    if let Some(table) = ruleset.tables.get(&suggestion.table) {
        if let Some(chain) = table.chains.get(&suggestion.chain) {
            for rule in &chain.rules {
                if let Some(spec) = &rule.parsed {
                    if let Some(source) = &spec.source {
                        if !source.negated {
                            // Check target matches the suggestion pattern
                            let is_terminal = matches!(
                                &spec.target,
                                Some(crate::iptables::types::Target::Drop)
                                    | Some(crate::iptables::types::Target::Reject)
                                    | Some(crate::iptables::types::Target::Accept)
                            );
                            if is_terminal {
                                ips.push(source.addr.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    let entries_count = ips.len();

    // Create the ipset
    crate::ipset::manager::create_ipset(
        &proxy,
        &suggestion.suggested_name,
        &crate::iptables::types::AddressFamily::V4,
    )
    .await
    .map_err(|e| IpcError::CommandFailed {
        stderr: format!("failed to create ipset: {}", e),
        exit_code: 1,
    })?;

    // Sync entries
    crate::ipset::manager::sync_ipset(
        &proxy,
        &suggestion.suggested_name,
        &ips,
        &crate::iptables::types::AddressFamily::V4,
    )
    .await
    .map_err(|e| IpcError::CommandFailed {
        stderr: format!("failed to sync ipset entries: {}", e),
        exit_code: 1,
    })?;

    Ok(ConvertToIpsetResult {
        ipset_created: true,
        ipset_name: suggestion.suggested_name,
        entries_added: entries_count,
        rules_replaced: 0, // Manual step — user must update rules to reference the ipset
    })
}

/// Check if remote iptables rules have changed outside of Traffic Rules.
#[tauri::command]
pub async fn check_drift(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<DriftCheckResult, IpcError> {
    let cmd = build_command("sudo", &["iptables-save"]);
    let output = state.pool.execute(&host_id, &cmd).await.map_err(|e| {
        exec_failed(&host_id, format!("failed to run iptables-save: {}", e))
    })?;

    if output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: output.stderr,
            exit_code: output.exit_code,
            explanation: None,
        });
    }

    let filtered = crate::snapshot::manager::filter_tr_chains(&output.stdout);
    let new_hash = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        filtered.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    };

    let previous = state.drift.get(&host_id).map(|v| v.clone());
    let previous_raw = state.drift_rulesets.get(&host_id).map(|v| v.clone());

    // Always store the current raw output for future diff computation
    state.drift_rulesets.insert(host_id.clone(), filtered.clone());
    state.drift.insert(host_id.clone(), new_hash.clone());

    match previous {
        None => {
            Ok(DriftCheckResult {
                drifted: false,
                added_rules: 0,
                removed_rules: 0,
                modified_rules: 0,
                changes: Vec::new(),
            })
        }
        Some(prev_hash) if prev_hash == new_hash => {
            Ok(DriftCheckResult {
                drifted: false,
                added_rules: 0,
                removed_rules: 0,
                modified_rules: 0,
                changes: Vec::new(),
            })
        }
        Some(_) => {
            // Compute actual diff if we have previous raw output
            let changes = if let Some(prev_raw) = previous_raw {
                let prev_parsed = parse_iptables_save(&prev_raw).ok();
                if let Some(prev) = prev_parsed {
                    match crate::iptables::diff::compute_diff(&prev, &filtered) {
                        Ok(diff) => diff.changes,
                        Err(e) => {
                            warn!("Failed to compute drift diff: {}", e);
                            Vec::new()
                        }
                    }
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            let mut added = 0usize;
            let mut removed = 0usize;
            let mut modified = 0usize;

            for change in &changes {
                match change {
                    crate::iptables::diff::DiffEntry::Added { .. }
                    | crate::iptables::diff::DiffEntry::ChainAdded { .. } => added += 1,
                    crate::iptables::diff::DiffEntry::Removed { .. }
                    | crate::iptables::diff::DiffEntry::ChainRemoved { .. } => removed += 1,
                    crate::iptables::diff::DiffEntry::Modified { .. }
                    | crate::iptables::diff::DiffEntry::PolicyChanged { .. } => modified += 1,
                }
            }

            // Fall back to total rule count if no diff was computed
            if changes.is_empty() {
                let ruleset = parse_iptables_save(&filtered).map_err(|e| {
                    IpcError::CommandFailed {
                        stderr: format!("failed to parse filtered rules: {}", e),
                        exit_code: 1,
                    }
                })?;

                let mut total_rules: usize = 0;
                for table in ruleset.tables.values() {
                    for (chain_name, chain_state) in &table.chains {
                        if chain_name.starts_with("TR-") {
                            total_rules += chain_state.rules.len();
                        }
                    }
                }
                modified = total_rules;
            }

            warn!("Drift detected on {}: +{} -{} ~{}", host_id, added, removed, modified);

            Ok(DriftCheckResult {
                drifted: true,
                added_rules: added,
                removed_rules: removed,
                modified_rules: modified,
                changes,
            })
        }
    }
}

/// Reset the drift baseline for a host (called after rules are refreshed).
#[tauri::command]
pub async fn reset_drift(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<(), IpcError> {
    let cmd = build_command("sudo", &["iptables-save"]);
    let output = state.pool.execute(&host_id, &cmd).await.map_err(|e| {
        exec_failed(&host_id, format!("failed to run iptables-save: {}", e))
    })?;

    if output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: output.stderr,
            exit_code: output.exit_code,
            explanation: None,
        });
    }

    let filtered = crate::snapshot::manager::filter_tr_chains(&output.stdout);
    let new_hash = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        filtered.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    };

    debug!("Drift baseline reset for {}", host_id);
    state.drift_rulesets.insert(host_id.clone(), filtered);
    state.drift.insert(host_id, new_hash);
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper functions for compare_hosts
// ---------------------------------------------------------------------------

fn extract_rule_lines(raw: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current_table = String::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('*') {
            current_table = trimmed[1..].to_string();
        } else if trimmed.starts_with("-A ") {
            result.push(format!("[{}] {}", current_table, trimmed));
        }
    }
    result
}

fn find_chain_diffs(raw_a: &str, raw_b: &str) -> Vec<String> {
    fn group_by_chain(raw: &str) -> HashMap<String, Vec<String>> {
        let mut result: HashMap<String, Vec<String>> = HashMap::new();
        let mut current_table = String::new();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('*') {
                current_table = trimmed[1..].to_string();
            } else if trimmed.starts_with("-A ") {
                let rest = &trimmed[3..];
                if let Some(space_idx) = rest.find(' ') {
                    let chain = &rest[..space_idx];
                    let spec = &rest[space_idx + 1..];
                    let key = format!("{}:{}", current_table, chain);
                    result.entry(key).or_default().push(spec.to_string());
                }
            }
        }
        result
    }

    let chains_a = group_by_chain(raw_a);
    let chains_b = group_by_chain(raw_b);
    let mut diffs = Vec::new();

    for (chain_key, specs_a) in &chains_a {
        if let Some(specs_b) = chains_b.get(chain_key) {
            let max_len = std::cmp::max(specs_a.len(), specs_b.len());
            for i in 0..max_len {
                match (specs_a.get(i), specs_b.get(i)) {
                    (Some(a), Some(b)) if a != b => {
                        diffs.push(format!("{} #{}: A has '{}', B has '{}'", chain_key, i + 1, a, b));
                    }
                    _ => {}
                }
            }
        }
    }

    diffs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use dashmap::DashMap;

    /// Simulate drift detection for two hosts concurrently, verifying that
    /// per-host hash tracking in the DashMap doesn't cause cross-host
    /// interference.
    #[tokio::test]
    async fn test_drift_concurrent_hosts() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let drift: Arc<DashMap<String, String>> = Arc::new(DashMap::new());

        // Simulate iptables-save output for two hosts
        let rules_a_v1 = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n";
        let rules_b_v1 = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 80 -j ACCEPT\nCOMMIT\n";

        // Helper to compute hash (mirrors check_drift logic)
        let compute_hash = |input: &str| -> String {
            let filtered = crate::snapshot::manager::filter_tr_chains(input);
            let mut hasher = DefaultHasher::new();
            filtered.hash(&mut hasher);
            format!("{:016x}", hasher.finish())
        };

        // First call: baseline for both hosts (no drift expected)
        let drift_a = drift.clone();
        let drift_b = drift.clone();

        let hash_a_v1 = compute_hash(rules_a_v1);
        let hash_b_v1 = compute_hash(rules_b_v1);

        // Run baseline insertion concurrently
        let handle_a = tokio::spawn({
            let drift = drift_a;
            let hash = hash_a_v1.clone();
            async move {
                let prev = drift.get("host-a").map(|v| v.clone());
                drift.insert("host-a".to_string(), hash);
                prev
            }
        });
        let handle_b = tokio::spawn({
            let drift = drift_b;
            let hash = hash_b_v1.clone();
            async move {
                let prev = drift.get("host-b").map(|v| v.clone());
                drift.insert("host-b".to_string(), hash);
                prev
            }
        });

        let prev_a = handle_a.await.unwrap();
        let prev_b = handle_b.await.unwrap();
        assert!(prev_a.is_none(), "host-a should have no previous hash");
        assert!(prev_b.is_none(), "host-b should have no previous hash");

        // Second call: same rules => no drift
        let prev_a2 = drift.get("host-a").map(|v| v.clone());
        drift.insert("host-a".to_string(), hash_a_v1.clone());
        assert_eq!(
            prev_a2.as_deref(),
            Some(hash_a_v1.as_str()),
            "hash should match — no drift for host-a"
        );

        let prev_b2 = drift.get("host-b").map(|v| v.clone());
        drift.insert("host-b".to_string(), hash_b_v1.clone());
        assert_eq!(
            prev_b2.as_deref(),
            Some(hash_b_v1.as_str()),
            "hash should match — no drift for host-b"
        );

        // Third call: host-a rules change, host-b stays the same
        let rules_a_v2 = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 443 -j ACCEPT\nCOMMIT\n";
        let hash_a_v2 = compute_hash(rules_a_v2);

        // Run both concurrently
        let drift_clone = drift.clone();
        let hash_a_v2_clone = hash_a_v2.clone();
        let hash_b_v1_clone = hash_b_v1.clone();

        let handle_a = tokio::spawn({
            let drift = drift_clone.clone();
            async move {
                let prev = drift.get("host-a").map(|v| v.clone());
                drift.insert("host-a".to_string(), hash_a_v2_clone);
                prev
            }
        });
        let handle_b = tokio::spawn({
            let drift = drift_clone;
            async move {
                let prev = drift.get("host-b").map(|v| v.clone());
                drift.insert("host-b".to_string(), hash_b_v1_clone.clone());
                prev
            }
        });

        let prev_a3 = handle_a.await.unwrap();
        let prev_b3 = handle_b.await.unwrap();

        // host-a should detect drift (hash changed)
        assert!(prev_a3.is_some(), "host-a should have a previous hash");
        assert_ne!(
            prev_a3.unwrap(),
            hash_a_v2,
            "host-a hash should differ — drift detected"
        );

        // host-b should NOT detect drift (hash unchanged)
        assert_eq!(
            prev_b3.as_deref(),
            Some(hash_b_v1.as_str()),
            "host-b hash should match — no drift, not affected by host-a changes"
        );

        // Verify final state: each host has its own independent hash
        assert_eq!(
            drift.get("host-a").map(|v| v.clone()),
            Some(hash_a_v2),
            "host-a should have updated hash"
        );
        assert_eq!(
            drift.get("host-b").map(|v| v.clone()),
            Some(hash_b_v1),
            "host-b should retain its own hash"
        );
    }
}
