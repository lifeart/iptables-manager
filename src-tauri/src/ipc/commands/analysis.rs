use std::collections::HashMap;

use tauri::State;

use crate::ipc::errors::IpcError;
use crate::iptables::parser::parse_iptables_save;
use crate::ssh::command::build_command;

use super::helpers::{fetch_current_ruleset, PoolProxyExecutor};
use super::types::{CompareHostsResult, DriftCheckResult, ImportExistingRulesResult};
use super::{DriftState, PoolState};

/// Compare iptables rules between two connected hosts.
#[tauri::command]
pub async fn compare_hosts(
    host_id_a: String,
    host_id_b: String,
    pool: State<'_, PoolState>,
) -> Result<CompareHostsResult, IpcError> {
    let proxy_a = PoolProxyExecutor {
        pool: pool.inner().clone(),
        host_id: host_id_a.clone(),
    };
    let proxy_b = PoolProxyExecutor {
        pool: pool.inner().clone(),
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
    pool: State<'_, PoolState>,
) -> Result<ImportExistingRulesResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: pool.inner().clone(),
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

/// Check if remote iptables rules have changed outside of Traffic Rules.
#[tauri::command]
pub async fn check_drift(
    host_id: String,
    pool: State<'_, PoolState>,
    drift_state: State<'_, DriftState>,
) -> Result<DriftCheckResult, IpcError> {
    let cmd = build_command("sudo", &["iptables-save"]);
    let output = pool.execute(&host_id, &cmd).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: format!("failed to run iptables-save: {}", e),
        }
    })?;

    if output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: output.stderr,
            exit_code: output.exit_code,
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

    let previous = drift_state.get(&host_id).map(|v| v.clone());
    drift_state.insert(host_id.clone(), new_hash.clone());

    match previous {
        None => {
            Ok(DriftCheckResult {
                drifted: false,
                added_rules: 0,
                removed_rules: 0,
                modified_rules: 0,
            })
        }
        Some(prev_hash) if prev_hash == new_hash => {
            Ok(DriftCheckResult {
                drifted: false,
                added_rules: 0,
                removed_rules: 0,
                modified_rules: 0,
            })
        }
        Some(_) => {
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

            Ok(DriftCheckResult {
                drifted: true,
                added_rules: 0,
                removed_rules: 0,
                modified_rules: total_rules,
            })
        }
    }
}

/// Reset the drift baseline for a host (called after rules are refreshed).
#[tauri::command]
pub async fn reset_drift(
    host_id: String,
    pool: State<'_, PoolState>,
    drift_state: State<'_, DriftState>,
) -> Result<(), IpcError> {
    let cmd = build_command("sudo", &["iptables-save"]);
    let output = pool.execute(&host_id, &cmd).await.map_err(|e| {
        IpcError::ConnectionFailed {
            host_id: host_id.clone(),
            reason: format!("failed to run iptables-save: {}", e),
        }
    })?;

    if output.exit_code != 0 {
        return Err(IpcError::CommandFailed {
            stderr: output.stderr,
            exit_code: output.exit_code,
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

    drift_state.insert(host_id, new_hash);
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
