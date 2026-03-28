use std::sync::Arc;

use tauri::State;
use tracing::{debug, warn};

use crate::host::detect::{detect_mixed_backend, MixedBackendStatus};
use crate::ipc::errors::IpcError;
use crate::iptables::explain::explain_rule;
use crate::iptables::system_detect::detect_chain_owner;
use crate::iptables::types::ChainOwner;
use crate::iptables::types::RuleSpec;
use crate::ssh::command::build_command;
use crate::ssh::executor::CommandExecutor;
use crate::ssh::pool::ConnectionPool;

use super::helpers::{create_pre_apply_backup, exec_failed, fetch_current_ruleset, PoolProxyExecutor};
use super::types::{
    ApplyResult, DuplicateCheckResult, GroupApplyResult, HostApplyResult, PreviewResult,
    RuleSetResult,
};
use super::AppState;

/// Fetch the current iptables rules for a host.
#[tauri::command]
pub async fn fetch_rules(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<RuleSetResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    let (raw, ruleset) = fetch_current_ruleset(&proxy, &host_id).await?;

    // Determine default policy from the filter table's INPUT chain
    let default_policy = ruleset
        .tables
        .get("filter")
        .and_then(|t| t.chains.get("INPUT"))
        .and_then(|c| c.policy.clone())
        .unwrap_or_else(|| "ACCEPT".to_string())
        .to_lowercase();

    let rules_json = serde_json::to_value(&ruleset).unwrap_or(serde_json::Value::Null);

    Ok(RuleSetResult {
        rules: rules_json,
        default_policy,
        raw_iptables_save: raw,
    })
}

/// Apply rule changes via iptables-restore.
///
/// Before applying, saves a backup of the current rules to
/// `/var/lib/traffic-rules/backup.v4` (and `.v6`), computes an HMAC
/// of the backup, and writes it alongside as `.hmac`. This ensures
/// the safety-timer revert script can verify backup integrity.
#[tauri::command]
pub async fn rules_apply(
    host_id: String,
    changes_json: String,
    safety_timeout_secs: Option<u32>,
    state: State<'_, AppState>,
) -> Result<ApplyResult, IpcError> {
    let pool = &state.pool;
    let _lock = pool.acquire_apply_lock(&host_id).await;

    let proxy = PoolProxyExecutor {
        pool: pool.clone(),
        host_id: host_id.clone(),
    };

    // Step 0a: Check for mixed backend — block apply if both legacy and nft rules exist
    if let Ok(MixedBackendStatus::Mixed {
        legacy_rule_count,
        nft_rule_count,
    }) = detect_mixed_backend(&proxy).await
    {
        return Err(IpcError::MixedBackend {
            legacy_count: legacy_rule_count,
            nft_count: nft_rule_count,
        });
    }

    // Step 0b: Check for external chain modifications
    let external_chain_warning = detect_external_chain_warning(&changes_json);

    // Step 1: Save backup of current rules
    create_pre_apply_backup(&proxy, &host_id).await?;
    debug!("Created pre-apply backup for {}", host_id);

    // Step 2: Arm safety timer BEFORE applying rules
    let timer_result = if let Some(timeout) = safety_timeout_secs {
        let mechanism = crate::safety::timer::detect_mechanism(&proxy).await;
        let backup_path = "/var/lib/traffic-rules/backup.v4";
        let job = crate::safety::timer::schedule_revert(
            &proxy, mechanism, backup_path, timeout,
        )
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: format!("safety timer failed (rules NOT applied): {}", e),
            exit_code: 1,
            explanation: None,
        })?;
        Some(job)
    } else {
        None
    };

    // Step 3: Apply the new rules (with xtables lock retry)
    let restore_cmd = build_command(
        "sudo",
        &["iptables-restore", "-w", "5", "--noflush", "--counters"],
    );

    use crate::iptables::lock::{execute_with_lock_retry, LockError};

    let output = match execute_with_lock_retry(
        &proxy,
        &restore_cmd,
        Some(changes_json.as_bytes()),
        3,
    )
    .await
    {
        Ok(output) => output,
        Err(LockError::Exhausted { holder, attempts }) => {
            return Err(IpcError::IptablesLocked {
                retry_after_ms: 5000,
                holder_process: holder.as_ref().map(|h| h.process_name.clone()),
                holder_pid: holder.as_ref().map(|h| h.pid),
                attempts,
            });
        }
        Err(LockError::Exec(e)) => {
            return Err(exec_failed(
                &host_id,
                format!("failed to apply rules: {}", e),
            ));
        }
    };

    if output.exit_code != 0 {
        return Err(super::helpers::enrich_command_error(
            &output.stderr,
            output.exit_code,
            None,
        ));
    }

    Ok(ApplyResult {
        success: true,
        safety_timer_active: timer_result.is_some(),
        safety_timer_expiry: safety_timeout_secs.map(|t| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
                + (t as u64) * 1000
        }),
        remote_job_id: timer_result.as_ref().map(|j| j.id.clone()),
        safety_timer_mechanism: timer_result.as_ref().map(|j| format!("{:?}", j.mechanism)),
        external_chain_warning,
    })
}

/// Apply rule changes to a group of hosts using a deployment strategy.
///
/// Supports canary, rolling, and parallel strategies via multi_apply::create_apply_plan.
/// For canary, stops on first failure. For rolling, applies one-by-one (also stops on failure).
/// For parallel, applies to all hosts concurrently.
#[tauri::command]
pub async fn rules_apply_group(
    host_ids: Vec<String>,
    changes_json: String,
    strategy: String,
    state: State<'_, AppState>,
) -> Result<GroupApplyResult, IpcError> {
    use crate::iptables::multi_apply::{create_apply_plan, ApplyStrategy};

    let strat = match strategy.as_str() {
        "canary" => ApplyStrategy::Canary,
        "rolling" => ApplyStrategy::Rolling,
        "parallel" => ApplyStrategy::Parallel,
        _ => ApplyStrategy::Rolling,
    };

    let pool_arc = state.pool.clone();
    let changes_json: Arc<String> = Arc::from(changes_json);
    let plan = create_apply_plan(strat, host_ids.clone());
    let mut all_results: Vec<HostApplyResult> = Vec::new();

    for step in &plan.steps {
        if step.max_concurrency > 1 && step.host_ids.len() > 1 {
            // Parallel execution within this step using tokio JoinSet
            let mut handles = Vec::new();
            for hid in &step.host_ids {
                let pool_clone = pool_arc.clone();
                let hid_clone = hid.clone();
                let hid_for_err = hid.clone();
                let changes = changes_json.clone();
                let handle = tokio::spawn(async move {
                    apply_to_single_host(&pool_clone, &hid_clone, changes.as_str(), None).await
                });
                handles.push((hid_for_err, handle));
            }
            for (hid, handle) in handles {
                match handle.await {
                    Ok(host_result) => all_results.push(host_result),
                    Err(e) => all_results.push(HostApplyResult {
                        host_id: hid,
                        success: false,
                        error: Some(format!("task join error: {}", e)),
                    }),
                }
            }
        } else {
            // Sequential execution
            for hid in &step.host_ids {
                let result = apply_to_single_host(&pool_arc, hid, &changes_json, None).await;
                let failed = !result.success;
                all_results.push(result);

                // For canary/rolling, stop on first failure
                if failed && (step.is_canary || plan.strategy == ApplyStrategy::Rolling) {
                    let succeeded = all_results.iter().filter(|r| r.success).count();
                    let total = host_ids.len();
                    return Ok(GroupApplyResult {
                        results: all_results,
                        strategy: strategy.clone(),
                        total,
                        succeeded,
                        failed: total - succeeded,
                    });
                }
            }
        }

        // For canary strategy, check canary step result before proceeding
        if step.is_canary {
            let canary_failed = all_results.iter().any(|r| !r.success);
            if canary_failed {
                let succeeded = all_results.iter().filter(|r| r.success).count();
                let total = host_ids.len();
                return Ok(GroupApplyResult {
                    results: all_results,
                    strategy: strategy.clone(),
                    total,
                    succeeded,
                    failed: total - succeeded,
                });
            }
        }
    }

    let succeeded = all_results.iter().filter(|r| r.success).count();
    let total = host_ids.len();
    Ok(GroupApplyResult {
        results: all_results,
        strategy,
        total,
        succeeded,
        failed: total - succeeded,
    })
}

/// Apply changes to a single host, returning a HostApplyResult.
///
/// If `safety_timeout_secs` is provided, the safety timer is armed BEFORE
/// applying rules so that a dropped connection still has rollback protection.
async fn apply_to_single_host(
    pool: &Arc<ConnectionPool>,
    host_id: &str,
    changes_json: &str,
    safety_timeout_secs: Option<u32>,
) -> HostApplyResult {
    let _lock = pool.acquire_apply_lock(host_id).await;

    let proxy = PoolProxyExecutor {
        pool: pool.clone(),
        host_id: host_id.to_string(),
    };

    // Check for mixed backend — block apply if both legacy and nft rules exist
    if let Ok(MixedBackendStatus::Mixed {
        legacy_rule_count,
        nft_rule_count,
    }) = detect_mixed_backend(&proxy).await
    {
        return HostApplyResult {
            host_id: host_id.to_string(),
            success: false,
            error: Some(format!(
                "Mixed backend: {} legacy rules, {} nft rules",
                legacy_rule_count, nft_rule_count
            )),
        };
    }

    // Create backup
    if let Err(e) = create_pre_apply_backup(&proxy, host_id).await {
        return HostApplyResult {
            host_id: host_id.to_string(),
            success: false,
            error: Some(format!("backup failed: {}", e)),
        };
    }

    // Arm safety timer BEFORE applying rules
    if let Some(timeout) = safety_timeout_secs {
        let mechanism = crate::safety::timer::detect_mechanism(&proxy).await;
        let backup_path = "/var/lib/traffic-rules/backup.v4";
        if let Err(e) = crate::safety::timer::schedule_revert(
            &proxy, mechanism, backup_path, timeout,
        ).await {
            return HostApplyResult {
                host_id: host_id.to_string(),
                success: false,
                error: Some(format!("safety timer failed (rules NOT applied): {}", e)),
            };
        }
    }

    // Apply
    let restore_cmd = build_command(
        "sudo",
        &["iptables-restore", "-w", "5", "--noflush", "--counters"],
    );
    match pool
        .execute_with_stdin(host_id, &restore_cmd, changes_json.as_bytes())
        .await
    {
        Ok(output) if output.exit_code == 0 => HostApplyResult {
            host_id: host_id.to_string(),
            success: true,
            error: None,
        },
        Ok(output) => HostApplyResult {
            host_id: host_id.to_string(),
            success: false,
            error: Some(format!("exit {}: {}", output.exit_code, output.stderr)),
        },
        Err(e) => HostApplyResult {
            host_id: host_id.to_string(),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

/// Preview rule changes without applying them.
#[tauri::command]
pub async fn rules_preview(
    _host_id: String,
    changes_json: String,
) -> Result<PreviewResult, IpcError> {
    let restore_command = "sudo iptables-restore -w 5 --noflush --counters".to_string();

    Ok(PreviewResult {
        restore_content: changes_json,
        restore_command,
    })
}

/// Revert rule changes on a host.
#[tauri::command]
pub async fn rules_revert(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<(), IpcError> {
    let cmd = build_command("sudo", &["/var/lib/traffic-rules/revert.sh"]);
    let output = state.pool.execute(&host_id, &cmd).await.map_err(|e| {
        exec_failed(&host_id, format!("failed to revert: {}", e))
    })?;
    if output.exit_code != 0 {
        return Err(super::helpers::enrich_command_error(
            &output.stderr,
            output.exit_code,
            None,
        ));
    }
    Ok(())
}

/// Confirm applied changes (cancel safety timer and clean up backup files).
#[tauri::command]
pub async fn rules_confirm(
    host_id: String,
    job_id: Option<String>,
    mechanism: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    // Cancel the scheduled revert job if we have job info
    if let Some(ref jid) = job_id {
        if !jid.is_empty() {
            let mech = match mechanism.as_deref() {
                Some("At") => crate::safety::timer::SafetyMechanism::At,
                Some("SystemdRun") => crate::safety::timer::SafetyMechanism::SystemdRun,
                Some("Nohup") => crate::safety::timer::SafetyMechanism::Nohup,
                Some("IptablesApply") => crate::safety::timer::SafetyMechanism::IptablesApply,
                _ => crate::safety::timer::SafetyMechanism::At,
            };

            let revert_job = crate::safety::timer::RevertJobId {
                mechanism: mech,
                id: jid.clone(),
            };

            crate::safety::timer::cancel_revert(&proxy, &revert_job)
                .await
                .map_err(|e| IpcError::CommandFailed {
                    stderr: format!("cancel safety timer: {}", e),
                    exit_code: 1,
                    explanation: None,
                })?;
        }
    }

    // Clean up backup files on the remote host
    let cleanup_cmd = build_command(
        "sudo",
        &[
            "rm", "-f",
            "/var/lib/traffic-rules/backup.v4",
            "/var/lib/traffic-rules/backup.v4.hmac",
            "/var/lib/traffic-rules/backup.v6",
        ],
    );
    // Best-effort cleanup
    if let Err(e) = proxy.exec(&cleanup_cmd).await {
        warn!("Cleanup command failed (non-fatal): {}", e);
    }

    Ok(())
}

/// Trace a test packet through the current iptables ruleset.
#[tauri::command]
pub async fn rules_trace(
    host_id: String,
    packet: crate::iptables::tracer::TestPacket,
    state: State<'_, AppState>,
) -> Result<crate::iptables::tracer::TraceResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    let (_raw, ruleset) = fetch_current_ruleset(&proxy, &host_id).await?;

    Ok(crate::iptables::tracer::trace_packet(&ruleset, &packet))
}

/// Check if a proposed rule duplicates an existing rule on the remote host.
#[tauri::command]
pub async fn rules_check_duplicate(
    host_id: String,
    rule: serde_json::Value,
    state: State<'_, AppState>,
) -> Result<DuplicateCheckResult, IpcError> {
    use crate::iptables::duplicate::{check_duplicate, ProposedRule};

    let proposed: ProposedRule = serde_json::from_value(rule).map_err(|e| {
        IpcError::CommandFailed {
            stderr: format!("invalid rule JSON: {}", e),
            exit_code: 1,
            explanation: None,
        }
    })?;

    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    let (_raw, ruleset) = fetch_current_ruleset(&proxy, &host_id).await?;

    const SIMILARITY_THRESHOLD: f64 = 0.5;
    const DUPLICATE_THRESHOLD: f64 = 0.8;

    match check_duplicate(&proposed, &ruleset, SIMILARITY_THRESHOLD) {
        Some(m) => Ok(DuplicateCheckResult {
            is_duplicate: m.similarity >= DUPLICATE_THRESHOLD,
            existing_rule_id: Some(m.rule_id),
            similarity: m.similarity,
        }),
        None => Ok(DuplicateCheckResult {
            is_duplicate: false,
            existing_rule_id: None,
            similarity: 0.0,
        }),
    }
}

/// Detect conflicts among the current rules on a host.
#[tauri::command]
pub async fn rules_detect_conflicts(
    host_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<crate::iptables::conflict::RuleConflict>, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    let (_raw, ruleset) = fetch_current_ruleset(&proxy, &host_id).await?;

    let effective = crate::iptables::conflict::ruleset_to_effective_rules(&ruleset);
    let result = crate::iptables::conflict::detect_conflicts(&effective);
    Ok(result.conflicts)
}

/// Run a live TRACE on the remote host's kernel.
///
/// Inserts TRACE rules into raw table, collects trace output via
/// xtables-monitor (nft) or dmesg (legacy), then removes TRACE rules.
#[tauri::command]
pub async fn rules_live_trace(
    host_id: String,
    request: crate::iptables::live_trace::LiveTraceRequest,
    state: State<'_, AppState>,
) -> Result<crate::iptables::live_trace::LiveTraceResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    // Detect iptables variant to choose collection method
    let version_cmd = build_command("sudo", &["iptables", "--version"]);
    let version_output = proxy.exec(&version_cmd).await.map_err(|e| {
        exec_failed(&host_id, format!("failed to detect iptables variant: {}", e))
    })?;

    let variant = if version_output.stdout.contains("nf_tables") {
        crate::host::detect::IptablesVariant::Nft
    } else {
        crate::host::detect::IptablesVariant::Legacy
    };

    crate::iptables::live_trace::run_live_trace(&proxy, &variant, &request)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: e.to_string(),
            exit_code: 1,
            explanation: None,
        })
}

/// Produce a human-readable explanation of a rule.
#[tauri::command]
pub async fn explain_rule_cmd(rule_json: String) -> Result<String, IpcError> {
    let spec: RuleSpec = serde_json::from_str(&rule_json).map_err(|e| {
        IpcError::CommandFailed {
            stderr: format!("invalid rule JSON: {}", e),
            exit_code: 1,
            explanation: None,
        }
    })?;

    Ok(explain_rule(&spec))
}

/// Export rules in the requested format.
#[tauri::command]
pub async fn export_rules(
    host_id: String,
    format: String,
    state: State<'_, AppState>,
) -> Result<String, IpcError> {
    match format.as_str() {
        "shell" | "ansible" | "iptables-save" => {}
        _ => {
            return Err(IpcError::CommandFailed {
                stderr: format!("unsupported export format: {}", format),
                exit_code: 1,
                explanation: None,
            });
        }
    }

    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    let (raw, _ruleset) = fetch_current_ruleset(&proxy, &host_id).await?;

    Ok(raw)
}

/// Parse iptables-restore content to extract chain names being modified,
/// then check if any belong to external tools.
fn detect_external_chain_warning(changes_json: &str) -> Option<String> {
    use std::collections::HashMap;

    let mut external_owners: HashMap<String, Vec<String>> = HashMap::new();

    for line in changes_json.lines() {
        let trimmed = line.trim();
        // Lines like "-A DOCKER-USER ..." or "-I f2b-sshd ..." modify chains
        if trimmed.starts_with("-A ")
            || trimmed.starts_with("-I ")
            || trimmed.starts_with("-D ")
            || trimmed.starts_with("-R ")
        {
            // Extract chain name (second token)
            let rest = &trimmed[3..];
            let chain_name = rest.split_whitespace().next().unwrap_or("");
            if chain_name.is_empty() || chain_name.starts_with("TR-") {
                continue;
            }
            let owner = detect_chain_owner(chain_name, &[]);
            if let ChainOwner::System(tool) = owner {
                let tool_name = format!("{:?}", tool);
                external_owners
                    .entry(tool_name)
                    .or_default()
                    .push(chain_name.to_string());
            }
        }
    }

    if external_owners.is_empty() {
        return None;
    }

    let tool_names: Vec<String> = external_owners.keys().cloned().collect();
    Some(format!(
        "Changes affect chains managed by {}. This may conflict with those tools' networking.",
        tool_names.join(", ")
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::helpers::tests::MockExecutor;
    use super::super::helpers::create_pre_apply_backup;
    use crate::ssh::command::build_command;
    use crate::ssh::executor::CommandExecutor;

    /// Verify that when safety_timeout_secs is provided, the call order is:
    /// iptables-save (backup) -> schedule_revert (at/systemd/nohup) -> iptables-restore
    #[tokio::test]
    async fn test_apply_arms_timer_before_restore() {
        let iptables_output = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n";
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, iptables_output, ""),
            ("tee /var/lib/traffic-rules/backup.v4", 0, "", ""),
            ("ip6tables-save", 1, "", "not found"),
            ("which at", 0, "/usr/bin/at", ""),
            ("is-active", 0, "active", ""),
            ("at ", 0, "", "job 42 at Thu Mar 22 10:00:00 2026\n"),
            ("iptables-restore", 0, "", ""),
        ]);

        let proxy = &executor;

        // Step 1: backup
        let backup_result = create_pre_apply_backup(proxy, "test-host").await;
        assert!(backup_result.is_ok(), "backup should succeed");

        // Step 2: arm safety timer
        let mechanism = crate::safety::timer::detect_mechanism(proxy).await;
        let job = crate::safety::timer::schedule_revert(
            proxy,
            mechanism,
            "/var/lib/traffic-rules/backup.v4",
            60,
        )
        .await;
        assert!(job.is_ok(), "safety timer should succeed");

        // Step 3: apply (simulated via exec_with_stdin)
        let restore_cmd = build_command(
            "sudo",
            &["iptables-restore", "-w", "5", "--noflush", "--counters"],
        );
        let apply_output: Result<crate::ssh::executor::CommandOutput, crate::ssh::executor::ExecError> = executor
            .exec_with_stdin(&restore_cmd, b"*filter\nCOMMIT\n")
            .await;
        assert!(apply_output.is_ok(), "apply should succeed");

        // Verify call order: iptables-save < at < iptables-restore
        let calls: Vec<String> = executor.get_calls();
        let save_idx = calls
            .iter()
            .position(|c| c.contains("iptables-save"))
            .expect("should call iptables-save");
        let at_idx = calls
            .iter()
            .position(|c| c.starts_with("at "))
            .expect("should call at for timer");
        let restore_idx = calls
            .iter()
            .position(|c| c.contains("iptables-restore"))
            .expect("should call iptables-restore");

        assert!(
            save_idx < at_idx,
            "iptables-save (idx {}) must come before at timer (idx {})",
            save_idx,
            at_idx
        );
        assert!(
            at_idx < restore_idx,
            "at timer (idx {}) must come before iptables-restore (idx {})",
            at_idx,
            restore_idx
        );
    }

    /// Verify that if the safety timer fails to schedule, iptables-restore
    /// is NOT called.
    #[tokio::test]
    async fn test_apply_aborts_if_timer_fails() {
        let iptables_output = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n";
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, iptables_output, ""),
            ("tee /var/lib/traffic-rules/backup.v4", 0, "", ""),
            ("ip6tables-save", 1, "", "not found"),
            ("which at", 0, "/usr/bin/at", ""),
            ("is-active", 0, "active", ""),
            ("at ", 1, "", "at: cannot open input: No such file or directory"),
            ("iptables-restore", 0, "", ""),
        ]);

        let proxy = &executor;

        // Step 1: backup
        let backup_result = create_pre_apply_backup(proxy, "test-host").await;
        assert!(backup_result.is_ok(), "backup should succeed");

        // Step 2: arm safety timer -- should fail
        let mechanism = crate::safety::timer::detect_mechanism(proxy).await;
        let job = crate::safety::timer::schedule_revert(
            proxy,
            mechanism,
            "/var/lib/traffic-rules/backup.v4",
            60,
        )
        .await;
        assert!(job.is_err(), "safety timer should fail");

        // Because the timer failed, we must NOT proceed to iptables-restore.
        let calls = executor.get_calls();
        assert!(
            !calls.iter().any(|c| c.contains("iptables-restore")),
            "iptables-restore must NOT be called when safety timer fails; calls: {:?}",
            calls
        );
    }

    /// Verify that when safety_timeout_secs is None, no `at` / `systemd-run` /
    /// `nohup` command is issued — only backup + restore.
    #[tokio::test]
    async fn test_apply_without_timeout_skips_timer() {
        let iptables_output = "*filter\n:TR-INPUT - [0:0]\n-A TR-INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n";
        let executor = MockExecutor::new(vec![
            ("iptables-save", 0, iptables_output, ""),
            ("tee /var/lib/traffic-rules/backup.v4", 0, "", ""),
            ("ip6tables-save", 1, "", "not found"),
            ("iptables-restore", 0, "", ""),
        ]);

        let proxy = &executor;

        // Step 1: backup
        let backup_result = create_pre_apply_backup(proxy, "test-host").await;
        assert!(backup_result.is_ok(), "backup should succeed");

        // Step 2: no safety timer — safety_timeout_secs is None, skip directly to apply
        // (mirrors the `rules_apply` code path when safety_timeout_secs is None)

        // Step 3: apply
        let restore_cmd = build_command(
            "sudo",
            &["iptables-restore", "-w", "5", "--noflush", "--counters"],
        );
        let apply_output = executor
            .exec_with_stdin(&restore_cmd, b"*filter\nCOMMIT\n")
            .await;
        assert!(apply_output.is_ok(), "apply should succeed");

        // Verify: no timer-related commands were issued
        let calls = executor.get_calls();
        assert!(
            !calls.iter().any(|c| c.contains("which at") || c.starts_with("at ")),
            "should NOT call `at` when no timeout; calls: {:?}",
            calls
        );
        assert!(
            !calls.iter().any(|c| c.contains("systemd-run")),
            "should NOT call `systemd-run` when no timeout; calls: {:?}",
            calls
        );
        assert!(
            !calls.iter().any(|c| c.contains("nohup")),
            "should NOT call `nohup` when no timeout; calls: {:?}",
            calls
        );

        // Verify the expected commands WERE called
        assert!(
            calls.iter().any(|c| c.contains("iptables-save")),
            "should call iptables-save for backup"
        );
        assert!(
            calls.iter().any(|c| c.contains("iptables-restore")),
            "should call iptables-restore to apply"
        );
    }
}
