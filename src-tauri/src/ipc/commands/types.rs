use serde::{Deserialize, Serialize};
use ts_rs::TS;

// ---------------------------------------------------------------------------
// Serializable response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct ConnectionResult {
    pub host_id: String,
    pub status: String,
    #[ts(type = "number")]
    pub latency_ms: u64,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct TestConnectionResult {
    pub success: bool,
    #[ts(type = "number")]
    pub latency_ms: u64,
    pub iptables_available: bool,
    pub root_access: bool,
    pub docker_detected: bool,
    pub fail2ban_detected: bool,
    pub nftables_backend: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct DetectionResult {
    pub completed: bool,
    #[ts(type = "Record<string, unknown> | null")]
    pub capabilities: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct ProvisionResult {
    pub success: bool,
    pub dirs_created: Vec<String>,
    pub revert_script_installed: bool,
    pub sudo_verified: bool,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct RuleSetResult {
    #[ts(type = "unknown")]
    pub rules: serde_json::Value,
    pub default_policy: String,
    pub raw_iptables_save: String,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct ApplyResult {
    pub success: bool,
    pub safety_timer_active: bool,
    #[ts(type = "number | null")]
    pub safety_timer_expiry: Option<u64>,
    pub remote_job_id: Option<String>,
    pub safety_timer_mechanism: Option<String>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct ActivityData {
    pub hit_counters: Vec<crate::activity::monitor::HitCounter>,
    #[ts(type = "number")]
    pub conntrack_current: u64,
    #[ts(type = "number")]
    pub conntrack_max: u64,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct SafetyTimerResult {
    pub job_id: String,
    pub mechanism: String,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct PreviewResult {
    pub restore_content: String,
    pub restore_command: String,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct CompareHostsResult {
    pub only_in_a: Vec<String>,
    pub only_in_b: Vec<String>,
    pub different: Vec<String>,
    pub identical: usize,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct ImportExistingRulesResult {
    #[ts(type = "unknown")]
    pub rules: serde_json::Value,
    pub raw_iptables_save: String,
    pub non_tr_rule_count: usize,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct DriftCheckResult {
    pub drifted: bool,
    pub added_rules: usize,
    pub removed_rules: usize,
    pub modified_rules: usize,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct TestConnectionParams {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String,
    pub key_path: Option<String>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct DuplicateCheckResult {
    pub is_duplicate: bool,
    pub existing_rule_id: Option<String>,
    pub similarity: f64,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct HostApplyResult {
    pub host_id: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct GroupApplyResult {
    pub results: Vec<HostApplyResult>,
    pub strategy: String,
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
}
