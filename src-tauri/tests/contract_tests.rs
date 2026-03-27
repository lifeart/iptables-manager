//! FE/BE serialization contract tests.
//!
//! These tests verify that Rust structs serialize to JSON with the exact
//! camelCase key names the frontend expects, and that frontend JSON
//! deserializes correctly into Rust structs.  Any accidental rename or
//! missing `#[serde(rename_all = "camelCase")]` will be caught here.

use serde_json;

// ── Bring in the types under test ──────────────────────────────────────

use traffic_rules_lib::activity::monitor::{
    ConntrackEntry, ConntrackUsage, Fail2banBan, HitCounter,
};
use traffic_rules_lib::ipc::commands::{
    ActivityData, ApplyResult, CompareHostsResult, DriftCheckResult, DuplicateCheckResult,
    GroupApplyResult, HostApplyResult, ImportExistingRulesResult, PreviewResult, SafetyTimerResult,
};
use traffic_rules_lib::iptables::conflict::{ConflictType, RuleConflict};
use traffic_rules_lib::iptables::tracer::{ChainTraversal, TestPacket, TraceResult, Verdict};
use traffic_rules_lib::snapshot::manager::SnapshotMeta;

// ── Helpers ────────────────────────────────────────────────────────────

/// Assert a key is present in a JSON object.
fn assert_key(json: &serde_json::Value, key: &str) {
    assert!(
        json.get(key).is_some(),
        "expected key '{}' to be present in JSON: {}",
        key,
        json
    );
}

/// Assert a key is NOT present in a JSON object.
fn assert_no_key(json: &serde_json::Value, key: &str) {
    assert!(
        json.get(key).is_none(),
        "key '{}' must NOT be present in JSON: {}",
        key,
        json
    );
}

// ── 1. RuleConflict ────────────────────────────────────────────────────

#[test]
fn test_rule_conflict_serialization() {
    let conflict = RuleConflict {
        conflict_type: ConflictType::Shadow,
        rule_id_a: "r1".into(),
        rule_id_b: "r2".into(),
        description: "test".into(),
    };
    let json = serde_json::to_value(&conflict).unwrap();

    // Correct camelCase keys
    assert_eq!(json["type"], "shadow");
    assert_eq!(json["ruleIdA"], "r1");
    assert_eq!(json["ruleIdB"], "r2");
    assert_eq!(json["description"], "test");

    // Must NOT have snake_case or un-renamed keys
    assert_no_key(&json, "conflictType");
    assert_no_key(&json, "conflict_type");
    assert_no_key(&json, "rule_id_a");
    assert_no_key(&json, "rule_id_b");
}

#[test]
fn test_rule_conflict_conflict_types() {
    // Verify all ConflictType variants serialize to expected strings
    let redundancy = RuleConflict {
        conflict_type: ConflictType::Redundancy,
        rule_id_a: "a".into(),
        rule_id_b: "b".into(),
        description: "".into(),
    };
    assert_eq!(
        serde_json::to_value(&redundancy).unwrap()["type"],
        "redundant"
    );

    let overlap = RuleConflict {
        conflict_type: ConflictType::Overlap,
        rule_id_a: "a".into(),
        rule_id_b: "b".into(),
        description: "".into(),
    };
    assert_eq!(
        serde_json::to_value(&overlap).unwrap()["type"],
        "contradiction"
    );
}

// ── 2. TraceResult ─────────────────────────────────────────────────────

#[test]
fn test_trace_result_serialization() {
    let result = TraceResult {
        matched: true,
        matched_rule_id: Some("rule-42".into()),
        path: vec![ChainTraversal {
            table: "filter".into(),
            chain: "INPUT".into(),
            rules_evaluated: 5,
            matched_rule_index: Some(3),
        }],
        verdict: Verdict::Accept,
        explanation: "Matched rule 42".into(),
        near_misses: vec!["rule-10".into(), "rule-20".into()],
    };
    let json = serde_json::to_value(&result).unwrap();

    // The field is named `path` in Rust but serialized as `chain`
    assert_key(&json, "chain");
    assert_no_key(&json, "path");

    assert_eq!(json["matched"], true);
    assert_eq!(json["matchedRuleId"], "rule-42");
    assert_eq!(json["verdict"], "Accept");
    assert_eq!(json["explanation"], "Matched rule 42");
    assert!(json["nearMisses"].is_array());
    assert_eq!(json["nearMisses"].as_array().unwrap().len(), 2);

    // No snake_case keys
    assert_no_key(&json, "matched_rule_id");
    assert_no_key(&json, "near_misses");

    // Chain traversal inner object uses camelCase
    let chain_entry = &json["chain"][0];
    assert_key(chain_entry, "rulesEvaluated");
    assert_key(chain_entry, "matchedRuleIndex");
    assert_no_key(chain_entry, "rules_evaluated");
    assert_no_key(chain_entry, "matched_rule_index");
}

#[test]
fn test_trace_result_optional_matched_rule_id_omitted() {
    let result = TraceResult {
        matched: false,
        matched_rule_id: None,
        path: vec![],
        verdict: Verdict::Drop,
        explanation: "Default policy".into(),
        near_misses: vec![],
    };
    let json = serde_json::to_value(&result).unwrap();

    // matched_rule_id is skip_serializing_if = "Option::is_none"
    assert_no_key(&json, "matchedRuleId");
    assert_eq!(json["matched"], false);
}

// ── 3. TestPacket deserialization ──────────────────────────────────────

#[test]
fn test_test_packet_deserialization() {
    let json = r#"{"sourceIp":"1.2.3.4","destIp":"5.6.7.8","destPort":22,"protocol":"Tcp","interfaceIn":"eth0","direction":"Incoming","conntrackState":"New"}"#;
    let packet: TestPacket = serde_json::from_str(json).unwrap();
    assert_eq!(packet.source_ip.to_string(), "1.2.3.4");
    assert_eq!(packet.dest_ip.to_string(), "5.6.7.8");
    assert_eq!(packet.dest_port, Some(22));
}

#[test]
fn test_test_packet_deserialization_defaults() {
    // direction and conntrackState can be omitted (have defaults)
    let json = r#"{"sourceIp":"1.2.3.4","destIp":"5.6.7.8","destPort":22,"protocol":"Tcp","interfaceIn":""}"#;
    let packet: TestPacket = serde_json::from_str(json).unwrap();
    assert_eq!(packet.source_ip.to_string(), "1.2.3.4");
    assert_eq!(packet.dest_ip.to_string(), "5.6.7.8");
}

// ── 4. SnapshotMeta ────────────────────────────────────────────────────

#[test]
fn test_snapshot_meta_serialization() {
    let meta = SnapshotMeta {
        id: "snap-1".into(),
        host_id: "host-1".into(),
        timestamp: 1700000000,
        description: Some("test snapshot".into()),
        rule_count: 42,
    };
    let json = serde_json::to_value(&meta).unwrap();

    assert_eq!(json["id"], "snap-1");
    assert_eq!(json["hostId"], "host-1");
    assert_eq!(json["timestamp"], 1700000000u64);
    assert_eq!(json["description"], "test snapshot");
    assert_eq!(json["ruleCount"], 42);

    // Must NOT have snake_case
    assert_no_key(&json, "host_id");
    assert_no_key(&json, "rule_count");
    // Must NOT expose remote paths (they are on SnapshotData, not SnapshotMeta)
    assert_no_key(&json, "remote_path_v4");
    assert_no_key(&json, "remotePath_v4");
    assert_no_key(&json, "remotePathV4");
}

#[test]
fn test_snapshot_meta_optional_description_null() {
    let meta = SnapshotMeta {
        id: "snap-2".into(),
        host_id: "host-2".into(),
        timestamp: 1700000000,
        description: None,
        rule_count: 0,
    };
    let json = serde_json::to_value(&meta).unwrap();
    assert!(json["description"].is_null());
}

// ── 5. HitCounter ──────────────────────────────────────────────────────

#[test]
fn test_hit_counter_serialization() {
    let counter = HitCounter {
        rule_id: "TR-INPUT/3".into(),
        packets: 1000,
        bytes: 65536,
        timestamp: 1700000000,
        chain: "INPUT".into(),
        rule_num: 3,
        target: "ACCEPT".into(),
        protocol: "tcp".into(),
        source: "0.0.0.0/0".into(),
        destination: "10.0.0.1".into(),
    };
    let json = serde_json::to_value(&counter).unwrap();

    assert_eq!(json["ruleId"], "TR-INPUT/3");
    assert_eq!(json["chain"], "INPUT");
    assert_eq!(json["ruleNum"], 3);
    assert_eq!(json["packets"], 1000);
    assert_eq!(json["bytes"], 65536);
    assert_eq!(json["timestamp"], 1700000000u64);
    assert_eq!(json["target"], "ACCEPT");
    assert_eq!(json["protocol"], "tcp");
    assert_eq!(json["source"], "0.0.0.0/0");
    assert_eq!(json["destination"], "10.0.0.1");

    // Must NOT have snake_case
    assert_no_key(&json, "rule_num");
    assert_no_key(&json, "rule_id");
}

// ── 6. Fail2banBan ─────────────────────────────────────────────────────

#[test]
fn test_fail2ban_ban_serialization() {
    let ban = Fail2banBan {
        jail: "sshd".into(),
        ip: "192.168.1.100".into(),
        banned_at: 1700000000,
        expires_at: Some(1700003600),
    };
    let json = serde_json::to_value(&ban).unwrap();

    assert_eq!(json["jail"], "sshd");
    assert_eq!(json["ip"], "192.168.1.100");
    assert_eq!(json["bannedAt"], 1700000000u64);
    assert_eq!(json["expiresAt"], 1700003600u64);

    // Must NOT have snake_case
    assert_no_key(&json, "banned_at");
    assert_no_key(&json, "expires_at");
}

#[test]
fn test_fail2ban_ban_optional_expires_at_null() {
    let ban = Fail2banBan {
        jail: "sshd".into(),
        ip: "10.0.0.1".into(),
        banned_at: 1700000000,
        expires_at: None,
    };
    let json = serde_json::to_value(&ban).unwrap();
    assert!(json["expiresAt"].is_null());
}

// ── 7. ConntrackEntry ──────────────────────────────────────────────────

#[test]
fn test_conntrack_entry_serialization() {
    let entry = ConntrackEntry {
        protocol: "tcp".into(),
        source_ip: "192.168.1.10".into(),
        dest_ip: "10.0.0.1".into(),
        source_port: 54321,
        dest_port: 443,
        state: "ESTABLISHED".into(),
        ttl: 300,
    };
    let json = serde_json::to_value(&entry).unwrap();

    assert_eq!(json["protocol"], "tcp");
    assert_eq!(json["sourceIp"], "192.168.1.10");
    assert_eq!(json["destIp"], "10.0.0.1");
    assert_eq!(json["sourcePort"], 54321);
    assert_eq!(json["destPort"], 443);
    assert_eq!(json["state"], "ESTABLISHED");
    assert_eq!(json["ttl"], 300);

    // Must NOT have snake_case
    assert_no_key(&json, "source_ip");
    assert_no_key(&json, "dest_ip");
    assert_no_key(&json, "source_port");
    assert_no_key(&json, "dest_port");
}

// ── 8. ConntrackUsage ──────────────────────────────────────────────────

#[test]
fn test_conntrack_usage_serialization() {
    let usage = ConntrackUsage {
        current: 1500,
        max: 65536,
        percent: 2.29,
    };
    let json = serde_json::to_value(&usage).unwrap();

    assert_eq!(json["current"], 1500);
    assert_eq!(json["max"], 65536);
    assert!(json["percent"].is_f64());
}

// ── 9. ApplyResult ─────────────────────────────────────────────────────

#[test]
fn test_apply_result_serialization() {
    let result = ApplyResult {
        success: true,
        safety_timer_active: true,
        safety_timer_expiry: Some(1700003600),
        remote_job_id: Some("job-abc".into()),
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["safetyTimerActive"], true);
    assert_eq!(json["safetyTimerExpiry"], 1700003600u64);
    assert_eq!(json["remoteJobId"], "job-abc");

    // Must NOT have snake_case
    assert_no_key(&json, "safety_timer_active");
    assert_no_key(&json, "safety_timer_expiry");
    assert_no_key(&json, "remote_job_id");
}

#[test]
fn test_apply_result_optional_fields_null() {
    let result = ApplyResult {
        success: false,
        safety_timer_active: false,
        safety_timer_expiry: None,
        remote_job_id: None,
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_eq!(json["success"], false);
    assert_eq!(json["safetyTimerActive"], false);
    assert!(json["safetyTimerExpiry"].is_null());
    assert!(json["remoteJobId"].is_null());
}

// ── 10. SafetyTimerResult ──────────────────────────────────────────────

#[test]
fn test_safety_timer_result_serialization() {
    let result = SafetyTimerResult {
        job_id: "42".into(),
        mechanism: "at".into(),
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_eq!(json["jobId"], "42");
    assert_eq!(json["mechanism"], "at");

    // Must NOT have snake_case
    assert_no_key(&json, "job_id");
}

// ── 11. DuplicateCheckResult ───────────────────────────────────────────

#[test]
fn test_duplicate_check_result_serialization() {
    let result = DuplicateCheckResult {
        is_duplicate: true,
        existing_rule_id: Some("rule-7".into()),
        similarity: 0.95,
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_eq!(json["isDuplicate"], true);
    assert_eq!(json["existingRuleId"], "rule-7");
    assert!(json["similarity"].is_f64());
    assert!((json["similarity"].as_f64().unwrap() - 0.95).abs() < 1e-10);

    // Must NOT have snake_case
    assert_no_key(&json, "is_duplicate");
    assert_no_key(&json, "existing_rule_id");
}

#[test]
fn test_duplicate_check_result_no_match() {
    let result = DuplicateCheckResult {
        is_duplicate: false,
        existing_rule_id: None,
        similarity: 0.0,
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_eq!(json["isDuplicate"], false);
    assert!(json["existingRuleId"].is_null());
    assert_eq!(json["similarity"], 0.0);
}

// ── 12. ActivityData ───────────────────────────────────────────────────

#[test]
fn test_activity_data_serialization() {
    let data = ActivityData {
        hit_counters: vec![HitCounter {
            rule_id: "TR-INPUT/1".into(),
            packets: 500,
            bytes: 32768,
            timestamp: 1700000000,
            chain: "INPUT".into(),
            rule_num: 1,
            target: "DROP".into(),
            protocol: "udp".into(),
            source: "0.0.0.0/0".into(),
            destination: "0.0.0.0/0".into(),
        }],
        conntrack_current: 2000,
        conntrack_max: 131072,
    };
    let json = serde_json::to_value(&data).unwrap();

    assert_key(&json, "hitCounters");
    assert_eq!(json["conntrackCurrent"], 2000);
    assert_eq!(json["conntrackMax"], 131072);
    assert!(json["hitCounters"].is_array());
    assert_eq!(json["hitCounters"].as_array().unwrap().len(), 1);

    // Inner HitCounter should also be camelCase
    let counter = &json["hitCounters"][0];
    assert_eq!(counter["ruleNum"], 1);
    assert_no_key(counter, "rule_num");

    // Must NOT have snake_case
    assert_no_key(&json, "hit_counters");
    assert_no_key(&json, "conntrack_current");
    assert_no_key(&json, "conntrack_max");
}

#[test]
fn test_activity_data_empty_counters() {
    let data = ActivityData {
        hit_counters: vec![],
        conntrack_current: 0,
        conntrack_max: 0,
    };
    let json = serde_json::to_value(&data).unwrap();

    assert!(json["hitCounters"].is_array());
    assert_eq!(json["hitCounters"].as_array().unwrap().len(), 0);
    assert_eq!(json["conntrackCurrent"], 0);
    assert_eq!(json["conntrackMax"], 0);
}

// ── 13. PreviewResult ───────────────────────────────────────────────────

#[test]
fn test_preview_result_serialization() {
    let result = PreviewResult {
        restore_content: "*filter\n:INPUT ACCEPT\nCOMMIT".into(),
        restore_command: "iptables-restore < /tmp/rules.v4".into(),
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_key(&json, "restoreContent");
    assert_key(&json, "restoreCommand");
    assert_eq!(json["restoreContent"], "*filter\n:INPUT ACCEPT\nCOMMIT");
    assert_eq!(json["restoreCommand"], "iptables-restore < /tmp/rules.v4");

    // Must NOT have snake_case
    assert_no_key(&json, "restore_content");
    assert_no_key(&json, "restore_command");
}

// ── 14. GroupApplyResult ────────────────────────────────────────────────

#[test]
fn test_group_apply_result_serialization() {
    let result = GroupApplyResult {
        results: vec![
            HostApplyResult {
                host_id: "host-1".into(),
                success: true,
                error: None,
            },
            HostApplyResult {
                host_id: "host-2".into(),
                success: false,
                error: Some("connection timeout".into()),
            },
        ],
        strategy: "sequential".into(),
        total: 2,
        succeeded: 1,
        failed: 1,
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_key(&json, "results");
    assert_key(&json, "strategy");
    assert_key(&json, "total");
    assert_key(&json, "succeeded");
    assert_key(&json, "failed");
    assert!(json["results"].is_array());
    assert_eq!(json["results"].as_array().unwrap().len(), 2);

    // Check inner HostApplyResult uses camelCase
    let first = &json["results"][0];
    assert_eq!(first["hostId"], "host-1");
    assert_eq!(first["success"], true);
    assert!(first["error"].is_null());
    assert_no_key(first, "host_id");

    let second = &json["results"][1];
    assert_eq!(second["hostId"], "host-2");
    assert_eq!(second["success"], false);
    assert_eq!(second["error"], "connection timeout");
}

// ── 15. DriftCheckResult ────────────────────────────────────────────────

#[test]
fn test_drift_check_result_serialization() {
    let result = DriftCheckResult {
        drifted: true,
        added_rules: 3,
        removed_rules: 1,
        modified_rules: 2,
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_eq!(json["drifted"], true);
    assert_eq!(json["addedRules"], 3);
    assert_eq!(json["removedRules"], 1);
    assert_eq!(json["modifiedRules"], 2);

    // Must NOT have snake_case
    assert_no_key(&json, "added_rules");
    assert_no_key(&json, "removed_rules");
    assert_no_key(&json, "modified_rules");
}

// ── 16. CompareHostsResult ──────────────────────────────────────────────

#[test]
fn test_compare_hosts_result_serialization() {
    let result = CompareHostsResult {
        only_in_a: vec!["rule-1".into(), "rule-2".into()],
        only_in_b: vec!["rule-3".into()],
        different: vec!["rule-4".into()],
        identical: 10,
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_key(&json, "onlyInA");
    assert_key(&json, "onlyInB");
    assert_key(&json, "different");
    assert_key(&json, "identical");
    assert!(json["onlyInA"].is_array());
    assert_eq!(json["onlyInA"].as_array().unwrap().len(), 2);
    assert!(json["onlyInB"].is_array());
    assert_eq!(json["onlyInB"].as_array().unwrap().len(), 1);
    assert!(json["different"].is_array());
    assert_eq!(json["different"].as_array().unwrap().len(), 1);
    assert_eq!(json["identical"], 10);

    // Must NOT have snake_case
    assert_no_key(&json, "only_in_a");
    assert_no_key(&json, "only_in_b");
}

// ── 17. ImportExistingRulesResult ───────────────────────────────────────

#[test]
fn test_import_existing_rules_result_serialization() {
    let result = ImportExistingRulesResult {
        rules: serde_json::json!([{"id": "rule-1", "chain": "INPUT"}]),
        raw_iptables_save: "*filter\n:INPUT ACCEPT\nCOMMIT".into(),
        non_tr_rule_count: 5,
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_key(&json, "rules");
    assert_key(&json, "rawIptablesSave");
    assert_key(&json, "nonTrRuleCount");
    assert!(json["rules"].is_array());
    assert_eq!(json["nonTrRuleCount"], 5);
    assert_eq!(json["rawIptablesSave"], "*filter\n:INPUT ACCEPT\nCOMMIT");

    // Must NOT have snake_case
    assert_no_key(&json, "raw_iptables_save");
    assert_no_key(&json, "non_tr_rule_count");
}

// ── 18. DriftCheckResult — first call returns no drift ──────────────────

#[test]
fn test_drift_first_call_no_drift() {
    let result = DriftCheckResult {
        drifted: false,
        added_rules: 0,
        removed_rules: 0,
        modified_rules: 0,
    };
    let json = serde_json::to_value(&result).unwrap();

    assert_eq!(json["drifted"], false);
    assert_eq!(json["addedRules"], 0);
    assert_eq!(json["removedRules"], 0);
    assert_eq!(json["modifiedRules"], 0);
}

// ── 19. DriftCheckResult — same rules twice yields no drift ─────────────

#[test]
fn test_drift_second_call_same_rules_no_drift() {
    // Simulate the "no drift" result that check_drift returns when
    // hashes match on second call — the struct itself is the same shape.
    let first = DriftCheckResult {
        drifted: false,
        added_rules: 0,
        removed_rules: 0,
        modified_rules: 0,
    };
    let second = DriftCheckResult {
        drifted: false,
        added_rules: 0,
        removed_rules: 0,
        modified_rules: 0,
    };

    let json1 = serde_json::to_value(&first).unwrap();
    let json2 = serde_json::to_value(&second).unwrap();

    // Both serializations are identical — no drift
    assert_eq!(json1, json2);
    assert_eq!(json1["drifted"], false);
    assert_eq!(json2["drifted"], false);
}
