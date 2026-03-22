use traffic_rules_lib::iptables::diff::*;
use traffic_rules_lib::iptables::parser::parse_iptables_save;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_current(text: &str) -> traffic_rules_lib::iptables::types::ParsedRuleset {
    parse_iptables_save(text).unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_diff_identical_rulesets() {
    let text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
-A TR-INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
";
    let current = make_current(text);
    let diff = compute_diff(&current, text).unwrap();
    assert!(diff.changes.is_empty(), "identical rulesets should have no diff");
    assert!(diff.app_chains_only);
}

#[test]
fn test_diff_added_rule() {
    let current_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
";
    let desired_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
-A TR-INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
";
    let current = make_current(current_text);
    let diff = compute_diff(&current, desired_text).unwrap();
    assert_eq!(diff.changes.len(), 1);
    match &diff.changes[0] {
        DiffEntry::Added { chain, rule_raw, position } => {
            assert_eq!(chain, "TR-INPUT");
            assert_eq!(*position, 1);
            assert!(rule_raw.contains("443"));
        }
        other => panic!("expected Added, got {:?}", other),
    }
}

#[test]
fn test_diff_removed_rule() {
    let current_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
-A TR-INPUT -p tcp --dport 80 -j ACCEPT
-A TR-INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
";
    let desired_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
-A TR-INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
";
    let current = make_current(current_text);
    let diff = compute_diff(&current, desired_text).unwrap();
    assert_eq!(diff.changes.len(), 1);
    match &diff.changes[0] {
        DiffEntry::Removed { chain, position, .. } => {
            assert_eq!(chain, "TR-INPUT");
            assert_eq!(*position, 2);
        }
        other => panic!("expected Removed, got {:?}", other),
    }
}

#[test]
fn test_diff_modified_rule() {
    let current_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
";
    let desired_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j DROP
COMMIT
";
    let current = make_current(current_text);
    let diff = compute_diff(&current, desired_text).unwrap();
    assert_eq!(diff.changes.len(), 1);
    match &diff.changes[0] {
        DiffEntry::Modified { chain, position, old_raw, new_raw } => {
            assert_eq!(chain, "TR-INPUT");
            assert_eq!(*position, 0);
            assert!(old_raw.contains("ACCEPT"));
            assert!(new_raw.contains("DROP"));
        }
        other => panic!("expected Modified, got {:?}", other),
    }
}

#[test]
fn test_diff_chain_added() {
    let current_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
";
    let desired_text = "\
*filter
:TR-INPUT - [0:0]
:TR-OUTPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
-A TR-OUTPUT -j ACCEPT
COMMIT
";
    let current = make_current(current_text);
    let diff = compute_diff(&current, desired_text).unwrap();

    let chain_added = diff.changes.iter().any(|c| {
        matches!(c, DiffEntry::ChainAdded { name } if name == "TR-OUTPUT")
    });
    assert!(chain_added, "should detect TR-OUTPUT added");
}

#[test]
fn test_diff_chain_removed() {
    let current_text = "\
*filter
:TR-INPUT - [0:0]
:TR-OUTPUT - [0:0]
-A TR-INPUT -j ACCEPT
-A TR-OUTPUT -j ACCEPT
COMMIT
";
    let desired_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -j ACCEPT
COMMIT
";
    let current = make_current(current_text);
    let diff = compute_diff(&current, desired_text).unwrap();

    let chain_removed = diff.changes.iter().any(|c| {
        matches!(c, DiffEntry::ChainRemoved { name } if name == "TR-OUTPUT")
    });
    assert!(chain_removed, "should detect TR-OUTPUT removed");
}

#[test]
fn test_diff_ignores_non_tr_chains() {
    let current_text = "\
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:TR-INPUT - [0:0]
-A INPUT -j TR-INPUT
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
";
    let desired_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
";
    let current = make_current(current_text);
    let diff = compute_diff(&current, desired_text).unwrap();
    // Should NOT flag INPUT/FORWARD/OUTPUT differences
    for change in &diff.changes {
        match change {
            DiffEntry::ChainAdded { name } | DiffEntry::ChainRemoved { name } => {
                assert!(name.starts_with("TR-"), "should not diff non-TR chain: {}", name);
            }
            _ => {}
        }
    }
}

#[test]
fn test_diff_multiple_changes() {
    let current_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
-A TR-INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
";
    let desired_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j DROP
-A TR-INPUT -p tcp --dport 80 -j ACCEPT
-A TR-INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
";
    let current = make_current(current_text);
    let diff = compute_diff(&current, desired_text).unwrap();
    // Position 0: ACCEPT -> DROP (Modified)
    // Position 2: new rule (Added)
    assert_eq!(diff.changes.len(), 2, "changes: {:?}", diff.changes);
}

#[test]
fn test_diff_app_chains_only_flag() {
    let current_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -j ACCEPT
COMMIT
";
    let desired_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -j DROP
COMMIT
";
    let current = make_current(current_text);
    let diff = compute_diff(&current, desired_text).unwrap();
    assert!(diff.app_chains_only);
}
