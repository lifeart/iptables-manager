use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::iptables::parser::parse_iptables_save;
use crate::iptables::types::*;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The result of comparing two rulesets.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct RulesetDiff {
    /// Individual change entries.
    pub changes: Vec<DiffEntry>,
    /// `true` when every change only affects TR-* chains (safe to apply with
    /// `--noflush`).
    pub app_chains_only: bool,
}

/// A single change between two rulesets.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DiffEntry {
    Added {
        chain: String,
        rule_raw: String,
        position: usize,
    },
    Removed {
        chain: String,
        rule_raw: String,
        position: usize,
    },
    Modified {
        chain: String,
        position: usize,
        old_raw: String,
        new_raw: String,
    },
    PolicyChanged {
        chain: String,
        old_policy: String,
        new_policy: String,
    },
    ChainAdded {
        name: String,
    },
    ChainRemoved {
        name: String,
    },
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute a diff between the *current* server state and the *desired* restore
/// file content.
///
/// Only app-managed chains (those starting with `TR-`) are compared.  System
/// chains, Docker chains, fail2ban chains, etc. are ignored.
pub fn compute_diff(current: &ParsedRuleset, desired_restore: &str) -> Result<RulesetDiff, ParseError> {
    // Parse the desired restore content to get its structure
    let desired = parse_iptables_save(desired_restore)?;

    let mut changes: Vec<DiffEntry> = Vec::new();
    let mut all_app_only = true;

    // Collect all TR-* chains from both sides, across all tables
    let current_chains = collect_tr_chains(current);
    let desired_chains = collect_tr_chains(&desired);

    let all_chain_keys: HashSet<&String> = current_chains
        .keys()
        .chain(desired_chains.keys())
        .collect();

    for chain_name in all_chain_keys {
        if !chain_name.starts_with("TR-") {
            all_app_only = false;
            continue;
        }

        let cur = current_chains.get(chain_name);
        let des = desired_chains.get(chain_name);

        match (cur, des) {
            (None, Some(desired_info)) => {
                // Chain added
                changes.push(DiffEntry::ChainAdded {
                    name: chain_name.clone(),
                });
                // All rules in the new chain are additions
                for (pos, rule_raw) in desired_info.rules.iter().enumerate() {
                    changes.push(DiffEntry::Added {
                        chain: chain_name.clone(),
                        rule_raw: rule_raw.clone(),
                        position: pos,
                    });
                }
            }
            (Some(_current_info), None) => {
                // Chain removed
                changes.push(DiffEntry::ChainRemoved {
                    name: chain_name.clone(),
                });
            }
            (Some(current_info), Some(desired_info)) => {
                // Compare policies
                if current_info.policy != desired_info.policy {
                    if let (Some(old_p), Some(new_p)) =
                        (&current_info.policy, &desired_info.policy)
                    {
                        changes.push(DiffEntry::PolicyChanged {
                            chain: chain_name.clone(),
                            old_policy: old_p.clone(),
                            new_policy: new_p.clone(),
                        });
                    }
                }

                // Compare rules position by position
                diff_rules(
                    chain_name,
                    &current_info.rules,
                    &desired_info.rules,
                    &mut changes,
                );
            }
            (None, None) => unreachable!(),
        }
    }

    Ok(RulesetDiff {
        changes,
        app_chains_only: all_app_only,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Simplified chain info for diff purposes.
struct ChainInfo {
    rules: Vec<String>,
    policy: Option<String>,
}

/// Collect all TR-* chains from a parsed ruleset, mapping chain name to its
/// rules (raw lines) and policy.
fn collect_tr_chains(ruleset: &ParsedRuleset) -> HashMap<String, ChainInfo> {
    let mut result: HashMap<String, ChainInfo> = HashMap::new();

    for table in ruleset.tables.values() {
        for (chain_name, chain_state) in &table.chains {
            if !chain_name.starts_with("TR-") {
                continue;
            }
            let rules: Vec<String> = chain_state
                .rules
                .iter()
                .map(|r| normalize_rule_raw(&r.raw, chain_name))
                .collect();

            result.insert(
                chain_name.clone(),
                ChainInfo {
                    rules,
                    policy: chain_state.policy.clone(),
                },
            );
        }
    }

    result
}

/// Normalize a raw rule line for comparison.
///
/// Strips the `-A CHAIN` prefix (and any counter prefix) so we compare only
/// the rule specification itself.  Also trims whitespace.
fn normalize_rule_raw(raw: &str, chain: &str) -> String {
    let trimmed = raw.trim();

    // Strip counter prefix [packets:bytes]
    let rest = if trimmed.starts_with('[') {
        if let Some(idx) = trimmed.find(']') {
            trimmed[idx + 1..].trim()
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    // Strip "-A CHAIN " prefix
    let prefix = format!("-A {} ", chain);
    if rest.starts_with(&prefix) {
        rest[prefix.len()..].to_string()
    } else {
        rest.to_string()
    }
}

/// Compare two ordered lists of rules (already normalized) and emit diff entries.
fn diff_rules(
    chain: &str,
    current: &[String],
    desired: &[String],
    changes: &mut Vec<DiffEntry>,
) {
    let max_len = std::cmp::max(current.len(), desired.len());

    for pos in 0..max_len {
        match (current.get(pos), desired.get(pos)) {
            (Some(cur), Some(des)) => {
                if cur != des {
                    changes.push(DiffEntry::Modified {
                        chain: chain.to_string(),
                        position: pos,
                        old_raw: cur.clone(),
                        new_raw: des.clone(),
                    });
                }
            }
            (None, Some(des)) => {
                changes.push(DiffEntry::Added {
                    chain: chain.to_string(),
                    rule_raw: des.clone(),
                    position: pos,
                });
            }
            (Some(cur), None) => {
                changes.push(DiffEntry::Removed {
                    chain: chain.to_string(),
                    rule_raw: cur.clone(),
                    position: pos,
                });
            }
            (None, None) => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_current_ruleset(rules_text: &str) -> ParsedRuleset {
        parse_iptables_save(rules_text).unwrap()
    }

    #[test]
    fn test_diff_no_changes() {
        let current_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
";
        let desired_text = current_text;
        let current = make_current_ruleset(current_text);
        let diff = compute_diff(&current, desired_text).unwrap();
        assert!(diff.changes.is_empty());
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
-A TR-INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
";
        let current = make_current_ruleset(current_text);
        let diff = compute_diff(&current, desired_text).unwrap();
        assert_eq!(diff.changes.len(), 1);
        match &diff.changes[0] {
            DiffEntry::Added { chain, position, .. } => {
                assert_eq!(chain, "TR-INPUT");
                assert_eq!(*position, 1);
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
COMMIT
";
        let desired_text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
";
        let current = make_current_ruleset(current_text);
        let diff = compute_diff(&current, desired_text).unwrap();
        assert_eq!(diff.changes.len(), 1);
        match &diff.changes[0] {
            DiffEntry::Removed { chain, position, .. } => {
                assert_eq!(chain, "TR-INPUT");
                assert_eq!(*position, 1);
            }
            other => panic!("expected Removed, got {:?}", other),
        }
    }

    #[test]
    fn test_diff_chain_added() {
        let current_text = "\
*filter
:TR-INPUT - [0:0]
COMMIT
";
        let desired_text = "\
*filter
:TR-INPUT - [0:0]
:TR-OUTPUT - [0:0]
-A TR-OUTPUT -p tcp --dport 443 -j ACCEPT
COMMIT
";
        let current = make_current_ruleset(current_text);
        let diff = compute_diff(&current, desired_text).unwrap();
        let has_chain_added = diff.changes.iter().any(|c| matches!(c, DiffEntry::ChainAdded { name } if name == "TR-OUTPUT"));
        assert!(has_chain_added);
    }

    #[test]
    fn test_diff_chain_removed() {
        let current_text = "\
*filter
:TR-INPUT - [0:0]
:TR-OUTPUT - [0:0]
-A TR-OUTPUT -p tcp --dport 443 -j ACCEPT
COMMIT
";
        let desired_text = "\
*filter
:TR-INPUT - [0:0]
COMMIT
";
        let current = make_current_ruleset(current_text);
        let diff = compute_diff(&current, desired_text).unwrap();
        let has_chain_removed = diff.changes.iter().any(|c| matches!(c, DiffEntry::ChainRemoved { name } if name == "TR-OUTPUT"));
        assert!(has_chain_removed);
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
        let current = make_current_ruleset(current_text);
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
    fn test_diff_ignores_system_chains() {
        let current_text = "\
*filter
:INPUT ACCEPT [0:0]
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
        let current = make_current_ruleset(current_text);
        let diff = compute_diff(&current, desired_text).unwrap();
        // INPUT chain differences should not appear
        assert!(diff.changes.is_empty());
    }
}
