use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::types::{ParsedRuleset, Target};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct IpsetSuggestion {
    pub chain: String,
    pub table: String,
    pub pattern_type: String,
    pub rule_count: usize,
    pub sample_ips: Vec<String>,
    pub suggested_name: String,
    pub estimated_improvement: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Analyze a parsed ruleset for ipset optimization opportunities.
///
/// Groups rules within each chain by a "pattern key" consisting of
/// (target, protocol, dest_port) — everything except the source IP.
/// When a group has `>= threshold` rules differing only in source IP,
/// it emits an [`IpsetSuggestion`].
pub fn analyze_ipset_opportunities(
    ruleset: &ParsedRuleset,
    threshold: usize,
) -> Vec<IpsetSuggestion> {
    let mut suggestions = Vec::new();

    for table in ruleset.tables.values() {
        for chain in table.chains.values() {
            // Group rules by pattern key (target, protocol, dest_port)
            let mut groups: HashMap<String, Vec<String>> = HashMap::new();

            for rule in &chain.rules {
                let spec = match &rule.parsed {
                    Some(s) => s,
                    None => continue,
                };

                // Only consider rules with a source IP defined
                let source_ip = match &spec.source {
                    Some(addr) if !addr.negated => addr.addr.clone(),
                    _ => continue,
                };

                // Only consider terminal targets (DROP/REJECT/ACCEPT)
                let target = match &spec.target {
                    Some(Target::Drop) | Some(Target::Reject) | Some(Target::Accept) => {
                        spec.target.as_ref().unwrap().to_string()
                    }
                    _ => continue,
                };

                // Build pattern key from (target, protocol, dest_port)
                let protocol = spec
                    .protocol
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                let dest_port = spec
                    .dest_port
                    .as_ref()
                    .map(|p| format!("{:?}", p))
                    .unwrap_or_default();

                let key = format!("{}|{}|{}", target, protocol, dest_port);
                groups.entry(key).or_default().push(source_ip);
            }

            // Check each group against threshold
            for (key, ips) in &groups {
                if ips.len() < threshold {
                    continue;
                }

                let parts: Vec<&str> = key.splitn(3, '|').collect();
                let target_str = parts.first().copied().unwrap_or("");

                let pattern_type = match target_str {
                    "DROP" | "REJECT" => "source-ip-block",
                    "ACCEPT" => "source-ip-allow",
                    _ => "source-ip-group",
                };

                let suggested_name = build_suggested_name(&chain.name);
                let sample_ips: Vec<String> = ips.iter().take(5).cloned().collect();

                suggestions.push(IpsetSuggestion {
                    chain: chain.name.clone(),
                    table: table.name.clone(),
                    pattern_type: pattern_type.to_string(),
                    rule_count: ips.len(),
                    sample_ips,
                    suggested_name,
                    estimated_improvement: format!(
                        "Replace {} linear rules with 1 ipset lookup (O(1) hash vs O(n) scan)",
                        ips.len()
                    ),
                });
            }
        }
    }

    suggestions
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build a suggested ipset name from a chain name, respecting the
/// 31-character limit imposed by the kernel ipset module.
fn build_suggested_name(chain: &str) -> String {
    let name = format!("TR-{}-blocklist", chain.to_lowercase());
    if name.len() > 31 {
        name[..31].to_string()
    } else {
        name
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iptables::parser::parse_iptables_save;

    /// Helper: build a ruleset from iptables-save text.
    fn make_ruleset(text: &str) -> ParsedRuleset {
        parse_iptables_save(text).unwrap()
    }

    /// Build an iptables-save string with `count` source-IP DROP rules.
    fn build_drop_rules(chain: &str, count: usize) -> String {
        let mut lines = String::new();
        lines.push_str("*filter\n");
        lines.push_str(&format!(":{} - [0:0]\n", chain));
        for i in 0..count {
            let a = (i / 256) % 256;
            let b = i % 256;
            lines.push_str(&format!(
                "-A {} -s 10.0.{}.{}/32 -j DROP\n",
                chain, a, b
            ));
        }
        lines.push_str("COMMIT\n");
        lines
    }

    /// Build an iptables-save string with `count` source-IP ACCEPT rules.
    fn build_accept_rules(chain: &str, count: usize) -> String {
        let mut lines = String::new();
        lines.push_str("*filter\n");
        lines.push_str(&format!(":{} - [0:0]\n", chain));
        for i in 0..count {
            let a = (i / 256) % 256;
            let b = i % 256;
            lines.push_str(&format!(
                "-A {} -s 10.0.{}.{}/32 -j ACCEPT\n",
                chain, a, b
            ));
        }
        lines.push_str("COMMIT\n");
        lines
    }

    #[test]
    fn test_suggest_when_many_source_drops() {
        let text = build_drop_rules("TR-INPUT", 60);
        let ruleset = make_ruleset(&text);
        let suggestions = analyze_ipset_opportunities(&ruleset, 50);
        assert_eq!(suggestions.len(), 1, "should return 1 suggestion");
        assert_eq!(suggestions[0].chain, "TR-INPUT");
        assert_eq!(suggestions[0].rule_count, 60);
        assert_eq!(suggestions[0].pattern_type, "source-ip-block");
        assert_eq!(suggestions[0].sample_ips.len(), 5);
        assert!(suggestions[0].suggested_name.starts_with("TR-"));
        assert!(suggestions[0].suggested_name.len() <= 31);
    }

    #[test]
    fn test_no_suggestion_below_threshold() {
        let text = build_drop_rules("TR-INPUT", 10);
        let ruleset = make_ruleset(&text);
        let suggestions = analyze_ipset_opportunities(&ruleset, 50);
        assert!(
            suggestions.is_empty(),
            "should not suggest for only 10 rules"
        );
    }

    #[test]
    fn test_suggest_multiple_patterns() {
        // Build a chain with 60 DROP rules and 60 ACCEPT rules
        let mut lines = String::from("*filter\n:TR-INPUT - [0:0]\n");
        for i in 0..60 {
            let a = (i / 256) % 256;
            let b = i % 256;
            lines.push_str(&format!("-A TR-INPUT -s 10.0.{}.{}/32 -j DROP\n", a, b));
        }
        for i in 0..60 {
            let a = (i / 256) % 256;
            let b = i % 256;
            lines.push_str(&format!(
                "-A TR-INPUT -s 192.168.{}.{}/32 -j ACCEPT\n",
                a, b
            ));
        }
        lines.push_str("COMMIT\n");

        let ruleset = make_ruleset(&lines);
        let mut suggestions = analyze_ipset_opportunities(&ruleset, 50);
        suggestions.sort_by(|a, b| a.pattern_type.cmp(&b.pattern_type));

        assert_eq!(suggestions.len(), 2, "should return 2 suggestions");
        assert!(suggestions.iter().any(|s| s.pattern_type == "source-ip-block"));
        assert!(suggestions.iter().any(|s| s.pattern_type == "source-ip-allow"));
    }

    #[test]
    fn test_ignores_rules_without_source() {
        // Build rules without source IP
        let text = "\
*filter
:TR-INPUT - [0:0]
-A TR-INPUT -p tcp --dport 80 -j ACCEPT
-A TR-INPUT -p tcp --dport 443 -j ACCEPT
-A TR-INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
";
        let ruleset = make_ruleset(text);
        let suggestions = analyze_ipset_opportunities(&ruleset, 1);
        assert!(
            suggestions.is_empty(),
            "should not suggest for rules without source IP"
        );
    }
}
