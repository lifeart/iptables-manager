use std::collections::HashMap;

use serde::Serialize;
use ts_rs::TS;

use crate::iptables::types::*;

// ---------------------------------------------------------------------------
// Coexistence profile types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct CoexistenceProfile {
    pub owners: Vec<ChainOwnerGroup>,
    pub total_chains: usize,
    pub app_managed_chains: usize,
    pub external_chains: usize,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct ChainOwnerGroup {
    pub owner: String,
    pub chains: Vec<String>,
    pub rule_count: usize,
    pub is_app_managed: bool,
}

/// Build a coexistence profile from a parsed ruleset.
///
/// Groups chains by detected owner and counts rules per group.
pub fn build_coexistence_profile(ruleset: &ParsedRuleset) -> CoexistenceProfile {
    let mut groups: HashMap<String, (Vec<String>, usize, bool)> = HashMap::new();
    let mut total_chains = 0usize;

    for table in ruleset.tables.values() {
        for (chain_name, chain_state) in &table.chains {
            total_chains += 1;
            let (owner_label, is_app) = match &chain_state.owner {
                ChainOwner::System(tool) => {
                    let label = match tool {
                        SystemTool::Docker => "Docker",
                        SystemTool::Fail2ban => "fail2ban",
                        SystemTool::Kubernetes => "Kubernetes",
                        SystemTool::Csf => "CSF",
                        SystemTool::WgQuick => "WireGuard",
                        SystemTool::Ufw => "UFW",
                        SystemTool::Firewalld => "firewalld",
                    };
                    (label.to_string(), false)
                }
                ChainOwner::App => ("App".to_string(), true),
                ChainOwner::BuiltIn => ("Built-in".to_string(), false),
                ChainOwner::Unknown => ("Unknown".to_string(), false),
            };

            let entry = groups.entry(owner_label).or_insert_with(|| (Vec::new(), 0, is_app));
            entry.0.push(chain_name.clone());
            entry.1 += chain_state.rules.len();
        }
    }

    let mut app_managed_chains = 0usize;
    let mut external_chains = 0usize;
    let mut owners: Vec<ChainOwnerGroup> = Vec::new();

    for (owner, (mut chains, rule_count, is_app)) in groups {
        chains.sort();
        let chain_count = chains.len();
        if is_app {
            app_managed_chains += chain_count;
        } else if owner != "Built-in" && owner != "Unknown" {
            external_chains += chain_count;
        }
        owners.push(ChainOwnerGroup {
            owner,
            chains,
            rule_count,
            is_app_managed: is_app,
        });
    }

    // Sort groups: App first, then external tools alphabetically, then Built-in/Unknown last
    owners.sort_by(|a, b| {
        fn sort_key(g: &ChainOwnerGroup) -> (u8, &str) {
            if g.is_app_managed {
                (0, &g.owner)
            } else if g.owner == "Built-in" {
                (2, &g.owner)
            } else if g.owner == "Unknown" {
                (3, &g.owner)
            } else {
                (1, &g.owner)
            }
        }
        sort_key(a).cmp(&sort_key(b))
    });

    CoexistenceProfile {
        owners,
        total_chains,
        app_managed_chains,
        external_chains,
    }
}

/// Detect who owns a chain based on its name and rule content.
///
/// The detection order matters: name-based checks are tried first (cheap),
/// then content-based heuristics for chains that can't be identified by name
/// alone (e.g. wg-quick modifies INPUT/FORWARD directly).
pub fn detect_chain_owner(chain_name: &str, rules: &[ParsedRule]) -> ChainOwner {
    // Built-in chains (INPUT, FORWARD, OUTPUT, PREROUTING, POSTROUTING)
    let is_builtin = matches!(chain_name,
        "INPUT" | "FORWARD" | "OUTPUT" | "PREROUTING" | "POSTROUTING"
    );

    // Name-based detection first
    match chain_name {
        // Docker
        "DOCKER" | "DOCKER-USER" | "DOCKER-ISOLATION-STAGE-1" | "DOCKER-ISOLATION-STAGE-2" => {
            return ChainOwner::System(SystemTool::Docker);
        }
        s if s.starts_with("DOCKER") => {
            return ChainOwner::System(SystemTool::Docker);
        }

        // fail2ban
        s if s.starts_with("f2b-") => {
            return ChainOwner::System(SystemTool::Fail2ban);
        }

        // Kubernetes / Calico
        s if s.starts_with("KUBE-") || s.starts_with("cali-") => {
            return ChainOwner::System(SystemTool::Kubernetes);
        }

        // CSF (ConfigServer Security & Firewall)
        "LOCALINPUT" | "LOCALOUTPUT" | "LOGDROPIN" | "LOGDROPOUT"
        | "DENYIN" | "DENYOUT" | "ALLOWIN" | "ALLOWOUT" => {
            return ChainOwner::System(SystemTool::Csf);
        }
        s if s.starts_with("acl_") => {
            return ChainOwner::System(SystemTool::Csf);
        }

        // UFW
        s if s.starts_with("ufw-") || s.starts_with("ufw6-") => {
            return ChainOwner::System(SystemTool::Ufw);
        }

        // Firewalld
        s if s.starts_with("IN_") || s.starts_with("FWDI_") || s.starts_with("FWDO_")
            || s.starts_with("OUTPUT_") => {
            return ChainOwner::System(SystemTool::Firewalld);
        }

        // App-managed chains
        s if s.starts_with("TR-") => {
            return ChainOwner::App;
        }

        _ => {}
    }

    if is_builtin {
        // Content-based detection for wg-quick in built-in chains
        if has_wg_interface_rules(rules) {
            return ChainOwner::System(SystemTool::WgQuick);
        }
        return ChainOwner::BuiltIn;
    }

    ChainOwner::Unknown
}

/// Check if any rules reference WireGuard interfaces (wg0, wg1, etc.).
fn has_wg_interface_rules(rules: &[ParsedRule]) -> bool {
    for rule in rules {
        if let Some(ref spec) = rule.parsed {
            if let Some(ref iface) = spec.in_iface {
                if iface.name.starts_with("wg") {
                    return true;
                }
            }
            if let Some(ref iface) = spec.out_iface {
                if iface.name.starts_with("wg") {
                    return true;
                }
            }
        }
    }
    false
}

/// Apply chain ownership detection to all chains in a parsed ruleset (in-place).
pub fn detect_all_chain_owners(ruleset: &mut ParsedRuleset) {
    for table in ruleset.tables.values_mut() {
        // Collect chain names and their rule refs to avoid borrow issues
        let chain_names: Vec<String> = table.chains.keys().cloned().collect();
        for name in chain_names {
            let owner = if let Some(chain) = table.chains.get(&name) {
                detect_chain_owner(&name, &chain.rules)
            } else {
                continue;
            };
            if let Some(chain_mut) = table.chains.get_mut(&name) {
                chain_mut.owner = owner;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule_with_iface(in_iface: Option<&str>, out_iface: Option<&str>) -> ParsedRule {
        ParsedRule {
            raw: String::new(),
            parsed: Some(RuleSpec {
                protocol: None,
                protocol_negated: false,
                source: None,
                destination: None,
                in_iface: in_iface.map(|n| InterfaceSpec { name: n.to_string(), negated: false }),
                out_iface: out_iface.map(|n| InterfaceSpec { name: n.to_string(), negated: false }),
                matches: Vec::new(),
                target: None,
                target_args: Vec::new(),
                comment: None,
                counters: None,
                fragment: None,
                source_port: None,
                dest_port: None,
                address_family: AddressFamily::V4,
            }),
            warnings: Vec::new(),
            chain: String::new(),
            table: String::new(),
        }
    }

    #[test]
    fn test_docker_chains() {
        assert_eq!(detect_chain_owner("DOCKER", &[]), ChainOwner::System(SystemTool::Docker));
        assert_eq!(detect_chain_owner("DOCKER-USER", &[]), ChainOwner::System(SystemTool::Docker));
        assert_eq!(detect_chain_owner("DOCKER-ISOLATION-STAGE-1", &[]), ChainOwner::System(SystemTool::Docker));
    }

    #[test]
    fn test_fail2ban_chains() {
        assert_eq!(detect_chain_owner("f2b-sshd", &[]), ChainOwner::System(SystemTool::Fail2ban));
        assert_eq!(detect_chain_owner("f2b-nginx-http-auth", &[]), ChainOwner::System(SystemTool::Fail2ban));
    }

    #[test]
    fn test_kubernetes_chains() {
        assert_eq!(detect_chain_owner("KUBE-SERVICES", &[]), ChainOwner::System(SystemTool::Kubernetes));
        assert_eq!(detect_chain_owner("cali-INPUT", &[]), ChainOwner::System(SystemTool::Kubernetes));
    }

    #[test]
    fn test_csf_chains() {
        assert_eq!(detect_chain_owner("LOCALINPUT", &[]), ChainOwner::System(SystemTool::Csf));
        assert_eq!(detect_chain_owner("acl_in", &[]), ChainOwner::System(SystemTool::Csf));
    }

    #[test]
    fn test_app_chains() {
        assert_eq!(detect_chain_owner("TR-INPUT", &[]), ChainOwner::App);
        assert_eq!(detect_chain_owner("TR-CONNTRACK", &[]), ChainOwner::App);
    }

    #[test]
    fn test_builtin_chains() {
        assert_eq!(detect_chain_owner("INPUT", &[]), ChainOwner::BuiltIn);
        assert_eq!(detect_chain_owner("FORWARD", &[]), ChainOwner::BuiltIn);
        assert_eq!(detect_chain_owner("OUTPUT", &[]), ChainOwner::BuiltIn);
    }

    #[test]
    fn test_wg_quick_detection() {
        let rules = vec![make_rule_with_iface(Some("wg0"), None)];
        assert_eq!(detect_chain_owner("FORWARD", &rules), ChainOwner::System(SystemTool::WgQuick));
    }

    #[test]
    fn test_unknown_chain() {
        assert_eq!(detect_chain_owner("MY-CUSTOM-CHAIN", &[]), ChainOwner::Unknown);
    }

    // ─── Coexistence profile tests ──────────────────────────

    fn make_chain(name: &str, rule_count: usize, owner: ChainOwner) -> (String, ChainState) {
        let rules: Vec<ParsedRule> = (0..rule_count)
            .map(|_| ParsedRule {
                raw: String::new(),
                parsed: None,
                warnings: Vec::new(),
                chain: name.to_string(),
                table: "filter".to_string(),
            })
            .collect();
        (
            name.to_string(),
            ChainState {
                name: name.to_string(),
                policy: None,
                counters: None,
                rules,
                owner,
            },
        )
    }

    fn make_ruleset(chains: Vec<(String, ChainState)>) -> ParsedRuleset {
        let mut table = TableState {
            name: "filter".to_string(),
            chains: HashMap::new(),
        };
        for (name, state) in chains {
            table.chains.insert(name, state);
        }
        let mut tables = HashMap::new();
        tables.insert("filter".to_string(), table);
        ParsedRuleset {
            tables,
            header_comments: Vec::new(),
        }
    }

    #[test]
    fn test_profile_docker_host() {
        let ruleset = make_ruleset(vec![
            make_chain("DOCKER-USER", 3, ChainOwner::System(SystemTool::Docker)),
            make_chain("DOCKER", 5, ChainOwner::System(SystemTool::Docker)),
            make_chain("INPUT", 0, ChainOwner::BuiltIn),
        ]);
        let profile = build_coexistence_profile(&ruleset);

        assert_eq!(profile.total_chains, 3);
        assert_eq!(profile.external_chains, 2);
        assert_eq!(profile.app_managed_chains, 0);

        let docker_group = profile.owners.iter().find(|g| g.owner == "Docker").unwrap();
        assert_eq!(docker_group.chains.len(), 2);
        assert_eq!(docker_group.rule_count, 8);
        assert!(!docker_group.is_app_managed);
    }

    #[test]
    fn test_profile_mixed() {
        let ruleset = make_ruleset(vec![
            make_chain("DOCKER-USER", 2, ChainOwner::System(SystemTool::Docker)),
            make_chain("f2b-sshd", 4, ChainOwner::System(SystemTool::Fail2ban)),
            make_chain("TR-INPUT", 3, ChainOwner::App),
            make_chain("INPUT", 0, ChainOwner::BuiltIn),
        ]);
        let profile = build_coexistence_profile(&ruleset);

        assert_eq!(profile.total_chains, 4);
        assert_eq!(profile.app_managed_chains, 1);
        assert_eq!(profile.external_chains, 2);

        // Should have at least Docker, fail2ban, and App groups
        let owner_names: Vec<&str> = profile.owners.iter().map(|g| g.owner.as_str()).collect();
        assert!(owner_names.contains(&"Docker"));
        assert!(owner_names.contains(&"fail2ban"));
        assert!(owner_names.contains(&"App"));
    }

    #[test]
    fn test_profile_empty() {
        let ruleset = ParsedRuleset {
            tables: HashMap::new(),
            header_comments: Vec::new(),
        };
        let profile = build_coexistence_profile(&ruleset);

        assert_eq!(profile.total_chains, 0);
        assert_eq!(profile.app_managed_chains, 0);
        assert_eq!(profile.external_chains, 0);
        assert!(profile.owners.is_empty());
    }
}
