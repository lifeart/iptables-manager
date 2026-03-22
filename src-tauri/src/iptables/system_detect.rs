use crate::iptables::types::*;

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
}
