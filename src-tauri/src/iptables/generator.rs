use std::collections::HashMap;

use crate::iptables::types::*;

/// Generate `iptables-restore` input from a set of rules.
///
/// This produces a complete restore file for a single table (e.g. `filter`,
/// `nat`, `raw`) with `:TR-CHAIN - [0:0]` reset lines for every app-managed
/// chain.  The `:TR-CHAIN - [0:0]` lines are **critical** — without them,
/// `--noflush` mode concatenates rules on every apply.
///
/// Built-in chain policies are **not** emitted here.  They are managed via
/// separate `iptables -P` commands so that `--noflush` preserves them.
pub fn generate_restore(
    rules: &[RuleSpec],
    chains: &HashMap<String, Vec<usize>>,
    table: &str,
) -> String {
    let mut out = String::new();

    // Table header
    out.push_str(&format!("*{}\n", table));

    // Collect all TR-* chain names referenced — sorted for deterministic output
    let mut chain_names: Vec<&String> = chains.keys().collect();
    chain_names.sort();

    // Emit :TR-CHAIN - [0:0] reset lines for every app-managed chain
    for chain_name in &chain_names {
        if chain_name.starts_with("TR-") {
            out.push_str(&format!(":{} - [0:0]\n", chain_name));
        }
    }

    // Emit rules grouped by chain
    for chain_name in &chain_names {
        if !chain_name.starts_with("TR-") {
            continue;
        }
        if let Some(indices) = chains.get(*chain_name) {
            for &idx in indices {
                if idx < rules.len() {
                    let args = rule_spec_to_args(&rules[idx]);
                    out.push_str(&format!("-A {} {}\n", chain_name, args.join(" ")));
                }
            }
        }
    }

    out.push_str("COMMIT\n");
    out
}

/// A simpler variant of `generate_restore` that takes pre-built rule lines
/// grouped by chain name.  Each value in `chain_rules` is a Vec of rule
/// argument strings (everything after `-A CHAIN`).
pub fn generate_restore_from_lines(
    chain_rules: &HashMap<String, Vec<String>>,
    table: &str,
) -> String {
    let mut out = String::new();

    out.push_str(&format!("*{}\n", table));

    let mut chain_names: Vec<&String> = chain_rules.keys().collect();
    chain_names.sort();

    // Reset lines
    for chain_name in &chain_names {
        if chain_name.starts_with("TR-") {
            out.push_str(&format!(":{} - [0:0]\n", chain_name));
        }
    }

    // Rules
    for chain_name in &chain_names {
        if !chain_name.starts_with("TR-") {
            continue;
        }
        if let Some(rules) = chain_rules.get(*chain_name) {
            for rule_line in rules {
                out.push_str(&format!("-A {} {}\n", chain_name, rule_line));
            }
        }
    }

    out.push_str("COMMIT\n");
    out
}

/// Convert a [`RuleSpec`] back to iptables command-line arguments.
///
/// Used for:
/// - Content-based rule deletion (`iptables -D INPUT <rule-spec>`)
/// - Display in the UI
/// - Round-trip verification
pub fn rule_spec_to_args(spec: &RuleSpec) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();

    // Protocol
    if let Some(ref proto) = spec.protocol {
        if spec.protocol_negated {
            args.push("!".to_string());
        }
        args.push("-p".to_string());
        args.push(proto.to_string());
    }

    // Source
    if let Some(ref src) = spec.source {
        if src.negated {
            args.push("!".to_string());
        }
        args.push("-s".to_string());
        args.push(src.addr.clone());
    }

    // Destination
    if let Some(ref dst) = spec.destination {
        if dst.negated {
            args.push("!".to_string());
        }
        args.push("-d".to_string());
        args.push(dst.addr.clone());
    }

    // Input interface
    if let Some(ref iface) = spec.in_iface {
        if iface.negated {
            args.push("!".to_string());
        }
        args.push("-i".to_string());
        args.push(iface.name.clone());
    }

    // Output interface
    if let Some(ref iface) = spec.out_iface {
        if iface.negated {
            args.push("!".to_string());
        }
        args.push("-o".to_string());
        args.push(iface.name.clone());
    }

    // Fragment
    if let Some(frag) = spec.fragment {
        if !frag {
            args.push("!".to_string());
        }
        args.push("-f".to_string());
    }

    // Match modules
    for m in &spec.matches {
        // Skip implicit protocol modules (tcp/udp) if they duplicate the -p flag
        // But still emit their args
        let is_implicit_proto = matches!(m.module.as_str(), "tcp" | "udp" | "icmp" | "icmpv6" | "sctp")
            && spec.protocol.as_ref().map_or(false, |p| {
                p.to_string().to_lowercase() == m.module
            });

        if !is_implicit_proto {
            args.push("-m".to_string());
            args.push(m.module.clone());
        }

        // Module arguments
        for arg in &m.args {
            args.push(arg.clone());
        }
    }

    // Source port
    if let Some(ref sp) = spec.source_port {
        args.push("--sport".to_string());
        args.push(port_spec_to_string(sp));
    }

    // Destination port
    if let Some(ref dp) = spec.dest_port {
        args.push("--dport".to_string());
        args.push(port_spec_to_string(dp));
    }

    // Target
    if let Some(ref target) = spec.target {
        args.push("-j".to_string());
        args.push(target.to_string());

        // Target-specific arguments
        for targ in &spec.target_args {
            args.push(targ.clone());
        }
    }

    args
}

/// Format a single `PortSpec` as a string suitable for iptables arguments.
pub fn port_spec_to_string(port: &PortSpec) -> String {
    match port {
        PortSpec::Single(p) => p.to_string(),
        PortSpec::Multi(ports) => ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
        PortSpec::Range(lo, hi) => format!("{}:{}", lo, hi),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_restore_basic() {
        let mut chains: HashMap<String, Vec<String>> = HashMap::new();
        chains.insert(
            "TR-INPUT".to_string(),
            vec![
                "-i lo -j ACCEPT".to_string(),
                "-p tcp --dport 22 -j ACCEPT".to_string(),
            ],
        );
        chains.insert(
            "TR-CONNTRACK".to_string(),
            vec![
                "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT".to_string(),
            ],
        );

        let result = generate_restore_from_lines(&chains, "filter");
        assert!(result.starts_with("*filter\n"));
        assert!(result.contains(":TR-CONNTRACK - [0:0]\n"));
        assert!(result.contains(":TR-INPUT - [0:0]\n"));
        assert!(result.contains("-A TR-CONNTRACK -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"));
        assert!(result.contains("-A TR-INPUT -i lo -j ACCEPT\n"));
        assert!(result.contains("-A TR-INPUT -p tcp --dport 22 -j ACCEPT\n"));
        assert!(result.ends_with("COMMIT\n"));
    }

    #[test]
    fn test_generate_restore_no_system_chains() {
        let mut chains: HashMap<String, Vec<String>> = HashMap::new();
        chains.insert("INPUT".to_string(), vec!["-j TR-INPUT".to_string()]);
        chains.insert("TR-INPUT".to_string(), vec!["-p tcp --dport 80 -j ACCEPT".to_string()]);

        let result = generate_restore_from_lines(&chains, "filter");
        // Should NOT emit :INPUT reset line — only TR-* chains
        assert!(!result.contains(":INPUT"));
        assert!(result.contains(":TR-INPUT - [0:0]"));
    }

    #[test]
    fn test_rule_spec_to_args_basic() {
        let spec = RuleSpec {
            protocol: Some(Protocol::Tcp),
            protocol_negated: false,
            source: Some(AddressSpec {
                addr: "10.0.0.0/8".to_string(),
                negated: false,
            }),
            destination: None,
            in_iface: None,
            out_iface: None,
            matches: vec![],
            target: Some(Target::Accept),
            target_args: vec![],
            comment: None,
            counters: None,
            fragment: None,
            source_port: None,
            dest_port: Some(PortSpec::Single(22)),
            address_family: AddressFamily::V4,
        };

        let args = rule_spec_to_args(&spec);
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"tcp".to_string()));
        assert!(args.contains(&"-s".to_string()));
        assert!(args.contains(&"10.0.0.0/8".to_string()));
        assert!(args.contains(&"-j".to_string()));
        assert!(args.contains(&"ACCEPT".to_string()));
    }

    #[test]
    fn test_rule_spec_to_args_negated_source() {
        let spec = RuleSpec {
            protocol: None,
            protocol_negated: false,
            source: Some(AddressSpec {
                addr: "192.168.1.0/24".to_string(),
                negated: true,
            }),
            destination: None,
            in_iface: None,
            out_iface: None,
            matches: vec![],
            target: Some(Target::Drop),
            target_args: vec![],
            comment: None,
            counters: None,
            fragment: None,
            source_port: None,
            dest_port: None,
            address_family: AddressFamily::V4,
        };

        let args = rule_spec_to_args(&spec);
        let joined = args.join(" ");
        assert!(joined.contains("! -s 192.168.1.0/24"));
    }

    #[test]
    fn test_generate_restore_nat_table() {
        let mut chains: HashMap<String, Vec<String>> = HashMap::new();
        chains.insert(
            "TR-PREROUTING".to_string(),
            vec!["-p tcp --dport 8080 -j DNAT --to-destination 10.0.0.1:80".to_string()],
        );

        let result = generate_restore_from_lines(&chains, "nat");
        assert!(result.starts_with("*nat\n"));
        assert!(result.contains(":TR-PREROUTING - [0:0]\n"));
        assert!(result.contains("-A TR-PREROUTING"));
        assert!(result.ends_with("COMMIT\n"));
    }

    #[test]
    fn test_generate_restore_raw_table() {
        let mut chains: HashMap<String, Vec<String>> = HashMap::new();
        chains.insert(
            "TR-CT-HELPERS".to_string(),
            vec!["-p tcp --dport 21 -j CT --helper ftp".to_string()],
        );

        let result = generate_restore_from_lines(&chains, "raw");
        assert!(result.starts_with("*raw\n"));
        assert!(result.contains(":TR-CT-HELPERS - [0:0]\n"));
        assert!(result.ends_with("COMMIT\n"));
    }

    #[test]
    fn test_rule_spec_to_args_with_match_module() {
        let spec = RuleSpec {
            protocol: Some(Protocol::Tcp),
            protocol_negated: false,
            source: None,
            destination: None,
            in_iface: None,
            out_iface: None,
            matches: vec![
                MatchSpec {
                    module: "multiport".to_string(),
                    args: vec!["--dports".to_string(), "80,443".to_string()],
                },
            ],
            target: Some(Target::Accept),
            target_args: vec![],
            comment: None,
            counters: None,
            fragment: None,
            source_port: None,
            dest_port: Some(PortSpec::Multi(vec![80, 443])),
            address_family: AddressFamily::V4,
        };

        let args = rule_spec_to_args(&spec);
        let joined = args.join(" ");
        assert!(joined.contains("-p tcp"));
        assert!(joined.contains("-m multiport --dports 80,443"));
        assert!(joined.contains("-j ACCEPT"));
    }

    #[test]
    fn test_rule_spec_to_args_dest_port() {
        let spec = RuleSpec {
            protocol: Some(Protocol::Tcp),
            protocol_negated: false,
            source: None,
            destination: None,
            in_iface: None,
            out_iface: None,
            matches: vec![],
            target: Some(Target::Accept),
            target_args: vec![],
            comment: None,
            counters: None,
            fragment: None,
            source_port: None,
            dest_port: Some(PortSpec::Single(22)),
            address_family: AddressFamily::V4,
        };

        let args = rule_spec_to_args(&spec);
        let joined = args.join(" ");
        assert!(joined.contains("--dport 22"), "expected --dport 22, got: {}", joined);
    }

    #[test]
    fn test_rule_spec_to_args_source_port() {
        let spec = RuleSpec {
            protocol: Some(Protocol::Tcp),
            protocol_negated: false,
            source: None,
            destination: None,
            in_iface: None,
            out_iface: None,
            matches: vec![],
            target: Some(Target::Accept),
            target_args: vec![],
            comment: None,
            counters: None,
            fragment: None,
            source_port: Some(PortSpec::Single(1024)),
            dest_port: None,
            address_family: AddressFamily::V4,
        };

        let args = rule_spec_to_args(&spec);
        let joined = args.join(" ");
        assert!(joined.contains("--sport 1024"), "expected --sport 1024, got: {}", joined);
    }

    #[test]
    fn test_port_spec_to_string() {
        assert_eq!(port_spec_to_string(&PortSpec::Single(22)), "22");
        assert_eq!(port_spec_to_string(&PortSpec::Multi(vec![80, 443])), "80,443");
        assert_eq!(port_spec_to_string(&PortSpec::Range(1024, 65535)), "1024:65535");
    }
}
