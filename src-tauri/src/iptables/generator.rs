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

/// Check whether a RuleSpec contains IPv4-only addresses (e.g. dotted-quad CIDR).
pub fn is_ipv4_only(spec: &RuleSpec) -> bool {
    let check_addr = |addr: &str| -> bool {
        // An address is IPv4-specific if it contains a dot (dotted-quad) and no colon
        addr.contains('.') && !addr.contains(':')
    };

    let src_v4 = spec.source.as_ref().map_or(false, |s| check_addr(&s.addr));
    let dst_v4 = spec.destination.as_ref().map_or(false, |d| check_addr(&d.addr));

    // Also check the address_family field
    if spec.address_family == AddressFamily::V4 {
        return true;
    }

    // If protocol is ICMP (not ICMPv6), it's v4-only
    if spec.protocol.as_ref() == Some(&Protocol::Icmp) {
        return true;
    }

    src_v4 || dst_v4
}

/// Check whether a RuleSpec contains IPv6-only addresses (e.g. `::` or hex-colon notation).
pub fn is_ipv6_only(spec: &RuleSpec) -> bool {
    let check_addr = |addr: &str| -> bool {
        // An address is IPv6-specific if it contains a colon (hex groups)
        addr.contains(':')
    };

    let src_v6 = spec.source.as_ref().map_or(false, |s| check_addr(&s.addr));
    let dst_v6 = spec.destination.as_ref().map_or(false, |d| check_addr(&d.addr));

    // Also check the address_family field
    if spec.address_family == AddressFamily::V6 {
        return true;
    }

    // If protocol is ICMPv6, it's v6-only
    if spec.protocol.as_ref() == Some(&Protocol::Icmpv6) {
        return true;
    }

    src_v6 || dst_v6
}

/// Generate dual-stack (IPv4 + IPv6) iptables-restore content from a set of rules.
///
/// Returns `(ipv4_restore, ipv6_restore)` where:
/// - IPv4 output includes rules that are IPv4-only or address-family-neutral
/// - IPv6 output includes rules that are IPv6-only or address-family-neutral
/// - Rules with IPv4 addresses are excluded from the v6 output and vice versa
pub fn generate_restore_dual_stack(
    rules: &[(&str, &RuleSpec)],
    chains: &[String],
    table: &str,
) -> (String, String) {
    let mut v4_chain_rules: HashMap<String, Vec<String>> = HashMap::new();
    let mut v6_chain_rules: HashMap<String, Vec<String>> = HashMap::new();

    // Ensure all chains exist in both maps
    for chain in chains {
        v4_chain_rules.entry(chain.clone()).or_default();
        v6_chain_rules.entry(chain.clone()).or_default();
    }

    for &(chain_name, spec) in rules {
        let args = rule_spec_to_args(spec);
        let rule_line = args.join(" ");

        let v4_only = is_ipv4_only(spec);
        let v6_only = is_ipv6_only(spec);

        if !v6_only {
            v4_chain_rules
                .entry(chain_name.to_string())
                .or_default()
                .push(rule_line.clone());
        }
        if !v4_only {
            v6_chain_rules
                .entry(chain_name.to_string())
                .or_default()
                .push(rule_line);
        }
    }

    let v4_output = generate_restore_from_lines(&v4_chain_rules, table);
    let v6_output = generate_restore_from_lines(&v6_chain_rules, table);

    (v4_output, v6_output)
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

    // ─── Dual-stack tests ───────────────────────────────────────

    fn make_spec(
        source: Option<&str>,
        dest: Option<&str>,
        protocol: Option<Protocol>,
        family: AddressFamily,
    ) -> RuleSpec {
        RuleSpec {
            protocol,
            protocol_negated: false,
            source: source.map(|s| AddressSpec {
                addr: s.to_string(),
                negated: false,
            }),
            destination: dest.map(|d| AddressSpec {
                addr: d.to_string(),
                negated: false,
            }),
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
            address_family: family,
        }
    }

    #[test]
    fn test_dual_stack_basic() {
        // Rules without IPs should appear in both outputs
        let spec = make_spec(None, None, Some(Protocol::Tcp), AddressFamily::Both);
        let rules: Vec<(&str, &RuleSpec)> = vec![("TR-INPUT", &spec)];
        let chains = vec!["TR-INPUT".to_string()];

        let (v4, v6) = generate_restore_dual_stack(&rules, &chains, "filter");

        assert!(v4.contains("-A TR-INPUT"), "v4 should contain the rule");
        assert!(v6.contains("-A TR-INPUT"), "v6 should contain the rule");
        assert!(v4.starts_with("*filter\n"));
        assert!(v6.starts_with("*filter\n"));
        assert!(v4.ends_with("COMMIT\n"));
        assert!(v6.ends_with("COMMIT\n"));
    }

    #[test]
    fn test_dual_stack_ipv4_only_rule() {
        // Rule with IPv4 source should only be in v4 output
        let spec = make_spec(
            Some("10.0.0.0/8"),
            None,
            Some(Protocol::Tcp),
            AddressFamily::Both,
        );
        let rules: Vec<(&str, &RuleSpec)> = vec![("TR-INPUT", &spec)];
        let chains = vec!["TR-INPUT".to_string()];

        let (v4, v6) = generate_restore_dual_stack(&rules, &chains, "filter");

        assert!(
            v4.contains("-s 10.0.0.0/8"),
            "v4 should contain the IPv4 rule"
        );
        assert!(
            !v6.contains("-s 10.0.0.0/8"),
            "v6 should NOT contain the IPv4 rule"
        );
    }

    #[test]
    fn test_dual_stack_ipv6_only_rule() {
        // Rule with IPv6 dest should only be in v6 output
        let spec = make_spec(
            None,
            Some("::1/128"),
            Some(Protocol::Tcp),
            AddressFamily::Both,
        );
        let rules: Vec<(&str, &RuleSpec)> = vec![("TR-INPUT", &spec)];
        let chains = vec!["TR-INPUT".to_string()];

        let (v4, v6) = generate_restore_dual_stack(&rules, &chains, "filter");

        assert!(
            !v4.contains("-d ::1/128"),
            "v4 should NOT contain the IPv6 rule"
        );
        assert!(
            v6.contains("-d ::1/128"),
            "v6 should contain the IPv6 rule"
        );
    }

    #[test]
    fn test_dual_stack_mixed() {
        // Mix of v4-only, v6-only, and both rules
        let v4_spec = make_spec(
            Some("192.168.1.0/24"),
            None,
            Some(Protocol::Tcp),
            AddressFamily::Both,
        );
        let v6_spec = make_spec(
            Some("fd00::1/64"),
            None,
            Some(Protocol::Tcp),
            AddressFamily::Both,
        );
        let both_spec = make_spec(None, None, Some(Protocol::Tcp), AddressFamily::Both);

        let rules: Vec<(&str, &RuleSpec)> = vec![
            ("TR-INPUT", &v4_spec),
            ("TR-INPUT", &v6_spec),
            ("TR-INPUT", &both_spec),
        ];
        let chains = vec!["TR-INPUT".to_string()];

        let (v4, v6) = generate_restore_dual_stack(&rules, &chains, "filter");

        // v4 output: should have v4_spec and both_spec, NOT v6_spec
        assert!(v4.contains("-s 192.168.1.0/24"), "v4 should contain IPv4 rule");
        assert!(!v4.contains("fd00::1/64"), "v4 should NOT contain IPv6 rule");
        // Count -A TR-INPUT lines in v4
        let v4_rule_count = v4.lines().filter(|l| l.starts_with("-A TR-INPUT")).count();
        assert_eq!(v4_rule_count, 2, "v4 should have 2 rules (v4-only + both)");

        // v6 output: should have v6_spec and both_spec, NOT v4_spec
        assert!(!v6.contains("192.168.1.0/24"), "v6 should NOT contain IPv4 rule");
        assert!(v6.contains("-s fd00::1/64"), "v6 should contain IPv6 rule");
        let v6_rule_count = v6.lines().filter(|l| l.starts_with("-A TR-INPUT")).count();
        assert_eq!(v6_rule_count, 2, "v6 should have 2 rules (v6-only + both)");
    }
}
