use std::collections::HashMap;

use traffic_rules_lib::iptables::generator::*;
use traffic_rules_lib::iptables::parser::parse_iptables_save;
use traffic_rules_lib::iptables::types::*;

// ---------------------------------------------------------------------------
// generate_restore_from_lines
// ---------------------------------------------------------------------------

#[test]
fn test_restore_has_tr_reset_lines() {
    let mut chains: HashMap<String, Vec<String>> = HashMap::new();
    chains.insert(
        "TR-INPUT".to_string(),
        vec!["-p tcp --dport 22 -j ACCEPT".to_string()],
    );
    chains.insert(
        "TR-CONNTRACK".to_string(),
        vec!["-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT".to_string()],
    );

    let result = generate_restore_from_lines(&chains, "filter");

    // Must have table header
    assert!(result.starts_with("*filter\n"));

    // Must have :TR- reset lines
    assert!(result.contains(":TR-CONNTRACK - [0:0]\n"));
    assert!(result.contains(":TR-INPUT - [0:0]\n"));

    // Must have COMMIT
    assert!(result.ends_with("COMMIT\n"));

    // Must have rules
    assert!(result.contains("-A TR-INPUT -p tcp --dport 22 -j ACCEPT\n"));
    assert!(result.contains("-A TR-CONNTRACK -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"));
}

#[test]
fn test_restore_never_emits_system_chain_reset() {
    let mut chains: HashMap<String, Vec<String>> = HashMap::new();
    chains.insert("INPUT".to_string(), vec!["-j TR-INPUT".to_string()]);
    chains.insert("TR-INPUT".to_string(), vec!["-p tcp --dport 80 -j ACCEPT".to_string()]);

    let result = generate_restore_from_lines(&chains, "filter");

    // Must NOT emit :INPUT (system chain)
    assert!(!result.contains(":INPUT"), "must not reset system chain INPUT");
    // Must emit :TR-INPUT
    assert!(result.contains(":TR-INPUT - [0:0]"));
}

#[test]
fn test_restore_nat_table() {
    let mut chains: HashMap<String, Vec<String>> = HashMap::new();
    chains.insert(
        "TR-PREROUTING".to_string(),
        vec!["-p tcp --dport 8080 -j DNAT --to-destination 10.0.0.1:80".to_string()],
    );

    let result = generate_restore_from_lines(&chains, "nat");
    assert!(result.starts_with("*nat\n"));
    assert!(result.contains(":TR-PREROUTING - [0:0]"));
    assert!(result.contains("DNAT"));
}

#[test]
fn test_restore_raw_table() {
    let mut chains: HashMap<String, Vec<String>> = HashMap::new();
    chains.insert(
        "TR-CT-HELPERS".to_string(),
        vec!["-p tcp --dport 21 -j CT --helper ftp".to_string()],
    );

    let result = generate_restore_from_lines(&chains, "raw");
    assert!(result.starts_with("*raw\n"));
    assert!(result.contains(":TR-CT-HELPERS - [0:0]"));
    assert!(result.contains("--helper ftp"));
}

#[test]
fn test_restore_chains_sorted() {
    let mut chains: HashMap<String, Vec<String>> = HashMap::new();
    chains.insert("TR-OUTPUT".to_string(), vec!["-j ACCEPT".to_string()]);
    chains.insert("TR-INPUT".to_string(), vec!["-j ACCEPT".to_string()]);
    chains.insert("TR-CONNTRACK".to_string(), vec!["-j ACCEPT".to_string()]);

    let result = generate_restore_from_lines(&chains, "filter");

    // Reset lines should be sorted
    let conntrack_pos = result.find(":TR-CONNTRACK").unwrap();
    let input_pos = result.find(":TR-INPUT").unwrap();
    let output_pos = result.find(":TR-OUTPUT").unwrap();
    assert!(conntrack_pos < input_pos);
    assert!(input_pos < output_pos);
}

// ---------------------------------------------------------------------------
// rule_spec_to_args round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_rule_spec_to_args_roundtrip_simple() {
    // Parse a rule, convert back to args, verify key components
    let input = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT\nCOMMIT\n";
    let ruleset = parse_iptables_save(input).unwrap();
    let rule = &ruleset.tables["filter"].chains["INPUT"].rules[0];
    let spec = rule.parsed.as_ref().unwrap();
    let args = rule_spec_to_args(spec);
    let joined = args.join(" ");

    assert!(joined.contains("-p tcp"), "missing protocol: {}", joined);
    assert!(joined.contains("-s 10.0.0.0/8"), "missing source: {}", joined);
    assert!(joined.contains("-j ACCEPT"), "missing target: {}", joined);
}

#[test]
fn test_rule_spec_to_args_roundtrip_conntrack() {
    let input = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\nCOMMIT\n";
    let ruleset = parse_iptables_save(input).unwrap();
    let rule = &ruleset.tables["filter"].chains["INPUT"].rules[0];
    let spec = rule.parsed.as_ref().unwrap();
    let args = rule_spec_to_args(spec);
    let joined = args.join(" ");

    assert!(joined.contains("-m conntrack"), "missing module: {}", joined);
    assert!(joined.contains("--ctstate"), "missing ctstate: {}", joined);
    assert!(joined.contains("ESTABLISHED,RELATED"), "missing states: {}", joined);
}

#[test]
fn test_rule_spec_to_args_roundtrip_comment() {
    let input = r#"*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -m comment --comment "Allow SSH" -j ACCEPT
COMMIT
"#;
    let ruleset = parse_iptables_save(input).unwrap();
    let rule = &ruleset.tables["filter"].chains["INPUT"].rules[0];
    let spec = rule.parsed.as_ref().unwrap();
    let args = rule_spec_to_args(spec);
    let joined = args.join(" ");

    assert!(joined.contains("--comment"), "missing comment flag: {}", joined);
    assert!(joined.contains("Allow SSH"), "missing comment text: {}", joined);
}

#[test]
fn test_rule_spec_to_args_negated_protocol() {
    let spec = RuleSpec {
        protocol: Some(Protocol::Udp),
        protocol_negated: true,
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
        dest_port: None,
        address_family: AddressFamily::V4,
    };
    let args = rule_spec_to_args(&spec);
    let joined = args.join(" ");
    assert!(joined.contains("! -p udp"), "should have negated protocol: {}", joined);
}

#[test]
fn test_rule_spec_to_args_interfaces() {
    let spec = RuleSpec {
        protocol: None,
        protocol_negated: false,
        source: None,
        destination: None,
        in_iface: Some(InterfaceSpec {
            name: "eth0".to_string(),
            negated: false,
        }),
        out_iface: Some(InterfaceSpec {
            name: "eth1".to_string(),
            negated: true,
        }),
        matches: vec![],
        target: Some(Target::Accept),
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
    assert!(joined.contains("-i eth0"), "missing in-interface: {}", joined);
    assert!(joined.contains("! -o eth1"), "missing negated out-interface: {}", joined);
}

// ---------------------------------------------------------------------------
// build_shell_command
// ---------------------------------------------------------------------------

#[test]
fn test_shell_command_basic() {
    let cmd = build_shell_command("iptables", &["-w", "5", "-A", "INPUT", "-j", "ACCEPT"]);
    assert_eq!(cmd, "iptables -w 5 -A INPUT -j ACCEPT");
}

#[test]
fn test_shell_command_with_spaces() {
    let cmd = build_shell_command(
        "iptables",
        &["-m", "comment", "--comment", "Allow SSH access"],
    );
    // shell_words should quote the argument containing spaces
    assert!(
        cmd.contains("'Allow SSH access'") || cmd.contains("\"Allow SSH access\""),
        "should quote argument with spaces: {}",
        cmd
    );
}

#[test]
fn test_shell_command_with_special_chars() {
    let cmd = build_shell_command("echo", &["hello; rm -rf /"]);
    // The dangerous string must be quoted (inside single or double quotes)
    // so it cannot be interpreted as a separate command by the shell.
    assert!(
        cmd.contains("'hello; rm -rf /'") || cmd.contains("\"hello; rm -rf /\""),
        "dangerous argument should be quoted: {}",
        cmd
    );
}

#[test]
fn test_shell_command_empty_args() {
    let cmd = build_shell_command("iptables", &[]);
    assert_eq!(cmd, "iptables");
}
