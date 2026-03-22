use traffic_rules_lib::iptables::explain::explain_rule;
use traffic_rules_lib::iptables::types::*;

fn make_spec() -> RuleSpec {
    RuleSpec {
        protocol: None,
        protocol_negated: false,
        source: None,
        destination: None,
        in_iface: None,
        out_iface: None,
        matches: vec![],
        target: None,
        target_args: vec![],
        comment: None,
        counters: None,
        fragment: None,
        source_port: None,
        dest_port: None,
        address_family: AddressFamily::V4,
    }
}

#[test]
fn test_explain_ssh() {
    let spec = RuleSpec {
        protocol: Some(Protocol::Tcp),
        source: Some(AddressSpec {
            addr: "10.0.0.0/8".to_string(),
            negated: false,
        }),
        dest_port: Some(PortSpec::Single(22)),
        target: Some(Target::Accept),
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("allows"), "{}", explanation);
    assert!(explanation.contains("TCP"), "{}", explanation);
    assert!(explanation.contains("22"), "{}", explanation);
    assert!(explanation.contains("10.0.0.0/8"), "{}", explanation);
    assert!(explanation.contains("SSH"), "{}", explanation);
}

#[test]
fn test_explain_web_multiport() {
    let spec = RuleSpec {
        protocol: Some(Protocol::Tcp),
        dest_port: Some(PortSpec::Multi(vec![80, 443])),
        target: Some(Target::Accept),
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("allows"), "{}", explanation);
    assert!(explanation.contains("80"), "{}", explanation);
    assert!(explanation.contains("443"), "{}", explanation);
    assert!(
        explanation.contains("web") || explanation.contains("HTTP"),
        "{}",
        explanation
    );
}

#[test]
fn test_explain_drop_all() {
    let spec = RuleSpec {
        target: Some(Target::Drop),
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("drops"), "{}", explanation);
}

#[test]
fn test_explain_dnat() {
    let spec = RuleSpec {
        protocol: Some(Protocol::Tcp),
        dest_port: Some(PortSpec::Single(8080)),
        target: Some(Target::Dnat),
        target_args: vec![
            "--to-destination".to_string(),
            "10.0.0.1:80".to_string(),
        ],
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("DNAT"), "{}", explanation);
    assert!(explanation.contains("10.0.0.1:80"), "{}", explanation);
}

#[test]
fn test_explain_log_with_prefix_and_rate() {
    let spec = RuleSpec {
        target: Some(Target::Log),
        target_args: vec![
            "--log-prefix".to_string(),
            "BLOCKED: ".to_string(),
        ],
        matches: vec![MatchSpec {
            module: "limit".to_string(),
            args: vec!["--limit".to_string(), "5/min".to_string()],
        }],
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("logs"), "{}", explanation);
    assert!(explanation.contains("BLOCKED:"), "{}", explanation);
    assert!(explanation.contains("5 per minute"), "{}", explanation);
}

#[test]
fn test_explain_conntrack_established() {
    let spec = RuleSpec {
        matches: vec![MatchSpec {
            module: "conntrack".to_string(),
            args: vec!["--ctstate".to_string(), "ESTABLISHED,RELATED".to_string()],
        }],
        target: Some(Target::Accept),
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("ESTABLISHED"), "{}", explanation);
    assert!(explanation.contains("allows"), "{}", explanation);
}

#[test]
fn test_explain_conntrack_invalid() {
    let spec = RuleSpec {
        matches: vec![MatchSpec {
            module: "conntrack".to_string(),
            args: vec!["--ctstate".to_string(), "INVALID".to_string()],
        }],
        target: Some(Target::Drop),
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("INVALID"), "{}", explanation);
    assert!(explanation.contains("drops"), "{}", explanation);
}

#[test]
fn test_explain_loopback() {
    let spec = RuleSpec {
        in_iface: Some(InterfaceSpec {
            name: "lo".to_string(),
            negated: false,
        }),
        target: Some(Target::Accept),
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("loopback"), "{}", explanation);
    assert!(explanation.contains("allows"), "{}", explanation);
}

#[test]
fn test_explain_with_comment() {
    let spec = RuleSpec {
        protocol: Some(Protocol::Tcp),
        dest_port: Some(PortSpec::Single(443)),
        target: Some(Target::Accept),
        comment: Some("Allow HTTPS traffic".to_string()),
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("Allow HTTPS traffic"), "{}", explanation);
}

#[test]
fn test_explain_snat() {
    let spec = RuleSpec {
        target: Some(Target::Snat),
        target_args: vec![
            "--to-source".to_string(),
            "203.0.113.1".to_string(),
        ],
        out_iface: Some(InterfaceSpec {
            name: "eth0".to_string(),
            negated: false,
        }),
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("SNAT"), "{}", explanation);
    assert!(explanation.contains("203.0.113.1"), "{}", explanation);
}

#[test]
fn test_explain_masquerade() {
    let spec = RuleSpec {
        target: Some(Target::Masquerade),
        out_iface: Some(InterfaceSpec {
            name: "eth0".to_string(),
            negated: false,
        }),
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("masquerade") || explanation.contains("NAT"), "{}", explanation);
}

#[test]
fn test_explain_jump_to_chain() {
    let spec = RuleSpec {
        target: Some(Target::Jump("TR-INPUT".to_string())),
        ..make_spec()
    };
    let explanation = explain_rule(&spec);
    assert!(explanation.contains("TR-INPUT"), "{}", explanation);
    assert!(explanation.contains("jumps"), "{}", explanation);
}
