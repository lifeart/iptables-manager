use traffic_rules_lib::iptables::parser::parse_iptables_save;
use traffic_rules_lib::iptables::system_detect::{detect_chain_owner, detect_all_chain_owners};
use traffic_rules_lib::iptables::types::*;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn load_fixture(name: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read fixture {}: {}", name, e))
}

// ---------------------------------------------------------------------------
// Fixture: clean_server.txt
// ---------------------------------------------------------------------------

#[test]
fn test_clean_server() {
    let input = load_fixture("clean_server.txt");
    let ruleset = parse_iptables_save(&input).unwrap();

    assert_eq!(ruleset.header_comments.len(), 1);
    assert!(ruleset.header_comments[0].contains("iptables-save"));

    let filter = ruleset.tables.get("filter").unwrap();
    assert_eq!(filter.chains.len(), 3);

    let input_chain = filter.chains.get("INPUT").unwrap();
    assert_eq!(input_chain.policy, Some("ACCEPT".to_string()));
    assert_eq!(input_chain.counters, Some((1024, 65536)));
    assert_eq!(input_chain.rules.len(), 4);

    // First rule: -i lo -j ACCEPT
    let r0 = input_chain.rules[0].parsed.as_ref().unwrap();
    assert_eq!(r0.in_iface.as_ref().unwrap().name, "lo");
    assert_eq!(r0.target, Some(Target::Accept));

    // Second rule: conntrack
    let r1 = input_chain.rules[1].parsed.as_ref().unwrap();
    assert_eq!(r1.matches[0].module, "conntrack");

    // Third rule: tcp --dport 22
    let r2 = input_chain.rules[2].parsed.as_ref().unwrap();
    assert_eq!(r2.protocol, Some(Protocol::Tcp));

    // Fourth rule: icmp
    let r3 = input_chain.rules[3].parsed.as_ref().unwrap();
    assert_eq!(r3.protocol, Some(Protocol::Icmp));

    let fwd = filter.chains.get("FORWARD").unwrap();
    assert_eq!(fwd.policy, Some("DROP".to_string()));
    assert_eq!(fwd.rules.len(), 0);
}

// ---------------------------------------------------------------------------
// Fixture: docker_host.txt
// ---------------------------------------------------------------------------

#[test]
fn test_docker_host() {
    let input = load_fixture("docker_host.txt");
    let mut ruleset = parse_iptables_save(&input).unwrap();

    // Should have filter and nat tables
    assert!(ruleset.tables.contains_key("filter"));
    assert!(ruleset.tables.contains_key("nat"));

    let filter = ruleset.tables.get("filter").unwrap();

    // Docker chains should exist
    assert!(filter.chains.contains_key("DOCKER"));
    assert!(filter.chains.contains_key("DOCKER-ISOLATION-STAGE-1"));
    assert!(filter.chains.contains_key("DOCKER-ISOLATION-STAGE-2"));
    assert!(filter.chains.contains_key("DOCKER-USER"));

    // Docker chains should have - policy (user-defined)
    assert_eq!(filter.chains.get("DOCKER").unwrap().policy, None);

    // DOCKER chain has 2 rules in filter
    assert_eq!(filter.chains.get("DOCKER").unwrap().rules.len(), 2);

    // NAT table
    let nat = ruleset.tables.get("nat").unwrap();
    assert!(nat.chains.contains_key("DOCKER"));

    // DNAT rules
    let nat_docker = nat.chains.get("DOCKER").unwrap();
    let dnat_rules: Vec<_> = nat_docker.rules.iter()
        .filter(|r| r.parsed.as_ref().map(|s| s.target == Some(Target::Dnat)).unwrap_or(false))
        .collect();
    assert_eq!(dnat_rules.len(), 2);

    // Verify DNAT target args
    let dnat0 = dnat_rules[0].parsed.as_ref().unwrap();
    assert!(dnat0.target_args.contains(&"--to-destination".to_string()));

    // System detection
    detect_all_chain_owners(&mut ruleset);
    let filter = ruleset.tables.get("filter").unwrap();
    assert_eq!(filter.chains.get("DOCKER").unwrap().owner, ChainOwner::System(SystemTool::Docker));
    assert_eq!(filter.chains.get("DOCKER-USER").unwrap().owner, ChainOwner::System(SystemTool::Docker));
}

// ---------------------------------------------------------------------------
// Fixture: fail2ban_active.txt
// ---------------------------------------------------------------------------

#[test]
fn test_fail2ban_active() {
    let input = load_fixture("fail2ban_active.txt");
    let mut ruleset = parse_iptables_save(&input).unwrap();

    let filter = ruleset.tables.get("filter").unwrap();
    assert!(filter.chains.contains_key("f2b-sshd"));

    let f2b = filter.chains.get("f2b-sshd").unwrap();
    // 3 ban rules + 1 RETURN
    assert_eq!(f2b.rules.len(), 4);

    // Check banned IPs
    let banned: Vec<String> = f2b.rules.iter()
        .filter_map(|r| {
            r.parsed.as_ref().and_then(|s| s.source.as_ref().map(|a| a.addr.clone()))
        })
        .collect();
    assert!(banned.contains(&"192.168.1.100/32".to_string()));
    assert!(banned.contains(&"10.0.0.50/32".to_string()));
    assert!(banned.contains(&"203.0.113.42/32".to_string()));

    // Reject target
    let reject_rule = f2b.rules[0].parsed.as_ref().unwrap();
    assert_eq!(reject_rule.target, Some(Target::Reject));
    assert!(reject_rule.target_args.contains(&"--reject-with".to_string()));

    // System detection
    detect_all_chain_owners(&mut ruleset);
    let filter = ruleset.tables.get("filter").unwrap();
    assert_eq!(filter.chains.get("f2b-sshd").unwrap().owner, ChainOwner::System(SystemTool::Fail2ban));
}

// ---------------------------------------------------------------------------
// Fixture: wg_quick.txt
// ---------------------------------------------------------------------------

#[test]
fn test_wg_quick() {
    let input = load_fixture("wg_quick.txt");
    let mut ruleset = parse_iptables_save(&input).unwrap();

    assert!(ruleset.tables.contains_key("filter"));
    assert!(ruleset.tables.contains_key("nat"));

    let filter = ruleset.tables.get("filter").unwrap();
    let fwd = filter.chains.get("FORWARD").unwrap();
    assert_eq!(fwd.rules.len(), 2);

    // First FORWARD rule should reference wg0
    let fwd0 = fwd.rules[0].parsed.as_ref().unwrap();
    assert_eq!(fwd0.in_iface.as_ref().unwrap().name, "wg0");

    // NAT: MASQUERADE
    let nat = ruleset.tables.get("nat").unwrap();
    let post = nat.chains.get("POSTROUTING").unwrap();
    assert_eq!(post.rules.len(), 1);
    let masq = post.rules[0].parsed.as_ref().unwrap();
    assert_eq!(masq.target, Some(Target::Masquerade));
    assert_eq!(masq.source.as_ref().unwrap().addr, "10.200.200.0/24");

    // System detection — FORWARD chain should be detected as wg-quick
    detect_all_chain_owners(&mut ruleset);
    let filter = ruleset.tables.get("filter").unwrap();
    assert_eq!(filter.chains.get("FORWARD").unwrap().owner, ChainOwner::System(SystemTool::WgQuick));
}

// ---------------------------------------------------------------------------
// Fixture: complex_mixed.txt
// ---------------------------------------------------------------------------

#[test]
fn test_complex_mixed() {
    let input = load_fixture("complex_mixed.txt");
    let mut ruleset = parse_iptables_save(&input).unwrap();

    // Should have filter, nat, raw tables
    assert!(ruleset.tables.contains_key("filter"));
    assert!(ruleset.tables.contains_key("nat"));
    assert!(ruleset.tables.contains_key("raw"));

    let filter = ruleset.tables.get("filter").unwrap();

    // Docker chains
    assert!(filter.chains.contains_key("DOCKER"));
    assert!(filter.chains.contains_key("DOCKER-USER"));

    // fail2ban chains
    assert!(filter.chains.contains_key("f2b-sshd"));
    assert!(filter.chains.contains_key("f2b-nginx-http-auth"));

    // App chains
    assert!(filter.chains.contains_key("TR-CONNTRACK"));
    assert!(filter.chains.contains_key("TR-INPUT"));

    // TR-INPUT rules
    let tr_input = filter.chains.get("TR-INPUT").unwrap();
    assert_eq!(tr_input.rules.len(), 2);

    // Check comment on TR-INPUT rule
    let web_rule = tr_input.rules[0].parsed.as_ref().unwrap();
    assert_eq!(web_rule.comment, Some("Web traffic".to_string()));

    // Check multiport on web rule
    assert!(web_rule.matches.iter().any(|m| m.module == "multiport"));

    // INPUT chain should have many rules
    let input_chain = filter.chains.get("INPUT").unwrap();
    assert!(input_chain.rules.len() >= 10);

    // Rate limited LOG rule
    let log_rules: Vec<_> = input_chain.rules.iter()
        .filter(|r| r.parsed.as_ref().map(|s| s.target == Some(Target::Log)).unwrap_or(false))
        .collect();
    assert!(!log_rules.is_empty());
    let log_spec = log_rules[0].parsed.as_ref().unwrap();
    assert!(log_spec.target_args.contains(&"--log-prefix".to_string()));
    assert!(log_spec.target_args.contains(&"TR-BLOCKED: ".to_string()));

    // System detection
    detect_all_chain_owners(&mut ruleset);
    let filter = ruleset.tables.get("filter").unwrap();
    assert_eq!(filter.chains.get("DOCKER").unwrap().owner, ChainOwner::System(SystemTool::Docker));
    assert_eq!(filter.chains.get("f2b-sshd").unwrap().owner, ChainOwner::System(SystemTool::Fail2ban));
    assert_eq!(filter.chains.get("TR-CONNTRACK").unwrap().owner, ChainOwner::App);
    assert_eq!(filter.chains.get("TR-INPUT").unwrap().owner, ChainOwner::App);

    // Total rule count >= 20
    let total_rules: usize = filter.chains.values().map(|c| c.rules.len()).sum();
    assert!(total_rules >= 20, "expected >= 20 rules, got {}", total_rules);
}

// ---------------------------------------------------------------------------
// Fixture: with_counters.txt
// ---------------------------------------------------------------------------

#[test]
fn test_with_counters() {
    let input = load_fixture("with_counters.txt");
    let ruleset = parse_iptables_save(&input).unwrap();

    let filter = ruleset.tables.get("filter").unwrap();
    let input_chain = filter.chains.get("INPUT").unwrap();

    // Chain-level counters
    assert_eq!(input_chain.counters, Some((50432, 12345678)));

    // Rule-level counters
    let r0 = input_chain.rules[0].parsed.as_ref().unwrap();
    assert_eq!(r0.counters, Some((1500, 120000)));

    let r1 = input_chain.rules[1].parsed.as_ref().unwrap();
    assert_eq!(r1.counters, Some((45000, 9876543)));

    // All rules should have counters
    for rule in &input_chain.rules {
        let spec = rule.parsed.as_ref().unwrap();
        assert!(spec.counters.is_some(), "rule should have counters: {}", rule.raw);
    }
}

// ---------------------------------------------------------------------------
// Fixture: iptables_nft.txt
// ---------------------------------------------------------------------------

#[test]
fn test_iptables_nft() {
    let input = load_fixture("iptables_nft.txt");
    let ruleset = parse_iptables_save(&input).unwrap();

    // Should parse nf_tables header comment
    assert!(ruleset.header_comments[0].contains("nf_tables"));

    // Should have filter, nat, mangle tables
    assert!(ruleset.tables.contains_key("filter"));
    assert!(ruleset.tables.contains_key("nat"));
    assert!(ruleset.tables.contains_key("mangle"));

    let filter = ruleset.tables.get("filter").unwrap();
    let input_chain = filter.chains.get("INPUT").unwrap();

    // iptables-nft uses -m tcp explicitly
    let tcp_rules: Vec<_> = input_chain.rules.iter()
        .filter(|r| r.parsed.as_ref().map(|s| s.protocol == Some(Protocol::Tcp)).unwrap_or(false))
        .collect();
    assert!(tcp_rules.len() >= 3);

    // Last INPUT rule should be DROP
    let last = input_chain.rules.last().unwrap().parsed.as_ref().unwrap();
    assert_eq!(last.target, Some(Target::Drop));

    // Mangle table should have 5 chains, all empty
    let mangle = ruleset.tables.get("mangle").unwrap();
    assert_eq!(mangle.chains.len(), 5);
    for chain in mangle.chains.values() {
        assert_eq!(chain.rules.len(), 0);
    }
}

// ---------------------------------------------------------------------------
// Round-trip: raw lines preserved
// ---------------------------------------------------------------------------

#[test]
fn test_round_trip_raw_preservation() {
    let input = load_fixture("clean_server.txt");
    let ruleset = parse_iptables_save(&input).unwrap();

    let filter = ruleset.tables.get("filter").unwrap();
    let input_chain = filter.chains.get("INPUT").unwrap();

    // Every rule's raw field should match the original line
    for rule in &input_chain.rules {
        assert!(!rule.raw.is_empty(), "raw should not be empty");
        assert!(
            input.contains(&rule.raw),
            "raw line should appear in original input: {}",
            rule.raw
        );
    }
}

// ---------------------------------------------------------------------------
// System detection tests
// ---------------------------------------------------------------------------

#[test]
fn test_system_detect_docker() {
    assert_eq!(
        detect_chain_owner("DOCKER", &[]),
        ChainOwner::System(SystemTool::Docker)
    );
    assert_eq!(
        detect_chain_owner("DOCKER-USER", &[]),
        ChainOwner::System(SystemTool::Docker)
    );
    assert_eq!(
        detect_chain_owner("DOCKER-ISOLATION-STAGE-1", &[]),
        ChainOwner::System(SystemTool::Docker)
    );
}

#[test]
fn test_system_detect_fail2ban() {
    assert_eq!(
        detect_chain_owner("f2b-sshd", &[]),
        ChainOwner::System(SystemTool::Fail2ban)
    );
    assert_eq!(
        detect_chain_owner("f2b-nginx-http-auth", &[]),
        ChainOwner::System(SystemTool::Fail2ban)
    );
}

#[test]
fn test_system_detect_kubernetes() {
    assert_eq!(
        detect_chain_owner("KUBE-SERVICES", &[]),
        ChainOwner::System(SystemTool::Kubernetes)
    );
    assert_eq!(
        detect_chain_owner("cali-INPUT", &[]),
        ChainOwner::System(SystemTool::Kubernetes)
    );
}

#[test]
fn test_system_detect_app() {
    assert_eq!(detect_chain_owner("TR-INPUT", &[]), ChainOwner::App);
    assert_eq!(detect_chain_owner("TR-CONNTRACK", &[]), ChainOwner::App);
}

#[test]
fn test_system_detect_builtin() {
    assert_eq!(detect_chain_owner("INPUT", &[]), ChainOwner::BuiltIn);
    assert_eq!(detect_chain_owner("FORWARD", &[]), ChainOwner::BuiltIn);
    assert_eq!(detect_chain_owner("OUTPUT", &[]), ChainOwner::BuiltIn);
    assert_eq!(detect_chain_owner("PREROUTING", &[]), ChainOwner::BuiltIn);
    assert_eq!(detect_chain_owner("POSTROUTING", &[]), ChainOwner::BuiltIn);
}

#[test]
fn test_system_detect_unknown() {
    assert_eq!(detect_chain_owner("MY-CHAIN", &[]), ChainOwner::Unknown);
}

// ---------------------------------------------------------------------------
// Malformed input — no panics
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_no_panic() {
    let inputs = vec![
        "",
        "garbage data that is not iptables output",
        "*filter\n:INPUT ACCEPT\n-A\nCOMMIT",
        "*filter\n:INPUT ACCEPT [bad:counters]\n-A INPUT\nCOMMIT",
        "*filter\n-A INPUT -p\nCOMMIT",
        "*filter\n-A INPUT -j\nCOMMIT",
        "*filter\n-A INPUT -m\nCOMMIT",
        "*filter\n-A INPUT -s -d -j ACCEPT\nCOMMIT",
        "*filter\n*filter\n*nat\nCOMMIT\nCOMMIT",
        "# just comments\n# more comments",
        "*filter\n:INPUT ACCEPT [0:0]\n[invalid] -A INPUT -j ACCEPT\nCOMMIT",
        "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m unknown_module --weird-flag value -j ACCEPT\nCOMMIT",
        // Unterminated quote
        "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m comment --comment \"unterminated\nCOMMIT",
    ];

    for input in inputs {
        let result = parse_iptables_save(input);
        // Should not panic; may return Ok or Err, but never crash
        match result {
            Ok(_) => {} // fine
            Err(_) => {} // also fine
        }
    }
}

// ---------------------------------------------------------------------------
// 10MB limit test
// ---------------------------------------------------------------------------

#[test]
fn test_10mb_limit() {
    let size = 10 * 1024 * 1024 + 1;
    let huge_input = "x".repeat(size);
    match parse_iptables_save(&huge_input) {
        Err(ParseError::InputTooLarge { size: s }) => {
            assert_eq!(s, size);
        }
        other => panic!("expected InputTooLarge, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_negated_protocol() {
    let input = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT ! -p tcp -j ACCEPT\nCOMMIT\n";
    let ruleset = parse_iptables_save(input).unwrap();
    let filter = ruleset.tables.get("filter").unwrap();
    let rule = &filter.chains.get("INPUT").unwrap().rules[0];
    let spec = rule.parsed.as_ref().unwrap();
    assert_eq!(spec.protocol, Some(Protocol::Tcp));
    assert!(spec.protocol_negated);
}

#[test]
fn test_negated_source() {
    let input = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT ! -s 10.0.0.0/8 -j DROP\nCOMMIT\n";
    let ruleset = parse_iptables_save(input).unwrap();
    let filter = ruleset.tables.get("filter").unwrap();
    let rule = &filter.chains.get("INPUT").unwrap().rules[0];
    let spec = rule.parsed.as_ref().unwrap();
    assert!(spec.source.as_ref().unwrap().negated);
    assert_eq!(spec.source.as_ref().unwrap().addr, "10.0.0.0/8");
}

#[test]
fn test_negated_interface() {
    let input = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT ! -i docker0 -j ACCEPT\nCOMMIT\n";
    let ruleset = parse_iptables_save(input).unwrap();
    let filter = ruleset.tables.get("filter").unwrap();
    let rule = &filter.chains.get("INPUT").unwrap().rules[0];
    let spec = rule.parsed.as_ref().unwrap();
    assert!(spec.in_iface.as_ref().unwrap().negated);
}

#[test]
fn test_multiple_tables() {
    let input = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n*mangle\n:INPUT ACCEPT [0:0]\nCOMMIT\n";
    let ruleset = parse_iptables_save(input).unwrap();
    assert_eq!(ruleset.tables.len(), 3);
    assert!(ruleset.tables.contains_key("filter"));
    assert!(ruleset.tables.contains_key("nat"));
    assert!(ruleset.tables.contains_key("mangle"));
}

#[test]
fn test_user_chain_jump() {
    let input = "*filter\n:INPUT ACCEPT [0:0]\n:MY-CHAIN - [0:0]\n-A INPUT -j MY-CHAIN\n-A MY-CHAIN -p tcp --dport 80 -j ACCEPT\n-A MY-CHAIN -j RETURN\nCOMMIT\n";
    let ruleset = parse_iptables_save(input).unwrap();
    let filter = ruleset.tables.get("filter").unwrap();

    let input_chain = filter.chains.get("INPUT").unwrap();
    let jump_rule = input_chain.rules[0].parsed.as_ref().unwrap();
    assert_eq!(jump_rule.target, Some(Target::Jump("MY-CHAIN".to_string())));

    let my_chain = filter.chains.get("MY-CHAIN").unwrap();
    assert_eq!(my_chain.policy, None); // user chain
    assert_eq!(my_chain.rules.len(), 2);
    let ret_rule = my_chain.rules[1].parsed.as_ref().unwrap();
    assert_eq!(ret_rule.target, Some(Target::Return));
}
