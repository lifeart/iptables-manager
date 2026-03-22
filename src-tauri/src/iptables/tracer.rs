use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use super::types::{
    MatchSpec, ParsedRuleset, PortSpec, Protocol, RuleSpec, Target,
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Incoming,
    Forwarded,
    Outgoing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConntrackState {
    New,
    Established,
    Related,
    Invalid,
    Untracked,
}

impl ConntrackState {
    fn as_str(&self) -> &str {
        match self {
            ConntrackState::New => "NEW",
            ConntrackState::Established => "ESTABLISHED",
            ConntrackState::Related => "RELATED",
            ConntrackState::Invalid => "INVALID",
            ConntrackState::Untracked => "UNTRACKED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestPacket {
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub protocol: Protocol,
    pub dest_port: Option<u16>,
    pub interface_in: String,
    pub direction: Direction,
    pub conntrack_state: ConntrackState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
    Unsimulatable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainTraversal {
    pub table: String,
    pub chain: String,
    pub rules_evaluated: usize,
    pub matched_rule_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    pub path: Vec<ChainTraversal>,
    pub verdict: Verdict,
    pub matching_rule: Option<String>,
    pub explanation: String,
    pub near_misses: Vec<String>,
}

// ---------------------------------------------------------------------------
// Unsimulatable modules
// ---------------------------------------------------------------------------

const UNSIMULATABLE_MODULES: &[&str] = &[
    "recent",
    "hashlimit",
    "connlimit",
    "time",
    "owner",
    "string",
    "statistic",
];

// ---------------------------------------------------------------------------
// CIDR matching
// ---------------------------------------------------------------------------

/// Parse a CIDR string like "10.0.0.0/8" or a bare IP "1.2.3.4" (treated as /32 or /128).
fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    if let Some(idx) = s.find('/') {
        let ip: IpAddr = s[..idx].parse().ok()?;
        let prefix: u8 = s[idx + 1..].parse().ok()?;
        Some((ip, prefix))
    } else {
        let ip: IpAddr = s.parse().ok()?;
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Some((ip, prefix))
    }
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let (net_ip, prefix) = match parse_cidr(cidr) {
        Some(v) => v,
        None => return false,
    };

    // Must be same address family
    match (&ip, &net_ip) {
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => return false,
        _ => {}
    }

    let max_bits = match ip {
        IpAddr::V4(_) => 32u8,
        IpAddr::V6(_) => 128u8,
    };

    if prefix == 0 {
        return true;
    }
    if prefix > max_bits {
        return false;
    }

    let shift = (max_bits - prefix) as u32;
    let ip_val = ip_to_u128(ip);
    let net_val = ip_to_u128(net_ip);

    (ip_val >> shift) == (net_val >> shift)
}

// ---------------------------------------------------------------------------
// Rule matching helpers
// ---------------------------------------------------------------------------

fn protocol_matches(rule_proto: &Protocol, packet_proto: &Protocol) -> bool {
    match rule_proto {
        Protocol::All => true,
        other => other == packet_proto,
    }
}

fn port_matches(spec: &PortSpec, port: u16) -> bool {
    match spec {
        PortSpec::Single(p) => *p == port,
        PortSpec::Multi(ports) => ports.contains(&port),
        PortSpec::Range(lo, hi) => port >= *lo && port <= *hi,
    }
}

fn interface_matches(spec_name: &str, actual: &str) -> bool {
    if spec_name.ends_with('+') {
        actual.starts_with(&spec_name[..spec_name.len() - 1])
    } else {
        spec_name == actual
    }
}

/// Check if a match module list contains any unsimulatable module.
/// Returns the first unsimulatable module name found, or None.
fn find_unsimulatable_module(matches: &[MatchSpec]) -> Option<&str> {
    for m in matches {
        if UNSIMULATABLE_MODULES.contains(&m.module.as_str()) {
            return Some(&m.module);
        }
    }
    None
}

/// Check if conntrack state matches the rule's conntrack match.
fn conntrack_state_matches(matches: &[MatchSpec], state: &ConntrackState) -> bool {
    for m in matches {
        if m.module == "conntrack" || m.module == "state" {
            for (i, arg) in m.args.iter().enumerate() {
                if (arg == "--ctstate" || arg == "--state") && i + 1 < m.args.len() {
                    let states_str = &m.args[i + 1];
                    let states: Vec<&str> = states_str.split(',').collect();
                    return states.contains(&state.as_str());
                }
            }
        }
    }
    // No conntrack match in rule — conntrack condition is not relevant, rule matches any state.
    true
}

/// Check if a rule's match modules have port specifications (multiport).
fn get_multiport_dports(matches: &[MatchSpec]) -> Option<PortSpec> {
    for m in matches {
        if m.module == "multiport" {
            for (i, arg) in m.args.iter().enumerate() {
                if arg == "--dports" && i + 1 < m.args.len() {
                    return PortSpec::parse(&m.args[i + 1]);
                }
            }
        }
    }
    None
}

/// Evaluate one rule against a packet. Returns:
///  - Ok(Some(target)) if rule matches
///  - Ok(None) if rule does not match
///  - Err(module_name) if an unsimulatable module is encountered
fn evaluate_rule<'a>(spec: &'a RuleSpec, packet: &TestPacket) -> Result<Option<&'a Target>, String> {
    // Check for unsimulatable modules first
    if let Some(module) = find_unsimulatable_module(&spec.matches) {
        return Err(module.to_string());
    }

    // Protocol
    if let Some(ref proto) = spec.protocol {
        let m = protocol_matches(proto, &packet.protocol);
        if spec.protocol_negated {
            if m {
                return Ok(None);
            }
        } else if !m {
            return Ok(None);
        }
    }

    // Source IP
    if let Some(ref src) = spec.source {
        let m = ip_in_cidr(packet.source_ip, &src.addr);
        if src.negated {
            if m {
                return Ok(None);
            }
        } else if !m {
            return Ok(None);
        }
    }

    // Destination IP
    if let Some(ref dst) = spec.destination {
        let m = ip_in_cidr(packet.dest_ip, &dst.addr);
        if dst.negated {
            if m {
                return Ok(None);
            }
        } else if !m {
            return Ok(None);
        }
    }

    // Input interface
    if let Some(ref iface) = spec.in_iface {
        let m = interface_matches(&iface.name, &packet.interface_in);
        if iface.negated {
            if m {
                return Ok(None);
            }
        } else if !m {
            return Ok(None);
        }
    }

    // Dest port (rule-level --dport)
    if let Some(ref port_spec) = spec.dest_port {
        if let Some(pkt_port) = packet.dest_port {
            if !port_matches(port_spec, pkt_port) {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }
    }

    // Multiport --dports from match modules
    if let Some(mp) = get_multiport_dports(&spec.matches) {
        if let Some(pkt_port) = packet.dest_port {
            if !port_matches(&mp, pkt_port) {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }
    }

    // Conntrack state
    if !conntrack_state_matches(&spec.matches, &packet.conntrack_state) {
        return Ok(None);
    }

    // If we reach here, all criteria matched.
    Ok(spec.target.as_ref())
}

// ---------------------------------------------------------------------------
// Chain traversal
// ---------------------------------------------------------------------------

enum ChainResult {
    /// A terminal verdict was reached.
    Terminal(Verdict, String),
    /// RETURN from a user chain (continue in calling chain).
    Return,
    /// No rule matched, fall through (equivalent to RETURN for user chains).
    FallThrough,
    /// An unsimulatable module was hit.
    Unsimulatable(String),
}

fn traverse_chain(
    ruleset: &ParsedRuleset,
    table_name: &str,
    chain_name: &str,
    packet: &TestPacket,
    path: &mut Vec<ChainTraversal>,
    near_misses: &mut Vec<String>,
    depth: usize,
) -> ChainResult {
    if depth > 20 {
        return ChainResult::Unsimulatable("Chain jump depth limit (20) exceeded".to_string());
    }

    let table = match ruleset.tables.get(table_name) {
        Some(t) => t,
        None => {
            // Table doesn't exist — nothing to evaluate.
            path.push(ChainTraversal {
                table: table_name.to_string(),
                chain: chain_name.to_string(),
                rules_evaluated: 0,
                matched_rule_index: None,
            });
            return ChainResult::FallThrough;
        }
    };

    let chain = match table.chains.get(chain_name) {
        Some(c) => c,
        None => {
            path.push(ChainTraversal {
                table: table_name.to_string(),
                chain: chain_name.to_string(),
                rules_evaluated: 0,
                matched_rule_index: None,
            });
            return ChainResult::FallThrough;
        }
    };

    let mut rules_evaluated = 0;

    for (i, rule) in chain.rules.iter().enumerate() {
        let spec = match &rule.parsed {
            Some(s) => s,
            None => {
                rules_evaluated += 1;
                continue;
            }
        };

        rules_evaluated += 1;

        match evaluate_rule(spec, packet) {
            Err(module_name) => {
                path.push(ChainTraversal {
                    table: table_name.to_string(),
                    chain: chain_name.to_string(),
                    rules_evaluated,
                    matched_rule_index: Some(i),
                });
                return ChainResult::Unsimulatable(format!(
                    "Rule uses -m {} which cannot be simulated",
                    module_name
                ));
            }
            Ok(None) => {
                // Near miss: check if the rule is a "close" match — only one criterion off.
                // Simple heuristic: if target is Accept/Drop/Reject and protocol matched,
                // report it as near miss.
                if let Some(ref target) = spec.target {
                    match target {
                        Target::Accept | Target::Drop | Target::Reject => {
                            if let Some(ref proto) = spec.protocol {
                                if protocol_matches(proto, &packet.protocol) {
                                    near_misses.push(rule.raw.clone());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                continue;
            }
            Ok(Some(target)) => {
                path.push(ChainTraversal {
                    table: table_name.to_string(),
                    chain: chain_name.to_string(),
                    rules_evaluated,
                    matched_rule_index: Some(i),
                });

                match target {
                    Target::Accept => {
                        return ChainResult::Terminal(Verdict::Accept, rule.raw.clone())
                    }
                    Target::Drop => {
                        return ChainResult::Terminal(Verdict::Drop, rule.raw.clone())
                    }
                    Target::Reject => {
                        return ChainResult::Terminal(Verdict::Reject, rule.raw.clone())
                    }
                    Target::Return => {
                        return ChainResult::Return;
                    }
                    Target::Log => {
                        // LOG is non-terminating, continue evaluation.
                        // But we already pushed a traversal entry — that's fine, it shows the log hit.
                        continue;
                    }
                    Target::Jump(ref target_chain) => {
                        let result = traverse_chain(
                            ruleset,
                            table_name,
                            target_chain,
                            packet,
                            path,
                            near_misses,
                            depth + 1,
                        );
                        match result {
                            ChainResult::Terminal(v, r) => {
                                return ChainResult::Terminal(v, r);
                            }
                            ChainResult::Unsimulatable(msg) => {
                                return ChainResult::Unsimulatable(msg);
                            }
                            ChainResult::Return | ChainResult::FallThrough => {
                                // Continue evaluating rules after the jump.
                                continue;
                            }
                        }
                    }
                    // Non-terminal targets (MARK, LOG, SNAT, DNAT, MASQUERADE, etc.)
                    _ => continue,
                }
            }
        }
    }

    // No rule matched. Record traversal.
    path.push(ChainTraversal {
        table: table_name.to_string(),
        chain: chain_name.to_string(),
        rules_evaluated,
        matched_rule_index: None,
    });

    // For built-in chains, apply chain policy.
    if let Some(ref policy) = chain.policy {
        match policy.as_str() {
            "DROP" => {
                return ChainResult::Terminal(
                    Verdict::Drop,
                    format!("Default policy {} for {}/{}", policy, table_name, chain_name),
                );
            }
            "ACCEPT" => {
                return ChainResult::Terminal(
                    Verdict::Accept,
                    format!("Default policy {} for {}/{}", policy, table_name, chain_name),
                );
            }
            "REJECT" => {
                return ChainResult::Terminal(
                    Verdict::Reject,
                    format!("Default policy {} for {}/{}", policy, table_name, chain_name),
                );
            }
            _ => {}
        }
    }

    ChainResult::FallThrough
}

// ---------------------------------------------------------------------------
// Netfilter paths
// ---------------------------------------------------------------------------

/// The three netfilter traversal paths.
fn get_chain_sequence(direction: &Direction) -> Vec<(&'static str, &'static str)> {
    match direction {
        Direction::Incoming => vec![
            ("raw", "PREROUTING"),
            ("mangle", "PREROUTING"),
            ("nat", "PREROUTING"),
            // routing decision (implicit)
            ("filter", "INPUT"),
        ],
        Direction::Forwarded => vec![
            ("raw", "PREROUTING"),
            ("mangle", "PREROUTING"),
            ("nat", "PREROUTING"),
            // routing decision (implicit)
            ("filter", "FORWARD"),
            ("nat", "POSTROUTING"),
        ],
        Direction::Outgoing => vec![
            ("raw", "OUTPUT"),
            ("mangle", "OUTPUT"),
            ("nat", "OUTPUT"),
            // routing decision (implicit)
            ("filter", "OUTPUT"),
            ("nat", "POSTROUTING"),
        ],
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn trace_packet(ruleset: &ParsedRuleset, packet: &TestPacket) -> TraceResult {
    let chain_seq = get_chain_sequence(&packet.direction);
    let mut path = Vec::new();
    let mut near_misses = Vec::new();

    for (table, chain) in chain_seq {
        let result =
            traverse_chain(ruleset, table, chain, packet, &mut path, &mut near_misses, 0);

        match result {
            ChainResult::Terminal(verdict, matching_rule) => {
                let explanation = format!(
                    "Packet {:?} {} -> {}:{} via {} reached verdict {:?} at {}/{}",
                    packet.protocol,
                    packet.source_ip,
                    packet.dest_ip,
                    packet.dest_port.map_or("*".to_string(), |p| p.to_string()),
                    packet.interface_in,
                    verdict,
                    table,
                    chain,
                );
                return TraceResult {
                    path,
                    verdict,
                    matching_rule: Some(matching_rule),
                    explanation,
                    near_misses,
                };
            }
            ChainResult::Unsimulatable(msg) => {
                return TraceResult {
                    path,
                    verdict: Verdict::Unsimulatable,
                    matching_rule: None,
                    explanation: msg,
                    near_misses,
                };
            }
            ChainResult::Return | ChainResult::FallThrough => {
                // Continue to next table/chain in the path.
            }
        }
    }

    // If we exhausted all chains without a terminal verdict, default ACCEPT.
    TraceResult {
        path,
        verdict: Verdict::Accept,
        matching_rule: None,
        explanation: "Packet traversed all chains without being dropped".to_string(),
        near_misses,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iptables::types::*;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Helper to build a minimal ruleset.
    fn empty_ruleset() -> ParsedRuleset {
        ParsedRuleset {
            tables: HashMap::new(),
            header_comments: vec![],
        }
    }

    fn make_chain(name: &str, policy: Option<&str>, rules: Vec<ParsedRule>) -> ChainState {
        ChainState {
            name: name.to_string(),
            policy: policy.map(|s| s.to_string()),
            counters: None,
            rules,
            owner: ChainOwner::BuiltIn,
        }
    }

    fn make_rule(table: &str, chain: &str, raw: &str, spec: RuleSpec) -> ParsedRule {
        ParsedRule {
            raw: raw.to_string(),
            parsed: Some(spec),
            warnings: vec![],
            chain: chain.to_string(),
            table: table.to_string(),
        }
    }

    fn default_spec() -> RuleSpec {
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

    fn ssh_packet() -> TestPacket {
        TestPacket {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            protocol: Protocol::Tcp,
            dest_port: Some(22),
            interface_in: "eth0".to_string(),
            direction: Direction::Incoming,
            conntrack_state: ConntrackState::New,
        }
    }

    #[test]
    fn test_ssh_allowed() {
        let mut ruleset = empty_ruleset();

        let rule = make_rule(
            "filter",
            "INPUT",
            "-A INPUT -p tcp --dport 22 -j ACCEPT",
            RuleSpec {
                protocol: Some(Protocol::Tcp),
                dest_port: Some(PortSpec::Single(22)),
                target: Some(Target::Accept),
                ..default_spec()
            },
        );

        let input_chain = make_chain("INPUT", Some("DROP"), vec![rule]);
        let mut filter = TableState {
            name: "filter".to_string(),
            chains: HashMap::new(),
        };
        filter.chains.insert("INPUT".to_string(), input_chain);
        ruleset.tables.insert("filter".to_string(), filter);

        let result = trace_packet(&ruleset, &ssh_packet());
        assert_eq!(result.verdict, Verdict::Accept);
        assert!(result.matching_rule.is_some());
        assert!(result
            .matching_rule
            .unwrap()
            .contains("-A INPUT -p tcp --dport 22 -j ACCEPT"));
    }

    #[test]
    fn test_ssh_blocked_by_policy() {
        let mut ruleset = empty_ruleset();

        // No rules that match SSH — policy DROP should apply.
        let http_rule = make_rule(
            "filter",
            "INPUT",
            "-A INPUT -p tcp --dport 80 -j ACCEPT",
            RuleSpec {
                protocol: Some(Protocol::Tcp),
                dest_port: Some(PortSpec::Single(80)),
                target: Some(Target::Accept),
                ..default_spec()
            },
        );

        let input_chain = make_chain("INPUT", Some("DROP"), vec![http_rule]);
        let mut filter = TableState {
            name: "filter".to_string(),
            chains: HashMap::new(),
        };
        filter.chains.insert("INPUT".to_string(), input_chain);
        ruleset.tables.insert("filter".to_string(), filter);

        let result = trace_packet(&ruleset, &ssh_packet());
        assert_eq!(result.verdict, Verdict::Drop);
        assert!(result.matching_rule.is_some());
        assert!(result.matching_rule.unwrap().contains("Default policy DROP"));
    }

    #[test]
    fn test_forwarded_packet() {
        let mut ruleset = empty_ruleset();

        let rule = make_rule(
            "filter",
            "FORWARD",
            "-A FORWARD -p tcp --dport 80 -j ACCEPT",
            RuleSpec {
                protocol: Some(Protocol::Tcp),
                dest_port: Some(PortSpec::Single(80)),
                target: Some(Target::Accept),
                ..default_spec()
            },
        );

        let fwd_chain = make_chain("FORWARD", Some("DROP"), vec![rule]);
        let mut filter = TableState {
            name: "filter".to_string(),
            chains: HashMap::new(),
        };
        filter.chains.insert("FORWARD".to_string(), fwd_chain);
        ruleset.tables.insert("filter".to_string(), filter);

        let packet = TestPacket {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            protocol: Protocol::Tcp,
            dest_port: Some(80),
            interface_in: "eth0".to_string(),
            direction: Direction::Forwarded,
            conntrack_state: ConntrackState::New,
        };

        let result = trace_packet(&ruleset, &packet);
        assert_eq!(result.verdict, Verdict::Accept);
    }

    #[test]
    fn test_custom_chain_jump() {
        let mut ruleset = empty_ruleset();

        // INPUT jumps to TR-INPUT, TR-INPUT accepts SSH.
        let jump_rule = make_rule(
            "filter",
            "INPUT",
            "-A INPUT -j TR-INPUT",
            RuleSpec {
                target: Some(Target::Jump("TR-INPUT".to_string())),
                ..default_spec()
            },
        );

        let ssh_accept = make_rule(
            "filter",
            "TR-INPUT",
            "-A TR-INPUT -p tcp --dport 22 -j ACCEPT",
            RuleSpec {
                protocol: Some(Protocol::Tcp),
                dest_port: Some(PortSpec::Single(22)),
                target: Some(Target::Accept),
                ..default_spec()
            },
        );

        let input_chain = make_chain("INPUT", Some("DROP"), vec![jump_rule]);
        let tr_input_chain = make_chain("TR-INPUT", None, vec![ssh_accept]);

        let mut filter = TableState {
            name: "filter".to_string(),
            chains: HashMap::new(),
        };
        filter.chains.insert("INPUT".to_string(), input_chain);
        filter
            .chains
            .insert("TR-INPUT".to_string(), tr_input_chain);
        ruleset.tables.insert("filter".to_string(), filter);

        let result = trace_packet(&ruleset, &ssh_packet());
        assert_eq!(result.verdict, Verdict::Accept);
        // Path should show both INPUT and TR-INPUT traversal.
        let chain_names: Vec<&str> = result.path.iter().map(|t| t.chain.as_str()).collect();
        assert!(chain_names.contains(&"INPUT"));
        assert!(chain_names.contains(&"TR-INPUT"));
    }

    #[test]
    fn test_unsimulatable_module() {
        let mut ruleset = empty_ruleset();

        let rule = make_rule(
            "filter",
            "INPUT",
            "-A INPUT -p tcp --dport 22 -m recent --set -j ACCEPT",
            RuleSpec {
                protocol: Some(Protocol::Tcp),
                dest_port: Some(PortSpec::Single(22)),
                matches: vec![MatchSpec {
                    module: "recent".to_string(),
                    args: vec!["--set".to_string()],
                }],
                target: Some(Target::Accept),
                ..default_spec()
            },
        );

        let input_chain = make_chain("INPUT", Some("DROP"), vec![rule]);
        let mut filter = TableState {
            name: "filter".to_string(),
            chains: HashMap::new(),
        };
        filter.chains.insert("INPUT".to_string(), input_chain);
        ruleset.tables.insert("filter".to_string(), filter);

        let result = trace_packet(&ruleset, &ssh_packet());
        assert_eq!(result.verdict, Verdict::Unsimulatable);
        assert!(result.explanation.contains("recent"));
    }

    #[test]
    fn test_cidr_matching_ipv4() {
        assert!(ip_in_cidr(
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            "10.0.0.0/8"
        ));
        assert!(!ip_in_cidr(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            "10.0.0.0/8"
        ));
        assert!(ip_in_cidr(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            "0.0.0.0/0"
        ));
    }

    #[test]
    fn test_cidr_matching_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(ip_in_cidr(ip, "2001:db8::/32"));
        assert!(!ip_in_cidr(ip, "2001:db9::/32"));
        assert!(ip_in_cidr(ip, "::/0"));
    }

    #[test]
    fn test_return_from_custom_chain() {
        let mut ruleset = empty_ruleset();

        // TR-CHECK returns without matching, then INPUT has an accept rule.
        let return_rule = make_rule(
            "filter",
            "TR-CHECK",
            "-A TR-CHECK -j RETURN",
            RuleSpec {
                target: Some(Target::Return),
                ..default_spec()
            },
        );

        let jump_rule = make_rule(
            "filter",
            "INPUT",
            "-A INPUT -j TR-CHECK",
            RuleSpec {
                target: Some(Target::Jump("TR-CHECK".to_string())),
                ..default_spec()
            },
        );

        let accept_rule = make_rule(
            "filter",
            "INPUT",
            "-A INPUT -p tcp --dport 22 -j ACCEPT",
            RuleSpec {
                protocol: Some(Protocol::Tcp),
                dest_port: Some(PortSpec::Single(22)),
                target: Some(Target::Accept),
                ..default_spec()
            },
        );

        let input_chain = make_chain("INPUT", Some("DROP"), vec![jump_rule, accept_rule]);
        let check_chain = make_chain("TR-CHECK", None, vec![return_rule]);

        let mut filter = TableState {
            name: "filter".to_string(),
            chains: HashMap::new(),
        };
        filter.chains.insert("INPUT".to_string(), input_chain);
        filter
            .chains
            .insert("TR-CHECK".to_string(), check_chain);
        ruleset.tables.insert("filter".to_string(), filter);

        let result = trace_packet(&ruleset, &ssh_packet());
        assert_eq!(result.verdict, Verdict::Accept);
    }

    #[test]
    fn test_source_cidr_match() {
        let mut ruleset = empty_ruleset();

        let rule = make_rule(
            "filter",
            "INPUT",
            "-A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT",
            RuleSpec {
                protocol: Some(Protocol::Tcp),
                source: Some(AddressSpec {
                    addr: "192.168.1.0/24".to_string(),
                    negated: false,
                }),
                dest_port: Some(PortSpec::Single(22)),
                target: Some(Target::Accept),
                ..default_spec()
            },
        );

        let input_chain = make_chain("INPUT", Some("DROP"), vec![rule]);
        let mut filter = TableState {
            name: "filter".to_string(),
            chains: HashMap::new(),
        };
        filter.chains.insert("INPUT".to_string(), input_chain);
        ruleset.tables.insert("filter".to_string(), filter);

        let result = trace_packet(&ruleset, &ssh_packet());
        assert_eq!(result.verdict, Verdict::Accept);

        // Packet from different subnet should be dropped.
        let mut other_packet = ssh_packet();
        other_packet.source_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let result2 = trace_packet(&ruleset, &other_packet);
        assert_eq!(result2.verdict, Verdict::Drop);
    }
}
