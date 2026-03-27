//! Duplicate rule detection.
//!
//! Compares a proposed rule (from the frontend, as JSON) against existing parsed
//! rules (from `iptables-save`) and returns the best match with a similarity score.

use serde::Deserialize;

use super::types::{ParsedRule, ParsedRuleset, PortSpec, Protocol, Target};

// ---------------------------------------------------------------------------
// Proposed rule — minimal struct deserialized from the frontend JSON
// ---------------------------------------------------------------------------

/// Protocol value from the frontend — can be a name ("tcp") or IANA number (6).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ProposedProtocol {
    Named(String),
    Number(u16),
}

/// Minimal fields extracted from the frontend `Rule` type for comparison.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedRule {
    /// "incoming" | "outgoing" | "forwarded"
    pub direction: Option<String>,
    /// "tcp" | "udp" | "icmp" | ... | 6 | 17 | ...
    pub protocol: Option<ProposedProtocol>,
    /// Port specification
    pub ports: Option<ProposedPortSpec>,
    /// Source address
    pub source: Option<ProposedAddress>,
    /// Destination address
    pub destination: Option<ProposedAddress>,
    /// "allow" | "block" | "block-reject" | "log" | ...
    pub action: Option<String>,
    /// Inbound interface name
    pub interface_in: Option<String>,
    /// Outbound interface name
    pub interface_out: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ProposedPortSpec {
    Single { port: u16 },
    Range { from: u16, to: u16 },
    Multi { ports: Vec<u16> },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ProposedAddress {
    Anyone,
    Cidr { value: String },
    Iplist { ip_list_id: String },
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DuplicateMatch {
    /// Index of the matching rule (chain-relative, for identification).
    pub rule_index: usize,
    /// Table + chain, e.g. "filter/INPUT".
    pub rule_id: String,
    /// Similarity 0.0 .. 1.0
    pub similarity: f64,
}

// ---------------------------------------------------------------------------
// Normalization helpers
// ---------------------------------------------------------------------------

fn direction_to_chain(direction: &str) -> &str {
    match direction {
        "incoming" => "INPUT",
        "outgoing" => "OUTPUT",
        "forwarded" => "FORWARD",
        _ => direction,
    }
}

fn action_to_target(action: &str) -> Option<Target> {
    match action {
        "allow" => Some(Target::Accept),
        "block" => Some(Target::Drop),
        "block-reject" => Some(Target::Reject),
        "log" | "log-block" => Some(Target::Log),
        "dnat" => Some(Target::Dnat),
        "snat" => Some(Target::Snat),
        "masquerade" => Some(Target::Masquerade),
        _ => None,
    }
}

fn proposed_protocol(p: &ProposedProtocol) -> Protocol {
    match p {
        ProposedProtocol::Named(s) => Protocol::from_str_loose(s),
        ProposedProtocol::Number(n) => Protocol::from_str_loose(&n.to_string()),
    }
}

fn proposed_port_to_spec(p: &ProposedPortSpec) -> PortSpec {
    match p {
        ProposedPortSpec::Single { port } => PortSpec::Single(*port),
        ProposedPortSpec::Range { from, to } => PortSpec::Range(*from, *to),
        ProposedPortSpec::Multi { ports } => PortSpec::Multi(ports.clone()),
    }
}

fn proposed_addr_string(a: &ProposedAddress) -> Option<String> {
    match a {
        ProposedAddress::Anyone => None,
        ProposedAddress::Cidr { value } => Some(value.clone()),
        ProposedAddress::Iplist { .. } => None, // can't compare IP list by content here
    }
}

// ---------------------------------------------------------------------------
// Port equality
// ---------------------------------------------------------------------------

fn port_specs_equal(a: &PortSpec, b: &PortSpec) -> bool {
    match (a, b) {
        (PortSpec::Single(x), PortSpec::Single(y)) => x == y,
        (PortSpec::Range(a1, a2), PortSpec::Range(b1, b2)) => a1 == b1 && a2 == b2,
        (PortSpec::Multi(va), PortSpec::Multi(vb)) => {
            let mut sa = va.clone();
            let mut sb = vb.clone();
            sa.sort();
            sb.sort();
            sa == sb
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Address equality (normalized)
// ---------------------------------------------------------------------------

fn addrs_equal(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => normalize_addr(x) == normalize_addr(y),
        _ => false,
    }
}

fn normalize_addr(s: &str) -> String {
    let s = s.trim();
    // Strip /32 for IPv4 and /128 for IPv6 — these are equivalent to bare IPs.
    if let Some(stripped) = s.strip_suffix("/32") {
        if !stripped.contains(':') {
            return stripped.to_string();
        }
    }
    if let Some(stripped) = s.strip_suffix("/128") {
        if stripped.contains(':') {
            return stripped.to_string();
        }
    }
    // Treat 0.0.0.0/0 and ::/0 as "any" → empty
    if s == "0.0.0.0/0" || s == "::/0" {
        return String::new();
    }
    s.to_string()
}

// ---------------------------------------------------------------------------
// Similarity scoring
// ---------------------------------------------------------------------------

/// Compare a proposed rule against an existing parsed rule.
/// Returns a similarity score from 0.0 to 1.0.
fn compute_similarity(proposed: &ProposedRule, existing: &ParsedRule) -> f64 {
    let spec = match &existing.parsed {
        Some(s) => s,
        None => return 0.0,
    };

    // We compare up to 5 fields, each worth 1 point:
    // 1. chain (direction)
    // 2. protocol
    // 3. destination port
    // 4. source address
    // 5. target (action)
    //
    // Destination address is a bonus 6th field if present.

    let mut matched = 0u32;
    let mut total = 0u32;

    // 1. Chain / direction
    total += 1;
    let proposed_chain = proposed
        .direction
        .as_deref()
        .map(direction_to_chain)
        .unwrap_or("");
    if !proposed_chain.is_empty() && existing.chain.eq_ignore_ascii_case(proposed_chain) {
        matched += 1;
    } else if proposed_chain.is_empty() {
        // No direction specified — don't penalize, but don't reward either.
        total -= 1;
    }

    // 2. Protocol (negation-aware: proposed rules are never negated)
    total += 1;
    let proto_match = match (&proposed.protocol, &spec.protocol) {
        (Some(pp), Some(ep)) => {
            let names_match = proposed_protocol(pp) == *ep;
            // If the existing rule negates the protocol, same name means NO match
            if spec.protocol_negated {
                !names_match
            } else {
                names_match
            }
        }
        (None, None) => true,
        (None, Some(Protocol::All)) => !spec.protocol_negated,
        _ => false,
    };
    if proto_match {
        matched += 1;
    }

    // 3. Destination port
    total += 1;
    let port_match = match (&proposed.ports, &spec.dest_port) {
        (Some(pp), Some(ep)) => port_specs_equal(&proposed_port_to_spec(pp), ep),
        (None, None) => true,
        _ => false,
    };
    if port_match {
        matched += 1;
    }

    // 4. Source address (negation-aware: proposed rules are never negated)
    total += 1;
    let src_negated = spec.source.as_ref().map_or(false, |a| a.negated);
    let proposed_src = proposed.source.as_ref().and_then(proposed_addr_string);
    let existing_src = spec.source.as_ref().map(|a| a.addr.clone());
    let norm_proposed_src = proposed_src.as_ref().map(|s| normalize_addr(s));
    let norm_existing_src = existing_src.as_ref().map(|s| normalize_addr(s));
    // Treat empty normalized strings as None (= any)
    let eff_proposed_src = norm_proposed_src.filter(|s| !s.is_empty());
    let eff_existing_src = norm_existing_src.filter(|s| !s.is_empty());
    let src_match = if src_negated && addrs_equal(&eff_proposed_src, &eff_existing_src) {
        // Existing rule negates this source — same address means opposite semantics
        false
    } else if src_negated {
        // Different addresses with negation — could overlap, treat as no match
        false
    } else {
        addrs_equal(&eff_proposed_src, &eff_existing_src)
    };
    if src_match {
        matched += 1;
    }

    // 5. Target / action
    total += 1;
    let target_match = match (&proposed.action, &spec.target) {
        (Some(pa), Some(et)) => {
            if let Some(pt) = action_to_target(pa) {
                pt == *et
            } else {
                false
            }
        }
        (None, None) => true,
        _ => false,
    };
    if target_match {
        matched += 1;
    }

    // 6. Destination address (negation-aware)
    total += 1;
    let dst_negated = spec.destination.as_ref().map_or(false, |a| a.negated);
    let proposed_dst = proposed.destination.as_ref().and_then(proposed_addr_string);
    let existing_dst = spec.destination.as_ref().map(|a| a.addr.clone());
    let norm_proposed_dst = proposed_dst.as_ref().map(|s| normalize_addr(s));
    let norm_existing_dst = existing_dst.as_ref().map(|s| normalize_addr(s));
    let eff_proposed_dst = norm_proposed_dst.filter(|s| !s.is_empty());
    let eff_existing_dst = norm_existing_dst.filter(|s| !s.is_empty());
    let dst_match = if dst_negated && addrs_equal(&eff_proposed_dst, &eff_existing_dst) {
        false
    } else if dst_negated {
        false
    } else {
        addrs_equal(&eff_proposed_dst, &eff_existing_dst)
    };
    if dst_match {
        matched += 1;
    }

    // 7. Inbound interface
    total += 1;
    let iface_in_match = match (&proposed.interface_in, &spec.in_iface) {
        (Some(pi), Some(ei)) => pi.eq_ignore_ascii_case(&ei.name),
        (None, _) | (_, None) => true, // one side is "any" → match
    };
    if iface_in_match {
        matched += 1;
    }

    // 8. Outbound interface
    total += 1;
    let iface_out_match = match (&proposed.interface_out, &spec.out_iface) {
        (Some(po), Some(eo)) => po.eq_ignore_ascii_case(&eo.name),
        (None, _) | (_, None) => true, // one side is "any" → match
    };
    if iface_out_match {
        matched += 1;
    }

    if total == 0 {
        return 0.0;
    }

    matched as f64 / total as f64
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check a proposed rule against all existing rules in the parsed ruleset.
/// Returns the best match (highest similarity), if any, with similarity >= threshold.
pub fn check_duplicate(
    proposed: &ProposedRule,
    ruleset: &ParsedRuleset,
    threshold: f64,
) -> Option<DuplicateMatch> {
    let mut best: Option<DuplicateMatch> = None;

    for (table_name, table) in &ruleset.tables {
        for (chain_name, chain) in &table.chains {
            for (idx, rule) in chain.rules.iter().enumerate() {
                let sim = compute_similarity(proposed, rule);
                if sim >= threshold {
                    let dominated = match &best {
                        Some(b) => sim > b.similarity,
                        None => true,
                    };
                    if dominated {
                        best = Some(DuplicateMatch {
                            rule_index: idx,
                            rule_id: format!("{}/{}/{}",table_name, chain_name, idx),
                            similarity: sim,
                        });
                    }
                }
            }
        }
    }

    best
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iptables::parser::parse_iptables_save;

    fn make_ruleset(iptables_save: &str) -> ParsedRuleset {
        parse_iptables_save(iptables_save).expect("parse should succeed")
    }

    fn proposed(
        direction: &str,
        protocol: &str,
        port: Option<u16>,
        source: Option<&str>,
        action: &str,
    ) -> ProposedRule {
        ProposedRule {
            direction: Some(direction.to_string()),
            protocol: if protocol.is_empty() {
                None
            } else {
                Some(ProposedProtocol::Named(protocol.to_string()))
            },
            ports: port.map(|p| ProposedPortSpec::Single { port: p }),
            source: source.map(|s| {
                if s == "any" {
                    ProposedAddress::Anyone
                } else {
                    ProposedAddress::Cidr {
                        value: s.to_string(),
                    }
                }
            }),
            destination: None,
            action: Some(action.to_string()),
            interface_in: None,
            interface_out: None,
        }
    }

    static SAMPLE_IPTABLES_SAVE: &str = "\
# Generated by iptables-save
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 3306 -j ACCEPT
-A INPUT -p udp -m udp --dport 53 -j DROP
-A INPUT -j DROP
COMMIT
";

    #[test]
    fn exact_duplicate_returns_1_0() {
        let ruleset = make_ruleset(SAMPLE_IPTABLES_SAVE);
        let p = proposed("incoming", "tcp", Some(22), None, "allow");
        let result = check_duplicate(&p, &ruleset, 0.5);
        assert!(result.is_some(), "should find a duplicate");
        let m = result.unwrap();
        assert!(
            (m.similarity - 1.0).abs() < f64::EPSILON,
            "similarity should be 1.0, got {}",
            m.similarity
        );
        assert!(m.rule_id.contains("INPUT"), "should match INPUT chain");
    }

    #[test]
    fn no_match_below_threshold() {
        let ruleset = make_ruleset(SAMPLE_IPTABLES_SAVE);
        // Completely different rule: outgoing UDP port 9999 REJECT
        let p = proposed("outgoing", "udp", Some(9999), None, "block-reject");
        let result = check_duplicate(&p, &ruleset, 0.8);
        assert!(result.is_none(), "should not find a duplicate above 0.8");
    }

    #[test]
    fn partial_match_same_port_different_action() {
        let ruleset = make_ruleset(SAMPLE_IPTABLES_SAVE);
        // Same chain, protocol, port as rule 0, but DROP instead of ACCEPT
        let p = proposed("incoming", "tcp", Some(22), None, "block");
        let result = check_duplicate(&p, &ruleset, 0.5);
        assert!(result.is_some(), "should find a partial match");
        let m = result.unwrap();
        // 5 out of 6 fields match (chain, protocol, port, source=any, dest=any) but not action
        assert!(
            m.similarity > 0.7 && m.similarity < 1.0,
            "should be a near-duplicate, got {}",
            m.similarity
        );
    }

    #[test]
    fn match_with_source_address() {
        let ruleset = make_ruleset(SAMPLE_IPTABLES_SAVE);
        // Matches the MySQL rule: INPUT tcp 3306 from 10.0.0.0/8 ACCEPT
        let p = proposed("incoming", "tcp", Some(3306), Some("10.0.0.0/8"), "allow");
        let result = check_duplicate(&p, &ruleset, 0.5);
        assert!(result.is_some());
        let m = result.unwrap();
        assert!(
            (m.similarity - 1.0).abs() < f64::EPSILON,
            "exact match should be 1.0, got {}",
            m.similarity
        );
    }

    #[test]
    fn different_source_reduces_similarity() {
        let ruleset = make_ruleset(SAMPLE_IPTABLES_SAVE);
        // Same as MySQL rule but different source
        let p = proposed(
            "incoming",
            "tcp",
            Some(3306),
            Some("192.168.1.0/24"),
            "allow",
        );
        let result = check_duplicate(&p, &ruleset, 0.5);
        assert!(result.is_some());
        let m = result.unwrap();
        // Should match the MySQL rule but with reduced similarity (source mismatch)
        assert!(
            m.similarity < 1.0,
            "should not be exact, got {}",
            m.similarity
        );
        assert!(
            m.similarity >= 0.5,
            "should still be above threshold, got {}",
            m.similarity
        );
    }

    #[test]
    fn drop_all_rule_matches_broadly() {
        let ruleset = make_ruleset(SAMPLE_IPTABLES_SAVE);
        // The last rule is: -A INPUT -j DROP (no protocol, no port, no source)
        // A proposed rule with just chain=INPUT action=block should match it well
        let p = ProposedRule {
            direction: Some("incoming".to_string()),
            protocol: None,
            ports: None,
            source: None,
            destination: None,
            action: Some("block".to_string()),
            interface_in: None,
            interface_out: None,
        };
        let result = check_duplicate(&p, &ruleset, 0.8);
        assert!(result.is_some(), "should match the catch-all DROP rule");
        let m = result.unwrap();
        assert!(
            m.similarity >= 0.8,
            "similarity should be high, got {}",
            m.similarity
        );
    }

    #[test]
    fn udp_rule_matches() {
        let ruleset = make_ruleset(SAMPLE_IPTABLES_SAVE);
        let p = proposed("incoming", "udp", Some(53), None, "block");
        let result = check_duplicate(&p, &ruleset, 0.9);
        assert!(result.is_some());
        let m = result.unwrap();
        assert!(
            (m.similarity - 1.0).abs() < f64::EPSILON,
            "exact match for UDP DNS drop, got {}",
            m.similarity
        );
    }

    #[test]
    fn deserialization_from_json() {
        let json = serde_json::json!({
            "direction": "incoming",
            "protocol": "tcp",
            "ports": { "type": "single", "port": 80 },
            "source": { "type": "anyone" },
            "destination": { "type": "anyone" },
            "action": "allow"
        });
        let p: ProposedRule = serde_json::from_value(json).expect("should deserialize");
        assert!(matches!(&p.protocol, Some(ProposedProtocol::Named(s)) if s == "tcp"));
    }

    #[test]
    fn deserialization_port_range() {
        let json = serde_json::json!({
            "direction": "incoming",
            "protocol": "tcp",
            "ports": { "type": "range", "from": 8000, "to": 9000 },
            "action": "allow"
        });
        let p: ProposedRule = serde_json::from_value(json).expect("should deserialize");
        assert!(matches!(
            p.ports,
            Some(ProposedPortSpec::Range { from: 8000, to: 9000 })
        ));
    }

    #[test]
    fn deserialization_multi_ports() {
        let json = serde_json::json!({
            "direction": "incoming",
            "protocol": "tcp",
            "ports": { "type": "multi", "ports": [80, 443, 8080] },
            "action": "allow"
        });
        let p: ProposedRule = serde_json::from_value(json).expect("should deserialize");
        assert!(matches!(p.ports, Some(ProposedPortSpec::Multi { .. })));
    }

    #[test]
    fn protocol_as_number_matches_tcp() {
        let ruleset = make_ruleset(SAMPLE_IPTABLES_SAVE);
        // Protocol 6 = TCP; should match the SSH rule (tcp port 22)
        let p = ProposedRule {
            direction: Some("incoming".to_string()),
            protocol: Some(ProposedProtocol::Number(6)),
            ports: Some(ProposedPortSpec::Single { port: 22 }),
            source: None,
            destination: None,
            action: Some("allow".to_string()),
            interface_in: None,
            interface_out: None,
        };
        let result = check_duplicate(&p, &ruleset, 0.5);
        assert!(result.is_some(), "protocol number 6 should match tcp rule");
        let m = result.unwrap();
        assert!(
            (m.similarity - 1.0).abs() < f64::EPSILON,
            "exact match expected, got {}",
            m.similarity
        );
    }

    #[test]
    fn deserialization_protocol_number() {
        let json = serde_json::json!({
            "direction": "incoming",
            "protocol": 6,
            "ports": { "type": "single", "port": 80 },
            "action": "allow"
        });
        let p: ProposedRule = serde_json::from_value(json).expect("should deserialize");
        assert!(matches!(&p.protocol, Some(ProposedProtocol::Number(6))));
    }

    // Helper to build a ruleset with a negated source rule
    static NEGATED_SOURCE_IPTABLES: &str = "\
*filter
:INPUT ACCEPT [0:0]
-A INPUT ! -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
";

    #[test]
    fn negated_source_does_not_match_non_negated() {
        let ruleset = make_ruleset(NEGATED_SOURCE_IPTABLES);
        // Proposed: allow tcp 22 from 10.0.0.0/8 (non-negated)
        // Existing: allow tcp 22 from ! 10.0.0.0/8 (negated)
        // Source should NOT match because of negation
        let p = proposed("incoming", "tcp", Some(22), Some("10.0.0.0/8"), "allow");
        let result = check_duplicate(&p, &ruleset, 0.0);
        assert!(result.is_some());
        let m = result.unwrap();
        // Source field should not match due to negation, so similarity < 1.0
        assert!(
            m.similarity < 1.0,
            "negated source should reduce similarity, got {}",
            m.similarity
        );
    }

    // Helper for negated protocol
    static NEGATED_PROTOCOL_IPTABLES: &str = "\
*filter
:INPUT ACCEPT [0:0]
-A INPUT ! -p tcp -m tcp --dport 80 -j DROP
COMMIT
";

    #[test]
    fn negated_protocol_does_not_match() {
        let ruleset = make_ruleset(NEGATED_PROTOCOL_IPTABLES);
        // Proposed: block tcp 80 (non-negated tcp)
        // Existing: block ! tcp 80 (negated tcp — means everything except tcp)
        let p = proposed("incoming", "tcp", Some(80), None, "block");
        let result = check_duplicate(&p, &ruleset, 0.0);
        assert!(result.is_some());
        let m = result.unwrap();
        // Protocol field should not match because existing negates tcp
        assert!(
            m.similarity < 1.0,
            "negated protocol should reduce similarity, got {}",
            m.similarity
        );
    }

    #[test]
    fn different_interfaces_reduce_similarity() {
        let ruleset = make_ruleset(SAMPLE_IPTABLES_SAVE);
        // Existing rules have no interface specified.
        // When proposed specifies an interface and existing doesn't → match (any).
        // But let's test with a rule that has an interface.
        let iface_iptables = "\
*filter
:INPUT ACCEPT [0:0]
-A INPUT -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
";
        let ruleset2 = make_ruleset(iface_iptables);

        // Same interface → should match
        let mut p = proposed("incoming", "tcp", Some(22), None, "allow");
        p.interface_in = Some("eth0".to_string());
        let result = check_duplicate(&p, &ruleset2, 0.0);
        assert!(result.is_some());
        let m = result.unwrap();
        assert!(
            (m.similarity - 1.0).abs() < f64::EPSILON,
            "same interface should be exact match, got {}",
            m.similarity
        );

        // Different interface → similarity should drop
        let mut p2 = proposed("incoming", "tcp", Some(22), None, "allow");
        p2.interface_in = Some("eth1".to_string());
        let result2 = check_duplicate(&p2, &ruleset2, 0.0);
        assert!(result2.is_some());
        let m2 = result2.unwrap();
        assert!(
            m2.similarity < 1.0,
            "different interface should reduce similarity, got {}",
            m2.similarity
        );
    }
}
