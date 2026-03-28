use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use super::types::{MatchSpec, ParsedRuleset, PortSpec, Protocol, Target};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Accept,
    Drop,
    Reject,
    Log,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDirection {
    Input,
    Output,
    Forward,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveRule {
    pub id: String,
    pub action: RuleAction,
    pub protocol: Option<Protocol>,
    pub source: Option<String>,      // CIDR notation or None (= any)
    pub destination: Option<String>,  // CIDR notation or None (= any)
    pub ports: Option<PortSpec>,
    pub direction: RuleDirection,
    pub position: usize,
    pub source_negated: bool,
    pub destination_negated: bool,
    pub protocol_negated: bool,
    pub in_interface: Option<String>,
    pub out_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConflictType {
    Shadow,
    #[serde(rename = "redundant")]
    Redundancy,
    #[serde(rename = "contradiction")]
    Overlap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleConflict {
    #[serde(rename = "type")]
    pub conflict_type: ConflictType,
    pub rule_id_a: String,
    pub rule_id_b: String,
    pub description: String,
}

// ---------------------------------------------------------------------------
// CIDR helpers
// ---------------------------------------------------------------------------

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

/// Check if CIDR `inner` is a subset of CIDR `outer`.
fn cidr_is_subset(inner: &str, outer: &str) -> bool {
    let (outer_ip, outer_prefix) = match parse_cidr(outer) {
        Some(v) => v,
        None => return false,
    };
    let (inner_ip, inner_prefix) = match parse_cidr(inner) {
        Some(v) => v,
        None => return false,
    };

    // Must be same address family
    match (&outer_ip, &inner_ip) {
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => return false,
        _ => {}
    }

    // Inner prefix must be >= outer prefix (more specific or equal).
    if inner_prefix < outer_prefix {
        return false;
    }

    let max_bits = match outer_ip {
        IpAddr::V4(_) => 32u8,
        IpAddr::V6(_) => 128u8,
    };

    if outer_prefix == 0 {
        return true;
    }
    if outer_prefix > max_bits {
        return false;
    }

    let shift = (max_bits - outer_prefix) as u32;
    (ip_to_u128(inner_ip) >> shift) == (ip_to_u128(outer_ip) >> shift)
}

/// Check if two CIDRs have any overlap.
fn cidrs_overlap(a: &str, b: &str) -> bool {
    // Two CIDRs overlap iff one is a subset of the other or they share a common prefix.
    // Equivalently: the network with the shorter prefix contains at least one address of the other.
    cidr_is_subset(a, b) || cidr_is_subset(b, a) || cidrs_share_addresses(a, b)
}

fn cidrs_share_addresses(a: &str, b: &str) -> bool {
    let (a_ip, a_prefix) = match parse_cidr(a) {
        Some(v) => v,
        None => return false,
    };
    let (b_ip, b_prefix) = match parse_cidr(b) {
        Some(v) => v,
        None => return false,
    };

    match (&a_ip, &b_ip) {
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => return false,
        _ => {}
    }

    let max_bits = match a_ip {
        IpAddr::V4(_) => 32u8,
        IpAddr::V6(_) => 128u8,
    };

    let shorter_prefix = a_prefix.min(b_prefix);
    if shorter_prefix == 0 {
        return true;
    }
    if shorter_prefix > max_bits {
        return false;
    }

    let shift = (max_bits - shorter_prefix) as u32;
    (ip_to_u128(a_ip) >> shift) == (ip_to_u128(b_ip) >> shift)
}

// ---------------------------------------------------------------------------
// Port helpers
// ---------------------------------------------------------------------------

fn port_spec_to_set(spec: &PortSpec) -> Vec<(u16, u16)> {
    match spec {
        PortSpec::Single(p) => vec![(*p, *p)],
        PortSpec::Multi(ports) => ports.iter().map(|p| (*p, *p)).collect(),
        PortSpec::Range(lo, hi) => vec![(*lo, *hi)],
    }
}

/// Check if port set `inner` is a subset of port set `outer`.
fn ports_is_subset(inner: &PortSpec, outer: &PortSpec) -> bool {
    let inner_ranges = port_spec_to_set(inner);
    let outer_ranges = port_spec_to_set(outer);

    for (ilo, ihi) in &inner_ranges {
        let mut covered = false;
        for (olo, ohi) in &outer_ranges {
            if ilo >= olo && ihi <= ohi {
                covered = true;
                break;
            }
        }
        if !covered {
            return false;
        }
    }
    true
}

/// Check if two port specs have any overlap.
fn ports_overlap(a: &PortSpec, b: &PortSpec) -> bool {
    let a_ranges = port_spec_to_set(a);
    let b_ranges = port_spec_to_set(b);

    for (alo, ahi) in &a_ranges {
        for (blo, bhi) in &b_ranges {
            if alo <= bhi && blo <= ahi {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Rule comparison helpers
// ---------------------------------------------------------------------------

fn addr_is_subset(inner: &Option<String>, outer: &Option<String>) -> bool {
    match (inner, outer) {
        (_, None) => true, // outer is "any" — everything is a subset
        (None, Some(_)) => false, // inner is "any" but outer is specific
        (Some(i), Some(o)) => cidr_is_subset(i, o),
    }
}

fn addr_overlaps(a: &Option<String>, a_negated: bool, b: &Option<String>, b_negated: bool) -> bool {
    match (a, b) {
        (None, None) => true,
        (None, Some(_)) => {
            // a is "any"; if b is negated, b matches everything except that addr,
            // so there is still partial overlap with "any".
            true
        }
        (Some(_), None) => {
            // symmetric case
            true
        }
        (Some(x), Some(y)) => {
            if a_negated != b_negated && cidrs_overlap(x, y) {
                // One is negated and the other is not, and they refer to
                // overlapping address ranges: they match opposite traffic.
                // e.g. !10.0.0.0/8 vs 10.0.0.0/8 => no overlap.
                // But if the CIDRs don't overlap at all, both could still
                // match the same traffic.
                false
            } else {
                cidrs_overlap(x, y)
            }
        }
    }
}

fn ports_is_subset_opt(inner: &Option<PortSpec>, outer: &Option<PortSpec>) -> bool {
    match (inner, outer) {
        (_, None) => true, // outer has no port constraint (any)
        (None, Some(_)) => false, // inner is any, outer is specific
        (Some(i), Some(o)) => ports_is_subset(i, o),
    }
}

fn ports_overlap_opt(a: &Option<PortSpec>, b: &Option<PortSpec>) -> bool {
    match (a, b) {
        (None, _) | (_, None) => true,
        (Some(x), Some(y)) => ports_overlap(x, y),
    }
}

fn protocol_matches(
    a: &Option<Protocol>,
    a_negated: bool,
    b: &Option<Protocol>,
    b_negated: bool,
) -> bool {
    match (a, b) {
        (None, _) | (_, None) => true,
        (Some(Protocol::All), _) | (_, Some(Protocol::All)) => true,
        (Some(x), Some(y)) => {
            if x == y && a_negated != b_negated {
                // Same protocol but one is negated: !tcp vs tcp => no overlap
                false
            } else {
                x == y
            }
        }
    }
}

fn protocol_is_subset(inner: &Option<Protocol>, outer: &Option<Protocol>) -> bool {
    match (inner, outer) {
        (_, None) => true,
        (_, Some(Protocol::All)) => true,
        (None, Some(_)) => false,
        (Some(Protocol::All), Some(_)) => false, // inner is broader
        (Some(x), Some(y)) => x == y,
    }
}

/// Check if rule B's criteria are a subset of rule A's criteria.
fn is_subset(b: &EffectiveRule, a: &EffectiveRule) -> bool {
    // If negation flags differ for any field, the subset relationship
    // doesn't hold in the simple sense. Use criteria_overlap as a
    // conservative gate: if they don't even overlap, certainly not a subset.
    if !criteria_overlap(b, a) {
        return false;
    }
    b.direction == a.direction
        && b.source_negated == a.source_negated
        && b.destination_negated == a.destination_negated
        && b.protocol_negated == a.protocol_negated
        && protocol_is_subset(&b.protocol, &a.protocol)
        && addr_is_subset(&b.source, &a.source)
        && addr_is_subset(&b.destination, &a.destination)
        && ports_is_subset_opt(&b.ports, &a.ports)
        && interfaces_overlap(&b.in_interface, &a.in_interface)
        && interfaces_overlap(&b.out_interface, &a.out_interface)
}

fn interfaces_overlap(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (None, _) | (_, None) => true, // "any" interface overlaps with everything
        (Some(a), Some(b)) => a == b,
    }
}

/// Check if two rules have overlapping criteria.
fn criteria_overlap(a: &EffectiveRule, b: &EffectiveRule) -> bool {
    a.direction == b.direction
        && protocol_matches(&a.protocol, a.protocol_negated, &b.protocol, b.protocol_negated)
        && addr_overlaps(&a.source, a.source_negated, &b.source, b.source_negated)
        && addr_overlaps(&a.destination, a.destination_negated, &b.destination, b.destination_negated)
        && ports_overlap_opt(&a.ports, &b.ports)
        && interfaces_overlap(&a.in_interface, &b.in_interface)
        && interfaces_overlap(&a.out_interface, &b.out_interface)
}

/// Check if two rules have the same criteria (mutual subset).
fn same_criteria(a: &EffectiveRule, b: &EffectiveRule) -> bool {
    is_subset(a, b) && is_subset(b, a)
}

// ---------------------------------------------------------------------------
// Conversion: ParsedRuleset -> Vec<EffectiveRule>
// ---------------------------------------------------------------------------

fn target_to_action(target: &Target) -> Option<RuleAction> {
    match target {
        Target::Accept => Some(RuleAction::Accept),
        Target::Drop => Some(RuleAction::Drop),
        Target::Reject => Some(RuleAction::Reject),
        Target::Log => Some(RuleAction::Log),
        _ => None, // Skip NAT, MARK, jumps, etc. — not relevant for conflict detection
    }
}

fn chain_to_direction(chain: &str) -> Option<RuleDirection> {
    match chain {
        "INPUT" => Some(RuleDirection::Input),
        "OUTPUT" => Some(RuleDirection::Output),
        "FORWARD" => Some(RuleDirection::Forward),
        _ => None, // Skip user-defined chains and NAT chains
    }
}

/// Scan match module args for port specifications.
/// When `dest` is true, looks for --dport/--dports; otherwise --sport/--sports.
fn extract_port_from_matches(matches: &[MatchSpec], dest: bool) -> Option<PortSpec> {
    let flags: &[&str] = if dest {
        &["--dport", "--dports", "--destination-ports"]
    } else {
        &["--sport", "--sports", "--source-ports"]
    };
    for m in matches {
        for (j, arg) in m.args.iter().enumerate() {
            if flags.contains(&arg.as_str()) {
                if let Some(val) = m.args.get(j + 1) {
                    return PortSpec::parse(val);
                }
            }
        }
    }
    None
}

/// Convert a `ParsedRuleset` into a flat list of `EffectiveRule`s suitable
/// for conflict detection.  Only rules in the `filter` table and built-in
/// chains (INPUT / OUTPUT / FORWARD) with terminal actions (ACCEPT / DROP /
/// REJECT / LOG) are included.
pub fn ruleset_to_effective_rules(ruleset: &ParsedRuleset) -> Vec<EffectiveRule> {
    let mut result = Vec::new();

    let filter = match ruleset.tables.get("filter") {
        Some(t) => t,
        None => return result,
    };

    for (chain_name, chain) in &filter.chains {
        let direction = match chain_to_direction(chain_name) {
            Some(d) => d,
            None => continue,
        };

        for (pos, parsed_rule) in chain.rules.iter().enumerate() {
            let spec = match &parsed_rule.parsed {
                Some(s) => s,
                None => continue,
            };

            let action = match &spec.target {
                Some(t) => match target_to_action(t) {
                    Some(a) => a,
                    None => continue,
                },
                None => continue,
            };

            // Use dest_port as the primary port (most common in firewall rules).
            // Fall back to source_port if dest_port is absent.
            // Also check match module args, since implicit protocol modules
            // (e.g. `-p tcp --dport 22` without explicit `-m tcp`) may not
            // populate spec.dest_port / spec.source_port.
            let ports = spec
                .dest_port
                .clone()
                .or_else(|| spec.source_port.clone())
                .or_else(|| extract_port_from_matches(&spec.matches, true))
                .or_else(|| extract_port_from_matches(&spec.matches, false));

            let source = spec.source.as_ref().map(|a| a.addr.clone());
            let source_negated = spec.source.as_ref().map_or(false, |a| a.negated);
            let destination = spec.destination.as_ref().map(|a| a.addr.clone());
            let destination_negated = spec.destination.as_ref().map_or(false, |a| a.negated);
            let protocol_negated = spec.protocol_negated;
            let in_interface = spec.in_iface.as_ref().map(|i| i.name.clone());
            let out_interface = spec.out_iface.as_ref().map(|i| i.name.clone());

            let id = format!(
                "{}:{}:{}",
                chain_name,
                pos + 1,
                parsed_rule.raw.chars().take(60).collect::<String>()
            );

            result.push(EffectiveRule {
                id,
                action,
                protocol: spec.protocol.clone(),
                source,
                destination,
                ports,
                direction: direction.clone(),
                position: pos + 1,
                source_negated,
                destination_negated,
                protocol_negated,
                in_interface,
                out_interface,
            });
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of conflict detection, including whether the result was truncated
/// due to hitting the `max_conflicts` limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictDetectionResult {
    pub conflicts: Vec<RuleConflict>,
    pub truncated: bool,
}

pub fn detect_conflicts(rules: &[EffectiveRule]) -> ConflictDetectionResult {
    detect_conflicts_with_limit(rules, 50)
}

pub fn detect_conflicts_with_limit(rules: &[EffectiveRule], max_conflicts: usize) -> ConflictDetectionResult {
    let mut conflicts = Vec::new();
    let mut truncated = false;

    'outer: for i in 0..rules.len() {
        for j in (i + 1)..rules.len() {
            let a = &rules[i];
            let b = &rules[j];

            // Skip if same action (no conflict for shadow/overlap, but check redundancy).
            if a.action == b.action {
                // Redundancy: consecutive (or near) rules with same action where one is subset.
                if is_subset(b, a) || is_subset(a, b) {
                    conflicts.push(RuleConflict {
                        conflict_type: ConflictType::Redundancy,
                        rule_id_a: a.id.clone(),
                        rule_id_b: b.id.clone(),
                        description: format!(
                            "Rules '{}' (pos {}) and '{}' (pos {}) have the same action and overlapping criteria; one is redundant",
                            a.id, a.position, b.id, b.position
                        ),
                    });
                    if conflicts.len() >= max_conflicts {
                        truncated = true;
                        break 'outer;
                    }
                }
                continue;
            }

            // Different actions — check shadow and overlap.
            // Shadow: B is a subset of A, so B never fires.
            if is_subset(b, a) && a.position < b.position {
                conflicts.push(RuleConflict {
                    conflict_type: ConflictType::Shadow,
                    rule_id_a: a.id.clone(),
                    rule_id_b: b.id.clone(),
                    description: format!(
                        "Rule '{}' (pos {}) shadows rule '{}' (pos {}): all traffic matching '{}' already matches '{}'",
                        a.id, a.position, b.id, b.position, b.id, a.id
                    ),
                });
                if conflicts.len() >= max_conflicts {
                    truncated = true;
                    break 'outer;
                }
                continue;
            }

            // Overlap: partially overlapping criteria with different actions.
            if criteria_overlap(a, b) && !same_criteria(a, b) {
                conflicts.push(RuleConflict {
                    conflict_type: ConflictType::Overlap,
                    rule_id_a: a.id.clone(),
                    rule_id_b: b.id.clone(),
                    description: format!(
                        "Rules '{}' (pos {}) and '{}' (pos {}) have partially overlapping criteria but different actions ({:?} vs {:?})",
                        a.id, a.position, b.id, b.position, a.action, b.action
                    ),
                });
                if conflicts.len() >= max_conflicts {
                    truncated = true;
                    break 'outer;
                }
            }
        }
    }

    ConflictDetectionResult { conflicts, truncated }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, action: RuleAction, pos: usize) -> EffectiveRule {
        EffectiveRule {
            id: id.to_string(),
            action,
            protocol: Some(Protocol::Tcp),
            source: None,
            destination: None,
            ports: Some(PortSpec::Single(22)),
            direction: RuleDirection::Input,
            position: pos,
            source_negated: false,
            destination_negated: false,
            protocol_negated: false,
            in_interface: None,
            out_interface: None,
        }
    }

    #[test]
    fn test_shadow_detection() {
        // Rule A: ACCEPT tcp any -> any port 22
        // Rule B: DROP tcp 10.0.0.0/8 -> any port 22
        // A is broader, B is subset of A with different action => shadow.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None, // any
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: Some("10.0.0.0/8".to_string()),
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].conflict_type, ConflictType::Shadow);
        assert_eq!(conflicts[0].rule_id_a, "A");
        assert_eq!(conflicts[0].rule_id_b, "B");
    }

    #[test]
    fn test_redundancy_detection() {
        // Two rules with same action, one is subset of the other.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None, // any
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: Some("10.0.0.0/8".to_string()),
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].conflict_type, ConflictType::Redundancy);
    }

    #[test]
    fn test_overlap_detection() {
        // Rule A: ACCEPT tcp from 10.0.0.0/8, ports 80,443
        // Rule B: DROP tcp from 10.0.0.0/16, port 80
        // B's source is a subset of A's source, port 80 is subset of {80,443}.
        // B is actually a full subset — that's a shadow.
        // Let's make a true partial overlap:
        // A: ACCEPT tcp from 10.0.0.0/8 port 80
        // B: DROP tcp from 10.0.0.0/16 port range 80-90
        // Overlap on port 80 from 10.0.0.0/16, but B also covers 81-90 which A doesn't.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: Some("10.0.0.0/8".to_string()),
                destination: None,
                ports: Some(PortSpec::Single(80)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: Some("10.0.0.0/16".to_string()),
                destination: None,
                ports: Some(PortSpec::Range(80, 90)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        // B is subset of A in source (10.0.0.0/16 subset of 10.0.0.0/8)
        // but B's ports (80-90) are NOT a subset of A's ports (80).
        // So is_subset(B, A) = false. criteria_overlap = true. Different actions.
        // => Overlap.
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].conflict_type, ConflictType::Overlap);
    }

    #[test]
    fn test_no_false_positives_valid_ruleset() {
        // Well-ordered rules with no conflicts.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: Some("192.168.1.0/24".to_string()),
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(80)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "C".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Udp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(53)),
                direction: RuleDirection::Input,
                position: 3,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(
            conflicts.is_empty(),
            "Expected no conflicts but got: {:?}",
            conflicts
        );
    }

    #[test]
    fn test_cidr_subset() {
        assert!(cidr_is_subset("10.1.0.0/16", "10.0.0.0/8"));
        assert!(cidr_is_subset("10.0.0.1/32", "10.0.0.0/8"));
        assert!(!cidr_is_subset("10.0.0.0/8", "10.1.0.0/16"));
        assert!(cidr_is_subset("10.0.0.0/8", "0.0.0.0/0"));
        assert!(cidr_is_subset("192.168.1.0/24", "0.0.0.0/0"));
    }

    #[test]
    fn test_port_subset() {
        assert!(ports_is_subset(
            &PortSpec::Single(80),
            &PortSpec::Multi(vec![80, 443])
        ));
        assert!(!ports_is_subset(
            &PortSpec::Multi(vec![80, 443]),
            &PortSpec::Single(80)
        ));
        assert!(ports_is_subset(
            &PortSpec::Single(85),
            &PortSpec::Range(80, 90)
        ));
    }

    #[test]
    fn test_port_overlap() {
        assert!(ports_overlap(
            &PortSpec::Range(80, 90),
            &PortSpec::Range(85, 95)
        ));
        assert!(!ports_overlap(
            &PortSpec::Range(80, 84),
            &PortSpec::Range(85, 95)
        ));
        assert!(ports_overlap(
            &PortSpec::Single(80),
            &PortSpec::Multi(vec![80, 443])
        ));
    }

    #[test]
    fn test_different_directions_no_conflict() {
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Output,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(conflicts.is_empty());
    }

    // -----------------------------------------------------------------------
    // Integration tests: ParsedRuleset -> EffectiveRule -> detect_conflicts
    // -----------------------------------------------------------------------

    use crate::iptables::parser::parse_iptables_save;

    #[test]
    fn test_ruleset_conversion_basic() {
        let input = r#"*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j DROP
COMMIT
"#;
        let ruleset = parse_iptables_save(input).unwrap();
        let effective = ruleset_to_effective_rules(&ruleset);
        assert_eq!(effective.len(), 2);
        assert_eq!(effective[0].action, RuleAction::Accept);
        assert_eq!(effective[0].protocol, Some(Protocol::Tcp));
        assert_eq!(effective[0].ports, Some(PortSpec::Single(22)));
        assert_eq!(effective[0].direction, RuleDirection::Input);
        assert_eq!(effective[1].action, RuleAction::Drop);
        assert_eq!(effective[1].ports, Some(PortSpec::Single(80)));
    }

    #[test]
    fn test_ruleset_skips_nat_and_jumps() {
        let input = r#"*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -j some-user-chain
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"#;
        let ruleset = parse_iptables_save(input).unwrap();
        let effective = ruleset_to_effective_rules(&ruleset);
        // Only the ACCEPT rule on port 22 should be included;
        // MASQUERADE (nat table) and jump to user-chain are skipped.
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].action, RuleAction::Accept);
    }

    #[test]
    fn test_end_to_end_shadow_detection() {
        let input = r#"*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j DROP
COMMIT
"#;
        let ruleset = parse_iptables_save(input).unwrap();
        let effective = ruleset_to_effective_rules(&ruleset);
        let conflicts = detect_conflicts(&effective).conflicts;

        assert_eq!(conflicts.len(), 1, "expected 1 shadow conflict, got {:?}", conflicts);
        assert_eq!(conflicts[0].conflict_type, ConflictType::Shadow);
    }

    #[test]
    fn test_end_to_end_redundancy_detection() {
        let input = r#"*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -s 192.168.1.0/24 --dport 443 -j ACCEPT
COMMIT
"#;
        let ruleset = parse_iptables_save(input).unwrap();
        let effective = ruleset_to_effective_rules(&ruleset);
        let conflicts = detect_conflicts(&effective).conflicts;

        assert_eq!(conflicts.len(), 1, "expected 1 redundancy, got {:?}", conflicts);
        assert_eq!(conflicts[0].conflict_type, ConflictType::Redundancy);
    }

    #[test]
    fn test_end_to_end_overlap_detection() {
        // Rule 1: ACCEPT tcp from 10.0.0.0/8 port 80
        // Rule 2: DROP tcp from 10.0.0.0/16 ports 80-90
        // Partial overlap (port 80 from 10.0.0.0/16) but B has extra ports.
        let input = r#"*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -s 10.0.0.0/8 --dport 80 -j ACCEPT
-A INPUT -p tcp -s 10.0.0.0/16 -m multiport --dports 80:90 -j DROP
COMMIT
"#;
        let ruleset = parse_iptables_save(input).unwrap();
        let effective = ruleset_to_effective_rules(&ruleset);
        let conflicts = detect_conflicts(&effective).conflicts;

        assert!(!conflicts.is_empty(), "expected at least one conflict, got none");
        // Should be an overlap (not a pure shadow, since B has broader ports).
        let has_overlap = conflicts.iter().any(|c| c.conflict_type == ConflictType::Overlap);
        assert!(has_overlap, "expected Overlap conflict, got {:?}", conflicts);
    }

    #[test]
    fn test_end_to_end_no_conflicts() {
        let input = r#"*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p udp --dport 53 -j DROP
COMMIT
"#;
        let ruleset = parse_iptables_save(input).unwrap();
        let effective = ruleset_to_effective_rules(&ruleset);
        let conflicts = detect_conflicts(&effective).conflicts;

        assert!(conflicts.is_empty(), "expected no conflicts, got {:?}", conflicts);
    }

    #[test]
    fn test_end_to_end_contradiction_same_criteria() {
        // Exact same criteria but ACCEPT vs DROP — shadow (B is subset of A).
        let input = r#"*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 22 -j DROP
COMMIT
"#;
        let ruleset = parse_iptables_save(input).unwrap();
        let effective = ruleset_to_effective_rules(&ruleset);
        let conflicts = detect_conflicts(&effective).conflicts;

        assert_eq!(conflicts.len(), 1, "expected 1 conflict, got {:?}", conflicts);
        assert_eq!(conflicts[0].conflict_type, ConflictType::Shadow);
    }

    // -----------------------------------------------------------------------
    // Negation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_opposite_source_negation_no_conflict() {
        // Rule A: ACCEPT tcp from 10.0.0.0/8, port 22
        // Rule B: DROP tcp from !10.0.0.0/8, port 22
        // They match opposite traffic => no conflict.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: Some("10.0.0.0/8".to_string()),
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: Some("10.0.0.0/8".to_string()),
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: true,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(
            conflicts.is_empty(),
            "Expected no conflicts for opposite negation, got: {:?}",
            conflicts
        );
    }

    #[test]
    fn test_opposite_protocol_negation_no_conflict() {
        // Rule A: ACCEPT tcp port 22
        // Rule B: DROP !tcp port 22
        // They match opposite protocols => no conflict.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: true,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(
            conflicts.is_empty(),
            "Expected no conflicts for opposite protocol negation, got: {:?}",
            conflicts
        );
    }

    #[test]
    fn test_negated_source_vs_any_partial_overlap() {
        // Rule A: ACCEPT tcp from any, port 22
        // Rule B: DROP tcp from !10.0.0.0/8, port 22
        // B matches everything except 10.0.0.0/8, A matches everything.
        // They partially overlap (on all traffic except 10.0.0.0/8 they
        // both match). This should be detected as a shadow (B subset of A).
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None, // any
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: Some("10.0.0.0/8".to_string()),
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: true,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        // A is "any" which is broader; B with !10.0.0.0/8 is a subset of "any".
        // criteria_overlap returns true (None vs Some with negated => true).
        assert!(
            !conflicts.is_empty(),
            "Expected a conflict for negated source vs any, got none"
        );
    }

    // -----------------------------------------------------------------------
    // Interface tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_different_interfaces_no_conflict() {
        // Rule A: ACCEPT tcp port 22 on eth0
        // Rule B: DROP tcp port 22 on eth1
        // Different in_interface => no conflict.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: Some("eth0".to_string()),
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: Some("eth1".to_string()),
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(
            conflicts.is_empty(),
            "Expected no conflicts for different interfaces, got: {:?}",
            conflicts
        );
    }

    #[test]
    fn test_same_interface_conflict_detected() {
        // Rule A: ACCEPT tcp port 22 on eth0
        // Rule B: DROP tcp port 22 on eth0
        // Same interface, same criteria, different action => shadow.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: Some("eth0".to_string()),
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: Some("eth0".to_string()),
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].conflict_type, ConflictType::Shadow);
    }

    #[test]
    fn test_negated_protocol_vs_same_protocol_no_overlap() {
        // Rule A: ACCEPT !tcp port 22
        // Rule B: DROP tcp port 22
        // !tcp vs tcp should not overlap => no conflict.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: true,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(
            conflicts.is_empty(),
            "Expected no conflicts for !tcp vs tcp, got: {:?}",
            conflicts
        );
    }

    #[test]
    fn test_both_negated_same_address_overlaps() {
        // Rule A: ACCEPT tcp from !10.0.0.0/8, port 22
        // Rule B: DROP tcp from !10.0.0.0/8, port 22
        // Both negated with same address => they match the same traffic => conflict (shadow).
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: Some("10.0.0.0/8".to_string()),
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: true,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: Some("10.0.0.0/8".to_string()),
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: true,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(
            !conflicts.is_empty(),
            "Expected a conflict for both-negated same address, got none"
        );
    }

    #[test]
    fn test_different_out_interfaces_no_conflict() {
        // Rule A: ACCEPT tcp port 80, out_interface=eth0
        // Rule B: DROP tcp port 80, out_interface=eth1
        // Different output interfaces => no conflict.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(80)),
                direction: RuleDirection::Forward,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: Some("eth0".to_string()),
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(80)),
                direction: RuleDirection::Forward,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: Some("eth1".to_string()),
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(
            conflicts.is_empty(),
            "Expected no conflicts for different out_interfaces, got: {:?}",
            conflicts
        );
    }

    #[test]
    fn test_any_interface_overlaps_specific() {
        // Rule A: ACCEPT tcp port 22, no interface (any)
        // Rule B: DROP tcp port 22, in_interface=eth0
        // "any" interface overlaps with specific => conflict (shadow).
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(22)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: Some("eth0".to_string()),
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(
            !conflicts.is_empty(),
            "Expected a conflict when one rule has no interface (any) and the other has a specific interface"
        );
    }

    #[test]
    fn test_port_range_overlap_detected() {
        // Rule A: ACCEPT tcp ports 80-100
        // Rule B: DROP tcp ports 90-110
        // Overlapping port ranges (90-100) with different actions => overlap conflict.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Range(80, 100)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Range(90, 110)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(
            !conflicts.is_empty(),
            "Expected a conflict for overlapping port ranges, got none"
        );
        let has_overlap = conflicts.iter().any(|c| c.conflict_type == ConflictType::Overlap);
        assert!(
            has_overlap,
            "Expected Overlap conflict for partially overlapping port ranges, got: {:?}",
            conflicts
        );
    }

    #[test]
    fn test_same_chain_different_protocols_no_conflict() {
        // Rule A: ACCEPT tcp port 53
        // Rule B: DROP udp port 53
        // Same port but different protocols => no conflict.
        let rules = vec![
            EffectiveRule {
                id: "A".to_string(),
                action: RuleAction::Accept,
                protocol: Some(Protocol::Tcp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(53)),
                direction: RuleDirection::Input,
                position: 1,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
            EffectiveRule {
                id: "B".to_string(),
                action: RuleAction::Drop,
                protocol: Some(Protocol::Udp),
                source: None,
                destination: None,
                ports: Some(PortSpec::Single(53)),
                direction: RuleDirection::Input,
                position: 2,
                source_negated: false,
                destination_negated: false,
                protocol_negated: false,
                in_interface: None,
                out_interface: None,
            },
        ];

        let conflicts = detect_conflicts(&rules).conflicts;
        assert!(
            conflicts.is_empty(),
            "Expected no conflicts for tcp vs udp on same port, got: {:?}",
            conflicts
        );
    }
}
