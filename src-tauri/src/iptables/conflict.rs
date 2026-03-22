use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use super::types::{PortSpec, Protocol};

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictType {
    Shadow,
    Redundancy,
    Overlap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConflict {
    pub conflict_type: ConflictType,
    pub rule_ids: Vec<String>,
    pub explanation: String,
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

fn addr_overlaps(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (None, _) | (_, None) => true, // "any" overlaps with everything
        (Some(x), Some(y)) => cidrs_overlap(x, y),
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

fn protocol_matches(a: &Option<Protocol>, b: &Option<Protocol>) -> bool {
    match (a, b) {
        (None, _) | (_, None) => true,
        (Some(Protocol::All), _) | (_, Some(Protocol::All)) => true,
        (Some(x), Some(y)) => x == y,
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
    b.direction == a.direction
        && protocol_is_subset(&b.protocol, &a.protocol)
        && addr_is_subset(&b.source, &a.source)
        && addr_is_subset(&b.destination, &a.destination)
        && ports_is_subset_opt(&b.ports, &a.ports)
}

/// Check if two rules have overlapping criteria.
fn criteria_overlap(a: &EffectiveRule, b: &EffectiveRule) -> bool {
    a.direction == b.direction
        && protocol_matches(&a.protocol, &b.protocol)
        && addr_overlaps(&a.source, &b.source)
        && addr_overlaps(&a.destination, &b.destination)
        && ports_overlap_opt(&a.ports, &b.ports)
}

/// Check if two rules have the same criteria (mutual subset).
fn same_criteria(a: &EffectiveRule, b: &EffectiveRule) -> bool {
    is_subset(a, b) && is_subset(b, a)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn detect_conflicts(rules: &[EffectiveRule]) -> Vec<RuleConflict> {
    let mut conflicts = Vec::new();

    for i in 0..rules.len() {
        for j in (i + 1)..rules.len() {
            let a = &rules[i];
            let b = &rules[j];

            // Skip if same action (no conflict for shadow/overlap, but check redundancy).
            if a.action == b.action {
                // Redundancy: consecutive (or near) rules with same action where one is subset.
                if is_subset(b, a) || is_subset(a, b) {
                    conflicts.push(RuleConflict {
                        conflict_type: ConflictType::Redundancy,
                        rule_ids: vec![a.id.clone(), b.id.clone()],
                        explanation: format!(
                            "Rules '{}' (pos {}) and '{}' (pos {}) have the same action and overlapping criteria; one is redundant",
                            a.id, a.position, b.id, b.position
                        ),
                    });
                }
                continue;
            }

            // Different actions — check shadow and overlap.
            // Shadow: B is a subset of A, so B never fires.
            if is_subset(b, a) && a.position < b.position {
                conflicts.push(RuleConflict {
                    conflict_type: ConflictType::Shadow,
                    rule_ids: vec![a.id.clone(), b.id.clone()],
                    explanation: format!(
                        "Rule '{}' (pos {}) shadows rule '{}' (pos {}): all traffic matching '{}' already matches '{}'",
                        a.id, a.position, b.id, b.position, b.id, a.id
                    ),
                });
                continue;
            }

            // Overlap: partially overlapping criteria with different actions.
            if criteria_overlap(a, b) && !same_criteria(a, b) {
                conflicts.push(RuleConflict {
                    conflict_type: ConflictType::Overlap,
                    rule_ids: vec![a.id.clone(), b.id.clone()],
                    explanation: format!(
                        "Rules '{}' (pos {}) and '{}' (pos {}) have partially overlapping criteria but different actions ({:?} vs {:?})",
                        a.id, a.position, b.id, b.position, a.action, b.action
                    ),
                });
            }
        }
    }

    conflicts
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
            },
        ];

        let conflicts = detect_conflicts(&rules);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].conflict_type, ConflictType::Shadow);
        assert_eq!(conflicts[0].rule_ids, vec!["A", "B"]);
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
            },
        ];

        let conflicts = detect_conflicts(&rules);
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
            },
        ];

        let conflicts = detect_conflicts(&rules);
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
            },
        ];

        let conflicts = detect_conflicts(&rules);
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
            },
        ];

        let conflicts = detect_conflicts(&rules);
        assert!(conflicts.is_empty());
    }
}
