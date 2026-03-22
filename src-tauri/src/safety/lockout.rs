use std::net::IpAddr;

use crate::iptables::types::*;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of a lockout safety check.
#[derive(Debug, Clone)]
pub enum LockoutCheckResult {
    /// The management connection would be preserved.
    Ok,
    /// The proposed ruleset would lock out the management connection.
    LockoutDetected { explanation: String },
}

impl LockoutCheckResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, LockoutCheckResult::Ok)
    }
}

// ---------------------------------------------------------------------------
// Simulated packet
// ---------------------------------------------------------------------------

/// A simulated packet for the lockout trace.
struct SimPacket<'a> {
    src_ip: &'a str,
    dest_port: u16,
    protocol: SimProtocol,
    in_iface: Option<&'a str>,
}

/// Protocol for the simulated packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimProtocol {
    Tcp,
    /// "Any" — matches any protocol rule (used for VPN where we don't know
    /// the exact protocol).
    Any,
}

// ---------------------------------------------------------------------------
// Lockout detection
// ---------------------------------------------------------------------------

/// Simulate a packet trace for the management SSH connection against the
/// proposed ruleset. Returns OK if the SSH connection would survive, or
/// LockoutDetected with an explanation if it would be blocked.
///
/// If a VPN port/interface is specified, the VPN path is also checked since
/// losing VPN connectivity would also break the management connection.
pub fn check_lockout(
    ruleset: &ParsedRuleset,
    management_ip: &str,
    management_port: u16,
    vpn_port: Option<u16>,
    vpn_interface: Option<&str>,
) -> LockoutCheckResult {
    // Check the SSH management connection (always TCP)
    let ssh_packet = SimPacket {
        src_ip: management_ip,
        dest_port: management_port,
        protocol: SimProtocol::Tcp,
        in_iface: None,
    };
    let ssh_result = trace_input_chain(ruleset, &ssh_packet, "Management SSH");
    if let LockoutCheckResult::LockoutDetected { .. } = &ssh_result {
        return ssh_result;
    }

    // If management is over VPN, also check VPN port accessibility
    if let Some(port) = vpn_port {
        // VPN could be any protocol (WireGuard=UDP, OpenVPN=UDP/TCP),
        // so we use SimProtocol::Any to match any protocol rule.
        let vpn_packet = SimPacket {
            src_ip: "0.0.0.0", // any source
            dest_port: port,
            protocol: SimProtocol::Any,
            in_iface: vpn_interface,
        };
        let vpn_result = trace_input_chain(ruleset, &vpn_packet, "VPN");
        if let LockoutCheckResult::LockoutDetected { explanation } = &vpn_result {
            return LockoutCheckResult::LockoutDetected {
                explanation: format!(
                    "VPN tunnel would be blocked, which carries the management SSH connection. {}",
                    explanation
                ),
            };
        }
    }

    LockoutCheckResult::Ok
}

/// Trace a packet through the filter/INPUT chain and return a lockout check.
fn trace_input_chain(
    ruleset: &ParsedRuleset,
    packet: &SimPacket<'_>,
    label: &str,
) -> LockoutCheckResult {
    let filter = match ruleset.tables.get("filter") {
        Some(t) => t,
        None => return LockoutCheckResult::Ok,
    };

    let result = trace_chain(filter, "INPUT", packet, 0);

    match result {
        TraceVerdict::Accept => LockoutCheckResult::Ok,
        TraceVerdict::Drop => LockoutCheckResult::LockoutDetected {
            explanation: format!(
                "{} connection from {} to port {} would be DROPPED by the INPUT chain",
                label, packet.src_ip, packet.dest_port
            ),
        },
        TraceVerdict::ChainPolicy(policy) => {
            if policy == "DROP" || policy == "REJECT" {
                LockoutCheckResult::LockoutDetected {
                    explanation: format!(
                        "{} connection from {} to port {} would hit the INPUT chain policy ({})",
                        label, packet.src_ip, packet.dest_port, policy
                    ),
                }
            } else {
                LockoutCheckResult::Ok
            }
        }
        TraceVerdict::Unsimulatable(reason) => LockoutCheckResult::LockoutDetected {
            explanation: format!(
                "Cannot verify {} safety: {}. Manual verification required.",
                label, reason
            ),
        },
    }
}

// ---------------------------------------------------------------------------
// Packet trace engine
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum TraceVerdict {
    Accept,
    Drop,
    /// Fell through to chain policy
    ChainPolicy(String),
    /// Hit a match module we cannot simulate
    Unsimulatable(String),
}

/// Unsimulatable match modules — these require runtime state we don't have.
const UNSIMULATABLE_MODULES: &[&str] = &[
    "recent", "hashlimit", "connlimit", "time", "owner", "string", "statistic",
];

/// Trace a packet through a single chain, following jumps to user chains.
fn trace_chain(
    table: &TableState,
    chain_name: &str,
    packet: &SimPacket<'_>,
    depth: usize,
) -> TraceVerdict {
    if depth > 20 {
        return TraceVerdict::Unsimulatable("chain depth exceeded 20".to_string());
    }

    let chain = match table.chains.get(chain_name) {
        Some(c) => c,
        None => return TraceVerdict::Unsimulatable(format!("chain '{}' not found", chain_name)),
    };

    for rule in &chain.rules {
        let spec = match &rule.parsed {
            Some(s) => s,
            None => continue,
        };

        // Check for unsimulatable modules
        for m in &spec.matches {
            if UNSIMULATABLE_MODULES.contains(&m.module.as_str()) {
                return TraceVerdict::Unsimulatable(format!(
                    "rule uses -m {} which cannot be simulated",
                    m.module
                ));
            }
        }

        if !rule_matches(spec, &rule.raw, packet) {
            continue;
        }

        match &spec.target {
            Some(Target::Accept) => return TraceVerdict::Accept,
            Some(Target::Drop) => return TraceVerdict::Drop,
            Some(Target::Reject) => return TraceVerdict::Drop,
            Some(Target::Return) => break,
            Some(Target::Log) => continue,
            Some(Target::Jump(target_chain)) => {
                let sub = trace_chain(table, target_chain, packet, depth + 1);
                match sub {
                    TraceVerdict::ChainPolicy(_) => continue,
                    other => return other,
                }
            }
            _ => continue,
        }
    }

    if let Some(policy) = &chain.policy {
        TraceVerdict::ChainPolicy(policy.clone())
    } else {
        TraceVerdict::ChainPolicy("RETURN".to_string())
    }
}

/// Check whether a rule matches our simulated packet.
fn rule_matches(spec: &RuleSpec, raw: &str, packet: &SimPacket<'_>) -> bool {
    // Protocol check
    if let Some(proto) = &spec.protocol {
        let proto_matches = match packet.protocol {
            SimProtocol::Tcp => matches!(proto, Protocol::Tcp | Protocol::All),
            SimProtocol::Any => true, // Any protocol matches any rule
        };
        if spec.protocol_negated {
            if proto_matches && packet.protocol != SimProtocol::Any {
                return false;
            }
        } else if !proto_matches {
            return false;
        }
    }

    // Source address check
    if let Some(addr_spec) = &spec.source {
        let matches_src = ip_matches(&addr_spec.addr, packet.src_ip);
        if addr_spec.negated {
            if matches_src {
                return false;
            }
        } else if !matches_src {
            return false;
        }
    }

    // Interface check — when the packet has no interface specified, treat any
    // interface rule as matching (conservative for safety — assume worst case).
    if let Some(iface_spec) = &spec.in_iface {
        let matches_iface = if let Some(pkt_iface) = packet.in_iface {
            interface_matches(&iface_spec.name, pkt_iface)
        } else {
            // No interface on the packet — conservatively assume it could
            // match any interface rule (worst case for lockout detection).
            true
        };
        if iface_spec.negated {
            if matches_iface {
                return false;
            }
        } else if !matches_iface {
            return false;
        }
    }

    // Destination port check — try multiple sources since the parser may store
    // --dport in different places depending on whether -m was explicit.
    let effective_dest_port = spec
        .dest_port
        .clone()
        .or_else(|| extract_dest_port_from_matches(&spec.matches))
        .or_else(|| extract_dest_port_from_raw(raw));
    if let Some(port_spec) = &effective_dest_port {
        if !port_matches(port_spec, packet.dest_port) {
            return false;
        }
    }

    // Check conntrack state — management connections are ESTABLISHED or NEW
    for m in &spec.matches {
        if m.module == "conntrack" || m.module == "state" {
            let state_flag = if m.module == "conntrack" {
                "--ctstate"
            } else {
                "--state"
            };
            for i in 0..m.args.len() {
                if m.args[i] == state_flag {
                    if let Some(states) = m.args.get(i + 1) {
                        let allowed: Vec<&str> = states.split(',').collect();
                        let matches_state = allowed
                            .iter()
                            .any(|s| *s == "NEW" || *s == "ESTABLISHED" || *s == "RELATED");
                        if !matches_state {
                            return false;
                        }
                    }
                }
            }
        }
    }

    true
}

/// Extract destination port from match module args (handles the case where
/// `--dport` is stored inside the implicit protocol module).
fn extract_dest_port_from_matches(matches: &[MatchSpec]) -> Option<PortSpec> {
    for m in matches {
        for i in 0..m.args.len() {
            if (m.args[i] == "--dport"
                || m.args[i] == "--dports"
                || m.args[i] == "--destination-ports")
                && i + 1 < m.args.len()
            {
                return PortSpec::parse(&m.args[i + 1]);
            }
        }
    }
    None
}

/// Extract destination port by tokenizing the raw rule line. This handles
/// cases where the structured parser missed `--dport` (e.g., implicit
/// protocol module without explicit `-m tcp`).
fn extract_dest_port_from_raw(raw: &str) -> Option<PortSpec> {
    let tokens = shell_words::split(raw).unwrap_or_default();
    for i in 0..tokens.len() {
        if (tokens[i] == "--dport" || tokens[i] == "--dports" || tokens[i] == "--destination-ports")
            && i + 1 < tokens.len()
        {
            return PortSpec::parse(&tokens[i + 1]);
        }
    }
    None
}

/// Check if `src_ip` matches an address spec (CIDR or single IP).
fn ip_matches(spec: &str, src_ip: &str) -> bool {
    if src_ip == "0.0.0.0" {
        return true;
    }
    if spec == "0.0.0.0/0" || spec == "::/0" {
        return true;
    }
    if spec.contains('/') {
        cidr_contains(spec, src_ip)
    } else {
        spec == src_ip
    }
}

/// Simple CIDR containment check.
fn cidr_contains(cidr: &str, ip_str: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let prefix_len: u32 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let net_ip: IpAddr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let target_ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match (net_ip, target_ip) {
        (IpAddr::V4(net), IpAddr::V4(tgt)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = !0u32 << (32 - prefix_len);
            (u32::from(net) & mask) == (u32::from(tgt) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(tgt)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let net_bits = u128::from(net);
            let tgt_bits = u128::from(tgt);
            let mask = !0u128 << (128 - prefix_len);
            (net_bits & mask) == (tgt_bits & mask)
        }
        _ => false,
    }
}

/// Check if an interface name matches (supports `+` wildcard suffix).
fn interface_matches(spec: &str, actual: &str) -> bool {
    if spec.ends_with('+') {
        actual.starts_with(&spec[..spec.len() - 1])
    } else {
        spec == actual
    }
}

/// Check if a port matches a PortSpec.
fn port_matches(spec: &PortSpec, port: u16) -> bool {
    match spec {
        PortSpec::Single(p) => *p == port,
        PortSpec::Multi(ports) => ports.contains(&port),
        PortSpec::Range(lo, hi) => port >= *lo && port <= *hi,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iptables::parser::parse_iptables_save;

    fn make_ruleset(iptables_save: &str) -> ParsedRuleset {
        parse_iptables_save(iptables_save).unwrap()
    }

    #[test]
    fn test_ssh_allowed_accept_all() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT ACCEPT [0:0]\n\
             COMMIT\n",
        );
        let result = check_lockout(&ruleset, "10.0.0.5", 22, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssh_allowed_explicit_rule() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             -A INPUT -p tcp --dport 22 -j ACCEPT\n\
             COMMIT\n",
        );
        let result = check_lockout(&ruleset, "10.0.0.5", 22, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssh_blocked_drop_policy_no_allow() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             -A INPUT -p tcp --dport 80 -j ACCEPT\n\
             COMMIT\n",
        );
        let result = check_lockout(&ruleset, "10.0.0.5", 22, None, None);
        assert!(
            !result.is_ok(),
            "SSH should be blocked when INPUT policy is DROP and no SSH rule exists"
        );
    }

    #[test]
    fn test_ssh_allowed_via_source_cidr() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             -A INPUT -s 10.0.0.0/24 -p tcp --dport 22 -j ACCEPT\n\
             COMMIT\n",
        );
        let result = check_lockout(&ruleset, "10.0.0.5", 22, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssh_blocked_wrong_source() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT\n\
             COMMIT\n",
        );
        let result = check_lockout(&ruleset, "10.0.0.5", 22, None, None);
        assert!(!result.is_ok());
    }

    #[test]
    fn test_ssh_allowed_through_chain_jump() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             :TR-INPUT - [0:0]\n\
             -A INPUT -j TR-INPUT\n\
             -A TR-INPUT -p tcp --dport 22 -j ACCEPT\n\
             COMMIT\n",
        );
        let result = check_lockout(&ruleset, "10.0.0.5", 22, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssh_allowed_conntrack_established() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n\
             COMMIT\n",
        );
        let result = check_lockout(&ruleset, "10.0.0.5", 22, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssh_blocked_conntrack_invalid_only() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             -A INPUT -m conntrack --ctstate INVALID -j DROP\n\
             COMMIT\n",
        );
        let result = check_lockout(&ruleset, "10.0.0.5", 22, None, None);
        assert!(!result.is_ok());
    }

    #[test]
    fn test_vpn_path_blocked() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             -A INPUT -p tcp --dport 22 -j ACCEPT\n\
             COMMIT\n",
        );
        // SSH is allowed but VPN port 51820 is not — VPN trace uses Any
        // protocol, but port 51820 doesn't match dport 22.
        let result = check_lockout(&ruleset, "10.0.0.5", 22, Some(51820), None);
        assert!(
            !result.is_ok(),
            "VPN port should be detected as blocked"
        );
    }

    #[test]
    fn test_vpn_path_allowed() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             -A INPUT -p tcp --dport 22 -j ACCEPT\n\
             -A INPUT -p udp --dport 51820 -j ACCEPT\n\
             COMMIT\n",
        );
        // VPN trace uses SimProtocol::Any, which matches any rule protocol.
        // The UDP rule for port 51820 should match.
        let result = check_lockout(&ruleset, "10.0.0.5", 22, Some(51820), None);
        assert!(result.is_ok(), "VPN port should be allowed via UDP rule");
    }

    #[test]
    fn test_no_filter_table() {
        let ruleset = make_ruleset(
            "*nat\n\
             :PREROUTING ACCEPT [0:0]\n\
             COMMIT\n",
        );
        let result = check_lockout(&ruleset, "10.0.0.5", 22, None, None);
        assert!(result.is_ok(), "No filter table means no blocking");
    }

    #[test]
    fn test_interface_match() {
        assert!(interface_matches("eth0", "eth0"));
        assert!(!interface_matches("eth0", "eth1"));
        assert!(interface_matches("eth+", "eth0"));
        assert!(interface_matches("eth+", "eth1"));
        assert!(!interface_matches("wg+", "eth0"));
    }

    #[test]
    fn test_cidr_contains() {
        assert!(cidr_contains("10.0.0.0/24", "10.0.0.5"));
        assert!(cidr_contains("10.0.0.0/24", "10.0.0.255"));
        assert!(!cidr_contains("10.0.0.0/24", "10.0.1.5"));
        assert!(cidr_contains("0.0.0.0/0", "192.168.1.1"));
        assert!(cidr_contains("10.0.0.0/8", "10.255.255.255"));
        assert!(!cidr_contains("10.0.0.0/8", "11.0.0.1"));
    }

    #[test]
    fn test_port_matches() {
        assert!(port_matches(&PortSpec::Single(22), 22));
        assert!(!port_matches(&PortSpec::Single(22), 80));
        assert!(port_matches(&PortSpec::Multi(vec![22, 80, 443]), 80));
        assert!(!port_matches(&PortSpec::Multi(vec![22, 80, 443]), 8080));
        assert!(port_matches(&PortSpec::Range(1024, 65535), 8080));
        assert!(!port_matches(&PortSpec::Range(1024, 65535), 22));
    }

    #[test]
    fn test_multiport_ssh_allowed() {
        let ruleset = make_ruleset(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             -A INPUT -p tcp -m multiport --dports 22,80,443 -j ACCEPT\n\
             COMMIT\n",
        );
        let result = check_lockout(&ruleset, "10.0.0.5", 22, None, None);
        assert!(result.is_ok());
    }
}
