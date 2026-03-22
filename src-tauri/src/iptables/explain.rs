use crate::iptables::types::*;

/// Produce a human-readable explanation of a parsed rule.
///
/// Uses well-known port-to-service mappings to provide context (e.g. "This is
/// typically SSH").
pub fn explain_rule(spec: &RuleSpec) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Determine action
    let action = match &spec.target {
        Some(Target::Accept) => "allows",
        Some(Target::Drop) => "drops",
        Some(Target::Reject) => "rejects",
        Some(Target::Log) => "logs",
        Some(Target::Return) => "returns from the current chain for",
        Some(Target::Dnat) => "performs DNAT (destination NAT) on",
        Some(Target::Snat) => "performs SNAT (source NAT) on",
        Some(Target::Masquerade) => "masquerades (NAT) for",
        Some(Target::ConntrackHelper) => "assigns a conntrack helper to",
        Some(Target::Mark) => "marks",
        Some(Target::Jump(chain)) => {
            parts.push(format!("This rule jumps to chain {} for matching traffic.", chain));
            return finalize_explanation(spec, parts);
        }
        Some(Target::Queue) => "queues",
        Some(Target::Other(name)) => {
            parts.push(format!("This rule applies the {} target to", name));
            "applies a target to"
        }
        None => "matches",
    };

    // Build the traffic description
    let traffic_desc = describe_traffic(spec);

    if matches!(&spec.target, Some(Target::Log)) {
        // Special handling for LOG rules
        let mut log_desc = format!("This rule logs {}", traffic_desc);
        // Check for log-prefix in target_args
        let log_prefix = extract_target_arg(&spec.target_args, "--log-prefix");
        if let Some(prefix) = log_prefix {
            log_desc.push_str(&format!(" with prefix '{}'", prefix));
        }
        // Check for rate limiting
        if let Some(limit_desc) = describe_rate_limit(spec) {
            log_desc.push_str(&format!(" {}", limit_desc));
        }
        log_desc.push('.');
        parts.push(log_desc);
    } else if matches!(&spec.target, Some(Target::Dnat)) {
        let mut desc = format!("This rule performs DNAT on {}", traffic_desc);
        if let Some(to_dest) = extract_target_arg(&spec.target_args, "--to-destination") {
            desc.push_str(&format!(", redirecting to {}", to_dest));
        }
        desc.push('.');
        parts.push(desc);
    } else if matches!(&spec.target, Some(Target::Snat)) {
        let mut desc = format!("This rule performs SNAT on {}", traffic_desc);
        if let Some(to_src) = extract_target_arg(&spec.target_args, "--to-source") {
            desc.push_str(&format!(", changing source to {}", to_src));
        }
        desc.push('.');
        parts.push(desc);
    } else if matches!(&spec.target, Some(Target::Masquerade)) {
        parts.push(format!("This rule {} {}.", action, traffic_desc));
    } else if matches!(&spec.target, Some(Target::ConntrackHelper)) {
        let mut desc = format!("This rule assigns a conntrack helper to {}", traffic_desc);
        if let Some(helper) = extract_target_arg(&spec.target_args, "--helper") {
            desc.push_str(&format!(" (helper: {})", helper));
        }
        desc.push('.');
        parts.push(desc);
    } else {
        parts.push(format!("This rule {} {}.", action, traffic_desc));
    }

    // Add service name context
    if let Some(service) = identify_service(spec) {
        parts.push(format!("This is typically {}.", service));
    }

    // Add comment if present
    if let Some(ref comment) = spec.comment {
        parts.push(format!("Comment: \"{}\".", comment));
    }

    finalize_explanation(spec, parts)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn finalize_explanation(_spec: &RuleSpec, parts: Vec<String>) -> String {
    parts.join(" ")
}

/// Build a human-readable description of what traffic the rule matches.
fn describe_traffic(spec: &RuleSpec) -> String {
    let mut desc_parts: Vec<String> = Vec::new();

    // Protocol
    let proto_str = match &spec.protocol {
        Some(proto) => {
            let name = proto.to_string().to_uppercase();
            if spec.protocol_negated {
                format!("non-{}", name)
            } else {
                name
            }
        }
        None => String::new(),
    };

    // Ports
    let port_desc = describe_ports(spec);

    // Build "TCP traffic on port 22" style string
    if !proto_str.is_empty() && !port_desc.is_empty() {
        desc_parts.push(format!("{} traffic on {}", proto_str, port_desc));
    } else if !proto_str.is_empty() {
        desc_parts.push(format!("{} traffic", proto_str));
    } else if !port_desc.is_empty() {
        desc_parts.push(format!("traffic on {}", port_desc));
    } else {
        // Check for conntrack state
        if let Some(ct_desc) = describe_conntrack(spec) {
            desc_parts.push(ct_desc);
        } else if spec.in_iface.is_none() && spec.out_iface.is_none()
            && spec.source.is_none() && spec.destination.is_none()
        {
            desc_parts.push("all incoming traffic".to_string());
        } else {
            desc_parts.push("traffic".to_string());
        }
    }

    // Source
    if let Some(ref src) = spec.source {
        if src.negated {
            desc_parts.push(format!("not from {}", describe_address(&src.addr)));
        } else {
            desc_parts.push(format!("from {}", describe_address(&src.addr)));
        }
    }

    // Destination
    if let Some(ref dst) = spec.destination {
        if dst.negated {
            desc_parts.push(format!("not to {}", describe_address(&dst.addr)));
        } else {
            desc_parts.push(format!("to {}", describe_address(&dst.addr)));
        }
    }

    // Interfaces
    if let Some(ref iface) = spec.in_iface {
        if iface.negated {
            desc_parts.push(format!("not on interface {}", iface.name));
        } else if iface.name == "lo" {
            desc_parts.push("on the loopback interface".to_string());
        } else {
            desc_parts.push(format!("on interface {}", iface.name));
        }
    }

    if let Some(ref iface) = spec.out_iface {
        if iface.negated {
            desc_parts.push(format!("not via output interface {}", iface.name));
        } else {
            desc_parts.push(format!("via output interface {}", iface.name));
        }
    }

    desc_parts.join(" ")
}

fn describe_ports(spec: &RuleSpec) -> String {
    let mut parts = Vec::new();

    if let Some(ref dp) = spec.dest_port {
        match dp {
            PortSpec::Single(p) => parts.push(format!("port {}", p)),
            PortSpec::Multi(ports) => {
                let port_strs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                parts.push(format!("ports {}", port_strs.join(", ")));
            }
            PortSpec::Range(lo, hi) => parts.push(format!("ports {}-{}", lo, hi)),
        }
    }

    if let Some(ref sp) = spec.source_port {
        match sp {
            PortSpec::Single(p) => parts.push(format!("source port {}", p)),
            PortSpec::Multi(ports) => {
                let port_strs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                parts.push(format!("source ports {}", port_strs.join(", ")));
            }
            PortSpec::Range(lo, hi) => parts.push(format!("source ports {}-{}", lo, hi)),
        }
    }

    // Also check match modules for multiport --dports
    for m in &spec.matches {
        if m.module == "multiport" {
            for i in 0..m.args.len() {
                if (m.args[i] == "--dports" || m.args[i] == "--destination-ports") && i + 1 < m.args.len() {
                    if spec.dest_port.is_none() {
                        parts.push(format!("ports {}", m.args[i + 1]));
                    }
                }
                if (m.args[i] == "--sports" || m.args[i] == "--source-ports") && i + 1 < m.args.len() {
                    if spec.source_port.is_none() {
                        parts.push(format!("source ports {}", m.args[i + 1]));
                    }
                }
            }
        }
    }

    parts.join(" and ")
}

fn describe_address(addr: &str) -> String {
    if addr.contains('/') {
        format!("the {} network", addr)
    } else {
        addr.to_string()
    }
}

fn describe_conntrack(spec: &RuleSpec) -> Option<String> {
    for m in &spec.matches {
        if m.module == "conntrack" || m.module == "state" {
            for i in 0..m.args.len() {
                if (m.args[i] == "--ctstate" || m.args[i] == "--state") && i + 1 < m.args.len() {
                    let states = &m.args[i + 1];
                    if states.contains("INVALID") && !states.contains("ESTABLISHED") {
                        return Some("packets in INVALID connection state".to_string());
                    }
                    if states.contains("ESTABLISHED") || states.contains("RELATED") {
                        return Some(format!("packets in {} connection state", states));
                    }
                    return Some(format!("{} connection state traffic", states));
                }
            }
        }
    }
    None
}

fn describe_rate_limit(spec: &RuleSpec) -> Option<String> {
    for m in &spec.matches {
        if m.module == "limit" {
            for i in 0..m.args.len() {
                if m.args[i] == "--limit" && i + 1 < m.args.len() {
                    let rate = &m.args[i + 1];
                    return Some(format!("at a rate of {}", format_rate(rate)));
                }
            }
        }
    }
    None
}

fn format_rate(rate: &str) -> String {
    // Rates like "5/min", "10/sec", etc.
    if let Some(idx) = rate.find('/') {
        let count = &rate[..idx];
        let unit = &rate[idx + 1..];
        let unit_full = match unit {
            "sec" | "second" | "s" => "per second",
            "min" | "minute" | "m" => "per minute",
            "hour" | "h" => "per hour",
            "day" | "d" => "per day",
            _ => return rate.to_string(),
        };
        format!("{} {}", count, unit_full)
    } else {
        rate.to_string()
    }
}

fn extract_target_arg(target_args: &[String], flag: &str) -> Option<String> {
    for i in 0..target_args.len() {
        if target_args[i] == flag && i + 1 < target_args.len() {
            return Some(target_args[i + 1].clone());
        }
    }
    None
}

/// Identify the well-known service for a rule based on its port(s).
fn identify_service(spec: &RuleSpec) -> Option<&'static str> {
    let port = match &spec.dest_port {
        Some(PortSpec::Single(p)) => Some(*p),
        _ => None,
    };

    let proto = spec.protocol.as_ref();

    match (port, proto) {
        (Some(22), Some(Protocol::Tcp)) => Some("SSH"),
        (Some(80), Some(Protocol::Tcp)) => Some("HTTP"),
        (Some(443), Some(Protocol::Tcp)) => Some("HTTPS"),
        (Some(21), Some(Protocol::Tcp)) => Some("FTP"),
        (Some(25), Some(Protocol::Tcp)) => Some("SMTP"),
        (Some(53), _) => Some("DNS"),
        (Some(110), Some(Protocol::Tcp)) => Some("POP3"),
        (Some(143), Some(Protocol::Tcp)) => Some("IMAP"),
        (Some(993), Some(Protocol::Tcp)) => Some("IMAPS"),
        (Some(995), Some(Protocol::Tcp)) => Some("POP3S"),
        (Some(3306), Some(Protocol::Tcp)) => Some("MySQL"),
        (Some(5432), Some(Protocol::Tcp)) => Some("PostgreSQL"),
        (Some(6379), Some(Protocol::Tcp)) => Some("Redis"),
        (Some(27017), Some(Protocol::Tcp)) => Some("MongoDB"),
        (Some(8080), Some(Protocol::Tcp)) => Some("HTTP alternate"),
        (Some(8443), Some(Protocol::Tcp)) => Some("HTTPS alternate"),
        (Some(9100), Some(Protocol::Tcp)) => Some("Prometheus node_exporter"),
        (Some(3000), Some(Protocol::Tcp)) => Some("Grafana / development server"),
        (Some(5000), Some(Protocol::Tcp)) => Some("a common application port"),
        (Some(6443), Some(Protocol::Tcp)) => Some("Kubernetes API server"),
        (Some(2049), _) => Some("NFS"),
        (Some(111), _) => Some("RPC portmapper"),
        (Some(123), Some(Protocol::Udp)) => Some("NTP"),
        (Some(161), Some(Protocol::Udp)) => Some("SNMP"),
        (Some(500), Some(Protocol::Udp)) => Some("IKE (IPsec)"),
        (Some(1194), Some(Protocol::Udp)) => Some("OpenVPN"),
        (Some(51820), Some(Protocol::Udp)) => Some("WireGuard"),
        _ => {
            // Check multiport
            if let Some(PortSpec::Multi(ports)) = &spec.dest_port {
                if ports.contains(&80) && ports.contains(&443) {
                    return Some("web traffic (HTTP/HTTPS)");
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_explain_ssh_rule() {
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
        assert!(explanation.contains("allows"), "should contain 'allows': {}", explanation);
        assert!(explanation.contains("TCP"), "should contain 'TCP': {}", explanation);
        assert!(explanation.contains("22"), "should contain '22': {}", explanation);
        assert!(explanation.contains("10.0.0.0/8"), "should contain source: {}", explanation);
        assert!(explanation.contains("SSH"), "should contain 'SSH': {}", explanation);
    }

    #[test]
    fn test_explain_drop_all() {
        let spec = RuleSpec {
            target: Some(Target::Drop),
            ..make_spec()
        };
        let explanation = explain_rule(&spec);
        assert!(explanation.contains("drops"), "should contain 'drops': {}", explanation);
        assert!(explanation.contains("all incoming traffic") || explanation.contains("traffic"),
            "should describe traffic: {}", explanation);
    }

    #[test]
    fn test_explain_log_rule() {
        let spec = RuleSpec {
            target: Some(Target::Log),
            target_args: vec!["--log-prefix".to_string(), "BLOCKED: ".to_string()],
            matches: vec![MatchSpec {
                module: "limit".to_string(),
                args: vec!["--limit".to_string(), "5/min".to_string()],
            }],
            ..make_spec()
        };
        let explanation = explain_rule(&spec);
        assert!(explanation.contains("logs"), "should contain 'logs': {}", explanation);
        assert!(explanation.contains("BLOCKED:"), "should contain prefix: {}", explanation);
        assert!(explanation.contains("5 per minute"), "should contain rate: {}", explanation);
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
        assert!(explanation.contains("DNAT"), "should contain DNAT: {}", explanation);
        assert!(explanation.contains("10.0.0.1:80"), "should contain dest: {}", explanation);
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
        assert!(explanation.contains("loopback"), "should contain 'loopback': {}", explanation);
    }

    #[test]
    fn test_explain_with_comment() {
        let spec = RuleSpec {
            protocol: Some(Protocol::Tcp),
            dest_port: Some(PortSpec::Single(443)),
            target: Some(Target::Accept),
            comment: Some("Allow HTTPS".to_string()),
            ..make_spec()
        };
        let explanation = explain_rule(&spec);
        assert!(explanation.contains("Allow HTTPS"), "should contain comment: {}", explanation);
    }

    #[test]
    fn test_explain_conntrack() {
        let spec = RuleSpec {
            matches: vec![MatchSpec {
                module: "conntrack".to_string(),
                args: vec!["--ctstate".to_string(), "ESTABLISHED,RELATED".to_string()],
            }],
            target: Some(Target::Accept),
            ..make_spec()
        };
        let explanation = explain_rule(&spec);
        assert!(explanation.contains("ESTABLISHED"), "should mention conntrack: {}", explanation);
    }

    #[test]
    fn test_explain_web_traffic() {
        let spec = RuleSpec {
            protocol: Some(Protocol::Tcp),
            dest_port: Some(PortSpec::Multi(vec![80, 443])),
            target: Some(Target::Accept),
            ..make_spec()
        };
        let explanation = explain_rule(&spec);
        assert!(explanation.contains("web traffic") || explanation.contains("80") && explanation.contains("443"),
            "should mention web: {}", explanation);
    }
}
