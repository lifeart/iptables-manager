use serde::{Deserialize, Serialize};
use thiserror::Error;
use ts_rs::TS;

use crate::ssh::command::build_command;
use crate::ssh::executor::{CommandExecutor, ExecError};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("command execution error: {0}")]
    Exec(#[from] ExecError),
    #[error("parsing failed: {0}")]
    ParseFailed(String),
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Per-rule packet/byte hit counters from `iptables -L -v -n -x`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct HitCounter {
    pub rule_id: String,
    #[ts(type = "number")]
    pub packets: u64,
    #[ts(type = "number")]
    pub bytes: u64,
    #[ts(type = "number")]
    pub timestamp: u64,
    // Raw fields kept for detailed display
    pub chain: String,
    pub rule_num: usize,
    pub target: String,
    pub protocol: String,
    pub source: String,
    pub destination: String,
}

/// A blocked connection entry parsed from kernel logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedEntry {
    pub timestamp: String,
    pub source_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    pub interface_in: String,
}

/// How blocked traffic logs are read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogMethod {
    /// Read from `journalctl -k`
    Journalctl,
    /// Read from `/var/log/kern.log` or `/var/log/messages`
    KernLog,
    /// Read from `dmesg`
    Dmesg,
    /// No log source available
    None,
}

/// Connection tracking table usage.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct ConntrackUsage {
    #[ts(type = "number")]
    pub current: u64,
    #[ts(type = "number")]
    pub max: u64,
    pub percent: f64,
}

/// A fail2ban ban entry (one entry per banned IP).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct Fail2banBan {
    pub jail: String,
    pub ip: String,
    #[ts(type = "number")]
    pub banned_at: u64,
    #[ts(type = "number | null")]
    pub expires_at: Option<u64>,
}

/// A single connection tracking table entry.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct ConntrackEntry {
    pub protocol: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub state: String,
    #[ts(type = "number")]
    pub ttl: u64,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch hit counters for all chains from `iptables -L -v -n -x`.
pub async fn fetch_hit_counters(
    executor: &dyn CommandExecutor,
) -> Result<Vec<HitCounter>, MonitorError> {
    let cmd = build_command("sudo", &["iptables", "-w", "5", "-L", "-v", "-n", "-x"]);
    let output = executor.exec(&cmd).await?;
    if output.exit_code != 0 {
        return Err(MonitorError::ParseFailed(format!(
            "iptables -L failed: {}",
            output.stderr.trim()
        )));
    }
    Ok(parse_hit_counters(&output.stdout))
}

/// Detect the best available log reading method on the remote host.
pub async fn detect_log_method(executor: &dyn CommandExecutor) -> LogMethod {
    // Try journalctl first
    let cmd = build_command("which", &["journalctl"]);
    if let Ok(output) = executor.exec(&cmd).await {
        if output.exit_code == 0 {
            return LogMethod::Journalctl;
        }
    }

    // Try kern.log
    let cmd = build_command("test", &["-f", "/var/log/kern.log"]);
    if let Ok(output) = executor.exec(&cmd).await {
        if output.exit_code == 0 {
            return LogMethod::KernLog;
        }
    }

    // Try /var/log/messages
    let cmd = build_command("test", &["-f", "/var/log/messages"]);
    if let Ok(output) = executor.exec(&cmd).await {
        if output.exit_code == 0 {
            return LogMethod::KernLog;
        }
    }

    // dmesg is usually available
    let cmd = build_command("which", &["dmesg"]);
    if let Ok(output) = executor.exec(&cmd).await {
        if output.exit_code == 0 {
            return LogMethod::Dmesg;
        }
    }

    LogMethod::None
}

/// Parse a kernel log line matching the "TR-BLOCKED:" prefix.
///
/// Returns `None` if the line does not match.
///
/// Example kernel log line:
/// ```text
/// Mar 22 10:15:32 server kernel: TR-BLOCKED: IN=eth0 OUT= SRC=192.168.1.100 DST=10.0.0.1 ... PROTO=TCP ... DPT=443
/// ```
pub fn parse_blocked_log_line(line: &str) -> Option<BlockedEntry> {
    if !line.contains("TR-BLOCKED:") {
        return None;
    }

    let timestamp = extract_log_timestamp(line);
    let source_ip = extract_field(line, "SRC=")?;
    let dest_port = extract_field(line, "DPT=")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let protocol = extract_field(line, "PROTO=").unwrap_or_default().to_lowercase();
    let interface_in = extract_field(line, "IN=").unwrap_or_default();

    Some(BlockedEntry {
        timestamp,
        source_ip,
        dest_port,
        protocol,
        interface_in,
    })
}

/// Fetch connection tracking table usage from /proc.
pub async fn fetch_conntrack_usage(
    executor: &dyn CommandExecutor,
) -> Result<ConntrackUsage, MonitorError> {
    let count_cmd = build_command("cat", &["/proc/sys/net/netfilter/nf_conntrack_count"]);
    let count_output = executor.exec(&count_cmd).await?;
    if count_output.exit_code != 0 {
        return Err(MonitorError::ParseFailed(
            "conntrack not available".to_string(),
        ));
    }

    let max_cmd = build_command("cat", &["/proc/sys/net/netfilter/nf_conntrack_max"]);
    let max_output = executor.exec(&max_cmd).await?;
    if max_output.exit_code != 0 {
        return Err(MonitorError::ParseFailed(
            "conntrack not available".to_string(),
        ));
    }

    let current = count_output
        .stdout
        .trim()
        .parse::<u64>()
        .map_err(|e| MonitorError::ParseFailed(format!("failed to parse conntrack count: {}", e)))?;

    let max = max_output
        .stdout
        .trim()
        .parse::<u64>()
        .map_err(|e| MonitorError::ParseFailed(format!("failed to parse conntrack max: {}", e)))?;

    let percent = if max > 0 {
        (current as f64 / max as f64) * 100.0
    } else {
        0.0
    };

    Ok(ConntrackUsage {
        current,
        max,
        percent,
    })
}

/// Fetch connection tracking table entries.
///
/// Parses output from `conntrack -L` into individual `ConntrackEntry` structs.
/// Returns an empty Vec if conntrack is not available.
pub async fn fetch_conntrack_table(
    executor: &dyn CommandExecutor,
) -> Result<Vec<ConntrackEntry>, MonitorError> {
    let cmd = build_command("sudo", &["conntrack", "-L", "-o", "extended"]);
    let output = match executor.exec(&cmd).await {
        Ok(o) if o.exit_code == 0 => o,
        _ => return Ok(Vec::new()), // conntrack tool may not be installed
    };
    Ok(parse_conntrack_entries(&output.stdout))
}

/// Fetch fail2ban ban information from `fail2ban-client status`.
pub async fn fetch_fail2ban_bans(
    executor: &dyn CommandExecutor,
) -> Result<Vec<Fail2banBan>, MonitorError> {
    // First get the list of jails
    let cmd = build_command("sudo", &["fail2ban-client", "status"]);
    let output = match executor.exec(&cmd).await {
        Ok(o) if o.exit_code == 0 => o,
        Ok(o) => {
            return Err(MonitorError::ParseFailed(format!(
                "fail2ban-client status failed: {}",
                o.stderr.trim()
            )));
        }
        Err(e) => return Err(MonitorError::Exec(e)),
    };

    let jails = parse_jail_list(&output.stdout);

    let mut bans = Vec::new();
    for jail in &jails {
        let cmd = build_command("sudo", &["fail2ban-client", "status", jail]);
        if let Ok(output) = executor.exec(&cmd).await {
            if output.exit_code == 0 {
                bans.extend(parse_jail_status(jail, &output.stdout));
            }
        }
    }

    Ok(bans)
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_hit_counters(output: &str) -> Vec<HitCounter> {
    let mut counters = Vec::new();
    let mut current_chain = String::new();
    let mut rule_num: usize = 0;

    for line in output.lines() {
        let trimmed = line.trim();

        // Chain header: "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
        // or "Chain TR-INPUT (0 references)"
        if let Some(rest) = trimmed.strip_prefix("Chain ") {
            if let Some(name_end) = rest.find(' ') {
                current_chain = rest[..name_end].to_string();
                rule_num = 0;
            }
            continue;
        }

        // Skip header line
        if trimmed.starts_with("pkts") || trimmed.is_empty() {
            continue;
        }

        // Only track TR- chains
        if !current_chain.starts_with("TR-") {
            continue;
        }

        // Rule line: "    1234    56789 ACCEPT  tcp  --  *  *  0.0.0.0/0  0.0.0.0/0  tcp dpt:22"
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }

        let packets = match fields[0].parse::<u64>() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let bytes = match fields[1].parse::<u64>() {
            Ok(b) => b,
            Err(_) => continue,
        };

        rule_num += 1;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        counters.push(HitCounter {
            rule_id: format!("{}/{}", current_chain, rule_num),
            packets,
            bytes,
            timestamp: now,
            chain: current_chain.clone(),
            rule_num,
            target: fields[2].to_string(),
            protocol: fields[3].to_string(),
            source: fields.get(7).unwrap_or(&"0.0.0.0/0").to_string(),
            destination: fields.get(8).unwrap_or(&"0.0.0.0/0").to_string(),
        });
    }

    counters
}

fn extract_log_timestamp(line: &str) -> String {
    // Typical syslog: "Mar 22 10:15:32 hostname ..."
    // Return the first 15 chars as timestamp
    if line.len() >= 15 {
        line[..15].to_string()
    } else {
        String::new()
    }
}

fn extract_field(line: &str, prefix: &str) -> Option<String> {
    let start = line.find(prefix)?;
    let value_start = start + prefix.len();
    let rest = &line[value_start..];
    let end = rest.find(' ').unwrap_or(rest.len());
    let value = rest[..end].to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn parse_conntrack_entries(output: &str) -> Vec<ConntrackEntry> {
    // conntrack -L -o extended output looks like:
    // ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=54321 dport=443 ...
    let mut entries = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }

        // Protocol is typically the 3rd field (e.g., "tcp", "udp")
        let protocol = fields.get(2).unwrap_or(&"").to_string();
        if protocol.is_empty() {
            continue;
        }

        // TTL is typically the 5th field
        let ttl = fields
            .get(4)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // State (e.g., ESTABLISHED, TIME_WAIT) is typically the 6th field if present
        let mut state = String::new();
        let mut source_ip = String::new();
        let mut dest_ip = String::new();
        let mut source_port: u16 = 0;
        let mut dest_port: u16 = 0;
        let mut found_reply = false;

        for field in &fields[5..] {
            // Stop parsing at the [UNREPLIED] / [ASSURED] / reply direction markers
            if *field == "[UNREPLIED]" || *field == "[ASSURED]" {
                continue;
            }
            // The second set of src/dst after "src=..." appears for the reply direction;
            // we only want the original direction (first occurrence).
            if field.starts_with("src=") {
                if source_ip.is_empty() {
                    source_ip = field.strip_prefix("src=").unwrap_or("").to_string();
                } else {
                    found_reply = true;
                }
            } else if field.starts_with("dst=") && !found_reply {
                dest_ip = field.strip_prefix("dst=").unwrap_or("").to_string();
            } else if field.starts_with("sport=") && !found_reply {
                source_port = field
                    .strip_prefix("sport=")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if field.starts_with("dport=") && !found_reply {
                dest_port = field
                    .strip_prefix("dport=")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if state.is_empty()
                && !field.contains('=')
                && field.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                && !field.is_empty()
            {
                state = field.to_string();
            }
        }

        if source_ip.is_empty() && dest_ip.is_empty() {
            continue;
        }

        entries.push(ConntrackEntry {
            protocol,
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            state,
            ttl,
        });
    }
    entries
}

fn parse_jail_list(output: &str) -> Vec<String> {
    // Output format:
    // Status
    // |- Number of jail:      2
    // `- Jail list:   sshd, postfix
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("`- Jail list:") {
            return rest
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    Vec::new()
}

fn parse_jail_status(jail: &str, output: &str) -> Vec<Fail2banBan> {
    let mut banned_ips = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // "`- Banned IP list:    1.2.3.4 5.6.7.8"
        if let Some(rest) = trimmed.strip_prefix("`- Banned IP list:") {
            banned_ips = rest
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
        }
    }

    // We don't have per-IP timestamps from fail2ban-client status,
    // so we use the current time as banned_at.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    banned_ips
        .into_iter()
        .map(|ip| Fail2banBan {
            jail: jail.to_string(),
            ip,
            banned_at: now,
            expires_at: None, // fail2ban-client status doesn't expose per-IP expiry
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hit_counters() {
        let output = r#"Chain INPUT (policy ACCEPT 1000 packets, 50000 bytes)
    pkts      bytes target     prot opt in     out     source               destination
    5000   400000 TR-CONNTRACK  all  --  *      *       0.0.0.0/0            0.0.0.0/0
    4500   350000 TR-INPUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0

Chain TR-CONNTRACK (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate INVALID
    4500   350000 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED

Chain TR-INPUT (1 references)
    pkts      bytes target     prot opt in     out     source               destination
     100     8000 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
      50     4000 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
"#;
        let counters = parse_hit_counters(output);

        // Only TR- chains should be included
        assert_eq!(counters.len(), 4);

        // First counter: TR-CONNTRACK rule 1
        assert_eq!(counters[0].chain, "TR-CONNTRACK");
        assert_eq!(counters[0].rule_num, 1);
        assert_eq!(counters[0].packets, 0);
        assert_eq!(counters[0].target, "DROP");

        // Second counter: TR-CONNTRACK rule 2
        assert_eq!(counters[1].chain, "TR-CONNTRACK");
        assert_eq!(counters[1].rule_num, 2);
        assert_eq!(counters[1].packets, 4500);

        // Third: TR-INPUT loopback
        assert_eq!(counters[2].chain, "TR-INPUT");
        assert_eq!(counters[2].packets, 100);
        assert_eq!(counters[2].target, "ACCEPT");

        // Fourth: TR-INPUT SSH
        assert_eq!(counters[3].chain, "TR-INPUT");
        assert_eq!(counters[3].rule_num, 2);
        assert_eq!(counters[3].packets, 50);
        assert_eq!(counters[3].protocol, "tcp");
    }

    #[test]
    fn test_parse_blocked_log_line_match() {
        let line = "Mar 22 10:15:32 server kernel: TR-BLOCKED: IN=eth0 OUT= SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0";
        let entry = parse_blocked_log_line(line).unwrap();
        assert_eq!(entry.source_ip, "192.168.1.100");
        assert_eq!(entry.dest_port, 443);
        assert_eq!(entry.protocol, "tcp");
        assert_eq!(entry.interface_in, "eth0");
        assert_eq!(entry.timestamp, "Mar 22 10:15:32");
    }

    #[test]
    fn test_parse_blocked_log_line_no_match() {
        let line = "Mar 22 10:15:32 server kernel: some other log message";
        assert!(parse_blocked_log_line(line).is_none());
    }

    #[test]
    fn test_parse_blocked_log_line_udp() {
        let line = "Mar 22 10:20:00 server kernel: TR-BLOCKED: IN=eth0 OUT= SRC=10.0.0.50 DST=10.0.0.1 PROTO=UDP SPT=12345 DPT=53";
        let entry = parse_blocked_log_line(line).unwrap();
        assert_eq!(entry.source_ip, "10.0.0.50");
        assert_eq!(entry.dest_port, 53);
        assert_eq!(entry.protocol, "udp");
    }

    #[test]
    fn test_extract_field() {
        assert_eq!(
            extract_field("SRC=1.2.3.4 DST=5.6.7.8", "SRC="),
            Some("1.2.3.4".to_string())
        );
        assert_eq!(
            extract_field("SRC=1.2.3.4 DST=5.6.7.8", "DST="),
            Some("5.6.7.8".to_string())
        );
        assert_eq!(
            extract_field("PROTO=TCP SPT=1234", "PROTO="),
            Some("TCP".to_string())
        );
        assert_eq!(extract_field("no match here", "SRC="), None);
    }

    #[test]
    fn test_parse_jail_list() {
        let output = r#"Status
|- Number of jail:      2
`- Jail list:   sshd, postfix
"#;
        let jails = parse_jail_list(output);
        assert_eq!(jails, vec!["sshd", "postfix"]);
    }

    #[test]
    fn test_parse_jail_list_single() {
        let output = r#"Status
|- Number of jail:      1
`- Jail list:   sshd
"#;
        let jails = parse_jail_list(output);
        assert_eq!(jails, vec!["sshd"]);
    }

    #[test]
    fn test_parse_jail_status() {
        let output = r#"Status for the jail: sshd
|- Filter
|  |- Currently failed: 5
|  |- Total failed:     123
|  `- File list:        /var/log/auth.log
`- Actions
   |- Currently banned: 3
   |- Total banned:     42
   `- Banned IP list:   1.2.3.4 5.6.7.8 9.10.11.12
"#;
        let bans = parse_jail_status("sshd", output);
        assert_eq!(bans.len(), 3);
        assert_eq!(bans[0].jail, "sshd");
        assert_eq!(bans[0].ip, "1.2.3.4");
        assert!(bans[0].banned_at > 0);
        assert!(bans[0].expires_at.is_none());
        assert_eq!(bans[1].ip, "5.6.7.8");
        assert_eq!(bans[2].ip, "9.10.11.12");
    }

    #[test]
    fn test_parse_jail_status_no_bans() {
        let output = r#"Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  `- File list:        /var/log/auth.log
`- Actions
   |- Currently banned: 0
   |- Total banned:     0
   `- Banned IP list:
"#;
        let bans = parse_jail_status("sshd", output);
        assert_eq!(bans.len(), 0);
    }

    #[test]
    fn test_parse_conntrack_entries() {
        let output = r#"ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=54321 dport=443 src=10.0.0.2 dst=10.0.0.1 sport=443 dport=54321 [ASSURED] mark=0 use=1
ipv4     2 udp      17 29 src=192.168.1.1 dst=8.8.8.8 sport=12345 dport=53 src=8.8.8.8 dst=192.168.1.1 sport=53 dport=12345 mark=0 use=1
"#;
        let entries = parse_conntrack_entries(output);
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].protocol, "tcp");
        assert_eq!(entries[0].source_ip, "10.0.0.1");
        assert_eq!(entries[0].dest_ip, "10.0.0.2");
        assert_eq!(entries[0].source_port, 54321);
        assert_eq!(entries[0].dest_port, 443);
        assert_eq!(entries[0].state, "ESTABLISHED");
        assert_eq!(entries[0].ttl, 431999);

        assert_eq!(entries[1].protocol, "udp");
        assert_eq!(entries[1].source_ip, "192.168.1.1");
        assert_eq!(entries[1].dest_ip, "8.8.8.8");
        assert_eq!(entries[1].source_port, 12345);
        assert_eq!(entries[1].dest_port, 53);
    }
}
