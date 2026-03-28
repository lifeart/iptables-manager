use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::host::detect::IptablesVariant;
use crate::ssh::command::{build_command, build_iptables_command};
use crate::ssh::executor::{CommandExecutor, ExecError};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct LiveTraceRequest {
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub protocol: Option<String>,
    pub dest_port: Option<u16>,
    pub interface_in: Option<String>,
    pub timeout_secs: u32,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct LiveTraceEvent {
    pub timestamp: String,
    pub table: String,
    pub chain: String,
    pub rule_num: usize,
    pub verdict: String,
    pub packet_info: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct LiveTraceResult {
    pub events: Vec<LiveTraceEvent>,
    pub trace_rule_inserted: bool,
    pub trace_rule_removed: bool,
    pub collection_method: String,
}

#[derive(Debug)]
pub enum LiveTraceError {
    Exec(ExecError),
    InsertFailed(String),
    CollectionFailed(String),
}

impl std::fmt::Display for LiveTraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LiveTraceError::Exec(e) => write!(f, "execution error: {}", e),
            LiveTraceError::InsertFailed(msg) => write!(f, "TRACE insert failed: {}", msg),
            LiveTraceError::CollectionFailed(msg) => write!(f, "trace collection failed: {}", msg),
        }
    }
}

impl From<ExecError> for LiveTraceError {
    fn from(e: ExecError) -> Self {
        LiveTraceError::Exec(e)
    }
}

// ---------------------------------------------------------------------------
// Filter args builder
// ---------------------------------------------------------------------------

/// Validate a live trace request. Returns an error message if any field is invalid.
fn validate_trace_request(req: &LiveTraceRequest) -> Result<(), String> {
    // IP address: digits, dots, colons (IPv6), slashes (CIDR) only
    fn is_valid_ip(s: &str) -> bool {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == ':' || c == '/' || c == 'a'
                    || c == 'b' || c == 'c' || c == 'd' || c == 'e' || c == 'f'
                    || c == 'A' || c == 'B' || c == 'C' || c == 'D' || c == 'E' || c == 'F')
    }

    // Protocol: alphanumeric only (tcp, udp, icmp, etc.)
    fn is_valid_protocol(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric())
    }

    // Interface: alphanumeric, dots, dashes, underscores
    fn is_valid_interface(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    }

    if let Some(ref ip) = req.source_ip {
        if !ip.is_empty() && !is_valid_ip(ip) {
            return Err(format!("invalid source IP: {}", ip));
        }
    }
    if let Some(ref ip) = req.dest_ip {
        if !ip.is_empty() && !is_valid_ip(ip) {
            return Err(format!("invalid destination IP: {}", ip));
        }
    }
    if let Some(ref proto) = req.protocol {
        if !proto.is_empty() && !is_valid_protocol(proto) {
            return Err(format!("invalid protocol: {}", proto));
        }
    }
    if let Some(ref iface) = req.interface_in {
        if !iface.is_empty() && !is_valid_interface(iface) {
            return Err(format!("invalid interface: {}", iface));
        }
    }
    Ok(())
}

/// Build iptables match arguments from a LiveTraceRequest.
pub fn build_trace_filter_args(req: &LiveTraceRequest) -> Vec<String> {
    let mut args = Vec::new();

    if let Some(ref src) = req.source_ip {
        if !src.is_empty() {
            args.push("-s".to_string());
            args.push(src.clone());
        }
    }

    if let Some(ref dst) = req.dest_ip {
        if !dst.is_empty() {
            args.push("-d".to_string());
            args.push(dst.clone());
        }
    }

    if let Some(ref proto) = req.protocol {
        if !proto.is_empty() {
            args.push("-p".to_string());
            args.push(proto.clone());
        }
    }

    if let Some(port) = req.dest_port {
        if port > 0 {
            // --dport requires a protocol; if not already set, default to tcp
            let has_proto = req
                .protocol
                .as_ref()
                .map(|p| !p.is_empty())
                .unwrap_or(false);
            if !has_proto {
                args.push("-p".to_string());
                args.push("tcp".to_string());
            }
            args.push("--dport".to_string());
            args.push(port.to_string());
        }
    }

    if let Some(ref iface) = req.interface_in {
        if !iface.is_empty() {
            args.push("-i".to_string());
            args.push(iface.clone());
        }
    }

    args
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run a live TRACE on a remote host.
///
/// Inserts TRACE rules into raw/PREROUTING and raw/OUTPUT, collects trace
/// output via xtables-monitor (nft) or dmesg (legacy), then always removes
/// the TRACE rules regardless of collection outcome.
///
/// **Limitation:** If the SSH connection drops during collection, cleanup
/// commands will also fail and TRACE rules will remain in the kernel's raw
/// table until manually removed or the host reboots. This is inherent to
/// the SSH-based architecture — consider using the safety timer for long traces.
pub async fn run_live_trace(
    executor: &dyn CommandExecutor,
    variant: &IptablesVariant,
    req: &LiveTraceRequest,
) -> Result<LiveTraceResult, LiveTraceError> {
    // Validate inputs to prevent flag injection via crafted IPC calls
    validate_trace_request(req)
        .map_err(|msg| LiveTraceError::InsertFailed(msg))?;

    // Clamp timeout to a safe maximum (120 seconds)
    let timeout_secs = req.timeout_secs.min(120);

    let filter_args = build_trace_filter_args(req);

    // Build filter args as &str slices for build_iptables_command
    let filter_refs: Vec<&str> = filter_args.iter().map(|s| s.as_str()).collect();

    // ── Step 1: Insert TRACE rules ──────────────────────────────

    // PREROUTING
    let mut pre_args = vec!["-t", "raw", "-I", "PREROUTING", "1"];
    pre_args.extend_from_slice(&filter_refs);
    pre_args.extend_from_slice(&["-j", "TRACE"]);
    let pre_cmd = build_iptables_command("iptables", &pre_args);

    let pre_output = executor.exec(&pre_cmd).await?;
    if pre_output.exit_code != 0 {
        return Err(LiveTraceError::InsertFailed(format!(
            "PREROUTING insert failed: {}",
            pre_output.stderr
        )));
    }

    // OUTPUT
    let mut out_args = vec!["-t", "raw", "-I", "OUTPUT", "1"];
    out_args.extend_from_slice(&filter_refs);
    out_args.extend_from_slice(&["-j", "TRACE"]);
    let out_cmd = build_iptables_command("iptables", &out_args);

    let out_output = executor.exec(&out_cmd).await;
    let trace_rule_inserted = match &out_output {
        Ok(o) if o.exit_code == 0 => true,
        _ => {
            // Try to clean up PREROUTING rule before returning
            let mut del_pre_args = vec!["-t", "raw", "-D", "PREROUTING"];
            del_pre_args.extend_from_slice(&filter_refs);
            del_pre_args.extend_from_slice(&["-j", "TRACE"]);
            let del_cmd = build_iptables_command("iptables", &del_pre_args);
            let _ = executor.exec(&del_cmd).await;

            let stderr = out_output
                .map(|o| o.stderr)
                .unwrap_or_else(|e| e.to_string());
            return Err(LiveTraceError::InsertFailed(format!(
                "OUTPUT insert failed: {}",
                stderr
            )));
        }
    };

    // ── Step 2: Collect trace output ────────────────────────────

    let timeout_str = timeout_secs.to_string();
    let (collection_method, collect_result) = match variant {
        IptablesVariant::Nft => {
            let cmd = build_command("timeout", &[&timeout_str, "xtables-monitor", "--trace"]);
            let result = executor.exec(&cmd).await;
            ("xtables-monitor".to_string(), result)
        }
        IptablesVariant::Legacy => {
            // dmesg --follow requires bash for the pipe and fallback
            let cmd = build_command("timeout", &[
                &timeout_str, "bash", "-c",
                "dmesg --follow 2>/dev/null || dmesg | grep -i trace",
            ]);
            let result = executor.exec(&cmd).await;
            ("dmesg".to_string(), result)
        }
    };

    // ── Step 3: ALWAYS remove TRACE rules ───────────────────────

    let mut del_pre_args = vec!["-t", "raw", "-D", "PREROUTING"];
    del_pre_args.extend_from_slice(&filter_refs);
    del_pre_args.extend_from_slice(&["-j", "TRACE"]);
    let del_pre_cmd = build_iptables_command("iptables", &del_pre_args);
    let pre_removed = executor.exec(&del_pre_cmd).await.map(|o| o.exit_code == 0).unwrap_or(false);

    let mut del_out_args = vec!["-t", "raw", "-D", "OUTPUT"];
    del_out_args.extend_from_slice(&filter_refs);
    del_out_args.extend_from_slice(&["-j", "TRACE"]);
    let del_out_cmd = build_iptables_command("iptables", &del_out_args);
    let out_removed = executor.exec(&del_out_cmd).await.map(|o| o.exit_code == 0).unwrap_or(false);

    let trace_rule_removed = pre_removed && out_removed;

    // ── Step 4: Parse output ────────────────────────────────────

    let events = match collect_result {
        Ok(output) => {
            // timeout command returns exit code 124 when it times out, which
            // is expected — we still want to parse any output captured.
            let raw = output.stdout.clone();
            let combined = if raw.is_empty() { &output.stderr } else { &raw };
            match variant {
                IptablesVariant::Nft => parse_xtables_monitor_trace(combined),
                IptablesVariant::Legacy => parse_dmesg_trace(combined),
            }
        }
        Err(_) => Vec::new(),
    };

    Ok(LiveTraceResult {
        events,
        trace_rule_inserted,
        trace_rule_removed,
        collection_method,
    })
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// Parse xtables-monitor --trace output.
///
/// Example line:
/// `TRACE: 2 fc475a39 raw:PREROUTING:policy:2 IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 ...`
pub fn parse_xtables_monitor_trace(output: &str) -> Vec<LiveTraceEvent> {
    let mut events = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if !line.contains("TRACE") {
            continue;
        }

        // Try to extract table:chain:verdict:rule_num pattern
        let (table, chain, verdict, rule_num) = if let Some(info) = extract_nft_chain_info(line) {
            info
        } else {
            continue;
        };

        let packet_info = extract_packet_info(line);

        events.push(LiveTraceEvent {
            timestamp: extract_timestamp(line),
            table,
            chain,
            rule_num,
            verdict,
            packet_info,
        });
    }

    events
}

/// Parse dmesg TRACE output.
///
/// Example line:
/// `[12345.678901] TRACE: raw:PREROUTING:policy:1 IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 ...`
pub fn parse_dmesg_trace(output: &str) -> Vec<LiveTraceEvent> {
    let mut events = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if !line.contains("TRACE") {
            continue;
        }

        // Extract timestamp from dmesg format [12345.678901]
        let timestamp = if let Some(start) = line.find('[') {
            if let Some(end) = line.find(']') {
                line[start..=end].to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Extract table:chain:verdict:rule_num after "TRACE: "
        let (table, chain, verdict, rule_num) = if let Some(info) = extract_dmesg_chain_info(line) {
            info
        } else {
            continue;
        };

        let packet_info = extract_packet_info(line);

        events.push(LiveTraceEvent {
            timestamp,
            table,
            chain,
            rule_num,
            verdict,
            packet_info,
        });
    }

    events
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn extract_timestamp(line: &str) -> String {
    // For xtables-monitor, no standard timestamp — use the line prefix
    if let Some(start) = line.find('[') {
        if let Some(end) = line.find(']') {
            return line[start..=end].to_string();
        }
    }
    String::new()
}

/// Extract table:chain:verdict:rule_num from nft-style trace.
/// Pattern: `raw:PREROUTING:policy:2` or `filter:INPUT:rule:3`
fn extract_nft_chain_info(line: &str) -> Option<(String, String, String, usize)> {
    // Look for the table:chain:type:num pattern after TRACE
    let trace_pos = line.find("TRACE")?;
    let after_trace = &line[trace_pos..];

    // Find the colon-separated pattern
    for word in after_trace.split_whitespace() {
        let parts: Vec<&str> = word.split(':').collect();
        if parts.len() >= 4 {
            let table = parts[0].to_string();
            let chain = parts[1].to_string();
            let verdict = parts[2].to_string();
            let rule_num = parts[3].parse::<usize>().unwrap_or(0);

            // Skip the "TRACE" word itself — we need a valid table name
            if table == "TRACE" || table.is_empty() {
                continue;
            }

            return Some((table, chain, verdict, rule_num));
        }
    }

    None
}

/// Extract table:chain:verdict:rule_num from dmesg-style TRACE line.
/// Pattern: `TRACE: raw:PREROUTING:policy:1 IN=...`
fn extract_dmesg_chain_info(line: &str) -> Option<(String, String, String, usize)> {
    let trace_idx = line.find("TRACE:")?;
    let after = line[trace_idx + 6..].trim();

    // First token should be table:chain:verdict:num
    let token = after.split_whitespace().next()?;
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() >= 4 {
        let table = parts[0].to_string();
        let chain = parts[1].to_string();
        let verdict = parts[2].to_string();
        let rule_num = parts[3].parse::<usize>().unwrap_or(0);
        Some((table, chain, verdict, rule_num))
    } else {
        None
    }
}

/// Extract packet info fields (IN=, OUT=, SRC=, DST=, etc.) from a trace line.
fn extract_packet_info(line: &str) -> String {
    let mut parts = Vec::new();
    for word in line.split_whitespace() {
        if word.contains('=') {
            // Include IN=, OUT=, SRC=, DST=, LEN=, PROTO=, SPT=, DPT=, etc.
            parts.push(word.to_string());
        }
    }
    parts.join(" ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::executor::{CommandOutput, ExecError};
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// Mock executor that records commands and returns configurable responses.
    struct MockExecutor {
        responses: Vec<(String, CommandOutput)>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl MockExecutor {
        fn new(responses: Vec<(&str, i32, &str, &str)>) -> Self {
            Self {
                responses: responses
                    .into_iter()
                    .map(|(pattern, exit_code, stdout, stderr)| {
                        (
                            pattern.to_string(),
                            CommandOutput {
                                stdout: stdout.to_string(),
                                stderr: stderr.to_string(),
                                exit_code,
                            },
                        )
                    })
                    .collect(),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn find_response(&self, command: &str) -> CommandOutput {
            for (pattern, output) in &self.responses {
                if command.contains(pattern) {
                    return output.clone();
                }
            }
            CommandOutput {
                stdout: String::new(),
                stderr: format!("{}: not found", command),
                exit_code: 1,
            }
        }

        fn get_calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CommandExecutor for MockExecutor {
        async fn exec(&self, command: &str) -> Result<CommandOutput, ExecError> {
            self.calls.lock().unwrap().push(command.to_string());
            Ok(self.find_response(command))
        }

        async fn exec_with_stdin(
            &self,
            command: &str,
            _stdin: &[u8],
        ) -> Result<CommandOutput, ExecError> {
            self.calls.lock().unwrap().push(command.to_string());
            Ok(self.find_response(command))
        }
    }

    #[test]
    fn test_parse_xtables_monitor_output() {
        let output = r#"
TRACE: 2 fc475a39 raw:PREROUTING:policy:2 IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 LEN=60 PROTO=TCP SPT=12345 DPT=22
TRACE: 2 fc475a39 filter:INPUT:rule:1 IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 LEN=60 PROTO=TCP SPT=12345 DPT=22
"#;

        let events = parse_xtables_monitor_trace(output);
        assert_eq!(events.len(), 2, "should parse 2 trace events");

        assert_eq!(events[0].table, "raw");
        assert_eq!(events[0].chain, "PREROUTING");
        assert_eq!(events[0].verdict, "policy");
        assert_eq!(events[0].rule_num, 2);
        assert!(events[0].packet_info.contains("SRC=10.0.0.1"));
        assert!(events[0].packet_info.contains("DST=10.0.0.2"));

        assert_eq!(events[1].table, "filter");
        assert_eq!(events[1].chain, "INPUT");
        assert_eq!(events[1].verdict, "rule");
        assert_eq!(events[1].rule_num, 1);
    }

    #[test]
    fn test_parse_dmesg_trace_output() {
        let output = r#"
[12345.678901] TRACE: raw:PREROUTING:policy:1 IN=eth0 OUT= SRC=192.168.1.1 DST=10.0.0.1 LEN=52 PROTO=TCP SPT=443 DPT=8080
[12345.679012] TRACE: filter:INPUT:rule:3 IN=eth0 OUT= SRC=192.168.1.1 DST=10.0.0.1 LEN=52 PROTO=TCP SPT=443 DPT=8080
"#;

        let events = parse_dmesg_trace(output);
        assert_eq!(events.len(), 2, "should parse 2 trace events");

        assert_eq!(events[0].timestamp, "[12345.678901]");
        assert_eq!(events[0].table, "raw");
        assert_eq!(events[0].chain, "PREROUTING");
        assert_eq!(events[0].verdict, "policy");
        assert_eq!(events[0].rule_num, 1);
        assert!(events[0].packet_info.contains("SRC=192.168.1.1"));

        assert_eq!(events[1].table, "filter");
        assert_eq!(events[1].chain, "INPUT");
        assert_eq!(events[1].verdict, "rule");
        assert_eq!(events[1].rule_num, 3);
    }

    #[test]
    fn test_build_trace_filter_args() {
        // Full request
        let req = LiveTraceRequest {
            source_ip: Some("10.0.0.1".to_string()),
            dest_ip: Some("192.168.1.1".to_string()),
            protocol: Some("tcp".to_string()),
            dest_port: Some(22),
            interface_in: Some("eth0".to_string()),
            timeout_secs: 10,
        };
        let args = build_trace_filter_args(&req);
        assert_eq!(
            args,
            vec!["-s", "10.0.0.1", "-d", "192.168.1.1", "-p", "tcp", "--dport", "22", "-i", "eth0"]
        );

        // Empty request — no filter args
        let req_empty = LiveTraceRequest {
            source_ip: None,
            dest_ip: None,
            protocol: None,
            dest_port: None,
            interface_in: None,
            timeout_secs: 10,
        };
        let args_empty = build_trace_filter_args(&req_empty);
        assert!(args_empty.is_empty(), "empty request should produce no args");

        // Only port, no protocol — should auto-add -p tcp
        let req_port_only = LiveTraceRequest {
            source_ip: None,
            dest_ip: None,
            protocol: None,
            dest_port: Some(80),
            interface_in: None,
            timeout_secs: 10,
        };
        let args_port = build_trace_filter_args(&req_port_only);
        assert_eq!(args_port, vec!["-p", "tcp", "--dport", "80"]);

        // Port with explicit udp protocol
        let req_udp = LiveTraceRequest {
            source_ip: None,
            dest_ip: None,
            protocol: Some("udp".to_string()),
            dest_port: Some(53),
            interface_in: None,
            timeout_secs: 10,
        };
        let args_udp = build_trace_filter_args(&req_udp);
        assert_eq!(args_udp, vec!["-p", "udp", "--dport", "53"]);
    }

    #[tokio::test]
    async fn test_trace_cleanup_always_runs() {
        // Simulate: insert succeeds, collection fails, delete should still run
        let executor = MockExecutor::new(vec![
            ("-I PREROUTING", 0, "", ""),
            ("-I OUTPUT", 0, "", ""),
            ("xtables-monitor", 1, "", "xtables-monitor: not found"),
            ("-D PREROUTING", 0, "", ""),
            ("-D OUTPUT", 0, "", ""),
        ]);

        let req = LiveTraceRequest {
            source_ip: Some("10.0.0.1".to_string()),
            dest_ip: None,
            protocol: Some("tcp".to_string()),
            dest_port: Some(22),
            interface_in: None,
            timeout_secs: 5,
        };

        let result = run_live_trace(&executor, &IptablesVariant::Nft, &req).await;
        assert!(result.is_ok(), "should succeed even if collection fails");

        let calls = executor.get_calls();

        // Verify delete commands were issued
        let has_del_pre = calls.iter().any(|c| c.contains("-D PREROUTING"));
        let has_del_out = calls.iter().any(|c| c.contains("-D OUTPUT"));
        assert!(has_del_pre, "should issue -D PREROUTING; calls: {:?}", calls);
        assert!(has_del_out, "should issue -D OUTPUT; calls: {:?}", calls);

        // Verify order: insert before delete
        let insert_idx = calls.iter().position(|c| c.contains("-I PREROUTING")).unwrap();
        let delete_idx = calls.iter().position(|c| c.contains("-D PREROUTING")).unwrap();
        assert!(insert_idx < delete_idx, "insert must come before delete");
    }

    #[tokio::test]
    async fn test_trace_insert_failure_returns_error() {
        let executor = MockExecutor::new(vec![
            ("-I PREROUTING", 1, "", "iptables: Permission denied"),
        ]);

        let req = LiveTraceRequest {
            source_ip: None,
            dest_ip: None,
            protocol: None,
            dest_port: None,
            interface_in: None,
            timeout_secs: 5,
        };

        let result = run_live_trace(&executor, &IptablesVariant::Nft, &req).await;
        assert!(result.is_err(), "should fail when insert fails");

        match result.unwrap_err() {
            LiveTraceError::InsertFailed(msg) => {
                assert!(msg.contains("PREROUTING"), "error should mention PREROUTING");
            }
            other => panic!("expected InsertFailed, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_output_insert_failure_cleans_up_prerouting() {
        // PREROUTING insert succeeds but OUTPUT insert fails.
        // The code MUST delete the PREROUTING rule before returning error.
        let executor = MockExecutor::new(vec![
            ("-I PREROUTING", 0, "", ""),
            ("-I OUTPUT", 1, "", "iptables: Permission denied"),
            ("-D PREROUTING", 0, "", ""),
        ]);

        let req = LiveTraceRequest {
            source_ip: Some("10.0.0.1".to_string()),
            dest_ip: None,
            protocol: Some("tcp".to_string()),
            dest_port: Some(22),
            interface_in: None,
            timeout_secs: 5,
        };

        let result = run_live_trace(&executor, &IptablesVariant::Nft, &req).await;
        assert!(result.is_err(), "should fail when OUTPUT insert fails");

        match result.unwrap_err() {
            LiveTraceError::InsertFailed(msg) => {
                assert!(msg.contains("OUTPUT"), "error should mention OUTPUT, got: {}", msg);
            }
            other => panic!("expected InsertFailed, got: {:?}", other),
        }

        // Verify PREROUTING was cleaned up
        let calls = executor.get_calls();
        let has_del_pre = calls.iter().any(|c| c.contains("-D PREROUTING"));
        assert!(
            has_del_pre,
            "MUST clean up PREROUTING rule on OUTPUT failure to avoid leaked TRACE rules; calls: {:?}",
            calls
        );
    }

    #[tokio::test]
    async fn test_legacy_variant_uses_dmesg() {
        // Verify the Legacy variant constructs a dmesg-based collection command
        let executor = MockExecutor::new(vec![
            ("-I PREROUTING", 0, "", ""),
            ("-I OUTPUT", 0, "", ""),
            ("dmesg", 0, "[12345.678] TRACE: raw:PREROUTING:policy:1 IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP DPT=80", ""),
            ("-D PREROUTING", 0, "", ""),
            ("-D OUTPUT", 0, "", ""),
        ]);

        let req = LiveTraceRequest {
            source_ip: Some("10.0.0.1".to_string()),
            dest_ip: None,
            protocol: None,
            dest_port: None,
            interface_in: None,
            timeout_secs: 5,
        };

        let result = run_live_trace(&executor, &IptablesVariant::Legacy, &req)
            .await
            .expect("legacy trace should succeed");

        assert_eq!(result.collection_method, "dmesg");
        assert!(!result.events.is_empty(), "should parse dmesg TRACE output");
        assert_eq!(result.events[0].table, "raw");
        assert_eq!(result.events[0].chain, "PREROUTING");
    }

    #[test]
    fn test_parse_malformed_trace_lines_skipped() {
        // Partial/malformed TRACE lines should be silently skipped
        let output = "TRACE: raw:PREROUTING\nTRACE: :::::\nTRACE: 2 abc raw:PREROUTING:policy:2 IN=eth0 SRC=1.2.3.4 DST=5.6.7.8\n";
        let events = parse_xtables_monitor_trace(output);
        // Only the last line has proper table:chain:verdict:num format
        assert!(events.len() <= 1, "malformed lines should be skipped, got {} events", events.len());
    }

    #[test]
    fn test_parse_empty_output() {
        let events_nft = parse_xtables_monitor_trace("");
        assert!(events_nft.is_empty());

        let events_dmesg = parse_dmesg_trace("");
        assert!(events_dmesg.is_empty());
    }

    #[test]
    fn test_parse_output_with_non_trace_lines() {
        let output = "some random output\nnothing relevant\n";
        let events = parse_xtables_monitor_trace(output);
        assert!(events.is_empty());

        let events_dmesg = parse_dmesg_trace(output);
        assert!(events_dmesg.is_empty());
    }
}
