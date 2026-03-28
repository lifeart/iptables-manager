use serde::{Deserialize, Serialize};
use thiserror::Error;
use ts_rs::TS;

use crate::safety::timer::{detect_mechanism, SafetyMechanism};
use crate::ssh::command::build_command;
use crate::ssh::executor::{CommandExecutor, ExecError};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum DetectError {
    #[error("command execution error: {0}")]
    Exec(#[from] ExecError),
    #[error("iptables not found on remote host")]
    IptablesNotFound,
    #[error("unsupported iptables variant: nft (native nftables without compat layer)")]
    NftUnsupported,
    #[error("detection step failed: {step} — {reason}")]
    StepFailed { step: String, reason: String },
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCapabilities {
    pub iptables_variant: IptablesVariant,
    pub iptables_version: String,
    pub safety_mechanism: String,
    pub ipset_available: bool,
    pub ip6tables_available: bool,
    pub cloud_environment: Option<CloudEnvironment>,
    pub distro: DistroInfo,
    pub interfaces: Vec<NetworkInterface>,
    pub running_services: Vec<DetectedService>,
    pub detected_tools: Vec<DetectedTool>,
    pub persistence_method: PersistenceMethod,
    pub persistence_status: PersistenceStatus,
    pub management_interface: Option<String>,
    pub management_is_vpn: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IptablesVariant {
    #[serde(rename = "iptables-legacy")]
    Legacy,
    #[serde(rename = "iptables-nft")]
    Nft,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudEnvironment {
    #[serde(rename = "aws")]
    Aws,
    #[serde(rename = "gcp")]
    Gcp,
    #[serde(rename = "azure")]
    Azure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistroInfo {
    pub name: String,
    pub family: DistroFamily,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistroFamily {
    #[serde(rename = "debian")]
    Debian,
    #[serde(rename = "rhel")]
    Rhel,
    #[serde(rename = "arch")]
    Arch,
    #[serde(rename = "alpine")]
    Alpine,
    #[serde(rename = "other")]
    Other,
}

impl DistroFamily {
    pub fn as_str(&self) -> &str {
        match self {
            DistroFamily::Debian => "debian",
            DistroFamily::Rhel => "rhel",
            DistroFamily::Arch => "arch",
            DistroFamily::Alpine => "alpine",
            DistroFamily::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub iface_type: InterfaceType,
    pub addresses: Vec<String>,
    pub is_up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceType {
    Physical,
    Vlan,
    Bridge,
    Bond,
    Tunnel,
    Wireguard,
    Loopback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedService {
    pub name: String,
    pub ports: Vec<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTool {
    pub tool_type: String,
    pub chains: Vec<String>,
    pub rule_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub enum PersistenceMethod {
    #[serde(rename = "iptables-persistent")]
    IptablesPersistent,
    #[serde(rename = "iptables-services")]
    IptablesServices,
    #[serde(rename = "manual")]
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/bindings/")]
#[serde(rename_all = "camelCase")]
pub struct PersistenceStatus {
    pub method: PersistenceMethod,
    pub package_installed: bool,
    pub service_enabled: bool,
    pub service_active: bool,
    pub last_saved: Option<String>,
}

// ---------------------------------------------------------------------------
// Main detection function
// ---------------------------------------------------------------------------

/// Detect capabilities of the remote host by running a series of commands.
pub async fn detect_capabilities(
    executor: &dyn CommandExecutor,
) -> Result<HostCapabilities, DetectError> {
    // 1. Detect iptables variant and version
    let (variant, version) = detect_iptables(executor).await?;

    // 2. Detect safety mechanism
    let safety = detect_mechanism(executor).await;
    let safety_str = match safety {
        SafetyMechanism::IptablesApply => "iptables-apply",
        SafetyMechanism::At => "at",
        SafetyMechanism::SystemdRun => "systemd-run",
        SafetyMechanism::Nohup => "background",
    };

    // 3. Detect ipset availability
    let ipset_available = check_binary_exists(executor, "ipset").await;

    // 4. Detect ip6tables availability
    let ip6tables_available = check_binary_exists(executor, "ip6tables").await;

    // 5. Detect distro
    let distro = detect_distro(executor).await;

    // 6. Detect running services
    let running_services = detect_services(executor).await;

    // 7. Detect network interfaces
    let interfaces = detect_interfaces(executor).await;

    // 8. Detect cloud environment
    let cloud_environment = detect_cloud(executor).await;

    // 9. Detect tools (docker, fail2ban, kubernetes, wireguard)
    let detected_tools = detect_tools(executor).await;

    // 10. Determine persistence method from distro
    let persistence_method = match distro.family {
        DistroFamily::Debian => PersistenceMethod::IptablesPersistent,
        DistroFamily::Rhel => PersistenceMethod::IptablesServices,
        _ => PersistenceMethod::Manual,
    };

    // 11. Detect persistence status
    let persistence_status =
        detect_persistence_status(executor, &distro.family).await;

    // 12. Detect management interface
    let (management_interface, management_is_vpn) =
        detect_management_interface(executor).await;

    Ok(HostCapabilities {
        iptables_variant: variant,
        iptables_version: version,
        safety_mechanism: safety_str.to_string(),
        ipset_available,
        ip6tables_available,
        cloud_environment,
        distro,
        interfaces,
        running_services,
        detected_tools,
        persistence_method,
        persistence_status,
        management_interface,
        management_is_vpn,
    })
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

async fn detect_iptables(
    executor: &dyn CommandExecutor,
) -> Result<(IptablesVariant, String), DetectError> {
    let cmd = build_command("sudo", &["iptables", "--version"]);
    let output = executor.exec(&cmd).await?;
    if output.exit_code != 0 {
        return Err(DetectError::IptablesNotFound);
    }
    let stdout = output.stdout.trim().to_string();

    // Parse version from output like "iptables v1.8.7 (nf_tables)" or "iptables v1.8.7 (legacy)"
    let variant = if stdout.contains("nf_tables") {
        IptablesVariant::Nft
    } else {
        IptablesVariant::Legacy
    };

    let version = parse_iptables_version(&stdout);

    Ok((variant, version))
}

fn parse_iptables_version(output: &str) -> String {
    // Typical: "iptables v1.8.7 (nf_tables)"
    for word in output.split_whitespace() {
        if word.starts_with('v') && word.contains('.') {
            return word.trim_start_matches('v').to_string();
        }
    }
    "unknown".to_string()
}

async fn check_binary_exists(executor: &dyn CommandExecutor, name: &str) -> bool {
    let cmd = build_command("which", &[name]);
    if let Ok(output) = executor.exec(&cmd).await {
        return output.exit_code == 0;
    }
    false
}

async fn detect_distro(executor: &dyn CommandExecutor) -> DistroInfo {
    let cmd = build_command("cat", &["/etc/os-release"]);
    let output = match executor.exec(&cmd).await {
        Ok(o) if o.exit_code == 0 => o,
        _ => {
            return DistroInfo {
                name: "unknown".to_string(),
                family: DistroFamily::Other,
            };
        }
    };

    let (id, id_like) = parse_os_release(&output.stdout);

    let family = classify_distro_family(&id, &id_like);

    DistroInfo {
        name: id,
        family,
    }
}

fn parse_os_release(content: &str) -> (String, String) {
    let mut id = String::new();
    let mut id_like = String::new();

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("ID=") {
            id = val.trim_matches('"').to_string();
        } else if let Some(val) = line.strip_prefix("ID_LIKE=") {
            id_like = val.trim_matches('"').to_string();
        }
    }

    (id, id_like)
}

fn classify_distro_family(id: &str, id_like: &str) -> DistroFamily {
    let combined = format!("{} {}", id, id_like).to_lowercase();

    if combined.contains("debian") || combined.contains("ubuntu") {
        DistroFamily::Debian
    } else if combined.contains("rhel")
        || combined.contains("centos")
        || combined.contains("fedora")
        || combined.contains("rocky")
        || combined.contains("alma")
        || combined.contains("oracle")
    {
        DistroFamily::Rhel
    } else if combined.contains("arch") || combined.contains("manjaro") {
        DistroFamily::Arch
    } else if combined.contains("alpine") {
        DistroFamily::Alpine
    } else {
        DistroFamily::Other
    }
}

async fn detect_services(executor: &dyn CommandExecutor) -> Vec<DetectedService> {
    let cmd = build_command("sudo", &["ss", "-tlnp"]);
    let output = match executor.exec(&cmd).await {
        Ok(o) if o.exit_code == 0 => o,
        _ => return Vec::new(),
    };

    parse_ss_output(&output.stdout)
}

fn parse_ss_output(output: &str) -> Vec<DetectedService> {
    let mut services: Vec<DetectedService> = Vec::new();
    // Use a map to aggregate ports by process name
    let mut service_map: std::collections::HashMap<String, (Vec<u16>, String)> =
        std::collections::HashMap::new();

    for line in output.lines().skip(1) {
        // State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }

        // Parse local address:port
        let local = fields[3];
        let port = parse_port_from_address(local);
        let port = match port {
            Some(p) => p,
            None => continue,
        };

        // Parse protocol (we know it's TCP from -t flag)
        let protocol = "tcp".to_string();

        // Parse process name from the users:(...) field
        let process_name = if fields.len() > 5 {
            extract_process_name(&fields[5..].join(" "))
        } else {
            "unknown".to_string()
        };

        let entry = service_map
            .entry(process_name.clone())
            .or_insert_with(|| (Vec::new(), protocol));
        if !entry.0.contains(&port) {
            entry.0.push(port);
        }
    }

    for (name, (ports, protocol)) in service_map {
        services.push(DetectedService {
            name,
            ports,
            protocol,
        });
    }

    services.sort_by(|a, b| a.name.cmp(&b.name));
    services
}

fn parse_port_from_address(addr: &str) -> Option<u16> {
    // Formats: "0.0.0.0:22", "*:22", "[::]:22", "127.0.0.1:631"
    if let Some(idx) = addr.rfind(':') {
        addr[idx + 1..].parse::<u16>().ok()
    } else {
        None
    }
}

fn extract_process_name(field: &str) -> String {
    // Format: users:(("sshd",pid=123,fd=3))
    if let Some(start) = field.find("((\"") {
        if let Some(end) = field[start + 3..].find('"') {
            return field[start + 3..start + 3 + end].to_string();
        }
    }
    "unknown".to_string()
}

async fn detect_interfaces(executor: &dyn CommandExecutor) -> Vec<NetworkInterface> {
    // Try JSON output first
    let cmd = build_command("ip", &["-j", "addr", "show"]);
    let output = match executor.exec(&cmd).await {
        Ok(o) if o.exit_code == 0 && o.stdout.starts_with('[') => o,
        _ => {
            // Fall back to plain text
            return detect_interfaces_plain(executor).await;
        }
    };

    parse_ip_json(&output.stdout)
}

fn parse_ip_json(json_str: &str) -> Vec<NetworkInterface> {
    #[derive(Deserialize)]
    struct IpAddr {
        ifname: Option<String>,
        operstate: Option<String>,
        link_type: Option<String>,
        addr_info: Option<Vec<AddrInfo>>,
    }

    #[derive(Deserialize)]
    struct AddrInfo {
        local: Option<String>,
        prefixlen: Option<u32>,
    }

    let ifaces: Vec<IpAddr> = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    ifaces
        .into_iter()
        .filter_map(|iface| {
            let name = iface.ifname?;
            let is_up = iface.operstate.as_deref() == Some("UP");
            let iface_type = classify_interface(&name, iface.link_type.as_deref());

            let addresses: Vec<String> = iface
                .addr_info
                .unwrap_or_default()
                .into_iter()
                .filter_map(|a| {
                    let local = a.local?;
                    let prefix = a.prefixlen.unwrap_or(0);
                    Some(format!("{}/{}", local, prefix))
                })
                .collect();

            Some(NetworkInterface {
                name,
                iface_type,
                addresses,
                is_up,
            })
        })
        .collect()
}

async fn detect_interfaces_plain(executor: &dyn CommandExecutor) -> Vec<NetworkInterface> {
    let cmd = build_command("ip", &["addr", "show"]);
    let output = match executor.exec(&cmd).await {
        Ok(o) if o.exit_code == 0 => o,
        _ => return Vec::new(),
    };

    parse_ip_addr_plain(&output.stdout)
}

fn parse_ip_addr_plain(output: &str) -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_addresses: Vec<String> = Vec::new();
    let mut current_up = false;

    for line in output.lines() {
        // Interface header: "2: eth0: <BROADCAST,...,UP,...> ..."
        if !line.starts_with(' ') && !line.starts_with('\t') {
            // Save previous
            if let Some(name) = current_name.take() {
                let iface_type = classify_interface(&name, None);
                interfaces.push(NetworkInterface {
                    name,
                    iface_type,
                    addresses: std::mem::take(&mut current_addresses),
                    is_up: current_up,
                });
            }
            // Parse new interface
            if let Some(colon_pos) = line.find(": ") {
                let rest = &line[colon_pos + 2..];
                if let Some(name_end) = rest.find(':') {
                    let name = rest[..name_end].to_string();
                    current_name = Some(name);
                    // Check <...UP...>
                    current_up = line.contains(",UP") || line.contains("<UP");
                }
            }
        } else {
            let trimmed = line.trim();
            // "inet 10.0.0.1/24 ..."
            if let Some(rest) = trimmed.strip_prefix("inet ").or_else(|| trimmed.strip_prefix("inet6 ")) {
                if let Some(addr) = rest.split_whitespace().next() {
                    current_addresses.push(addr.to_string());
                }
            }
        }
    }

    // Save last
    if let Some(name) = current_name {
        let iface_type = classify_interface(&name, None);
        interfaces.push(NetworkInterface {
            name,
            iface_type,
            addresses: std::mem::take(&mut current_addresses),
            is_up: current_up,
        });
    }

    interfaces
}

fn classify_interface(name: &str, link_type: Option<&str>) -> InterfaceType {
    if name == "lo" {
        return InterfaceType::Loopback;
    }
    if name.starts_with("wg") {
        return InterfaceType::Wireguard;
    }
    if name.starts_with("tun") || name.starts_with("tap") {
        return InterfaceType::Tunnel;
    }
    if name.starts_with("br") || name.starts_with("docker") || name.starts_with("virbr") {
        return InterfaceType::Bridge;
    }
    if name.starts_with("bond") {
        return InterfaceType::Bond;
    }
    if name.contains('.') {
        return InterfaceType::Vlan;
    }
    if let Some(lt) = link_type {
        if lt == "loopback" {
            return InterfaceType::Loopback;
        }
        if lt == "bridge" {
            return InterfaceType::Bridge;
        }
    }
    InterfaceType::Physical
}

async fn detect_cloud(executor: &dyn CommandExecutor) -> Option<CloudEnvironment> {
    // Run AWS, GCP, and Azure checks in parallel (each has -m 1 timeout,
    // so parallel = max ~1s instead of sequential ~3s).
    let aws_cmd = build_command(
        "curl",
        &["-s", "-m", "1", "http://169.254.169.254/latest/meta-data/"],
    );
    let gcp_cmd = build_command(
        "curl",
        &[
            "-s",
            "-m",
            "1",
            "-H",
            "Metadata-Flavor: Google",
            "-D",
            "-",
            "http://169.254.169.254/computeMetadata/v1/",
        ],
    );
    let azure_cmd = build_command(
        "curl",
        &[
            "-s",
            "-m",
            "1",
            "-H",
            "Metadata: true",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ],
    );

    let (aws_result, gcp_result, azure_result) = tokio::join!(
        executor.exec(&aws_cmd),
        executor.exec(&gcp_cmd),
        executor.exec(&azure_cmd),
    );

    // AWS: Check for AWS-specific content (ami-id or instance-id) to avoid
    // false positives from other metadata services on 169.254.169.254.
    if let Ok(output) = aws_result {
        if output.exit_code == 0
            && !output.stdout.is_empty()
            && !output.stdout.contains("404")
            && (output.stdout.contains("ami-id") || output.stdout.contains("instance-id"))
        {
            return Some(CloudEnvironment::Aws);
        }
    }

    // GCP: Require Metadata-Flavor: Google header in the response
    if let Ok(output) = gcp_result {
        if output.exit_code == 0
            && !output.stdout.is_empty()
            && !output.stdout.contains("404")
            && output.stdout.contains("Metadata-Flavor: Google")
        {
            return Some(CloudEnvironment::Gcp);
        }
    }

    // Azure: IMDS
    if let Ok(output) = azure_result {
        if output.exit_code == 0
            && !output.stdout.is_empty()
            && output.stdout.contains("compute")
        {
            return Some(CloudEnvironment::Azure);
        }
    }

    None
}

async fn detect_tools(executor: &dyn CommandExecutor) -> Vec<DetectedTool> {
    let mut tools = Vec::new();

    // Docker
    if check_service_active(executor, "docker").await
        || check_path_exists(executor, "/var/run/docker.sock").await
    {
        tools.push(DetectedTool {
            tool_type: "docker".to_string(),
            chains: vec![
                "DOCKER".to_string(),
                "DOCKER-USER".to_string(),
                "DOCKER-ISOLATION-STAGE-1".to_string(),
            ],
            rule_count: 0,
        });
    }

    // fail2ban
    if check_service_active(executor, "fail2ban").await
        || check_binary_exists(executor, "fail2ban-client").await
    {
        tools.push(DetectedTool {
            tool_type: "fail2ban".to_string(),
            chains: vec!["f2b-sshd".to_string()],
            rule_count: 0,
        });
    }

    // Kubernetes
    if check_process_running(executor, "kubelet").await
        || check_path_exists(executor, "/etc/kubernetes").await
    {
        tools.push(DetectedTool {
            tool_type: "kubernetes".to_string(),
            chains: vec!["KUBE-SERVICES".to_string(), "KUBE-FORWARD".to_string()],
            rule_count: 0,
        });
    }

    // WireGuard (wg-quick)
    let cmd = build_command("ls", &["/etc/wireguard/"]);
    if let Ok(output) = executor.exec(&cmd).await {
        if output.exit_code == 0 && output.stdout.contains(".conf") {
            tools.push(DetectedTool {
                tool_type: "wg-quick".to_string(),
                chains: Vec::new(),
                rule_count: 0,
            });
        }
    }

    tools
}

async fn check_service_active(executor: &dyn CommandExecutor, service: &str) -> bool {
    let cmd = build_command("systemctl", &["is-active", service]);
    if let Ok(output) = executor.exec(&cmd).await {
        return output.exit_code == 0 && output.stdout.trim() == "active";
    }
    false
}

async fn check_path_exists(executor: &dyn CommandExecutor, path: &str) -> bool {
    let cmd = build_command("test", &["-e", path]);
    if let Ok(output) = executor.exec(&cmd).await {
        return output.exit_code == 0;
    }
    false
}

async fn check_process_running(executor: &dyn CommandExecutor, process: &str) -> bool {
    let cmd = build_command("pgrep", &[process]);
    if let Ok(output) = executor.exec(&cmd).await {
        return output.exit_code == 0;
    }
    false
}

async fn detect_management_interface(
    executor: &dyn CommandExecutor,
) -> (Option<String>, bool) {
    // Determine SSH connection source by checking SSH_CONNECTION env var
    let cmd = build_command("bash", &["-c", "echo $SSH_CONNECTION"]);
    let output = match executor.exec(&cmd).await {
        Ok(o) if o.exit_code == 0 => o,
        _ => return (None, false),
    };

    let ssh_conn = output.stdout.trim();
    if ssh_conn.is_empty() {
        return (None, false);
    }

    // SSH_CONNECTION: "client_ip client_port server_ip server_port"
    let parts: Vec<&str> = ssh_conn.split_whitespace().collect();
    if parts.len() < 4 {
        return (None, false);
    }
    let server_ip = parts[2];

    // Find which interface has this IP
    let cmd = build_command("ip", &["route", "get", server_ip]);
    if let Ok(output) = executor.exec(&cmd).await {
        if output.exit_code == 0 {
            // Output like: "10.0.0.1 dev eth0 src 10.0.0.1 uid 0"
            let iface = extract_dev_from_route(&output.stdout);
            let is_vpn = iface
                .as_ref()
                .map(|i| {
                    i.starts_with("wg")
                        || i.starts_with("tun")
                        || i.starts_with("tap")
                })
                .unwrap_or(false);
            return (iface, is_vpn);
        }
    }

    (None, false)
}

fn extract_dev_from_route(output: &str) -> Option<String> {
    let words: Vec<&str> = output.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        if *word == "dev" && i + 1 < words.len() {
            return Some(words[i + 1].to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Persistence detection
// ---------------------------------------------------------------------------

/// Detect whether iptables rule persistence is properly configured.
///
/// Checks if the appropriate package is installed, the service is enabled
/// and active, and when rules were last saved.
pub async fn detect_persistence_status(
    executor: &dyn CommandExecutor,
    distro_family: &DistroFamily,
) -> PersistenceStatus {
    match distro_family {
        DistroFamily::Debian => detect_persistence_debian(executor).await,
        DistroFamily::Rhel => detect_persistence_rhel(executor).await,
        _ => PersistenceStatus {
            method: PersistenceMethod::Manual,
            package_installed: false,
            service_enabled: false,
            service_active: false,
            last_saved: None,
        },
    }
}

async fn detect_persistence_debian(executor: &dyn CommandExecutor) -> PersistenceStatus {
    // Check if iptables-persistent is installed
    let dpkg_cmd = build_command(
        "bash",
        &["-c", "dpkg -l iptables-persistent 2>/dev/null | grep '^ii'"],
    );
    let package_installed = match executor.exec(&dpkg_cmd).await {
        Ok(o) => o.exit_code == 0 && !o.stdout.trim().is_empty(),
        Err(_) => false,
    };

    // Check if netfilter-persistent service is enabled
    let enabled_cmd = build_command(
        "bash",
        &["-c", "systemctl is-enabled netfilter-persistent 2>/dev/null"],
    );
    let service_enabled = match executor.exec(&enabled_cmd).await {
        Ok(o) => o.exit_code == 0 && o.stdout.trim() == "enabled",
        Err(_) => false,
    };

    // Check if netfilter-persistent service is active
    let active_cmd = build_command(
        "bash",
        &["-c", "systemctl is-active netfilter-persistent 2>/dev/null"],
    );
    let service_active = match executor.exec(&active_cmd).await {
        Ok(o) => o.exit_code == 0 && o.stdout.trim() == "active",
        Err(_) => false,
    };

    // Check last saved timestamp
    let stat_cmd = build_command(
        "bash",
        &["-c", "stat -c %Y /etc/iptables/rules.v4 2>/dev/null"],
    );
    let last_saved = match executor.exec(&stat_cmd).await {
        Ok(o) if o.exit_code == 0 && !o.stdout.trim().is_empty() => {
            Some(o.stdout.trim().to_string())
        }
        _ => None,
    };

    PersistenceStatus {
        method: PersistenceMethod::IptablesPersistent,
        package_installed,
        service_enabled,
        service_active,
        last_saved,
    }
}

async fn detect_persistence_rhel(executor: &dyn CommandExecutor) -> PersistenceStatus {
    // Check if iptables-services is installed
    let rpm_cmd = build_command(
        "bash",
        &["-c", "rpm -q iptables-services 2>/dev/null"],
    );
    let package_installed = match executor.exec(&rpm_cmd).await {
        Ok(o) => o.exit_code == 0,
        Err(_) => false,
    };

    // Check if iptables service is enabled
    let enabled_cmd = build_command(
        "bash",
        &["-c", "systemctl is-enabled iptables 2>/dev/null"],
    );
    let service_enabled = match executor.exec(&enabled_cmd).await {
        Ok(o) => o.exit_code == 0 && o.stdout.trim() == "enabled",
        Err(_) => false,
    };

    // Check if iptables service is active
    let active_cmd = build_command(
        "bash",
        &["-c", "systemctl is-active iptables 2>/dev/null"],
    );
    let service_active = match executor.exec(&active_cmd).await {
        Ok(o) => o.exit_code == 0 && o.stdout.trim() == "active",
        Err(_) => false,
    };

    // Check last saved timestamp
    let stat_cmd = build_command(
        "bash",
        &["-c", "stat -c %Y /etc/sysconfig/iptables 2>/dev/null"],
    );
    let last_saved = match executor.exec(&stat_cmd).await {
        Ok(o) if o.exit_code == 0 && !o.stdout.trim().is_empty() => {
            Some(o.stdout.trim().to_string())
        }
        _ => None,
    };

    PersistenceStatus {
        method: PersistenceMethod::IptablesServices,
        package_installed,
        service_enabled,
        service_active,
        last_saved,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::executor::{CommandOutput, ExecError};
    use async_trait::async_trait;

    /// Simple mock executor for persistence detection tests.
    struct MockExec {
        responses: Vec<(String, CommandOutput)>,
    }

    impl MockExec {
        fn new(responses: Vec<(&str, i32, &str)>) -> Self {
            Self {
                responses: responses
                    .into_iter()
                    .map(|(pattern, exit_code, stdout)| {
                        (
                            pattern.to_string(),
                            CommandOutput {
                                stdout: stdout.to_string(),
                                stderr: String::new(),
                                exit_code,
                            },
                        )
                    })
                    .collect(),
            }
        }
    }

    #[async_trait]
    impl CommandExecutor for MockExec {
        async fn exec(&self, command: &str) -> Result<CommandOutput, ExecError> {
            for (pattern, output) in &self.responses {
                if command.contains(pattern) {
                    return Ok(output.clone());
                }
            }
            Ok(CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 1,
            })
        }

        async fn exec_with_stdin(
            &self,
            command: &str,
            _stdin: &[u8],
        ) -> Result<CommandOutput, ExecError> {
            self.exec(command).await
        }
    }

    #[tokio::test]
    async fn test_persistence_debian_installed() {
        let exec = MockExec::new(vec![
            ("dpkg -l iptables-persistent", 0, "ii  iptables-persistent  1.0.16  all  boot-time loader for netfilter"),
            ("systemctl is-enabled netfilter-persistent", 0, "enabled"),
            ("systemctl is-active netfilter-persistent", 0, "active"),
            ("stat -c %Y /etc/iptables/rules.v4", 0, "1700000000"),
        ]);

        let status = detect_persistence_status(&exec, &DistroFamily::Debian).await;
        assert_eq!(status.method, PersistenceMethod::IptablesPersistent);
        assert!(status.package_installed);
        assert!(status.service_enabled);
        assert!(status.service_active);
        assert_eq!(status.last_saved, Some("1700000000".to_string()));
    }

    #[tokio::test]
    async fn test_persistence_debian_not_installed() {
        let exec = MockExec::new(vec![
            ("dpkg -l iptables-persistent", 1, ""),
            ("systemctl is-enabled netfilter-persistent", 1, ""),
            ("systemctl is-active netfilter-persistent", 1, ""),
            ("stat -c %Y /etc/iptables/rules.v4", 1, ""),
        ]);

        let status = detect_persistence_status(&exec, &DistroFamily::Debian).await;
        assert_eq!(status.method, PersistenceMethod::IptablesPersistent);
        assert!(!status.package_installed);
        assert!(!status.service_enabled);
        assert!(!status.service_active);
        assert_eq!(status.last_saved, None);
    }

    #[tokio::test]
    async fn test_persistence_rhel_installed() {
        let exec = MockExec::new(vec![
            ("rpm -q iptables-services", 0, "iptables-services-1.8.4-22.el8.x86_64"),
            ("systemctl is-enabled iptables", 0, "enabled"),
            ("systemctl is-active iptables", 0, "active"),
            ("stat -c %Y /etc/sysconfig/iptables", 0, "1700000000"),
        ]);

        let status = detect_persistence_status(&exec, &DistroFamily::Rhel).await;
        assert_eq!(status.method, PersistenceMethod::IptablesServices);
        assert!(status.package_installed);
        assert!(status.service_enabled);
        assert!(status.service_active);
        assert_eq!(status.last_saved, Some("1700000000".to_string()));
    }

    #[tokio::test]
    async fn test_persistence_manual() {
        let exec = MockExec::new(vec![]);

        let status = detect_persistence_status(&exec, &DistroFamily::Arch).await;
        assert_eq!(status.method, PersistenceMethod::Manual);
        assert!(!status.package_installed);
        assert!(!status.service_enabled);
        assert!(!status.service_active);
        assert_eq!(status.last_saved, None);
    }

    #[test]
    fn test_parse_iptables_version_nft() {
        assert_eq!(
            parse_iptables_version("iptables v1.8.7 (nf_tables)"),
            "1.8.7"
        );
    }

    #[test]
    fn test_parse_iptables_version_legacy() {
        assert_eq!(
            parse_iptables_version("iptables v1.6.1"),
            "1.6.1"
        );
    }

    #[test]
    fn test_parse_iptables_version_unknown() {
        assert_eq!(parse_iptables_version(""), "unknown");
    }

    #[test]
    fn test_parse_os_release() {
        let content = r#"
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
"#;
        let (id, id_like) = parse_os_release(content);
        assert_eq!(id, "ubuntu");
        assert_eq!(id_like, "debian");
    }

    #[test]
    fn test_parse_os_release_centos() {
        let content = r#"
NAME="CentOS Stream"
ID="centos"
ID_LIKE="rhel fedora"
"#;
        let (id, id_like) = parse_os_release(content);
        assert_eq!(id, "centos");
        assert_eq!(id_like, "rhel fedora");
    }

    #[test]
    fn test_classify_distro_family() {
        assert_eq!(classify_distro_family("ubuntu", "debian"), DistroFamily::Debian);
        assert_eq!(classify_distro_family("debian", ""), DistroFamily::Debian);
        assert_eq!(classify_distro_family("centos", "rhel fedora"), DistroFamily::Rhel);
        assert_eq!(classify_distro_family("fedora", ""), DistroFamily::Rhel);
        assert_eq!(classify_distro_family("rocky", "rhel centos fedora"), DistroFamily::Rhel);
        assert_eq!(classify_distro_family("arch", ""), DistroFamily::Arch);
        assert_eq!(classify_distro_family("manjaro", "arch"), DistroFamily::Arch);
        assert_eq!(classify_distro_family("alpine", ""), DistroFamily::Alpine);
        assert_eq!(classify_distro_family("nixos", ""), DistroFamily::Other);
    }

    #[test]
    fn test_parse_ss_output() {
        let output = r#"State    Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN   0       128     0.0.0.0:22          0.0.0.0:*          users:(("sshd",pid=1234,fd=3))
LISTEN   0       511     0.0.0.0:80          0.0.0.0:*          users:(("nginx",pid=5678,fd=6))
LISTEN   0       511     0.0.0.0:443         0.0.0.0:*          users:(("nginx",pid=5678,fd=7))
"#;
        let services = parse_ss_output(output);
        assert!(services.iter().any(|s| s.name == "sshd" && s.ports.contains(&22)));

        let nginx = services.iter().find(|s| s.name == "nginx").unwrap();
        assert!(nginx.ports.contains(&80));
        assert!(nginx.ports.contains(&443));
    }

    #[test]
    fn test_parse_ss_output_empty() {
        let output = "State    Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n";
        let services = parse_ss_output(output);
        assert!(services.is_empty());
    }

    #[test]
    fn test_classify_interface() {
        assert_eq!(classify_interface("lo", None), InterfaceType::Loopback);
        assert_eq!(classify_interface("eth0", None), InterfaceType::Physical);
        assert_eq!(classify_interface("wg0", None), InterfaceType::Wireguard);
        assert_eq!(classify_interface("tun0", None), InterfaceType::Tunnel);
        assert_eq!(classify_interface("br-abc123", None), InterfaceType::Bridge);
        assert_eq!(classify_interface("docker0", None), InterfaceType::Bridge);
        assert_eq!(classify_interface("bond0", None), InterfaceType::Bond);
        assert_eq!(classify_interface("eth0.100", None), InterfaceType::Vlan);
    }

    #[test]
    fn test_parse_port_from_address() {
        assert_eq!(parse_port_from_address("0.0.0.0:22"), Some(22));
        assert_eq!(parse_port_from_address("*:80"), Some(80));
        assert_eq!(parse_port_from_address("[::]:443"), Some(443));
        assert_eq!(parse_port_from_address("127.0.0.1:631"), Some(631));
    }

    #[test]
    fn test_extract_process_name() {
        assert_eq!(
            extract_process_name("users:((\"sshd\",pid=1234,fd=3))"),
            "sshd"
        );
        assert_eq!(
            extract_process_name("users:((\"nginx\",pid=5678,fd=6))"),
            "nginx"
        );
        assert_eq!(extract_process_name(""), "unknown");
    }

    #[test]
    fn test_extract_dev_from_route() {
        assert_eq!(
            extract_dev_from_route("10.0.0.1 dev eth0 src 10.0.0.2 uid 0"),
            Some("eth0".to_string())
        );
        assert_eq!(
            extract_dev_from_route("default via 10.0.0.1 dev wg0"),
            Some("wg0".to_string())
        );
        assert_eq!(extract_dev_from_route("nothing here"), None);
    }

    #[test]
    fn test_parse_ip_addr_plain() {
        let output = r#"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0
    inet6 fe80::1/64 scope link
3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420
    inet 10.10.0.1/24 scope global wg0
"#;
        let ifaces = parse_ip_addr_plain(output);
        assert_eq!(ifaces.len(), 3);

        let lo = &ifaces[0];
        assert_eq!(lo.name, "lo");
        assert_eq!(lo.iface_type, InterfaceType::Loopback);
        assert!(lo.is_up);
        assert!(lo.addresses.contains(&"127.0.0.1/8".to_string()));

        let eth0 = &ifaces[1];
        assert_eq!(eth0.name, "eth0");
        assert_eq!(eth0.iface_type, InterfaceType::Physical);
        assert!(eth0.is_up);

        let wg0 = &ifaces[2];
        assert_eq!(wg0.name, "wg0");
        assert_eq!(wg0.iface_type, InterfaceType::Wireguard);
    }
}
