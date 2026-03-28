use serde::Serialize;
use ts_rs::TS;

use crate::host::detect::{DistroFamily, IptablesVariant};

/// Human-readable explanation for a common iptables or SSH error.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct ErrorExplanation {
    pub code: String,
    pub title: String,
    pub explanation: String,
    pub remediation: Vec<String>,
}

/// Contextual information about the remote host, used to tailor
/// remediation steps (e.g. apt vs yum install commands).
pub struct ErrorContext {
    pub iptables_variant: Option<IptablesVariant>,
    pub distro_family: Option<DistroFamily>,
    pub has_docker: bool,
    pub has_fail2ban: bool,
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self {
            iptables_variant: None,
            distro_family: None,
            has_docker: false,
            has_fail2ban: false,
        }
    }
}

/// Match `stderr` content against known error patterns and return
/// a human-readable explanation with remediation steps.
/// Returns the FIRST matching explanation, or `None` if unrecognized.
pub fn explain_error(
    stderr: &str,
    exit_code: i32,
    context: &ErrorContext,
) -> Option<ErrorExplanation> {
    // 1. Chain/target/match not found
    if stderr.contains("No chain/target/match by that name") {
        return Some(ErrorExplanation {
            code: "CHAIN_NOT_FOUND".into(),
            title: "Chain or target not found".into(),
            explanation: "The specified chain, target, or match extension does not exist. This usually means a chain hasn't been created yet, or a required kernel module isn't loaded.".into(),
            remediation: vec![
                "Create the missing chain with: iptables -N <chain-name>".into(),
                "Check available targets with: iptables -j HELP".into(),
                "Load required module with: modprobe <module>".into(),
            ],
        });
    }

    // 2. Table init failure
    if stderr.contains("can't initialize iptables table") || stderr.contains("Table does not exist")
    {
        return Some(ErrorExplanation {
            code: "TABLE_INIT_FAILED".into(),
            title: "Cannot initialize iptables table".into(),
            explanation: "The kernel module for the requested table is not loaded or not available. This commonly happens in containers or minimal kernel configurations.".into(),
            remediation: vec![
                "Load the kernel module: sudo modprobe ip_tables (or ip6_tables, iptable_filter, iptable_nat)".into(),
                "Check if modules are available: lsmod | grep ip_tables".into(),
                "In containers, the host kernel must support the required modules".into(),
            ],
        });
    }

    // 3. Permission denied (but not exit_code 4, which is xtables lock)
    if (stderr.contains("Permission denied") || stderr.contains("Operation not permitted"))
        && exit_code != 4
        // Avoid matching SSH auth failures here — those are handled below
        && !stderr.contains("publickey")
    {
        return Some(ErrorExplanation {
            code: "PERMISSION_DENIED".into(),
            title: "Permission denied".into(),
            explanation: "The command requires elevated privileges. Either sudo is not configured for this user, or SELinux/AppArmor is blocking the operation.".into(),
            remediation: vec![
                "Ensure the user has passwordless sudo for iptables: <user> ALL=(ALL) NOPASSWD: /sbin/iptables, /sbin/iptables-restore".into(),
                "Check SELinux status: getenforce".into(),
                "Check AppArmor status: aa-status".into(),
            ],
        });
    }

    // 4. Mixed backend
    if stderr.contains("is incompatible") || stderr.contains("has incompatible") {
        return Some(ErrorExplanation {
            code: "MIXED_BACKEND".into(),
            title: "Incompatible iptables backend".into(),
            explanation: "The ruleset was created with a different iptables backend (legacy vs nf_tables). You cannot mix rules from both backends.".into(),
            remediation: vec![
                "Check which backend is active: iptables --version".into(),
                "Flush legacy rules: iptables-legacy -F".into(),
                "Or switch to the matching backend: update-alternatives --set iptables /usr/sbin/iptables-nft".into(),
            ],
        });
    }

    // 5. iptables-restore syntax error
    if stderr.contains("iptables-restore: line") && stderr.contains("failed") {
        return Some(ErrorExplanation {
            code: "RESTORE_SYNTAX".into(),
            title: "Syntax error in rule".into(),
            explanation: "The iptables-restore input contains a syntax error. This is usually caused by an invalid option, missing argument, or unsupported match module.".into(),
            remediation: vec![
                "Check the line mentioned in the error for typos".into(),
                "Verify all match modules are available on the target system".into(),
                "Try applying rules one at a time to isolate the problematic rule".into(),
            ],
        });
    }

    // 6. xtables lock contention
    if (stderr.contains("xtables lock") || stderr.contains("Resource temporarily unavailable"))
        && exit_code == 4
    {
        let mut remediation = vec![
            "Wait a few seconds and retry".into(),
            "Check what holds the lock: fuser /run/xtables.lock".into(),
        ];
        let mut holders = Vec::new();
        if context.has_fail2ban {
            holders.push("fail2ban");
        }
        if context.has_docker {
            holders.push("Docker");
        }
        holders.extend_from_slice(&["ufw", "firewalld"]);
        remediation.push(format!("Common lock holders: {}", holders.join(", ")));

        return Some(ErrorExplanation {
            code: "XTABLES_LOCKED".into(),
            title: "iptables lock contention".into(),
            explanation: "Another process is currently modifying iptables rules. The lock is held to prevent concurrent modifications.".into(),
            remediation,
        });
    }

    // 7. SSH connection refused
    if stderr.contains("Connection refused") {
        return Some(ErrorExplanation {
            code: "SSH_CONN_REFUSED".into(),
            title: "SSH connection refused".into(),
            explanation: "The SSH server is not accepting connections on the specified port. The SSH service may not be running, or a firewall may be blocking the port.".into(),
            remediation: vec![
                "Verify SSH service is running on the target".into(),
                "Check the port number is correct".into(),
                "Check if a firewall is blocking SSH access".into(),
            ],
        });
    }

    // 8. SSH timeout
    if stderr.contains("Connection timed out") || stderr.contains("Operation timed out") {
        return Some(ErrorExplanation {
            code: "SSH_TIMEOUT".into(),
            title: "Connection timed out".into(),
            explanation: "Could not establish a connection within the timeout period. The host may be unreachable, or network routing may be broken.".into(),
            remediation: vec![
                "Verify the host is reachable: ping <host>".into(),
                "Check network routing: traceroute <host>".into(),
                "Verify no firewall is blocking the connection".into(),
            ],
        });
    }

    // 9. SSH host key verification
    if stderr.contains("Host key verification failed") {
        return Some(ErrorExplanation {
            code: "SSH_HOST_KEY".into(),
            title: "Host key verification failed".into(),
            explanation: "The SSH host key doesn't match what's stored in known_hosts. This could indicate the server was reinstalled, or a potential security issue.".into(),
            remediation: vec![
                "If the server was reinstalled, remove the old key: ssh-keygen -R <host>".into(),
                "Verify the server identity through another channel before proceeding".into(),
            ],
        });
    }

    // 10. SSH authentication failure
    if stderr.contains("Authentication failed") || stderr.contains("Permission denied (publickey")
    {
        return Some(ErrorExplanation {
            code: "SSH_AUTH".into(),
            title: "SSH authentication failed".into(),
            explanation: "Could not authenticate with the provided credentials. The key may be incorrect, or the server may not accept this authentication method.".into(),
            remediation: vec![
                "Verify the SSH key is correct and has proper permissions (chmod 600)".into(),
                "Check if the server accepts key-based auth: grep PubkeyAuthentication /etc/ssh/sshd_config".into(),
                "Try connecting manually: ssh -v <user>@<host>".into(),
            ],
        });
    }

    // 11. No route to host
    if stderr.contains("No route to host") {
        return Some(ErrorExplanation {
            code: "NO_ROUTE".into(),
            title: "No route to host".into(),
            explanation: "There is no network route to reach the target host.".into(),
            remediation: vec![
                "Check network connectivity: ip route".into(),
                "Verify the host IP is correct".into(),
                "Check if VPN is required and connected".into(),
            ],
        });
    }

    // 12. iptables not found (context-aware)
    if stderr.contains("command not found") && stderr.contains("iptables") {
        let remediation = match context.distro_family {
            Some(DistroFamily::Debian) => {
                vec!["Install: sudo apt install iptables".into()]
            }
            Some(DistroFamily::Rhel) => {
                vec!["Install: sudo yum install iptables".into()]
            }
            _ => {
                vec!["Install iptables using your distribution's package manager".into()]
            }
        };

        return Some(ErrorExplanation {
            code: "IPTABLES_NOT_FOUND".into(),
            title: "iptables not installed".into(),
            explanation: "The iptables command is not found on the target system.".into(),
            remediation,
        });
    }

    // 13. Out of memory
    if stderr.contains("Memory allocation") || stderr.contains("Out of memory") {
        return Some(ErrorExplanation {
            code: "OUT_OF_MEMORY".into(),
            title: "Out of memory".into(),
            explanation: "The system ran out of memory while processing iptables rules. This can happen with very large rulesets.".into(),
            remediation: vec![
                "Consider using ipset for large IP lists instead of individual rules".into(),
                "Check available memory: free -h".into(),
                "Reduce the number of rules".into(),
            ],
        });
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explain_no_chain() {
        let ctx = ErrorContext::default();
        let result =
            explain_error("iptables: No chain/target/match by that name", 1, &ctx).unwrap();
        assert_eq!(result.code, "CHAIN_NOT_FOUND");
        assert!(!result.remediation.is_empty());
    }

    #[test]
    fn test_explain_permission_denied() {
        let ctx = ErrorContext::default();
        let result = explain_error("Permission denied", 1, &ctx).unwrap();
        assert_eq!(result.code, "PERMISSION_DENIED");
    }

    #[test]
    fn test_explain_table_init() {
        let ctx = ErrorContext::default();
        let result =
            explain_error("can't initialize iptables table 'filter'", 1, &ctx).unwrap();
        assert_eq!(result.code, "TABLE_INIT_FAILED");
    }

    #[test]
    fn test_explain_mixed_backend() {
        let ctx = ErrorContext::default();
        let result = explain_error("table 'filter' is incompatible", 1, &ctx).unwrap();
        assert_eq!(result.code, "MIXED_BACKEND");
    }

    #[test]
    fn test_explain_unknown_returns_none() {
        let ctx = ErrorContext::default();
        let result = explain_error("some random unrecognized error output", 1, &ctx);
        assert!(result.is_none());
    }

    #[test]
    fn test_explain_context_aware_remediation() {
        let ctx = ErrorContext {
            distro_family: Some(DistroFamily::Debian),
            ..ErrorContext::default()
        };
        let result =
            explain_error("bash: iptables: command not found", 127, &ctx).unwrap();
        assert_eq!(result.code, "IPTABLES_NOT_FOUND");
        assert!(result.remediation.iter().any(|r| r.contains("apt")));
    }

    #[test]
    fn test_explain_context_aware_remediation_rhel() {
        let ctx = ErrorContext {
            distro_family: Some(DistroFamily::Rhel),
            ..ErrorContext::default()
        };
        let result =
            explain_error("bash: iptables: command not found", 127, &ctx).unwrap();
        assert_eq!(result.code, "IPTABLES_NOT_FOUND");
        assert!(result.remediation.iter().any(|r| r.contains("yum")));
    }

    #[test]
    fn test_explain_xtables_locked() {
        let ctx = ErrorContext {
            has_docker: true,
            has_fail2ban: true,
            ..ErrorContext::default()
        };
        let result = explain_error("xtables lock contention", 4, &ctx).unwrap();
        assert_eq!(result.code, "XTABLES_LOCKED");
        // Remediation should mention detected lock holders
        let holders_line = result
            .remediation
            .iter()
            .find(|r| r.contains("Common lock holders"))
            .unwrap();
        assert!(holders_line.contains("fail2ban"));
        assert!(holders_line.contains("Docker"));
    }

    #[test]
    fn test_explain_ssh_connection_refused() {
        let ctx = ErrorContext::default();
        let result = explain_error("ssh: connect to host 10.0.0.1 port 22: Connection refused", 255, &ctx).unwrap();
        assert_eq!(result.code, "SSH_CONN_REFUSED");
    }

    #[test]
    fn test_explain_ssh_timeout() {
        let ctx = ErrorContext::default();
        let result = explain_error("ssh: connect to host 10.0.0.1 port 22: Connection timed out", 255, &ctx).unwrap();
        assert_eq!(result.code, "SSH_TIMEOUT");
    }

    #[test]
    fn test_explain_ssh_host_key() {
        let ctx = ErrorContext::default();
        let result = explain_error("Host key verification failed", 255, &ctx).unwrap();
        assert_eq!(result.code, "SSH_HOST_KEY");
    }

    #[test]
    fn test_explain_ssh_auth() {
        let ctx = ErrorContext::default();
        let result = explain_error("Permission denied (publickey)", 255, &ctx).unwrap();
        assert_eq!(result.code, "SSH_AUTH");
    }

    #[test]
    fn test_explain_no_route() {
        let ctx = ErrorContext::default();
        let result = explain_error("No route to host", 255, &ctx).unwrap();
        assert_eq!(result.code, "NO_ROUTE");
    }

    #[test]
    fn test_explain_restore_syntax() {
        let ctx = ErrorContext::default();
        let result = explain_error(
            "iptables-restore: line 3 failed",
            1,
            &ctx,
        )
        .unwrap();
        assert_eq!(result.code, "RESTORE_SYNTAX");
    }

    #[test]
    fn test_explain_out_of_memory() {
        let ctx = ErrorContext::default();
        let result = explain_error("Out of memory", 1, &ctx).unwrap();
        assert_eq!(result.code, "OUT_OF_MEMORY");
    }

    #[test]
    fn test_ssh_auth_takes_priority_over_generic_permission_denied() {
        let ctx = ErrorContext::default();

        // "Permission denied (publickey)" must match SSH_AUTH, not PERMISSION_DENIED
        let result = explain_error("Permission denied (publickey)", 255, &ctx).unwrap();
        assert_eq!(
            result.code, "SSH_AUTH",
            "SSH auth error must not be caught by generic Permission denied matcher"
        );

        // Plain "Permission denied" without publickey should match PERMISSION_DENIED
        let result2 = explain_error("Permission denied", 1, &ctx).unwrap();
        assert_eq!(
            result2.code, "PERMISSION_DENIED",
            "Generic permission denied should match when no publickey keyword"
        );
    }

    #[test]
    fn test_empty_stderr_returns_none() {
        let ctx = ErrorContext::default();
        assert!(explain_error("", 0, &ctx).is_none(), "empty stderr should not match any pattern");
        assert!(explain_error("", 1, &ctx).is_none());
    }

    #[test]
    fn test_weak_tests_check_remediation_content() {
        let ctx = ErrorContext::default();

        // Permission denied should suggest sudo config
        let r = explain_error("Permission denied", 1, &ctx).unwrap();
        assert!(r.remediation.iter().any(|s| s.contains("sudo")),
            "PERMISSION_DENIED should suggest sudo, got: {:?}", r.remediation);

        // Table init should suggest modprobe
        let r = explain_error("can't initialize iptables table 'filter'", 1, &ctx).unwrap();
        assert!(r.remediation.iter().any(|s| s.contains("modprobe") || s.contains("module")),
            "TABLE_INIT_FAILED should mention kernel modules, got: {:?}", r.remediation);

        // SSH timeout should suggest ping
        let r = explain_error("Connection timed out", 255, &ctx).unwrap();
        assert!(r.remediation.iter().any(|s| s.contains("ping") || s.contains("reachable")),
            "SSH_TIMEOUT should suggest checking connectivity, got: {:?}", r.remediation);

        // Host key should suggest ssh-keygen
        let r = explain_error("Host key verification failed", 255, &ctx).unwrap();
        assert!(r.remediation.iter().any(|s| s.contains("ssh-keygen") || s.contains("known_hosts")),
            "SSH_HOST_KEY should suggest removing old key, got: {:?}", r.remediation);

        // Restore syntax should mention line number
        let r = explain_error("iptables-restore: line 3 failed", 1, &ctx).unwrap();
        assert!(r.remediation.iter().any(|s| s.contains("line")),
            "RESTORE_SYNTAX should mention line, got: {:?}", r.remediation);
    }
}
