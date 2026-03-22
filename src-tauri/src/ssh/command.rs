use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Error)]
pub enum ValidationError {
    #[error("comment too long ({len} chars, max 256)")]
    CommentTooLong { len: usize },
    #[error("comment contains invalid characters")]
    InvalidChars,
}

// ---------------------------------------------------------------------------
// Command construction
// ---------------------------------------------------------------------------

/// Build a shell-safe command string from a program and its arguments.
///
/// Uses `shell_words::join` for proper quoting — never raw string interpolation.
pub fn build_command(program: &str, args: &[&str]) -> String {
    let mut all: Vec<&str> = Vec::with_capacity(1 + args.len());
    all.push(program);
    all.extend_from_slice(args);
    shell_words::join(&all)
}

/// Build an iptables/ip6tables command with `sudo` and `-w 5`.
///
/// `subcmd` is typically `"iptables"` or `"ip6tables"`.
/// The `-w 5` flag is always appended (wait up to 5s for xtables lock).
///
/// # Example
/// ```ignore
/// let cmd = build_iptables_command("iptables", &["-I", "INPUT", "1", "-j", "TR-CONNTRACK"]);
/// assert_eq!(cmd, "sudo iptables -w 5 -I INPUT 1 -j TR-CONNTRACK");
/// ```
pub fn build_iptables_command(subcmd: &str, args: &[&str]) -> String {
    let mut all: Vec<&str> = Vec::with_capacity(4 + args.len());
    all.push("sudo");
    all.push(subcmd);
    all.push("-w");
    all.push("5");
    all.extend_from_slice(args);
    shell_words::join(&all)
}

/// Build the `iptables-restore` or `ip6tables-restore` command string.
///
/// Always includes `sudo`, `-w 5`, `--noflush`, and `--counters`.
pub fn build_restore_command(ipv6: bool) -> String {
    let program = if ipv6 {
        "ip6tables-restore"
    } else {
        "iptables-restore"
    };
    build_command("sudo", &[program, "-w", "5", "--noflush", "--counters"])
}

/// Validate and sanitize an iptables comment string.
///
/// - Max 256 characters
/// - No newlines, carriage returns, or null bytes
/// - Shell escaping is handled by `build_command`, so the returned string is
///   the raw comment text.
pub fn sanitize_comment(input: &str) -> Result<String, ValidationError> {
    if input.len() > 256 {
        return Err(ValidationError::CommentTooLong { len: input.len() });
    }
    if input.contains('\n') || input.contains('\r') || input.contains('\0') {
        return Err(ValidationError::InvalidChars);
    }
    Ok(input.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_command_simple() {
        assert_eq!(build_command("ls", &["-la"]), "ls -la");
    }

    #[test]
    fn test_build_command_escapes_spaces() {
        let cmd = build_command("echo", &["hello world"]);
        assert_eq!(cmd, "echo 'hello world'");
    }

    #[test]
    fn test_build_command_escapes_single_quotes() {
        let cmd = build_command("echo", &["it's"]);
        let parsed = shell_words::split(&cmd).unwrap();
        assert_eq!(parsed, vec!["echo", "it's"]);
    }

    #[test]
    fn test_build_command_escapes_double_quotes() {
        let cmd = build_command("echo", &["say \"hi\""]);
        let parsed = shell_words::split(&cmd).unwrap();
        assert_eq!(parsed, vec!["echo", "say \"hi\""]);
    }

    #[test]
    fn test_build_command_escapes_backticks() {
        let cmd = build_command("echo", &["`whoami`"]);
        let parsed = shell_words::split(&cmd).unwrap();
        assert_eq!(parsed, vec!["echo", "`whoami`"]);
    }

    #[test]
    fn test_build_command_escapes_dollar() {
        let cmd = build_command("echo", &["$HOME"]);
        let parsed = shell_words::split(&cmd).unwrap();
        assert_eq!(parsed, vec!["echo", "$HOME"]);
    }

    #[test]
    fn test_build_command_escapes_semicolons() {
        let cmd = build_command("echo", &["a; rm -rf /"]);
        let parsed = shell_words::split(&cmd).unwrap();
        assert_eq!(parsed, vec!["echo", "a; rm -rf /"]);
    }

    #[test]
    fn test_build_command_escapes_pipes() {
        let cmd = build_command("echo", &["a | cat /etc/passwd"]);
        let parsed = shell_words::split(&cmd).unwrap();
        assert_eq!(parsed, vec!["echo", "a | cat /etc/passwd"]);
    }

    #[test]
    fn test_build_iptables_command() {
        let cmd = build_iptables_command("iptables", &["-I", "INPUT", "1", "-j", "TR-CONNTRACK"]);
        assert_eq!(cmd, "sudo iptables -w 5 -I INPUT 1 -j TR-CONNTRACK");
    }

    #[test]
    fn test_build_iptables_command_ip6() {
        let cmd = build_iptables_command("ip6tables", &["-S", "INPUT"]);
        assert_eq!(cmd, "sudo ip6tables -w 5 -S INPUT");
    }

    #[test]
    fn test_build_iptables_command_with_comment() {
        let cmd = build_iptables_command(
            "iptables",
            &["-A", "TR-INPUT", "-p", "tcp", "--dport", "22",
              "-m", "comment", "--comment", "Allow SSH access",
              "-j", "ACCEPT"],
        );
        let parsed = shell_words::split(&cmd).unwrap();
        assert!(parsed.contains(&"Allow SSH access".to_string()));
    }

    #[test]
    fn test_build_restore_command_v4() {
        let cmd = build_restore_command(false);
        assert_eq!(cmd, "sudo iptables-restore -w 5 --noflush --counters");
    }

    #[test]
    fn test_build_restore_command_v6() {
        let cmd = build_restore_command(true);
        assert_eq!(cmd, "sudo ip6tables-restore -w 5 --noflush --counters");
    }

    #[test]
    fn test_sanitize_comment_valid() {
        assert_eq!(
            sanitize_comment("Allow SSH from office").unwrap(),
            "Allow SSH from office"
        );
    }

    #[test]
    fn test_sanitize_comment_empty() {
        assert_eq!(sanitize_comment("").unwrap(), "");
    }

    #[test]
    fn test_sanitize_comment_max_length() {
        let s = "a".repeat(256);
        assert!(sanitize_comment(&s).is_ok());
    }

    #[test]
    fn test_sanitize_comment_too_long() {
        let s = "a".repeat(257);
        assert!(matches!(
            sanitize_comment(&s),
            Err(ValidationError::CommentTooLong { len: 257 })
        ));
    }

    #[test]
    fn test_sanitize_comment_newline() {
        assert!(matches!(
            sanitize_comment("line1\nline2"),
            Err(ValidationError::InvalidChars)
        ));
    }

    #[test]
    fn test_sanitize_comment_carriage_return() {
        assert!(matches!(
            sanitize_comment("line1\rline2"),
            Err(ValidationError::InvalidChars)
        ));
    }

    #[test]
    fn test_sanitize_comment_null_byte() {
        assert!(matches!(
            sanitize_comment("hello\0world"),
            Err(ValidationError::InvalidChars)
        ));
    }

    #[test]
    fn test_sanitize_comment_special_chars_ok() {
        assert!(sanitize_comment("Allow $HOME; `rm -rf /`").is_ok());
    }
}
