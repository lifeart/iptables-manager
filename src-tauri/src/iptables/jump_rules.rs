/// Idempotent jump rule management for built-in chains.
///
/// Jump rules in built-in chains (`-j TR-CONNTRACK`, `-j TR-INPUT`, etc.) are
/// managed separately from the restore file because the restore file uses
/// `--noflush` mode which never touches built-in chains.
///
/// Position matters:
/// - INPUT chain: TR-CONNTRACK at position 1 (INVALID/ESTABLISHED checked
///   first), TR-INPUT at position 2.
/// - OUTPUT chain: TR-OUTPUT at position 1.
/// - FORWARD chain: TR-FORWARD at position 1.

/// Mapping of built-in chains to the TR-* chains that should be jumped to,
/// in order.  The order determines insertion position.
const JUMP_MAP: &[(&str, &[&str])] = &[
    ("INPUT", &["TR-CONNTRACK", "TR-INPUT"]),
    ("OUTPUT", &["TR-OUTPUT"]),
    ("FORWARD", &["TR-FORWARD"]),
];

/// Given the current `iptables -S` output for all chains (or just the relevant
/// built-in chains), return a list of iptables commands to run to ensure all
/// jump rules exist at the correct positions.
///
/// Each returned string is a complete iptables command (without `sudo` or
/// `-w 5` — the caller adds those).
///
/// This function is **idempotent**: calling it when all jump rules already
/// exist at the correct positions returns an empty list.
pub fn generate_ensure_jump_rules(current_rules: &[String]) -> Vec<String> {
    let mut commands: Vec<String> = Vec::new();

    for &(builtin_chain, tr_chains) in JUMP_MAP {
        // Collect rules that belong to this built-in chain
        let chain_rules: Vec<&str> = current_rules
            .iter()
            .filter_map(|line| {
                let trimmed = line.trim();
                // Match both "-A INPUT ..." and "-P INPUT ..." (policy)
                if trimmed.starts_with(&format!("-A {} ", builtin_chain)) {
                    Some(trimmed)
                } else {
                    None
                }
            })
            .collect();

        // For each TR-* chain, check if a jump rule exists
        for (desired_pos, &tr_chain) in tr_chains.iter().enumerate() {
            let jump_target = format!("-j {}", tr_chain);

            // Find the current position of this jump rule (if any)
            let current_pos = chain_rules
                .iter()
                .position(|rule| rule.contains(&jump_target));

            match current_pos {
                Some(pos) if pos == desired_pos => {
                    // Already at the correct position — nothing to do
                }
                Some(_pos) => {
                    // Exists but at wrong position — delete and re-insert
                    commands.push(format!(
                        "iptables -w 5 -D {} -j {}",
                        builtin_chain, tr_chain
                    ));
                    commands.push(format!(
                        "iptables -w 5 -I {} {} -j {}",
                        builtin_chain,
                        desired_pos + 1,
                        tr_chain
                    ));
                }
                None => {
                    // Missing — insert at the correct position
                    commands.push(format!(
                        "iptables -w 5 -I {} {} -j {}",
                        builtin_chain,
                        desired_pos + 1,
                        tr_chain
                    ));
                }
            }
        }
    }

    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input_generates_all_jumps() {
        let commands = generate_ensure_jump_rules(&[]);
        // Should generate inserts for TR-CONNTRACK, TR-INPUT, TR-OUTPUT, TR-FORWARD
        assert_eq!(commands.len(), 4);
        assert!(commands[0].contains("-I INPUT 1 -j TR-CONNTRACK"));
        assert!(commands[1].contains("-I INPUT 2 -j TR-INPUT"));
        assert!(commands[2].contains("-I OUTPUT 1 -j TR-OUTPUT"));
        assert!(commands[3].contains("-I FORWARD 1 -j TR-FORWARD"));
    }

    #[test]
    fn test_existing_correct_jumps_no_commands() {
        let rules = vec![
            "-A INPUT -j TR-CONNTRACK".to_string(),
            "-A INPUT -j TR-INPUT".to_string(),
            "-A OUTPUT -j TR-OUTPUT".to_string(),
            "-A FORWARD -j TR-FORWARD".to_string(),
        ];
        let commands = generate_ensure_jump_rules(&rules);
        assert!(commands.is_empty(), "expected no commands, got: {:?}", commands);
    }

    #[test]
    fn test_missing_one_jump() {
        let rules = vec![
            "-A INPUT -j TR-CONNTRACK".to_string(),
            // TR-INPUT missing
            "-A OUTPUT -j TR-OUTPUT".to_string(),
            "-A FORWARD -j TR-FORWARD".to_string(),
        ];
        let commands = generate_ensure_jump_rules(&rules);
        assert_eq!(commands.len(), 1);
        assert!(commands[0].contains("-I INPUT 2 -j TR-INPUT"));
    }

    #[test]
    fn test_wrong_position_reinserts() {
        let rules = vec![
            "-A INPUT -p tcp --dport 22 -j ACCEPT".to_string(), // some other rule at pos 0
            "-A INPUT -j TR-CONNTRACK".to_string(),              // should be at 0, is at 1
            "-A INPUT -j TR-INPUT".to_string(),
            "-A OUTPUT -j TR-OUTPUT".to_string(),
            "-A FORWARD -j TR-FORWARD".to_string(),
        ];
        let commands = generate_ensure_jump_rules(&rules);
        // TR-CONNTRACK is at position 1 instead of 0, needs delete + reinsert
        assert!(commands.len() >= 2);
        assert!(commands[0].contains("-D INPUT -j TR-CONNTRACK"));
        assert!(commands[1].contains("-I INPUT 1 -j TR-CONNTRACK"));
    }

    #[test]
    fn test_idempotent() {
        let rules = vec![
            "-A INPUT -j TR-CONNTRACK".to_string(),
            "-A INPUT -j TR-INPUT".to_string(),
            "-A OUTPUT -j TR-OUTPUT".to_string(),
            "-A FORWARD -j TR-FORWARD".to_string(),
        ];
        // Call twice — should both return empty
        let cmd1 = generate_ensure_jump_rules(&rules);
        let cmd2 = generate_ensure_jump_rules(&rules);
        assert!(cmd1.is_empty());
        assert!(cmd2.is_empty());
    }

    #[test]
    fn test_all_commands_include_w_flag() {
        let commands = generate_ensure_jump_rules(&[]);
        for cmd in &commands {
            assert!(cmd.contains("-w 5"), "command missing -w 5: {}", cmd);
        }
    }
}
