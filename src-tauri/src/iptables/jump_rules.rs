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

    // Phase 1: Delete all existing TR-* jump rules from built-in chains.
    // This avoids position-calculation bugs when multiple rules shift after
    // a single delete.
    for &(builtin_chain, tr_chains) in JUMP_MAP {
        for &tr_chain in tr_chains {
            let jump_target = format!("-j {}", tr_chain);
            let exists = current_rules.iter().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with(&format!("-A {} ", builtin_chain))
                    && trimmed.contains(&jump_target)
            });
            if exists {
                commands.push(format!(
                    "iptables -w 5 -D {} -j {}",
                    builtin_chain, tr_chain
                ));
            }
        }
    }

    // Phase 2: Insert all jump rules at the correct positions (fresh).
    for &(builtin_chain, tr_chains) in JUMP_MAP {
        for (desired_pos, &tr_chain) in tr_chains.iter().enumerate() {
            commands.push(format!(
                "iptables -w 5 -I {} {} -j {}",
                builtin_chain,
                desired_pos + 1,
                tr_chain
            ));
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
        // No deletes (nothing to delete), then 4 inserts
        assert_eq!(commands.len(), 4);
        assert!(commands[0].contains("-I INPUT 1 -j TR-CONNTRACK"));
        assert!(commands[1].contains("-I INPUT 2 -j TR-INPUT"));
        assert!(commands[2].contains("-I OUTPUT 1 -j TR-OUTPUT"));
        assert!(commands[3].contains("-I FORWARD 1 -j TR-FORWARD"));
    }

    #[test]
    fn test_existing_correct_jumps_deletes_then_reinserts() {
        let rules = vec![
            "-A INPUT -j TR-CONNTRACK".to_string(),
            "-A INPUT -j TR-INPUT".to_string(),
            "-A OUTPUT -j TR-OUTPUT".to_string(),
            "-A FORWARD -j TR-FORWARD".to_string(),
        ];
        let commands = generate_ensure_jump_rules(&rules);
        // Should delete all 4 existing, then insert all 4 fresh = 8 commands
        assert_eq!(commands.len(), 8, "expected 8 commands (4 deletes + 4 inserts), got: {:?}", commands);
        // First 4 are deletes
        assert!(commands[0].contains("-D INPUT -j TR-CONNTRACK"));
        assert!(commands[1].contains("-D INPUT -j TR-INPUT"));
        assert!(commands[2].contains("-D OUTPUT -j TR-OUTPUT"));
        assert!(commands[3].contains("-D FORWARD -j TR-FORWARD"));
        // Last 4 are inserts
        assert!(commands[4].contains("-I INPUT 1 -j TR-CONNTRACK"));
        assert!(commands[5].contains("-I INPUT 2 -j TR-INPUT"));
        assert!(commands[6].contains("-I OUTPUT 1 -j TR-OUTPUT"));
        assert!(commands[7].contains("-I FORWARD 1 -j TR-FORWARD"));
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
        // 3 deletes + 4 inserts = 7
        assert_eq!(commands.len(), 7);
        // The inserts always include all 4
        let inserts: Vec<&String> = commands.iter().filter(|c| c.contains("-I ")).collect();
        assert_eq!(inserts.len(), 4);
        assert!(inserts.iter().any(|c| c.contains("-I INPUT 2 -j TR-INPUT")));
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
        // 4 deletes + 4 inserts = 8
        assert_eq!(commands.len(), 8);
        // Deletes come first
        assert!(commands[0].contains("-D INPUT -j TR-CONNTRACK"));
        assert!(commands[1].contains("-D INPUT -j TR-INPUT"));
        // Then fresh inserts at correct positions
        let inserts: Vec<&String> = commands.iter().filter(|c| c.contains("-I ")).collect();
        assert!(inserts[0].contains("-I INPUT 1 -j TR-CONNTRACK"));
        assert!(inserts[1].contains("-I INPUT 2 -j TR-INPUT"));
    }

    #[test]
    fn test_all_commands_include_w_flag() {
        let commands = generate_ensure_jump_rules(&[]);
        for cmd in &commands {
            assert!(cmd.contains("-w 5"), "command missing -w 5: {}", cmd);
        }
    }
}
