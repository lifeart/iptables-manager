use traffic_rules_lib::iptables::jump_rules::generate_ensure_jump_rules;

#[test]
fn test_empty_input_generates_all_jumps() {
    let commands = generate_ensure_jump_rules(&[]);
    assert_eq!(commands.len(), 4);
    assert!(commands[0].contains("-I INPUT 1 -j TR-CONNTRACK"));
    assert!(commands[1].contains("-I INPUT 2 -j TR-INPUT"));
    assert!(commands[2].contains("-I OUTPUT 1 -j TR-OUTPUT"));
    assert!(commands[3].contains("-I FORWARD 1 -j TR-FORWARD"));
}

#[test]
fn test_all_jumps_present_correct_position() {
    let rules = vec![
        "-A INPUT -j TR-CONNTRACK".to_string(),
        "-A INPUT -j TR-INPUT".to_string(),
        "-A OUTPUT -j TR-OUTPUT".to_string(),
        "-A FORWARD -j TR-FORWARD".to_string(),
    ];
    let commands = generate_ensure_jump_rules(&rules);
    assert!(commands.is_empty(), "should need no changes: {:?}", commands);
}

#[test]
fn test_missing_tr_input_jump() {
    let rules = vec![
        "-A INPUT -j TR-CONNTRACK".to_string(),
        // TR-INPUT is missing
        "-A OUTPUT -j TR-OUTPUT".to_string(),
        "-A FORWARD -j TR-FORWARD".to_string(),
    ];
    let commands = generate_ensure_jump_rules(&rules);
    assert_eq!(commands.len(), 1);
    assert!(commands[0].contains("-I INPUT 2 -j TR-INPUT"));
}

#[test]
fn test_wrong_position_delete_and_reinsert() {
    let rules = vec![
        "-A INPUT -p tcp --dport 22 -j ACCEPT".to_string(),
        "-A INPUT -j TR-CONNTRACK".to_string(),
        "-A INPUT -j TR-INPUT".to_string(),
        "-A OUTPUT -j TR-OUTPUT".to_string(),
        "-A FORWARD -j TR-FORWARD".to_string(),
    ];
    let commands = generate_ensure_jump_rules(&rules);
    // TR-CONNTRACK at pos 1 instead of 0 -> delete + reinsert
    assert!(commands.len() >= 2, "expected delete+insert commands: {:?}", commands);
    let has_delete = commands.iter().any(|c| c.contains("-D INPUT -j TR-CONNTRACK"));
    let has_insert = commands.iter().any(|c| c.contains("-I INPUT 1 -j TR-CONNTRACK"));
    assert!(has_delete, "should delete mispositioned rule");
    assert!(has_insert, "should reinsert at correct position");
}

#[test]
fn test_idempotent_correct_state() {
    let rules = vec![
        "-A INPUT -j TR-CONNTRACK".to_string(),
        "-A INPUT -j TR-INPUT".to_string(),
        "-A OUTPUT -j TR-OUTPUT".to_string(),
        "-A FORWARD -j TR-FORWARD".to_string(),
    ];
    let cmd1 = generate_ensure_jump_rules(&rules);
    let cmd2 = generate_ensure_jump_rules(&rules);
    assert!(cmd1.is_empty());
    assert!(cmd2.is_empty());
}

#[test]
fn test_all_commands_include_wait_flag() {
    let commands = generate_ensure_jump_rules(&[]);
    for cmd in &commands {
        assert!(cmd.contains("-w 5"), "command missing -w 5: {}", cmd);
    }
}

#[test]
fn test_existing_with_extra_rules() {
    // Jump rules exist at correct positions, with other rules following
    let rules = vec![
        "-A INPUT -j TR-CONNTRACK".to_string(),
        "-A INPUT -j TR-INPUT".to_string(),
        "-A INPUT -p tcp --dport 22 -j ACCEPT".to_string(),
        "-A INPUT -p tcp --dport 80 -j ACCEPT".to_string(),
        "-A OUTPUT -j TR-OUTPUT".to_string(),
        "-A FORWARD -j TR-FORWARD".to_string(),
    ];
    let commands = generate_ensure_jump_rules(&rules);
    assert!(commands.is_empty(), "should need no changes when jumps are correct: {:?}", commands);
}

#[test]
fn test_missing_all_forward_and_output() {
    let rules = vec![
        "-A INPUT -j TR-CONNTRACK".to_string(),
        "-A INPUT -j TR-INPUT".to_string(),
        // No OUTPUT or FORWARD jump rules
    ];
    let commands = generate_ensure_jump_rules(&rules);
    assert_eq!(commands.len(), 2);
    assert!(commands[0].contains("-I OUTPUT 1 -j TR-OUTPUT"));
    assert!(commands[1].contains("-I FORWARD 1 -j TR-FORWARD"));
}
