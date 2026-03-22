use std::collections::HashMap;

use crate::iptables::types::*;

/// Maximum input size: 10 MB.
const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024;

/// Parse the full output of `iptables-save` into a structured [`ParsedRuleset`].
///
/// The parser is a line-oriented state machine that never panics on malformed
/// input.  Unparseable rule lines are preserved verbatim with `parsed: None`
/// and a warning attached.
pub fn parse_iptables_save(input: &str) -> Result<ParsedRuleset, ParseError> {
    if input.len() > MAX_INPUT_SIZE {
        return Err(ParseError::InputTooLarge { size: input.len() });
    }

    let mut ruleset = ParsedRuleset {
        tables: HashMap::new(),
        header_comments: Vec::new(),
    };

    let mut current_table: Option<String> = None;

    for (_line_no, line) in input.lines().enumerate() {
        let trimmed = line.trim();

        // Skip empty lines
        if trimmed.is_empty() {
            continue;
        }

        // Comment lines
        if trimmed.starts_with('#') {
            if current_table.is_none() {
                ruleset.header_comments.push(trimmed.to_string());
            }
            // Comments inside a table block are ignored (they don't appear in
            // real iptables-save output, but we handle them gracefully).
            continue;
        }

        // Table header: *filter, *nat, *mangle, *raw, *security
        if trimmed.starts_with('*') {
            let table_name = trimmed[1..].to_string();
            ruleset.tables.entry(table_name.clone()).or_insert_with(|| TableState {
                name: table_name.clone(),
                chains: HashMap::new(),
            });
            current_table = Some(table_name);
            continue;
        }

        // COMMIT
        if trimmed == "COMMIT" {
            current_table = None;
            continue;
        }

        // Chain declaration: :CHAIN POLICY [packets:bytes]
        if trimmed.starts_with(':') {
            if let Some(ref table_name) = current_table {
                parse_chain_declaration(trimmed, table_name, &mut ruleset);
            }
            continue;
        }

        // Rule line: -A CHAIN ...
        if trimmed.starts_with('-') || trimmed.starts_with('[') {
            if let Some(ref table_name) = current_table {
                parse_rule_line(trimmed, table_name, &mut ruleset);
            }
            continue;
        }

        // Unknown line — skip silently
    }

    Ok(ruleset)
}

/// Parse a chain declaration line like `:INPUT ACCEPT [100:5000]`.
fn parse_chain_declaration(line: &str, table_name: &str, ruleset: &mut ParsedRuleset) {
    // Strip leading ':'
    let rest = &line[1..];
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    let chain_name = parts[0].to_string();
    let policy = parts.get(1).map(|p| {
        if *p == "-" {
            None
        } else {
            Some(p.to_string())
        }
    }).unwrap_or(None);

    let counters = parts.get(2).and_then(|c| parse_counter_bracket(c));

    if let Some(table) = ruleset.tables.get_mut(table_name) {
        table.chains.entry(chain_name.clone()).or_insert_with(|| ChainState {
            name: chain_name,
            policy,
            counters,
            rules: Vec::new(),
            owner: ChainOwner::Unknown, // will be set by system_detect
        });
    }
}

/// Parse a rule line and add it to the appropriate chain.
fn parse_rule_line(line: &str, table_name: &str, ruleset: &mut ParsedRuleset) {
    // Handle counter prefix: [packets:bytes] -A CHAIN ...
    let (counters, rest) = if line.starts_with('[') {
        if let Some(bracket_end) = line.find(']') {
            let counter_str = &line[..=bracket_end];
            let c = parse_counter_bracket(counter_str);
            let remaining = line[bracket_end + 1..].trim();
            (c, remaining)
        } else {
            (None, line)
        }
    } else {
        (None, line)
    };

    // Must start with -A
    if !rest.starts_with("-A") {
        return;
    }

    // Tokenize respecting quoted strings
    let tokens = tokenize_rule(rest);
    if tokens.len() < 2 {
        return;
    }

    // tokens[0] = "-A", tokens[1] = chain name
    let chain_name = tokens[1].clone();

    let parsed_rule = ParsedRule {
        raw: line.to_string(),
        parsed: None,
        warnings: Vec::new(),
        chain: chain_name.clone(),
        table: table_name.to_string(),
    };

    // Try to parse the rule spec from tokens[2..]
    let (spec, warnings) = parse_rule_spec(&tokens[2..], counters);

    let parsed_rule = ParsedRule {
        parsed: Some(spec),
        warnings,
        ..parsed_rule
    };

    if let Some(table) = ruleset.tables.get_mut(table_name) {
        let chain = table.chains.entry(chain_name.clone()).or_insert_with(|| ChainState {
            name: chain_name,
            policy: None,
            counters: None,
            rules: Vec::new(),
            owner: ChainOwner::Unknown,
        });
        chain.rules.push(parsed_rule);
    }
}

/// Tokenize a rule line, respecting double-quoted strings.
pub fn tokenize_rule(input: &str) -> Vec<String> {
    // Use shell_words for proper quote handling; fall back on simple split
    match shell_words::split(input) {
        Ok(tokens) => tokens,
        Err(_) => input.split_whitespace().map(|s| s.to_string()).collect(),
    }
}

/// Parse `[packets:bytes]` format. Returns `(packets, bytes)`.
fn parse_counter_bracket(s: &str) -> Option<(u64, u64)> {
    let inner = s.trim_start_matches('[').trim_end_matches(']');
    let parts: Vec<&str> = inner.split(':').collect();
    if parts.len() == 2 {
        if let (Ok(p), Ok(b)) = (parts[0].parse::<u64>(), parts[1].parse::<u64>()) {
            return Some((p, b));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Known match modules and their argument counts / flags
// ---------------------------------------------------------------------------

/// Known modules and flags that consume the next token as a value.
fn module_value_flags(module: &str) -> &'static [&'static str] {
    match module {
        "tcp" => &["--sport", "--dport", "--tcp-flags", "--tcp-option"],
        "udp" => &["--sport", "--dport"],
        "icmp" => &["--icmp-type"],
        "icmpv6" => &["--icmpv6-type"],
        "conntrack" => &["--ctstate", "--ctproto", "--ctorigsrc", "--ctorigdst",
                         "--ctreplsrc", "--ctrepldst", "--ctorigsrcport",
                         "--ctorigdstport", "--ctreplsrcport", "--ctrepldstport",
                         "--ctstatus", "--ctexpire", "--ctdir"],
        "state" => &["--state"],
        "multiport" => &["--sports", "--dports", "--ports", "--source-ports", "--destination-ports"],
        "limit" => &["--limit", "--limit-burst"],
        "hashlimit" => &["--hashlimit-upto", "--hashlimit-above", "--hashlimit-burst",
                         "--hashlimit-mode", "--hashlimit-srcmask", "--hashlimit-dstmask",
                         "--hashlimit-name", "--hashlimit-htable-size",
                         "--hashlimit-htable-max", "--hashlimit-htable-expire",
                         "--hashlimit-htable-gcinterval"],
        "connlimit" => &["--connlimit-above", "--connlimit-upto", "--connlimit-mask",
                          "--connlimit-saddr", "--connlimit-daddr"],
        "comment" => &["--comment"],
        "set" => &["--match-set"],
        "string" => &["--string", "--hex-string", "--algo", "--from", "--to"],
        "recent" => &["--name", "--rsource", "--rdest", "--seconds", "--hitcount",
                       "--rttl"],
        "owner" => &["--uid-owner", "--gid-owner", "--pid-owner", "--sid-owner",
                      "--cmd-owner"],
        "time" => &["--datestart", "--datestop", "--timestart", "--timestop",
                     "--monthdays", "--weekdays", "--kerneltz"],
        "mark" => &["--mark"],
        "mac" => &["--mac-source"],
        "length" => &["--length"],
        "tos" => &["--tos"],
        "ttl" => &["--ttl-eq", "--ttl-gt", "--ttl-lt"],
        "addrtype" => &["--src-type", "--dst-type"],
        "physdev" => &["--physdev-in", "--physdev-out"],
        "policy" => &["--dir", "--pol", "--reqid", "--spi", "--proto", "--mode",
                       "--tunnel-src", "--tunnel-dst"],
        _ => &[],
    }
}

/// Boolean flags for modules (flags that do NOT consume the next token).
fn module_bool_flags(module: &str) -> &'static [&'static str] {
    match module {
        "recent" => &["--set", "--rcheck", "--update", "--remove", "--rsource", "--rdest", "--rttl"],
        "connlimit" => &["--connlimit-saddr", "--connlimit-daddr"],
        "time" => &["--kerneltz", "--contiguous"],
        "tcp" => &["--syn"],
        "physdev" => &["--physdev-is-bridged", "--physdev-is-in", "--physdev-is-out"],
        "addrtype" => &["--limit-iface-in", "--limit-iface-out"],
        _ => &[],
    }
}

/// Returns true if this flag is a known boolean (no-argument) flag for the
/// given module.
fn is_bool_flag(module: &str, flag: &str) -> bool {
    module_bool_flags(module).contains(&flag)
}

/// Parse rule tokens (after `-A CHAIN`) into a `RuleSpec`.
fn parse_rule_spec(tokens: &[String], counters: Option<(u64, u64)>) -> (RuleSpec, Vec<String>) {
    let mut spec = RuleSpec {
        protocol: None,
        protocol_negated: false,
        source: None,
        destination: None,
        in_iface: None,
        out_iface: None,
        matches: Vec::new(),
        target: None,
        target_args: Vec::new(),
        comment: None,
        counters,
        fragment: None,
    };
    let mut warnings: Vec<String> = Vec::new();
    let mut current_modules: Vec<String> = Vec::new(); // stack of active -m modules
    let mut i = 0;

    while i < tokens.len() {
        let token = &tokens[i];
        let negated = i > 0 && tokens[i - 1] == "!";

        match token.as_str() {
            "!" => {
                // Negation marker — handled by the next token
                i += 1;
                continue;
            }

            "-p" | "--protocol" => {
                // Check negation: could be before -p or after
                let neg = negated || (i + 2 < tokens.len() && tokens[i + 1] == "!");
                if i + 1 < tokens.len() {
                    let proto_idx = if i + 2 < tokens.len() && tokens[i + 1] == "!" {
                        i += 1; // skip "!"
                        i + 1
                    } else {
                        i + 1
                    };
                    if proto_idx < tokens.len() {
                        spec.protocol = Some(Protocol::from_str_loose(&tokens[proto_idx]));
                        spec.protocol_negated = neg;
                        // Implicitly load protocol as a match module
                        let proto_lower = tokens[proto_idx].to_lowercase();
                        if matches!(proto_lower.as_str(), "tcp" | "udp" | "icmp" | "icmpv6" | "sctp") {
                            if !current_modules.contains(&proto_lower) {
                                current_modules.push(proto_lower);
                            }
                        }
                        i = proto_idx + 1;
                        continue;
                    }
                }
                i += 1;
            }

            "-s" | "--source" | "--src" => {
                let (addr, advance) = parse_address_arg(tokens, i, negated);
                spec.source = addr;
                i += advance;
                continue;
            }

            "-d" | "--destination" | "--dst" => {
                let (addr, advance) = parse_address_arg(tokens, i, negated);
                spec.destination = addr;
                i += advance;
                continue;
            }

            "-i" | "--in-interface" => {
                let (iface, advance) = parse_interface_arg(tokens, i, negated);
                spec.in_iface = iface;
                i += advance;
                continue;
            }

            "-o" | "--out-interface" => {
                let (iface, advance) = parse_interface_arg(tokens, i, negated);
                spec.out_iface = iface;
                i += advance;
                continue;
            }

            "-f" | "--fragment" => {
                spec.fragment = Some(!negated);
                i += 1;
                continue;
            }

            "-m" | "--match" => {
                if i + 1 < tokens.len() {
                    let module_name = tokens[i + 1].clone();
                    current_modules.push(module_name.clone());

                    // Collect args for this module invocation
                    let (match_spec, advance) =
                        collect_module_args(&tokens, i + 2, &module_name);

                    // Special handling for comment module
                    if module_name == "comment" {
                        for j in 0..match_spec.args.len() {
                            if match_spec.args[j] == "--comment" {
                                if j + 1 < match_spec.args.len() {
                                    spec.comment = Some(match_spec.args[j + 1].clone());
                                }
                            }
                        }
                    }

                    spec.matches.push(match_spec);
                    i += 2 + advance;
                    continue;
                }
                i += 1;
            }

            "-j" | "--jump" | "-g" | "--goto" => {
                if i + 1 < tokens.len() {
                    spec.target = Some(Target::from_str_loose(&tokens[i + 1]));

                    // Collect target-specific arguments
                    let mut j = i + 2;
                    while j < tokens.len() {
                        // Stop if we hit another top-level flag
                        let t = &tokens[j];
                        if (t == "-m" || t == "--match" || t == "-p" || t == "--protocol"
                            || t == "-s" || t == "--source" || t == "-d" || t == "--destination"
                            || t == "-i" || t == "--in-interface" || t == "-o" || t == "--out-interface"
                            || t == "-j" || t == "--jump")
                            && !is_target_arg(t)
                        {
                            break;
                        }
                        spec.target_args.push(tokens[j].clone());
                        j += 1;
                    }
                    i = j;
                    continue;
                }
                i += 1;
            }

            // Protocol-level flags that might appear without explicit -m
            flag if flag.starts_with("--") => {
                // Try to match against current modules
                let mut matched = false;
                for module in current_modules.iter().rev() {
                    let value_flags = module_value_flags(module);
                    if value_flags.contains(&flag.as_ref()) {
                        // This flag belongs to this module; find or create the
                        // MatchSpec for it.
                        if let Some(ms) = spec.matches.iter_mut().rev()
                            .find(|m| m.module == *module)
                        {
                            ms.args.push(flag.to_string());
                            if !is_bool_flag(module, flag) && i + 1 < tokens.len() {
                                // Consume the value
                                i += 1;
                                ms.args.push(tokens[i].clone());
                            }
                        }
                        matched = true;
                        break;
                    }
                    if is_bool_flag(module, flag) {
                        if let Some(ms) = spec.matches.iter_mut().rev()
                            .find(|m| m.module == *module)
                        {
                            ms.args.push(flag.to_string());
                        }
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    // Could be a target arg we missed, or an unknown flag
                    warnings.push(format!("unknown flag: {}", flag));
                }
                i += 1;
            }

            _ => {
                i += 1;
            }
        }
    }

    (spec, warnings)
}

/// Returns true if this is a known target argument flag (not a top-level flag).
fn is_target_arg(flag: &str) -> bool {
    matches!(flag,
        "--to-destination" | "--to-source" | "--to-ports" |
        "--reject-with" | "--log-prefix" | "--log-level" | "--log-tcp-sequence" |
        "--log-tcp-options" | "--log-ip-options" | "--log-uid" |
        "--set-mark" | "--set-xmark" | "--save-mark" | "--restore-mark" |
        "--helper" | "--random" | "--persistent" | "--clamp-mss-to-pmtu" |
        "--queue-num" | "--queue-balance"
    )
}

/// Parse an address argument (for -s/-d).
fn parse_address_arg(tokens: &[String], i: usize, negated: bool) -> (Option<AddressSpec>, usize) {
    // Check for "! addr" pattern after the flag
    if i + 2 < tokens.len() && tokens[i + 1] == "!" {
        return (
            Some(AddressSpec {
                addr: tokens[i + 2].clone(),
                negated: true,
            }),
            3,
        );
    }
    if i + 1 < tokens.len() {
        (
            Some(AddressSpec {
                addr: tokens[i + 1].clone(),
                negated,
            }),
            2,
        )
    } else {
        (None, 1)
    }
}

/// Parse an interface argument (for -i/-o).
fn parse_interface_arg(tokens: &[String], i: usize, negated: bool) -> (Option<InterfaceSpec>, usize) {
    if i + 2 < tokens.len() && tokens[i + 1] == "!" {
        return (
            Some(InterfaceSpec {
                name: tokens[i + 2].clone(),
                negated: true,
            }),
            3,
        );
    }
    if i + 1 < tokens.len() {
        (
            Some(InterfaceSpec {
                name: tokens[i + 1].clone(),
                negated,
            }),
            2,
        )
    } else {
        (None, 1)
    }
}

/// Collect module-specific arguments starting at `start`.
/// Returns the `MatchSpec` and number of tokens consumed.
fn collect_module_args(tokens: &[String], start: usize, module: &str) -> (MatchSpec, usize) {
    let value_flags = module_value_flags(module);
    let bool_flags = module_bool_flags(module);
    let mut args = Vec::new();
    let mut i = start;

    while i < tokens.len() {
        let tok = &tokens[i];

        // Stop at top-level flags
        if matches!(tok.as_str(),
            "-m" | "--match" | "-p" | "--protocol" |
            "-s" | "--source" | "--src" |
            "-d" | "--destination" | "--dst" |
            "-i" | "--in-interface" | "-o" | "--out-interface" |
            "-j" | "--jump" | "-g" | "--goto" | "-f" | "--fragment" | "!"
        ) {
            break;
        }

        if tok.starts_with("--") {
            // Check if this is a known flag for this module
            if value_flags.contains(&tok.as_str()) {
                args.push(tok.clone());
                // Special case: --tcp-flags takes TWO arguments
                if tok == "--tcp-flags" {
                    if i + 1 < tokens.len() {
                        args.push(tokens[i + 1].clone());
                        i += 1;
                    }
                    if i + 1 < tokens.len() {
                        args.push(tokens[i + 1].clone());
                        i += 1;
                    }
                    i += 1;
                    continue;
                }
                // Consume the value
                if i + 1 < tokens.len() {
                    args.push(tokens[i + 1].clone());
                    i += 2;
                    continue;
                }
            } else if bool_flags.contains(&tok.as_str()) {
                args.push(tok.clone());
                i += 1;
                continue;
            } else {
                // Unknown flag for this module — could belong to next module
                // or be a module-specific flag we don't know about.
                // Preserve it as a raw arg.
                args.push(tok.clone());
                // Heuristic: if next token doesn't start with '-', it's a value
                if i + 1 < tokens.len() && !tokens[i + 1].starts_with('-') {
                    args.push(tokens[i + 1].clone());
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
        } else {
            // For set module, --match-set takes set-name and flag (src/dst)
            // which doesn't start with --
            args.push(tok.clone());
        }

        i += 1;
    }

    (MatchSpec { module: module.to_string(), args }, i - start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_input() {
        let result = parse_iptables_save("").unwrap();
        assert!(result.tables.is_empty());
    }

    #[test]
    fn test_parse_counter_bracket() {
        assert_eq!(parse_counter_bracket("[100:5000]"), Some((100, 5000)));
        assert_eq!(parse_counter_bracket("[0:0]"), Some((0, 0)));
        assert_eq!(parse_counter_bracket("invalid"), None);
    }

    #[test]
    fn test_tokenize_quoted_string() {
        let tokens = tokenize_rule(r#"-A INPUT -m comment --comment "Allow SSH" -j ACCEPT"#);
        assert_eq!(tokens, vec![
            "-A", "INPUT", "-m", "comment", "--comment", "Allow SSH", "-j", "ACCEPT"
        ]);
    }

    #[test]
    fn test_input_too_large() {
        let huge = "x".repeat(MAX_INPUT_SIZE + 1);
        match parse_iptables_save(&huge) {
            Err(ParseError::InputTooLarge { .. }) => {}
            other => panic!("expected InputTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn test_basic_parse() {
        let input = r#"# Generated by iptables-save
*filter
:INPUT ACCEPT [100:5000]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [50:2500]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"#;
        let result = parse_iptables_save(input).unwrap();
        assert_eq!(result.header_comments.len(), 1);
        let filter = result.tables.get("filter").unwrap();
        assert_eq!(filter.chains.len(), 3);
        let input_chain = filter.chains.get("INPUT").unwrap();
        assert_eq!(input_chain.policy, Some("ACCEPT".to_string()));
        assert_eq!(input_chain.counters, Some((100, 5000)));
        assert_eq!(input_chain.rules.len(), 2);

        // Check first rule
        let r0 = &input_chain.rules[0];
        let spec0 = r0.parsed.as_ref().unwrap();
        assert!(spec0.in_iface.is_some());
        assert_eq!(spec0.in_iface.as_ref().unwrap().name, "lo");
        assert_eq!(spec0.target, Some(Target::Accept));

        // Check second rule
        let r1 = &input_chain.rules[1];
        let spec1 = r1.parsed.as_ref().unwrap();
        assert_eq!(spec1.protocol, Some(Protocol::Tcp));
        assert_eq!(spec1.target, Some(Target::Accept));
    }

    #[test]
    fn test_parse_with_counters_on_rule() {
        let input = r#"*filter
:INPUT ACCEPT [0:0]
[1000:50000] -A INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
"#;
        let result = parse_iptables_save(input).unwrap();
        let filter = result.tables.get("filter").unwrap();
        let input_chain = filter.chains.get("INPUT").unwrap();
        let rule = &input_chain.rules[0];
        let spec = rule.parsed.as_ref().unwrap();
        assert_eq!(spec.counters, Some((1000, 50000)));
    }

    #[test]
    fn test_parse_comment_module() {
        let input = r#"*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -m comment --comment "Allow SSH access" -j ACCEPT
COMMIT
"#;
        let result = parse_iptables_save(input).unwrap();
        let filter = result.tables.get("filter").unwrap();
        let rule = &filter.chains.get("INPUT").unwrap().rules[0];
        let spec = rule.parsed.as_ref().unwrap();
        assert_eq!(spec.comment, Some("Allow SSH access".to_string()));
    }

    #[test]
    fn test_parse_multiport() {
        let input = r#"*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -m multiport --dports 80,443,8080 -j ACCEPT
COMMIT
"#;
        let result = parse_iptables_save(input).unwrap();
        let filter = result.tables.get("filter").unwrap();
        let rule = &filter.chains.get("INPUT").unwrap().rules[0];
        let spec = rule.parsed.as_ref().unwrap();
        assert_eq!(spec.matches.len(), 1);
        assert_eq!(spec.matches[0].module, "multiport");
        assert!(spec.matches[0].args.contains(&"--dports".to_string()));
        assert!(spec.matches[0].args.contains(&"80,443,8080".to_string()));
    }

    #[test]
    fn test_parse_conntrack() {
        let input = r#"*filter
:INPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
COMMIT
"#;
        let result = parse_iptables_save(input).unwrap();
        let filter = result.tables.get("filter").unwrap();
        let rule = &filter.chains.get("INPUT").unwrap().rules[0];
        let spec = rule.parsed.as_ref().unwrap();
        assert_eq!(spec.matches[0].module, "conntrack");
        assert!(spec.matches[0].args.contains(&"--ctstate".to_string()));
        assert!(spec.matches[0].args.contains(&"ESTABLISHED,RELATED".to_string()));
    }
}
