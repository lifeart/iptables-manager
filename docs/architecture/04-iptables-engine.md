# iptables Abstraction Engine

## Parser

Line-oriented state machine + `winnow` (successor to `nom`) for rule argument parsing. Better error messages than `nom`.

```rust
pub fn parse_iptables_save(input: &str) -> Result<ParsedRuleset, ParseError>;
```

### Lossless Round-Trip

- `ParsedRule.raw`: original line (authoritative for unmodified rules)
- `ParsedRule.parsed`: structured RuleSpec (for display, editing, diffing)
- Unmodified rules emit `raw`. Modified rules regenerate from `parsed`, discard `raw`
- Unrecognized match modules preserved in `customMatches` with raw argument strings
- **Never panic on malformed input** — unparseable rules become `RawRule` variant with warning

### Format Variations Handled

- Counter format: `[packets:bytes]` present or absent
- `iptables-nft` vs `iptables-legacy` output differences
- `--ctstate` vs `--state` (older iptables)
- Empty chains included or omitted
- Table ordering variations

### Performance

500 rules: <1ms. 50,000 rules (K8s node): <100ms. Not a concern.

Resource limit: reject `iptables-save` output > 10MB.

## System Rule Detection

```rust
fn detect_chain_owner(chain_name: &str, rules: &[ParsedRule]) -> ChainOwner {
    match chain_name {
        "DOCKER" | "DOCKER-USER" | "DOCKER-ISOLATION-STAGE-1" | "DOCKER-ISOLATION-STAGE-2" => System(Docker),
        s if s.starts_with("DOCKER") => System(Docker),
        s if s.starts_with("f2b-") => System(Fail2ban),
        s if s.starts_with("KUBE-") || s.starts_with("cali-") => System(Kubernetes),
        s if s.starts_with("acl_") || s == "LOCALINPUT" || s == "LOCALOUTPUT" => System(CSF),
        s if s.starts_with("TR-") => App,
        _ => {
            // Content-based detection for wg-quick:
            // FORWARD rules referencing wg* interfaces + MASQUERADE = wg-quick
            if has_wg_interface_rules(rules) { System(WgQuick) }
            else { Unknown }
        }
    }
}
```

## Generator

### Restore File Format (CRITICAL)

The generator MUST emit `:TR-CHAIN - [0:0]` lines to **flush and reset** app-managed chains. Without this, every `--noflush` apply concatenates rules.

```
*filter
:TR-CONNTRACK - [0:0]
:TR-INPUT - [0:0]
:TR-OUTPUT - [0:0]
:TR-FORWARD - [0:0]
-A TR-CONNTRACK -m conntrack --ctstate INVALID -j DROP
-A TR-CONNTRACK -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A TR-INPUT -i lo -j ACCEPT
-A TR-INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
-A TR-INPUT -p tcp --dport 22 -s 83.12.44.0/24 -m comment --comment "Allow office SSH" -j ACCEPT
-A TR-INPUT -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "TR-BLOCKED: "
COMMIT
```

**Note**: No built-in chain policies in the restore file. `--noflush` preserves existing policies. Policies are managed via separate `iptables -P` commands.

### Jump Rule Management

Jump rules in built-in chains (`-j TR-CONNTRACK`, `-j TR-INPUT`) are managed separately from the restore file:

```rust
async fn ensure_jump_rules(session: &Session) -> Result<()> {
    // Check if jump rules already exist (idempotent)
    let existing = exec(session, "sudo iptables -w 5 -S INPUT").await?;

    if !existing.contains("-j TR-CONNTRACK") {
        exec(session, "sudo iptables -w 5 -I INPUT 1 -j TR-CONNTRACK").await?;
    }
    if !existing.contains("-j TR-INPUT") {
        // Insert after TR-CONNTRACK (position 2)
        exec(session, "sudo iptables -w 5 -I INPUT 2 -j TR-INPUT").await?;
    }
    // Same for OUTPUT, FORWARD as needed
}
```

Position matters: TR-CONNTRACK at position 1 (INVALID/ESTABLISHED checked first), TR-INPUT at position 2.

### `-w` Flag

**Every iptables command includes `-w 5`** (wait up to 5 seconds for xtables lock). fail2ban and Docker constantly contend for the lock.

### Raw Table for Conntrack Helpers

When a rule references FTP/SIP/etc., the generator also creates raw table rules:

```
*raw
:TR-CT-HELPERS - [0:0]
-A TR-CT-HELPERS -p tcp --dport 21 -j CT --helper ftp
COMMIT
```

On modern kernels (4.7+), `nf_conntrack_helper=0` by default. Without explicit CT target, RELATED state matching doesn't work for these protocols.

### Counter Preservation

Use `--counters` flag with `iptables-restore` to preserve packet/byte counters across applies:

```rust
cmd.arg("--counters");  // preserve hit counters
cmd.arg("--noflush");   // preserve system chains
```

Without `--counters`, counters reset to zero on every apply, breaking Activity tab rates.

## Diff Computation

```rust
fn compute_diff(current: &ParsedRuleset, desired: &[Rule]) -> RulesetDiff {
    // Only compares app-managed chains (TR-*)
    // Returns structured diff for UI display
}
```

## Packet Tracer

Simulates packet flow client-side against the last-fetched ruleset.

```rust
pub fn trace_packet(ruleset: &ParsedRuleset, packet: &TestPacket) -> TraceResult;

struct TestPacket {
    source_ip: IpAddr,
    dest_ip: IpAddr,
    protocol: Protocol,
    dest_port: Option<u16>,
    interface_in: String,
    direction: Direction,
    conntrack_state: ConntrackState,
}
```

### Unsimulatable Modules

The tracer flags these as "cannot simulate" rather than silently ignoring:
- `-m recent` (requires state)
- `-m hashlimit` (requires per-IP counters)
- `-m connlimit` (requires live conntrack)
- `-m time` (requires server clock)
- `-m owner` (requires process context)
- `-m string` (requires packet payload)
- `-m statistic` (nondeterministic)

### Jump/Return Traversal

Handles `-j TR-INPUT` (jump to chain) and implicit RETURN at end of chain. Tracks chain depth to prevent infinite loops.

## Apply Algorithm

```
apply(hostId, changes[]):
  1. ACQUIRE per-host apply lock (Mutex — prevents concurrent applies)

  2. CHECK disk space on remote: df /var/lib/traffic-rules/

  3. FETCH current: sudo iptables-save -w 5
     Parse, verify size < 10MB

  4. COMPUTE effective desired ruleset
     Generate restore file with :TR-CHAIN reset lines

  5. SAFETY CHECK: trace management connection
     - Get mgmt IP from SSH session
     - Trace: (mgmt_ip, *, tcp, ssh_port, incoming, new)
     - If mgmt is VPN: also trace VPN port on physical interface
     - If DROPPED: return LockoutDetected error

  6. PERSIST safety timer state to IndexedDB (survives force-quit)

  7. CREATE BACKUP (filtered to TR- chains + jump rules only):
     - Generate filtered iptables-save output
     - Write to /var/lib/traffic-rules/backup.v4 (root:root 0600)
     - Write HMAC to /var/lib/traffic-rules/backup.v4.hmac

  8. SCHEDULE REVERT (fallback chain):
     a. iptables-apply (if available)
     b. at + verify atd is running (systemctl is-active atd || pgrep atd)
     c. systemd-run --on-active=60s
     d. nohup background process (last resort)

     Revert script reads HMAC secret from /var/lib/traffic-rules/.hmac_secret
     (never passed as CLI argument — not visible in ps)

  9. APPLY (always atomic):
     a. Create/update ipsets FIRST (ipset swap for atomic updates)
     b. Ensure jump rules exist (idempotent check)
     c. iptables-restore --noflush --counters -w 5 < restore_file
     d. If IPv6 enabled: ip6tables-restore --noflush --counters -w 5 < restore_v6_file
     e. Never flush conntrack

  10. EMIT safety:tick events to frontend

  11. VERIFY: re-fetch iptables-save, confirm TR- chains match desired

  12. WAIT for confirm/timeout:
      - Connection alive at 60s: cancel revert, confirm
      - "Revert" clicked: trigger revert, cancel timer
      - Connection lost: remote timer fires automatically

  13. POST-CONFIRM:
      - Create snapshot (local IndexedDB + remote /var/lib/traffic-rules/snapshots/)
      - Update lastSyncedRuleHash
      - Save persistently (distro-specific: iptables-persistent, iptables-services, etc.)
      - Clear safety timer from IndexedDB
      - RELEASE apply lock
```

### IPv6 Dual-Stack Apply

When IPv6 is enabled:
- Steps 7-9 run for BOTH v4 and v6
- Safety timer covers both: single 60s window
- Backup includes both `.v4` and `.v6` files
- Revert script restores both
- If v4 succeeds but v6 fails: revert BOTH (treat as atomic pair)
- Rules with `addressFamily: 'v4'` only go in v4 restore. `'v6'` only in v6. `'both'` in both

### Revert Script

Deployed to `/var/lib/traffic-rules/revert.sh` during host provisioning:

```bash
#!/bin/bash
set -e
BACKUP_V4="/var/lib/traffic-rules/backup.v4"
BACKUP_V6="/var/lib/traffic-rules/backup.v6"
HMAC_FILE="${BACKUP_V4}.hmac"
SECRET_FILE="/var/lib/traffic-rules/.hmac_secret"

# Verify HMAC
if [ -f "$HMAC_FILE" ] && [ -f "$SECRET_FILE" ]; then
    SECRET=$(cat "$SECRET_FILE")
    EXPECTED=$(cat "$HMAC_FILE")
    ACTUAL=$(openssl dgst -sha256 -hmac "$SECRET" "$BACKUP_V4" | awk '{print $NF}')
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "HMAC verification failed" >&2
        exit 1
    fi
fi

# Restore (filtered backup — only TR- chains, safe with --noflush)
if [ -f "$BACKUP_V4" ]; then
    /usr/sbin/iptables-restore -w 5 --noflush --counters < "$BACKUP_V4"
fi
if [ -f "$BACKUP_V6" ]; then
    /usr/sbin/ip6tables-restore -w 5 --noflush --counters < "$BACKUP_V6"
fi

# Cleanup
rm -f "$BACKUP_V4" "$BACKUP_V6" "$HMAC_FILE"
```

### ipset Atomic Swap

For updating IP Lists with many entries:

```rust
async fn update_ipset(session: &Session, name: &str, entries: &[String]) -> Result<()> {
    let tmp_name = format!("{}-tmp", name);
    // Create temp set
    exec(session, &format!("sudo ipset create {} hash:net", tmp_name)).await?;
    // Bulk add via stdin (restore format)
    let restore_data = entries.iter()
        .map(|e| format!("add {} {}", tmp_name, e))
        .collect::<Vec<_>>()
        .join("\n");
    pipe_stdin(session, "sudo", &["ipset", "restore"], restore_data.as_bytes()).await?;
    // Atomic swap
    exec(session, &format!("sudo ipset swap {} {}", name, tmp_name)).await?;
    exec(session, &format!("sudo ipset destroy {}", tmp_name)).await?;
    Ok(())
}
```

## Export

```rust
pub fn export_shell_script(rules: &[Rule]) -> String;
pub fn export_ansible_playbook(rules: &[Rule], host: &Host) -> String;
pub fn export_iptables_save(rules: &[Rule]) -> String;
```

### Rule Explanation

```rust
pub fn explain_rule(rule: &ParsedRule) -> String {
    // "This rule allows TCP traffic on port 22 from the 83.12.44.0/24 network.
    //  This is typically SSH access restricted to an office IP range."
    // Uses service-templates.json for service name recognition
}
```
