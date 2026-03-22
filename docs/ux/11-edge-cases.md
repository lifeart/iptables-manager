# Edge Cases & Corner Cases

## Connection Issues

### SSH Connection Interrupted Mid-Session

```
  Connection to web-01 lost.
  Attempting to reconnect...

  [Retry now]  [Work offline]
```

Staged changes are preserved locally (IndexedDB). On reconnect, refresh rules and check for drift.

### SSH Host Key Changed

```
  ⚠️  The host key for web-01 has changed.

  This could mean:
  • The server was reinstalled
  • Someone is intercepting the connection (MITM)

  Previous fingerprint: SHA256:abc123...
  New fingerprint:      SHA256:xyz789...

  [Accept new key]  [Reject and disconnect]
```

### Slow Connection (High Latency)

```
  ⏳ web-01 is responding slowly (latency: 2300ms).
  Commands may take longer than usual.
```

### Connection Through Jump Host Fails

```
  ❌ Cannot reach web-01 through bastion.example.com.

  Jump host connected, but final hop to 10.0.1.5 failed.

  [Edit connection settings]  [Retry]
```

### Credentials Expired / Rotated

```
  ❌ Authentication failed for web-01.
  The SSH key or password may have been changed.

  [Update credentials]  [Remove host]
```

---

## System Rules (Docker / fail2ban / K8s)

### Docker Coexistence

Docker chains (`DOCKER`, `DOCKER-ISOLATION`) are:
- Auto-detected during host setup
- Displayed read-only in a collapsed "System Rules (Docker)" section
- **Never modified** during apply or safety revert

**Exception: DOCKER-USER** chain is editable through the GUI — this is Docker's recommended place for user firewall rules that interact with container traffic.

Kubernetes chains (`KUBE-*`, `cali-*`) are:
- Detected but **never displayed** (thousands of rules would overwhelm the UI)
- Completely hands-off — never modified, never shown

**Important**: Docker's `-p` flag publishes ports via DNAT in the nat table, bypassing INPUT chain entirely. The app warns users:

```
  ⚠️  Docker containers with published ports (-p) are
  accessible even when "Block Everything Else" is set.

  To restrict container access, add rules to the
  DOCKER-USER chain via the Terminal tab.

  [Learn more]  [Dismiss]
```

### fail2ban Coexistence

fail2ban chains (`f2b-*`) are:
- Auto-detected and shown in Activity tab under "Automated Bans"
- Never touched during apply or safety revert
- Dynamic bans preserved across all app operations

**Race condition protection**: Before applying changes, the app acquires iptables lock (`iptables -w`) to prevent conflicts with fail2ban adding/removing bans simultaneously.

### Kubernetes Coexistence

K8s chains (`KUBE-SERVICES`, `KUBE-SVC-*`, `KUBE-SEP-*`, `KUBE-NODEPORTS`) are:
- Completely hands-off — never displayed, never modified
- Only user-managed chains are shown and editable
- Thousands of kube-proxy rules are hidden from the rule list

---

## iptables State Issues

### iptables-legacy vs iptables-nft

Detected during host setup:

```
  ℹ️  Detected backend: iptables-nft

  The app uses the iptables compatibility layer.
  All features work normally.
```

If legacy and nft backends are mixed (broken state):
```
  ⚠️  Both iptables-legacy and iptables-nft are present.
  Rules may be split between backends.

  [Use iptables-nft (recommended)]  [Use iptables-legacy]
```

### Cloud Environment Detected

```
  ℹ️  This server is running on AWS (detected via metadata).

  AWS Security Groups may also be filtering traffic.
  iptables rules apply in addition to cloud-level firewalls.

  Note: Cloud metadata endpoint (169.254.169.254) is
  automatically protected — it cannot be blocked.

  [OK]
```

### iptables Locked by Another Process

```
  ❌ Cannot modify rules: iptables is locked.

  Another process is modifying the firewall.
  (fail2ban, Docker, or another admin session)

  [Retry in 5 seconds]  [Cancel]
```

No "Force" option — forcing the lock is too dangerous. The app uses `iptables -w` (wait for lock) to prevent conflicts with concurrent processes like fail2ban.

### wg-quick Rules Detected

```
  ℹ️  WireGuard (wg-quick) manages firewall rules via
  PostUp/PostDown scripts in /etc/wireguard/wg0.conf.

  These rules are shown read-only and will not be
  modified during apply or safety revert.

  PostUp rules detected:
  - FORWARD between wg0 and eth0
  - MASQUERADE on eth0 for 10.200.0.0/24

  [Got it]
```

### Rules Changed Externally (Drift)

```
  ⚠️  Rules on web-01 have changed since last sync.

  3 differences found:
  + New: Allow port 3306 from Anyone
  ~ Changed: SSH now allows Anyone (was Office Only)
  − Missing: Monitoring rule

  This could be from:
  • Another admin using iptables CLI
  • Automated tools (fail2ban, Docker, Ansible)
  • A server restart with different saved rules

  [Accept server's rules]  [Push my rules]  [Review each]
```

### Kernel Module Not Loaded

```
  ❌ Cannot apply rule: module "string" not available.

  [Try loading module]  [Remove this condition]  [Cancel]
```

---

## Rule Logic Issues

### Rule Shadows Another

```
  ⚠️  Rule conflict

  Rule #2: Block All Traffic from Anyone
  Rule #5: Allow SSH from Office IPs

  Rule #5 will never match.
  Suggestion: Move Rule #5 above Rule #2.

  [Move rule #5 up]  [Ignore]
```

### Contradictory Group Rules

```
  ⚠️  web-01 has conflicting group rules:

  "Web Servers":  Allow port 80 from Anyone
  "Restricted":   Block All Incoming

  Rules from "Web Servers" appear first, so port 80 IS allowed.

  [Yes, keep order]  [Adjust group priority]
```

### Rule Would Allow Everything

```
  ⚠️  This rule allows all traffic from anywhere.
  Your firewall would be ineffective.

  Did you mean a specific service?

  [Choose a service]  [Allow everything anyway]
```

---

## Platform Issues

### Linux Distribution Detection

The app detects the distro for rule persistence:
- **Debian/Ubuntu**: `iptables-persistent`, `netfilter-persistent`
- **RHEL/CentOS**: `iptables-services`, `systemctl`
- **Arch**: manual `iptables.rules` file
- **Alpine**: `iptables` with OpenRC

If detection fails:
```
  ℹ️  Could not detect how rules are saved.

  Select your system:
  ○ Debian / Ubuntu
  ○ RHEL / CentOS / Fedora
  ○ Arch Linux
  ○ Alpine Linux
  ○ Other (manual iptables-save/restore)
```

### SELinux Blocking SSH

```
  ❌ Connection failed: Permission denied.

  SELinux may be blocking SSH on non-standard port.

  [Edit port]  [Retry]  [Cancel]
```

---

## State Persistence

### Staged Changes Survive App Close

Staged changes are persisted to IndexedDB immediately on every edit. On reopen:

```
  You have 3 unsaved changes from 2 hours ago.

  [Resume editing]  [Discard]
```

Changes older than 24 hours prompt more aggressively to discard.

### Multiple Browser Tabs

Detected via BroadcastChannel:

```
  Traffic Rules is open in another tab.
  Changes made here may conflict.

  [Continue anyway]  [Switch to other tab]
```

### Corrupted Local Data

```
  ⚠️  Some local data appears corrupted.
  Host configurations will be refreshed from servers.

  [Refresh from servers]
```

---

## Scale Issues

### Host with 500+ Rules

Mostly Docker/K8s auto-generated:
- System chains are auto-collapsed in "System Rules" section
- Toggle: "Show 23 user rules" vs "Show all 512 rules"
- User rules always shown first
- Virtual scrolling for 100+ visible rules

### 100+ Managed Hosts

- Search becomes primary navigation (`Cmd+K`)
- Groups collapse in sidebar
- Recently accessed hosts at top
- Filter: "Show only hosts with issues"

### Slow Server

```
  Loading rules from web-01...
  ████████░░░░░░░░ 50%
```

Cache results. Show "Last refreshed: 30s ago" with manual refresh.
