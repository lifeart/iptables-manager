# Host Management

## The Sidebar

The sidebar is the primary navigation. It shows all managed hosts and groups.

```
┌──────────────────┐
│  Search hosts...  │
│                   │
│  All Hosts        │
│                   │
│  ● web-01    ›    │  ← filled circle = connected
│  ● web-02    ›    │
│  ▲ db-01     ›    │  ← triangle = drifted
│  ○ cache-01  ›    │  ← hollow circle = unreachable
│  ◌ api-01    ›    │  ← ring = connecting
│  ⊙ lb-01     ›    │  ← dot-in-circle = pending changes
│                   │
│  Groups           │
│  ▸ Web Servers    │
│  ▸ Databases      │
│  ▸ All Servers    │
│                   │
│  IP Lists         │
│  ▸ Office IPs     │
│  ▸ App Servers    │
│                   │
│  [+ Add Host]     │
│                   │
└──────────────────┘
```

### Status Indicators

Each status uses a **distinct shape** (not just color) for accessibility:

| Shape | Color | Meaning |
|-------|-------|---------|
| `●` filled circle | green | Connected via SSH, rules in sync |
| `▲` filled triangle | yellow | Connected, but rules have drifted from expected |
| `⊗` circle with X | red | Connection lost (was previously connected) |
| `○` hollow circle | grey | Unreachable / never connected |
| `◌` animated ring | blue | Connecting... |
| `⊙` circle with dot | blue | Changes pending (not yet applied) |

On hover/focus, a text label appears: "Connected", "Drifted", "Unreachable", etc.

### Selecting Hosts

- **Click a host** → main area shows that host's rules
- **Click a group** → main area shows the group's shared rules (template)
- **Active host/group** is highlighted in sidebar
- Switching hosts does NOT discard staged changes — they are per-host and independent

### Host Search & Command Palette

- Search field at top filters hosts by name, IP, or group
- `Cmd+K` / `Ctrl+K` opens the full command palette (search, actions, navigation)
- For 50+ hosts, search becomes the primary navigation method
- Status filter: "Show only hosts with issues"

---

## Adding a Host

### Quick Add (default)

Click `[+ Add Host]` → a single-field input:

```
┌─────────────────────────────────────────────────┐
│  Add Host                                    ×  │
│                                                 │
│  [root@192.168.1.50                        ] 🔗 │
│                                                 │
│  Parsed: user=root, host=192.168.1.50, port=22  │
│  Key: ~/.ssh/id_rsa (default)                   │
│                                                 │
│  [Edit details ▸]              [Connect]        │
└─────────────────────────────────────────────────┘
```

Paste `root@192.168.1.50` or `deploy@myserver.com:2222` and it parses automatically:
- Username (default: `root`)
- Host (IP or hostname)
- Port (default: `22`)
- SSH key (default: `~/.ssh/id_rsa`)

One field, one click. Time-to-first-connection under 10 seconds.

### Full Form (Edit details)

Clicking `[Edit details]` reveals the complete form:

```
┌─────────────────────────────────────────────────┐
│  Add Host                                    ×  │
│                                                 │
│  Name        [web-03                       ]    │
│  Host        [192.168.1.50                 ]    │
│  Port        [22                           ]    │
│                                                 │
│  Authentication                                 │
│  ◉ SSH Key        ○ Password                    │
│                                                 │
│  Key             [~/.ssh/id_rsa            ] 📁 │
│  Username        [root                     ]    │
│                                                 │
│  Groups          [Web Servers, Production  ] ▾  │
│                                                 │
│  Advanced ▸                                     │
│  Jump Host     [                           ]    │
│  Jump User     [                           ]    │
│  Jump Key      [                           ] 📁 │
│                                                 │
│  [Test Connection]                              │
│                                                 │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
│  Connection status:                             │
│  ✅ Connected (latency: 23ms)                   │
│  ✅ iptables available (iptables-nft backend)   │
│  ✅ Root/sudo access confirmed                  │
│  ℹ️ Docker detected — system rules will be      │
│     preserved                                   │
│                                                 │
│               [Cancel]    [Add Host]            │
└─────────────────────────────────────────────────┘
```

### Host Setup Detection

On first connection, the app detects:
- **iptables variant**: `iptables-legacy` vs `iptables-nft` vs native `nft`
- **External tools**: Docker, fail2ban, Kubernetes, wg-quick, CSF/cPHulk, firewalld, UFW
- **Cloud environment**: AWS/GCP/Azure via metadata endpoint or DMI data
- **Hypervisor role**: Proxmox/KVM/LXC (adjusts default view to emphasize FORWARD rules)
- **Distro type**: For rule persistence method (Debian, RHEL, Arch, Alpine)
- **Network interfaces**: Single vs multi-homed, with type labels (physical, VLAN, bridge, bond, tunnel)
- **VPN interfaces**: wg0, tun0, tap0 — labeled distinctly in interface selector
- **Running services**: Via `ss -tlnp`
- **Safety timer mechanism**: Tests for `iptables-apply`, `at`, `systemd-run`
- **Management path**: Whether SSH arrives via a VPN interface (triggers VPN rule pinning)

### Corner Cases: Adding a Host

**No iptables installed:**
```
  ⚠️ iptables not found on this host.
  Install it? [Install iptables]  [Cancel]
```

**No root/sudo access:**
```
  ⚠️ User "deploy" does not have sudo access for iptables.
  The app needs root or sudo privileges to manage firewall rules.
  [Try different user]  [Cancel]
```

**Host already managed:**
```
  ⚠️ This host (192.168.1.50) is already managed as "web-01".
  [Open web-01]  [Add anyway as separate host]
```

**SSH key with passphrase:**
```
  Key passphrase: [••••••••••]
  ☐ Remember for this session
```

**Connection timeout:**
```
  ⚠️ Connection timed out after 10 seconds.
  Check that:
  • The host is reachable from this machine
  • SSH is running on port 22
  • The firewall allows your connection
  [Retry]  [Edit settings]  [Cancel]
```

**nftables detected:**
```
  ℹ️ web-01 uses nftables (with iptables compatibility layer).

  The app will work normally using the compatibility layer.
  Detected backend: iptables-nft

  [OK]
```

**firewalld running:**
```
  ⚠️ firewalld is running on web-01.

  firewalld manages iptables rules and may override
  changes made by this app.

  Options:
  ○ Disable firewalld and manage rules directly
  ○ Cancel (use firewalld instead)

  [Apply choice]  [Cancel]
```

---

## First Connection: Service Detection & Import

When a host is first added, the app scans for running services, existing rules, and external tool chains. Service detection and rule suggestions are shown in a **single combined screen**.

### Scenario A: No existing rules (clean server)

```
┌─────────────────────────────────────────────────┐
│  web-03 — Quick Setup                           │
│                                                 │
│  This server has no firewall rules.             │
│  All traffic is currently allowed.              │
│                                                 │
│  Detected services:                             │
│  🌐  nginx          ports 80, 443               │
│  🔑  sshd           port 22                     │
│  📊  node_exporter  port 9100                   │
│                                                 │
│  Suggested rules:                               │
│  ┌───────────────────────────────────────────┐  │
│  │ ✅ Allow Web Traffic (80, 443) from Anyone│  │
│  │ ✅ Allow SSH (22) from 83.12.44.7 *       │  │
│  │ ✅ Allow Monitoring (9100) from local net │  │
│  │ ✅ Allow Ping from Anyone                 │  │
│  │ 🔴 Block Everything Else                  │  │
│  └───────────────────────────────────────────┘  │
│  * Your current IP address                      │
│                                                 │
│  [Skip — I'll configure manually]               │
│  [Customize First]          [Apply & Secure]    │
└─────────────────────────────────────────────────┘
```

On first setup with no prior rules, the safety timer auto-confirms immediately — reverting to "no rules" is safe (all traffic allowed), so the countdown adds friction without value.

**Corner case: many services detected (15+)**
Show the top 5 with an expandable "Show 10 more services..." link.

**Corner case: unknown service on unusual port**
```
  ❓  Unknown service     port 8443
  [Name this service: ____________]
```

### Scenario B: Existing rules found

```
┌─────────────────────────────────────────────────┐
│  web-03 — Existing Rules Detected               │
│                                                 │
│  This server has 12 existing firewall rules.    │
│  We imported them — no changes were made.       │
│                                                 │
│  Rule Health Check:                             │
│  ✅ 9 rules look good                           │
│  ⚠️ 2 rules may have issues:                    │
│    − Rule #4 is shadowed by Rule #2             │
│    − Rule #7 allows all traffic (very broad)    │
│  💡 1 suggestion:                                │
│    − Rules #5, #6 could be combined             │
│                                                 │
│  Preview:                                       │
│  ┌───────────────────────────────────────────┐  │
│  │ ✅ Allow Established Connections          │  │
│  │ ✅ Allow Loopback                         │  │
│  │ ✅ Allow SSH (22) from Anyone             │  │
│  │ ✅ Allow HTTP (80) from Anyone            │  │
│  │ ... 6 more rules                          │  │
│  │ 🔴 Block Everything Else                  │  │
│  └───────────────────────────────────────────┘  │
│                                                 │
│                              [Import & Manage]  │
└─────────────────────────────────────────────────┘
```

**Rules that can't be auto-labeled** show as raw iptables with an "Explain" action:
```
  │ ⚙️  -A INPUT -m string --string "X-Mal..."       │
  │     [Explain] [Label this rule: ____________]     │
```

Clicking "Explain" shows plain English: "This rule matches packets containing the string 'X-Mal...' and drops them. This is typically used for..."

### Scenario C: Docker / Kubernetes / fail2ban detected

```
┌─────────────────────────────────────────────────┐
│  System Rules Detected                          │
│                                                 │
│  🐳 Docker                                      │
│     12 rules in DOCKER, DOCKER-USER chains      │
│     These manage container networking.           │
│                                                 │
│  🛡️ fail2ban                                    │
│     3 rules in f2b-sshd chain                   │
│     Currently banning 2 IPs.                    │
│                                                 │
│  System rules are shown read-only and will      │
│  never be modified by this app. Your rules      │
│  coexist safely alongside them.                 │
│                                                 │
│  [Got it]                                       │
└─────────────────────────────────────────────────┘
```

### Post-Setup Screen

After applying initial rules:

```
┌─────────────────────────────────────────────────┐
│  ✅ Your server is secured.                     │
│                                                 │
│  Incoming:  3 services allowed, rest blocked    │
│  Outgoing:  All allowed                         │
│  SSH:       Restricted to your current IP       │
│                                                 │
│  Next steps:                                    │
│  • Set up an IP List for your team's IPs        │
│  • Add this host to a group for shared rules    │
│                                                 │
│  [Go to Rules]                                  │
└─────────────────────────────────────────────────┘
```

---

## Groups

Groups let you define shared rules applied to multiple hosts.

### Creating a Group

Right-click sidebar → "New Group", or drag hosts onto each other.

```
┌─────────────────────────────────────────────────┐
│  New Group                                   ×  │
│                                                 │
│  Name     [Web Servers                     ]    │
│                                                 │
│  Members                                        │
│  ☑ web-01                                       │
│  ☑ web-02                                       │
│  ☑ web-03                                       │
│  ☐ db-01                                        │
│  ☐ cache-01                                     │
│                                                 │
│               [Cancel]    [Create Group]        │
└─────────────────────────────────────────────────┘
```

### Group Rules vs Host Rules

When viewing a host that belongs to a group, rules show their origin:

```
  Incoming Traffic
  ┌─────────────────────────────────────────────────────────┐
  │ ALLOW  Web Traffic (80, 443)   Anyone     web-servers  │
  │ ALLOW  SSH (22)                Office     all-servers   │
  │ ── host-specific rules ────────────────────────────── │
  │ ALLOW  Redis (6379)            10.0.1.0/24    host    │
  │ BLOCK  Everything Else         —          all-servers   │
  └─────────────────────────────────────────────────────────┘
```

- Group rules show a subtle **provenance tag** (e.g., `web-servers`) in muted text
- Group-inherited rules have slightly reduced font-weight (regular 400 vs medium 500 for host-specific)
- Group rules are not directly editable from host view — click the provenance tag to jump to the group
- Host-specific rules can be added between group rules

### Group Rule Overrides

When a host needs to deviate from a group rule, users can create a **per-host override**:

Right-click a group rule → "Override for this host":

```
  │ ALLOW  SSH (22)    VPN Network    (overrides web-servers) │
```

The override replaces the group rule for this host only. If the group rule later changes, the user is notified:

```
  ⚠️ Group "Web Servers" SSH rule changed.
  web-03 has an override for this rule.

  [Keep override]  [Use new group rule]
```

### Group Priority

When a host belongs to multiple groups, group rule order is determined by the group order in the sidebar (drag to reorder). A "View effective rules" button shows the final merged, flattened ruleset.

### Group Rule Propagation

Group rule changes are **always staged, never auto-applied**. When a group rule changes, all member hosts show a banner:

```
  Group "Web Servers" rules were updated.
  [Review changes]  [Apply to this host]
```

Member hosts in the sidebar show the drifted indicator (▲).

### Corner Cases: Groups

**Host removed from group:**
```
  Removing web-03 from "Web Servers" will remove
  these rules from web-03:

  − Allow Web Traffic (80, 443) from Anyone

  The rules remain on other group members.

  [Remove from Group]  [Cancel]
```

**Conflicting rules between groups:**
```
  ⚠️  Rule conflict detected on web-01

  "Web Servers" allows ports 80, 443
  "Locked Down" blocks all incoming traffic

  The rule that appears first takes priority.
  Current order: Web Servers rules → Locked Down rules

  [Adjust group order]  [Dismiss]
```

**Empty group:**
Show: "Add hosts to this group by dragging them from the sidebar, or click [Add Members]"

---

## Offline / Disconnected Hosts

When a host goes offline, its entry dims and uses the disconnected shape (⊗) in the sidebar.

Clicking it shows the **last known state**:

```
┌─────────────────────────────────────────────────┐
│  cache-01                         ○ Unreachable │
│                                                 │
│  Last connected: 3 hours ago                    │
│  Last known rules (may have changed):           │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │ ALLOW  SSH (22)              Office Only  │  │
│  │ ALLOW  Redis (6379)          App Servers  │  │
│  │ BLOCK  Everything Else       —            │  │
│  └───────────────────────────────────────────┘  │
│                                                 │
│  You can edit rules offline. They'll be applied │
│  when the connection is restored.               │
│                                                 │
│  [Retry Connection]                             │
└─────────────────────────────────────────────────┘
```

### Corner Cases: Reconnection

**Host reconnects with different rules than expected (drift):**
```
  ⚠️  Rules on cache-01 have changed since last sync.

  Someone (or something) modified the rules directly.

  Differences:
  + New rule: Allow 3306 from Anyone     (not in your config)
  − Missing: Block Everything Else       (was in your config)

  [Use server's rules]  [Push my rules]  [Review diff]
```

**Queued changes applied on reconnect:**
```
  cache-01 reconnected.
  You have 2 pending changes from 2 hours ago.

  + Allow Monitoring (9100) from local network
  ~ Change SSH access: Anyone → Office Only

  [Apply now]  [Discard changes]  [Review]
```

**Empty ruleset after reboot:**
```
  ⚠️  web-01 has no firewall rules after reboot.

  This usually means rules weren't saved persistently.

  Last known good rules (from 2 hours ago):
  4 rules in the INPUT chain

  [Restore last known rules]  [Start fresh]
```
