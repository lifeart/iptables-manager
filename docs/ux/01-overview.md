# UX Overview: Traffic Rules

## Philosophy

"Make the complex feel simple."

This is not an iptables GUI. It's a **traffic rules manager** that happens to use iptables under the hood. Users should never need to know what a "chain" or "table" is to secure their servers.

## Core Principles

1. **Sentence-first**: Every rule reads as English: "Allow Web Traffic from Anyone"
2. **Progressive disclosure**: 3 layers of detail, users choose their depth
3. **Smart defaults**: Detect services, suggest rules, one-click secure setup
4. **Safety by design**: Auto-revert on connection loss, lockout prevention, assume success
5. **Invisible complexity**: iptables tables, chains, match modules — all abstracted away unless the user asks
6. **Coexist, don't conquer**: System rules (Docker, fail2ban, K8s, wg-quick, CSF) are detected and left untouched
7. **Warmth over caution**: Safety features are framed as confidence ("You can't lock yourself out"), not warnings

## First Launch

On first launch (no hosts added), show a trust-building empty state:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Traffic Rules                                                    ⚙        │
├──────────────────┬──────────────────────────────────────────────────────────┤
│                  │                                                          │
│   No servers     │                                                          │
│                  │                                                          │
│                  │              ◉                                           │
│                  │         Secure your servers.                             │
│                  │                                                          │
│                  │         Every change auto-reverts                        │
│                  │         if your connection drops.                        │
│                  │         You can't lock yourself out.                     │
│                  │                                                          │
│                  │         ┌──────────────────────┐                         │
│                  │         │   Add a Host       │                         │
│                  │         └──────────────────────┘                         │
│                  │            or press ⌘N                                   │
│                  │                                                          │
└──────────────────┴──────────────────────────────────────────────────────────┘
```

Design details:
- **Shield icon** (`shield.checkmark` SF Symbol, 48pt, #007AFF) with subtle breathing animation (scale 1.0↔1.03, 3s ease-in-out)
- **"Secure your servers."** — 22px, weight 600. A statement, not a title. Period at the end. Confidence.
- Safety description in 15px, weight 400, secondary color. No box, no container, no border — text floats on background
- **"Add a Host"** — standard primary button (not "Add your first server" — that's patronizing)
- Cascade animation on first paint: icon fades in (400ms) → text (200ms later) → button (200ms later)
- The empty sidebar shows "No servers" to establish spatial model before any exist

## Abstraction Layers

```
Layer 3 (Intent):    "Allow Web Traffic from Anyone"
Layer 2 (Details):   Protocol: TCP, Ports: 80, 443, Direction: Incoming
Layer 1 (Raw):       iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
```

- Layer 3 is the default. It's what everyone sees.
- Layer 2 is revealed by "More options" in the side panel — for users who want to understand.
- Layer 1 is behind a disclosure triangle ("Show iptables command") or in the Terminal tab.

## Application Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Traffic Rules                                    ⌘K          ⚙   user ▾   │
├───────────────────┬─────────────────────────────────────────────────────────┤
│  220px sidebar    │  Main Content                 │ 420px side panel       │
│  (resizable       │  ┌────────────────────────────┤ (opens on rule click)  │
│   180-320px)      │  │ Rule table / Activity /    │                        │
│                   │  │ Terminal                    │ Detail / Edit form     │
│  HOSTS          │  │                            │                        │
│  GROUPS           │  │                            │                        │
│  IP LISTS         │  └────────────────────────────┤                        │
│                   │  ┌────────────────────────────┤                        │
│  [+ Add Host]   │  │ Split panel (optional)     │                        │
│                   │  └────────────────────────────┘                        │
└───────────────────┴─────────────────────────────────────────────────────────┘
```

### Navigation

- **Sidebar** (left, 220px): Host list + groups + IP Lists. Resizable 180-320px. Collapses to 36px icon strip on narrow screens or via `⌘0`
- **Main area** (center): Three tabs per host/group: Rules | Activity | Terminal
- **Side panel** (right, 420px): Opens on rule click for viewing/editing. Preserves rule list context. Becomes bottom sheet on narrow screens
- **Split panel** (bottom): Activity or Terminal as a bottom panel alongside Rules during troubleshooting
- **Command palette** (`⌘K`): Quick access to hosts, rules, and actions from anywhere
- **No nested menus, no dropdown navigation, no settings pages buried 3 levels deep**

## Command Palette (⌘K)

Spotlight-style overlay, centered at 20% from top. 680px wide, 12px radius, blur backdrop.

```
┌────────────────────────────────────────────────────────────────┐
│  🔍 block 45.33                                                │
├────────────────────────────────────────────────────────────────┤
│  BEST MATCH                                                    │
│   ⊘  Block 45.33.12.8 on web-01                               │
│      IP found in recent blocked log                            │
│  ALSO                                                          │
│   ⊘  Block 45.33.12.8 on all hosts                            │
│   🔍  Search rules for "45.33"                                 │
└────────────────────────────────────────────────────────────────┘
```

- Search field: 48px height, 17px text, auto-focused
- Results: 44px rows, keyboard navigable (↑/↓/Enter), first result auto-selected
- Supports: jump to host, quick actions (`block <ip>`, `allow <port>`), search rules, commands
- Shadow: 0 24px 80px rgba(0,0,0,0.25). Backdrop: blur(20px) saturate(180%)
- Opens with scale 0.95→1.0 + fade, 200ms. Closes at 150ms

## Terminology Mapping

| iptables term         | Traffic Rules term        |
|-----------------------|---------------------------|
| Chain INPUT           | Incoming Traffic          |
| Chain OUTPUT          | Outgoing Traffic          |
| Chain FORWARD         | Forwarded Traffic         |
| Target ACCEPT         | Allow                     |
| Target DROP           | Block (silent)            |
| Target REJECT         | Block (with response)     |
| Target LOG            | Log                       |
| Table filter          | (default, hidden)         |
| Table nat             | NAT Rules / Port Forwarding |
| Table mangle          | (Terminal only — count shown in Rules tab) |
| Table raw             | (Terminal only)           |
| Custom chain          | Rule Group                |
| Match module          | Condition (advanced)      |
| conntrack ESTABLISHED | (visible as system rule, configurable) |
| Default policy        | "Everything Else" rule    |
| Address group / ipset | IP List                   |
| Docker/f2b/K8s/wg-quick chains | System Rules (read-only) |
| IP protocol (ESP/GRE/AH) | Protocol in Custom Service |

## Rule Ownership Model

Rules on a host come from three sources:

1. **System Rules** (read-only): Auto-detected chains owned by Docker, fail2ban, Kubernetes, wg-quick, CSF, firewalld. Displayed in a collapsed "System Rules" section. Never modified during apply or safety revert.
2. **Group Rules** (inherited): Rules from host groups. Editable from the group view. Can be overridden per-host.
3. **Host Rules** (direct): Rules defined for this host. Fully editable.

### Connection Tracking Rules

The auto-generated conntrack rules (ESTABLISHED, RELATED, INVALID) are shown as **visible system rules** that users can configure:

```
  ── Connection Tracking (system) ────────────────── ▾ ──
  ▎BLOCK  Invalid Packets                    system
  ▎ALLOW  Established Connections             system
  ▎ALLOW  Related Connections                 system    (configurable)
```

- INVALID packets are dropped before ESTABLISHED (security best practice)
- RELATED can be toggled independently from ESTABLISHED (hardened servers may want to disable conntrack helpers)
- These appear at the top of the rule list, before user rules

### Apply Mechanism

The app **always** uses **`iptables-restore --noflush`** for atomic operations, even for single-rule changes. Atomicity is more important than saving one SSH round-trip. This preserves Docker/fail2ban/K8s chains while atomically replacing app-managed rules.

The conntrack table is **never flushed** during apply operations. This prevents VPN sessions, established connections, and fail2ban state from being disrupted.

### Non-Filter Table Awareness

When mangle or raw table rules exist (created via Terminal), the Rules tab shows a notice:

```
  3 additional rules in mangle/raw tables [view in Terminal]
```

## Target Users

1. **Developers** deploying their own servers who need basic firewall setup
2. **Junior sysadmins** who know networking basics but not iptables syntax
3. **Senior sysadmins/DevOps** who want a faster workflow than CLI + SSH
4. **Small teams** managing 5-50 servers without enterprise firewall tools

## Security Model

- **App authentication**: OS-level security for v1 (macOS Keychain prompts, OS login). App-level MFA planned for v2
- **Least privilege**: Defaults to `root` user for v1. Documented sudoers entry available for hardened setups (see architecture/01-overview.md)
- **Credential storage**: SSH keys/passwords stored in OS keychain (macOS Keychain, libsecret), never in browser storage
- **Input sanitization**: All rule parameters shell-escaped via `shell_words::join()`, never raw string interpolation
- **Safety timer integrity**: Backup files are root:root 0600 with HMAC verification before restore
- **Export encryption**: Infrastructure exports are password-protected
