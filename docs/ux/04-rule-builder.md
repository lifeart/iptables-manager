# Rule Builder

The rule builder creates and edits rules via a **compact form** in the side panel. Results render as readable sentences in the rule table. One unified builder scales from simple to complex via progressive disclosure.

## Adding a Rule

Click `[+ Add Rule]` — a split button:
- **Main click**: Opens the rule builder in the side panel
- **Dropdown arrow (▾)**: Shows "Add from template..." option

## The Rule Builder Form

### Default View (3-4 fields)

```
│  New Rule                        ×  │
│  ──────────────────────────────── │
│                                     │
│  Action                             │
│  ┌─────────────────────────────────┐│
│  │ Allow │ Block │ Log │ Log+Block ││
│  └─────────────────────────────────┘│
│                                     │
│  Service                            │
│  ┌─────────────────────────────────┐│
│  │ choose...                     ▾ ││
│  └─────────────────────────────────┘│
│                                     │
│  Source                             │
│  ┌─────────────────────────────────┐│
│  │ Anyone                        ▾ ││
│  └─────────────────────────────────┘│
│                                     │
│  Comment                            │
│  ┌─────────────────────────────────┐│
│  │                                 ││
│  └─────────────────────────────────┘│
│                                     │
│  More options...                    │
│                                     │
│            ┌────────┐ ┌──────────┐  │
│            │ Cancel │ │ Add Rule │  │
│            └────────┘ └──────────┘  │
```

Each field is a **combobox** (type-to-filter). Tab between fields. The result renders as a sentence: "Allow Web Traffic from Anyone".

### The Action Field

Inline **segmented control** — no dropdown for 4 options:

```
  ┌─────────────────────────────────┐
  │ Allow │ Block │ Log │ Log+Block │
  └─────────────────────────────────┘
```

Standard macOS segmented control: #F2F2F7 container, white selected capsule with shadow, 150ms slide animation.

### The Service Field

Combobox with categorized options. Type to filter. Supports **non-port protocols**.

```
┌─────────────────────────────────────┐
│ 🔍 Search...                        │
│                                     │
│ Common                              │
│   Web Traffic (80, 443)     TCP     │
│   SSH (22)                  TCP     │
│   Email (25, 587, 993)      TCP     │
│   DNS (53)                  TCP/UDP │
│   Monitoring (9090, 9100)   TCP     │
│   Ping                      ICMP    │
│                                     │
│ VPN                                 │
│   WireGuard (51820)         UDP     │
│   OpenVPN (1194)            UDP     │
│   IPSec/IKE (500, 4500)    UDP     │
│   IPSec Data                ESP     │ ← non-TCP/UDP protocol
│                                     │
│ Databases                           │
│   PostgreSQL (5432)         TCP     │
│   MySQL (3306)              TCP     │
│   MongoDB (27017)           TCP     │
│   Redis (6379)              TCP     │
│                                     │
│ Custom                              │
│   Custom Service...                 │ ← renamed from "Custom Port"
│                                     │
│ Detected on this host               │
│   nginx (80, 443) — running         │
│   sshd (22) — running               │
└─────────────────────────────────────┘
```

**Key changes from earlier spec:**
- **IPSec Data (ESP)** is a separate entry from IPSec/IKE — because ESP is protocol 50, not TCP/UDP
- **"Custom Port" renamed to "Custom Service"** — because some services have no port (GRE, ESP, AH)
- Protocol column shown in dropdown for clarity
- Typing a number ("6379") jumps to Custom Service with that port pre-filled

### The Source/Destination Field

```
┌─────────────────────────────────────┐
│ 🔍 Search...                        │
│                                     │
│   Anyone                            │
│   My Current IP (83.12.44.7) *      │
│   Local Network (auto-detected)     │
│                                     │
│ IP Lists                            │
│   Office IPs                        │
│   App Servers                       │
│   Monitoring Servers                │
│                                     │
│ Managed Hosts                       │
│   web-01 (10.0.1.1)                 │
│   db-01 (10.0.2.1)                  │
│                                     │
│ Enter manually                      │
│   IP Address...                     │
│   IP Range (CIDR)...                │
│   Create new IP List...             │
└─────────────────────────────────────┘
```

\* "My Current IP" is detected from the SSH connection's source address (the remote server knows the connecting IP). Never calls an external IP detection service.

---

## More Options (Progressive Disclosure)

Clicking "More options..." reveals additional fields inline — the form extends with a 200ms height animation:

```
│  On           [Any interface ▾]     │ ← only multi-homed hosts
│  Duration     [Permanent ▾]         │
│                                     │
│  ─── Details ─────────────────────  │
│  Protocol     TCP                   │
│  Port         22                    │
│  Direction    Incoming              │
│  Interface    Any                   │
│                                     │
│  ─── Advanced ────────────────────  │
│  Conntrack    [☑ New ☑ Est ☐ Rel]   │
│  Rate Limit   [☐ Enable]           │
│    └ [___]/[source IP ▾]/[sec ▾]   │
│  Block type   [Silent drop ▾]      │
│  Log before   [☐ Enable]           │
│    └ Prefix [___] Limit [5/min]    │ ← rate limit on LOG by default
│  + Add match module                 │
│                                     │
│  ▸ Show iptables command            │ ← behind disclosure, not visible by default
```

### Interface Field

Only appears when host has multiple non-loopback interfaces. Interfaces are labeled by type:

```
  On: [eth0 — physical ▾]
       eth0 — physical (192.168.1.1)
       eth0.100 — VLAN 100
       br0 — bridge
       wg0 — WireGuard VPN (10.200.0.1)
       tun0 — OpenVPN (10.8.0.1)
       bond0 — bonded
```

VPN interfaces may not exist at rule creation time. The dropdown allows typing an interface name with a note: "This interface is not currently active. Rules will apply when it becomes available."

For bridge interfaces, a note appears: "Traffic to VMs/containers on this bridge uses Forwarded Traffic rules, not Incoming."

### Duration Field (Temporary Rules)

```
  Duration: [Permanent ▾]
             ├ Permanent (default)
             ├ 1 hour
             ├ 4 hours
             ├ 24 hours
             ├ 1 week
             └ Custom...
```

Temporary rules auto-remove via `at` daemon or cron. In the rule table, a countdown badge:

```
  ▎ALLOW  SSH (22)    203.0.113.5    host    expires in 3h 42m
```

### LOG Rate Limiting

All LOG rules include `--limit 5/min --limit-burst 10` by default. On busy servers, unthrottled LOG rules saturate the kernel log, consume CPU, and fill disk. The app uses NFLOG target where available (more efficient, sends to userspace via netlink).

The rate limit is shown in the form and adjustable.

### Rate Limiting (hashlimit)

Supports **per-source-IP** rate limiting via `-m hashlimit`, not just global limits:

```
  Rate Limit  [☑ Enable]
  Max:        [50] connections per [source IP ▾] per [second ▾]
  Burst:      [100]
```

---

## Custom Service Builder

When selecting "Custom Service..." — supports both port-based and protocol-based services:

```
│  Custom Service                     │
│  ──────────────────────────────── │
│                                     │
│  Name        [My API Server      ]  │
│                                     │
│  Protocol    [TCP ▾]                │
│               ├ TCP                 │
│               ├ UDP                 │
│               ├ ICMP                │
│               ├ ICMPv6              │
│               ├ GRE (47)            │
│               ├ ESP (50)            │ ← IPSec data
│               ├ AH (51)            │ ← IPSec auth
│               ├ SCTP (132)          │
│               └ Other (number)...   │
│                                     │
│  Port(s)     [8080, 8443         ]  │ ← disabled for GRE/ESP/AH
│                                     │
│  Tip: Commas for multiple (80,443)  │
│       Dash for ranges (8000-8100)   │
```

When protocol is GRE, ESP, or AH, the Port field is disabled with a note: "This protocol does not use ports."

### Port Validation

Validates on blur:
```
Valid:     80
Valid:     80, 443
Valid:     8000-8100
Invalid:  abc         → "Ports must be numbers (0-65535)"
Invalid:  99999       → "Port must be between 0 and 65535"
Invalid:  100-50      → "Range end must be greater than start"
```

---

## Custom Conditions

Clicking "+ Add match module" extends the form with the condition builder:

```
│  Match Conditions:                  │
│  ┌────────────────────────────────┐ │
│  │ [Source IP ▾] [is in ▾]       │ │
│  │ [10.0.0.0/8              ] [×]│ │
│  │            AND                 │ │
│  │ [Dest Port ▾] [is ▾]         │ │
│  │ [6379                    ] [×]│ │
│  │         [+ Add condition]     │ │
│  └────────────────────────────────┘ │
```

### Available Fields

| Category | Fields |
|----------|--------|
| Common | Source IP, Dest IP, Source Port, Dest Port, Protocol, Interface |
| Connection | Connection State, Connection Limit |
| Advanced | Rate Limit (hashlimit), MAC Address, String Match, Owner/User, Time of Day, Packet Mark, TCP Flags, IPSec Policy (`-m policy`) |

The **IPSec Policy** match (`-m policy --dir in --pol ipsec`) is included for policy-based VPN setups where there's no dedicated tunnel interface.

---

## NAT Rules Section

The app manages **both DNAT and SNAT/MASQUERADE** through the GUI.

### Port Forwarding (DNAT)

```
│  New Port Forward                   │
│  ──────────────────────────────── │
│                                     │
│  When traffic arrives on port       │
│  [8080    ]                         │
│  forward it to                      │
│  [10.0.1.5    ] port [80      ]     │
│                                     │
│  From:     [Anyone ▾]               │
│  Protocol: [TCP ▾]                  │
│  Name:     [Web backend         ]   │
│                                     │
│  ☐ Allow internal clients to reach  │ ← hairpin NAT
│    this via the external IP         │
│                                     │
│  [Cancel]       [Add Forward]       │
```

The **hairpin NAT checkbox** auto-generates the MASQUERADE rule on the internal interface for the return path.

### Source NAT / MASQUERADE

A "Source NAT" section appears alongside Port Forwarding:

```
  NAT Rules                                       [+ Add Rule ▾]
  ─────────────────────────────────────────────────────────────
  Port Forwarding
  ▎FWD   Port 8080 → 10.0.1.5:80              Web Backend

  Source NAT
  ▎SNAT  10.200.0.0/24 → eth0                 VPN Masquerade
```

The app detects static vs dynamic IP on the outbound interface:
- **Static IP** (datacenter): Uses SNAT with `--to-source` (better performance)
- **Dynamic IP** (DHCP/PPPoE): Uses MASQUERADE

---

## Templates

Templates add **multiple rules across multiple chains and tables** as a single action.

### VPN Server Template (WireGuard)

The VPN Server template creates a complete, functional VPN — not just the listening port:

```
│  Template: VPN Server (WireGuard)    │
│  ──────────────────────────────────  │
│                                      │
│  Detected WireGuard config:          │
│  Interface: wg0                      │
│  Subnet: 10.200.0.0/24              │
│  Physical: eth0                      │
│                                      │
│  This will add:                      │
│  ✅ Allow WireGuard (UDP 51820)      │
│     from Anyone              [INPUT] │
│  ✅ Allow SSH (22)                   │
│     from your IP             [INPUT] │
│  ✅ Forward VPN ↔ network            │
│                            [FORWARD] │
│  ✅ NAT VPN clients (MASQUERADE)     │
│                                [NAT] │
│  ✅ Enable IP forwarding             │
│                             [sysctl] │
│  🔴 Block Everything Else           │
│                              [INPUT] │
│                                      │
│  [Cancel]     [Add 5 Rules + Enable] │
```

### Available Templates

| Template | Includes |
|----------|----------|
| Web Server | HTTP/HTTPS + SSH + Ping |
| Database Server | DB port + SSH, internal only |
| Mail Server | SMTP/IMAP/POP + SSH |
| Bastion Host | SSH only, strict egress |
| Docker Host | Docker-aware (DOCKER-USER chain) |
| NAT Gateway | Forwarding + SNAT/MASQUERADE |
| VPN Server (WireGuard) | INPUT + FORWARD + NAT + sysctl |
| VPN Server (OpenVPN) | INPUT + FORWARD + NAT + sysctl |
| IPSec Gateway | IKE + ESP + FORWARD + NAT |
| Lockdown | Block all except SSH |
| Minimal | INVALID drop + Established + SSH |

---

## Quick Block (⌘⇧B)

Global shortcut for incident response:

```
┌───────────────────────────────────────────┐
│                                           │
│   Block IP Address                        │
│                                           │
│   ┌───────────────────────────────────┐   │
│   │ _                                 │   │
│   └───────────────────────────────────┘   │
│   IP address or CIDR range                │
│                                           │
│   On   ┌─────────────────────────────┐    │
│        │ All Connected Hosts       ▾ │    │
│        └─────────────────────────────┘    │
│                                           │
│        ┌────────┐  ┌──────────────┐       │
│        │ Cancel │  │  Block Now   │       │
│        └────────┘  └──────────────┘       │
│                                           │
└───────────────────────────────────────────┘
```

- Width: 380px. Compact — feels like a quick action
- **Blue primary button** (not red) — block rules can't lock you out
- "All Connected Hosts" as first dropdown option (not a separate checkbox)
- Validates: rejects 0.0.0.0/0, 127.0.0.1, management IP
- Paste detection: pasting an IP validates instantly and enables button
- Flow: ⌘⇧B → paste IP → Enter. Three keystrokes to block.
- **Repeated blocks auto-convert to ipset.** After 20+ individual block rules, the app migrates them to a single ipset-backed rule.

---

## Corner Cases

### IPv6 Safety

ICMPv6 mandatory auto-rules (non-deletable):
- **Type 2 (Packet Too Big)** — blocking causes PMTUD black holes
- **Types 133-137 (Neighbor Discovery)** — blocking breaks IPv6 connectivity

```
  ▎ALLOW  IPv6 Neighbor Discovery    Required    (system)
  ▎ALLOW  IPv6 Packet Too Big        Required    (system)
  ▎       Blocking these breaks IPv6 connectivity
```

### FTP/SIP Conntrack Helpers

When FTP or SIP is selected as a service, the app checks if the conntrack helper module is loaded:

```
  ⚠️  FTP active mode requires nf_conntrack_ftp.
  This module is not loaded on web-01.

  [Load module]  [Continue without active mode support]
```

### Duplicate Rule Detection

```
  ⚠️  A similar rule already exists:

  Existing:  Allow Web Traffic (80, 443) from Anyone
  New:       Allow Custom Port 80 from 10.0.0.0/24

  The existing rule already allows this traffic.

  [Add anyway]  [Cancel]
```
