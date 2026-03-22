# Activity View

The Activity tab shows live traffic, rule hit information, and automated bans. A simplified network monitor — like Little Snitch for remote servers.

Can be opened as a **split panel** alongside Rules for simultaneous viewing during troubleshooting.

## Layout

```
┌─────────────────────────────────────────────────────────┐
│  web-01                                    ● Connected  │
│                                                         │
│  [ Rules ]  [ Activity ]  [ Terminal ]                  │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Rule Hits (live)                  [⏸️ Pause] [↻ Refresh]│
│  ─────────────────────────────────────────────────────  │
│  Rule                          Hits    Rate   Last Hit  │
│  ▎ALLOW Web Traffic (80,443)  1,247   ~4/s   just now  │
│  ▎ALLOW SSH (22)                  3          2 min ago  │
│  ▎ALLOW Monitoring (9100)        89   ~1/s   just now  │
│  ▎BLOCK Everything Else         412   ~2/s   just now  │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Recent Blocked                           [Show all ▸]  │
│  ─────────────────────────────────────────────────────  │
│  🔴  3s ago   45.33.12.8    → :22    SSH    [Block IP] │
│  🔴  5s ago   91.240.11.2   → :3389  RDP   [Block IP] │
│  🔴  12s ago  185.7.33.100  → :445   SMB   [Block IP] │
│  🔴  15s ago  45.33.12.8    → :22    SSH               │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Automated Bans (fail2ban)                [Show all ▸]  │
│  ─────────────────────────────────────────────────────  │
│  🛡️  45.33.12.8     banned 2h ago   f2b-sshd           │
│  🛡️  91.240.11.2    banned 45m ago  f2b-sshd           │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Connection Tracking                                    │
│  ─────────────────────────────────────────────────────  │
│  Active connections: 1,247 / 65,536 (1.9%)             │
│  ─────────────────────────────────────────────────────  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Rule Hits

Sorted by **hit count descending** (most active first) — not by rule order. In the Activity context, the question is "what is happening?" not "what is the rule order?"

Each row uses the same 52px height with 3px status bar. Columns: Status | Name | Hits (weight 600 — primary data here) | Sparkline | Rate | Last Hit.

### Sparkline Mini-Charts

Each rule with a rate >0 shows a **sparkline** (16px tall, 80px wide) — a tiny area chart of the last 5 minutes. Adds temporal context without a separate chart view (Activity Monitor pattern).

### What Hit Counters Tell You

- **High hits on "Everything Else" (Block)** → lots of unwanted traffic
- **Zero hits on a rule** → might be unnecessary or no traffic
- **Unexpected hits** → possible misconfiguration

### Hit Counter Details (click a rule)

Opens in the side panel:

```
│  Web Traffic (80, 443)              │
│  ─────────────────────────────────  │
│                                     │
│  Total hits:  1,247 packets (2.3MB) │
│  Last hit:    just now              │
│  Rate:        ~4 packets/sec        │
│                                     │
│  Since: Mar 15, 2026                │
│  (counters reset on rule change     │
│   or reboot)                        │
```

---

## Recent Blocked Log

Shows blocked connection attempts with inline [Block IP] quick actions.

### Expanded Entry (click)

```
│  Blocked — 3 seconds ago            │
│  ─────────────────────────────────  │
│                                     │
│  Source:    45.33.12.8              │
│  Dest:     port 22 (SSH)           │
│  Protocol: TCP (SYN)               │
│  Rule:     "Everything Else"       │
│                                     │
│  This IP: 14 attempts last hour    │
│                                     │
│  [Block this IP]  [Ignore]          │
```

### Quick Block from Activity

[Block IP] button **only appears on the first occurrence** of each unique source IP (not on subsequent hits from the same IP). Reduces visual noise.

Clicking creates a rule instantly:
```
  Block  All Traffic  from  45.33.12.8
```
Block rules use a reduced 10-second safety timer (they can't lock you out).

After 20+ individual block rules, the app automatically migrates them to a single ipset-backed rule for performance.

### Repeated Offender Alert

```
  ⚠️  45.33.12.8 has been blocked 847 times today.
  [Add permanent block rule]  [Dismiss]
```

### High Traffic Aggregation

When block rate is high, aggregate by port/IP:

```
  Recent Blocked — 412 in last 5 minutes
  ─────────────────────────────────────
  Top blocked ports:
  :22 (SSH)    — 234 attempts, 18 IPs
  :3389 (RDP)  — 89 attempts, 12 IPs
  :445 (SMB)   — 67 attempts, 8 IPs

  Top sources:
  45.33.12.8   — 147 attempts       [Block]
  91.240.11.2  — 89 attempts        [Block]
```

---

## Automated Bans (fail2ban)

When fail2ban is detected, its chains are shown. **Hidden entirely** when not detected (absence is sufficient — no "fail2ban not found" message).

```
  Automated Bans                          fail2ban · 1 jail · 2 bans
  ─────────────────────────────────────────────────
  🛡  45.33.12.8     banned 2h ago   f2b-sshd
  🛡  91.240.11.2    banned 45m ago  f2b-sshd
```

- Section header includes metadata: jail count + ban count
- Shield icon (SF Symbol `shield.fill`, not emoji) per entry
- 40px row height. Read-only — managed by fail2ban, not this app

---

## Connection Tracking

Compact bar showing `nf_conntrack` usage:

```
  Connections                               1,247 / 65,536 (1.9%)
  ███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
```

Bar: 4px height. Fill color: #34C759 (<50%), #FF9500 (50-75%), #FF3B30 (>75%).

When count exceeds 75%:
```
  ⚠️  Connection tracking table is 78% full (1,247 / 65,536).
  Current nf_conntrack_max: 65,536
  Recommended for this server: 262,144 (based on 1GB RAM)

  [Increase to recommended]  [View connections]  [Dismiss]
```

[View connections] shows a filterable table of active connections with protocol, source, destination, state, and timeout.

Clicking [View connections] shows a filtered table of active connections:

```
  Active Connections                    🔍 Filter...
  ─────────────────────────────────────────────────
  TCP  10.0.1.5:443    83.12.44.7:52341  ESTABLISHED  42s
  TCP  10.0.1.5:443    91.2.33.8:48822   ESTABLISHED  18s
  TCP  10.0.1.5:22     83.12.44.7:51002  ESTABLISHED  5m
  UDP  10.0.1.5:53     8.8.8.8:53        ASSURED      2s
```

---

## Corner Cases

### No LOG Rules

```
  Recent Blocked
  ─────────────────────────────────────────────
  Detailed blocking log is not available.
  Your "Everything Else" rule uses silent drop.

  To see blocked connections:
  [Enable logging on block rules]

  Note: Logging adds slight overhead.
```

### Activity When Host is Offline

```
  Activity data is not available.
  web-01 is currently unreachable.

  Last snapshot from 3 hours ago:
  ▎ALLOW Web Traffic: 12,847 total hits
  ▎ALLOW SSH: 45 total hits
  ▎BLOCK Blocked: 3,412 total hits
```

---

## Refresh Behavior

- Hit counters refresh every 30 seconds
- "Last updated: 5s ago" indicator
- Manual refresh button
- Blocked log streams in real-time (tail of kernel log)
- Pause button stops auto-refresh
- Connection tracking refreshes every 60 seconds
