# Safety & Applying Changes

Safety is the #1 UX priority. The app makes SSH lockout nearly impossible through layered defenses: packet trace simulation, auto-revert, VPN path detection, and surgical rule operations.

## Design Principle: Assume Success

Users only act when something goes **wrong**, not when it goes right.

Old: Click Apply → modal → click Apply again → countdown → click Confirm (3 actions)
New: Click Apply → changes applied → auto-confirms (1 action, interrupt on failure)

---

## The Apply Flow

### Step 1: Click "Apply Changes"

The bottom bar shows pending changes. **Hovering** "Apply" shows an inline diff tooltip above the button:

```
  ┌─────────────────────────────────────────────┐
  │ + Allow Redis (6379) from App Servers        │
  │ ~ SSH: Anyone → Office Only                  │
  │ ✅ SSH from your IP is preserved              │
  └─────────────────────────────────────────────┘
```

Clicking "Apply" applies immediately — **no confirmation modal** for the normal case.

A modal ONLY appears when SSH/VPN lockout is detected.

### Step 2: Confirmation Banner

A **top-center banner** with green progress bar:

```
                ┌───────────────────────────────────────────┐
                │                                           │
                │   Changes applied to web-01               │
                │   Confirming in 47 seconds                │
                │                                           │
                │   ████████████████████░░░░░░░░░░░░░░░░░   │
                │                                           │
                │              Revert Changes               │
                │                                           │
                └───────────────────────────────────────────┘
```

Design decisions:
- **Position**: Top-center, 20px from tab bar. Width: 400px fixed
- **Background**: #1C1C1E (dark on light — macOS notification convention). Dark mode: #3A3A3C
- **"Changes applied to web-01"** — 14px, weight 500, white. Past tense ("applied") = confidence
- **"Confirming in 47 seconds"** — 13px, weight 400, 70% white. "Confirming" implies the system is doing the work
- **Progress bar fills LEFT TO RIGHT** (green, #34C759, 4px height). This is progress, not countdown. Empty→full feels constructive. Full→empty feels destructive
- **"Revert Changes"** — text-only, 13px, 80% white. Centered below progress bar. Deliberately secondary — the primary action is to do nothing
- Countdown number transitions with subtle vertical slide (old slides up, new slides in, 200ms)
- **After 5+ successful confirmations**: banner shrinks to compact single line: "Confirming changes... 47s [Revert]" — 44px height

### Animation Sequence

1. Banner slides down: 300ms ease, slight overshoot (4px past target, settles)
2. Progress bar fills linearly over 60 seconds
3. **Success**: content cross-fades to "Changes confirmed on web-01 ✓". Green pulse. Lingers 2s, slides up
4. **Revert clicked**: instantly shows "Changes reverted on web-01 ↩". Lingers 2s, slides up
5. **Connection lost**: progress bar turns red (#FF453A), stops. Text: "Connection lost. Waiting for auto-revert..."

### Step 3a: Auto-Confirmed

When countdown completes and connection is alive:
```
  ┌──────────────────────────────────────────┐
  │  ✓  Changes confirmed on web-01          │ ← lingers 2s, slides up
  └──────────────────────────────────────────┘
```

### Step 3b: Connection Lost

Server-side auto-reverts. When connection recovers:
```
  ⚠️  Rules on web-01 were automatically reverted.
  Your changes are still staged locally.

  [Try again]  [Discard changes]
```

---

## Lockout Prevention

Before applying, the app **simulates a packet trace** for the management connection against the proposed ruleset. Checks actual rule matching, not just SSH rule existence.

### SSH Lockout

The ONLY case where a modal interrupts the apply flow:

```
┌─────────────────────────────────────────────────────────┐
│  ⛔ These changes would lock you out!                ×  │
│                                                         │
│  Packet trace: SSH from 83.12.44.7 → DROPPED by #6     │
│                                                         │
│  [Add SSH Rule for My IP]              [Cancel]         │
│                                                         │
│  I know what I'm doing [Apply anyway — dangerous]       │
└─────────────────────────────────────────────────────────┘
```

### VPN Management Path

If SSH arrives via a VPN interface (wg0, tun0), VPN rules are treated as critical:

```
  You are connected through a VPN (wg0).

  VPN-critical rules detected:
  - UDP 51820 on eth0 (WireGuard handshake)
  - FORWARD on wg0 (VPN traffic routing)
  - MASQUERADE on eth0 (VPN NAT)

  These rules are pinned and cannot be removed
  without explicit confirmation.
```

The safety timer protects VPN connectivity, not just SSH port rules.

### Default Policy Change

```
  ⚠️  Changing "Everything Else" to "Block" will drop
  all unmatched traffic.

  ✅ SSH (port 22) — you have this
  ⚠️ DNS (port 53) — missing (may break hostname resolution)
  ✅ Established connections — auto-included

  [Add missing rules]  [Apply as is]  [Cancel]
```

---

## How Rules Are Applied (Technical)

### Atomic Batch Operations

The app uses **`iptables-restore --noflush`** for atomic batch operations. This:
- Atomically replaces app-managed chain rules
- Preserves Docker/fail2ban/K8s/wg-quick chains untouched
- Eliminates the window of inconsistency from sequential -A/-D/-I

For single-rule changes, surgical `-I/-D` operations are used.

### conntrack Preservation

The conntrack table is **never flushed** during apply. This prevents:
- VPN sessions from dropping
- Established connections from breaking
- fail2ban state from being lost

### Safety Timer Mechanism

Uses the most reliable mechanism available (tested during host setup):

1. **`iptables-apply`** if available (battle-tested, purpose-built)
2. **`at` daemon** — schedules restore job
3. **`systemd-run`** — one-shot timer
4. **Background process** (last resort)

The safety revert only restores **app-managed chains**. System rules untouched.

**Backup file security**: root:root 0600 permissions, HMAC integrity check before restore. Prevents tampering attack where attacker modifies backup to inject rules on revert.

### First Setup Exception

On a host with **no prior rules**, the safety timer auto-confirms immediately. Reverting to "no rules" = all traffic allowed = not a lockout risk.

---

## Snapshot History

Every applied change creates a snapshot. Clock icon in Rules tab header opens history in side panel:

```
│  Rule History — web-01              │
│  ● Current                 active   │
│  │                                  │
│  ● Mar 21, 14:32                    │
│  │ + Redis from App Servers         │
│  │ ~ SSH: Anyone → Office           │
│  │                                  │
│  ● Mar 20, 09:15                    │
│  │ + Monitoring from Local          │
│  │                                  │
│  ● Mar 15, 16:44                    │
│    Initial setup                    │
```

Snapshots stored **both locally (IndexedDB) and on the remote host** (`/var/lib/traffic-rules/snapshots/`). Laptop dies ≠ history gone.

---

## Multi-Host Apply

### Canary Deployment (default)

```
┌─────────────────────────────────────────────────────────┐
│  Apply to "Web Servers" (3 hosts)?                   ×  │
│                                                         │
│  + Allow API (8080) from Load Balancer                  │
│                                                         │
│  ● web-01    connected                                  │
│  ● web-02    connected                                  │
│  ○ web-03    unreachable — skipped                      │
│                                                         │
│  Strategy:                                              │
│  ◉ Canary (1 first, then rest)                          │
│  ○ Rolling (one at a time, stop on failure)             │
│  ○ Parallel (all at once)                               │
│                                                         │
│                      [Cancel]  [Apply to 2 hosts]       │
└─────────────────────────────────────────────────────────┘
```

---

## Corner Cases

### App Crash During Safety Window

On relaunch, checks for pending restore jobs on remote hosts:
```
  web-01 has a pending auto-revert in ~30 seconds.
  [Confirm current rules]  [Let it revert]
```

### Multiple Browser Tabs

Detected via BroadcastChannel:
```
  Traffic Rules is open in another tab.
  [Continue anyway]  [Switch to other tab]
```

### Clock Skew

```
  ⚠️  Clock on web-01 is 15 minutes ahead.
  Using a longer 120-second safety timeout.
```

### iptables Locked

```
  ❌ iptables is locked by another process.
  [Retry in 5 seconds]  [Cancel]
```

The app uses `iptables -w` (wait for lock) to prevent conflicts with fail2ban.
