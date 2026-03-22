# Rules View

The Rules tab is the primary interface. It shows all traffic rules for the selected host or group.

## Layout

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  web-01                                                    ● Connected      │
│                                                                             │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐              ⊞ Split   ⟳ History   │
│  │  Rules  │ │ Activity │ │ Terminal │                                      │
│  └─────────┘ └──────────┘ └──────────┘                                      │
│  ───────────────────────────────────────────────────────────────────────────│
│                                                                             │
│  Incoming Traffic                                                           │
│  ┌──────────────────────────┐                                               │
│  │ All │ Allow │ Block │    │    🔍 Filter rules...            + Add Rule ▾ │
│  └──────────────────────────┘                                               │
│                                                                             │
│  ── Connection Tracking (system) ───────────────────────────── ▾ ──        │
│                                                                             │
│  ┃  BLOCK   Invalid Packets               system                           │
│  │          Drop packets with invalid connection state                      │
│  │                                                                          │
│  ┃  ALLOW   Established Connections       system                           │
│  │          Auto-included for stateful filtering                            │
│  │                                                                          │
│  ┃  ALLOW   Related Connections           system       (configurable)      │
│  │          Conntrack helpers (FTP, SIP)                                    │
│  │                                                                          │
│  ── Web Servers ───────────────────────────────────── 3 rules ── ▾ ──      │
│                                                                             │
│  ┃  ALLOW   Web Traffic (80, 443)       Anyone            web-svrs    1.2k │
│  │          TCP                                                             │
│  │                                                                          │
│  ┃  ALLOW   SSH (22)                    Office IPs        web-svrs       3 │
│  │          TCP · Allow office SSH — JIRA-1234                              │
│  │                                                                          │
│  ── Host ──────────────────────────────────────────── 1 rule ─── ▾ ──      │
│                                                                             │
│  ┃  ALLOW   Monitoring (9100)           Local Net         host          89 │
│  │          TCP                                                             │
│  │                                                                          │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
│                                                                             │
│  ┃  BLOCK   Everything Else                                            412 │
│  │          Default policy · Drop silently                                  │
│  │                                                                          │
│  ── System Rules (Docker) ─────────────── 12 rules · Read-only ── ▸ ──    │
│                                                                             │
│  3 additional rules in mangle/raw tables [view in Terminal]                 │
│                                                                             │
│  ───────────────────────────────────────────────────────────────────────────│
│                                                                             │
│  Outgoing Traffic                                              + Add Rule ▾ │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
│  All outgoing traffic is allowed.                                           │
│  ───────────────────────────────────────────────────────────────────────────│
│                                                                             │
│  NAT Rules                                                                  │
│  + Port Forwarding   + Source NAT                                           │
│                                                                             │
│ ┌───────────────────────────────────────────────────────────────────────────┐│
│ │  ●  2 pending changes  ▸ Show   ·                [Discard] [Apply ⌘S]   ││
│ └───────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## Rule Table

Rules use **table rows** (not cards) for density. Each row is **52px tall** to accommodate two-line content with Apple-level breathing room.

### Row Structure

| Element | Position | Spec |
|---------|----------|------|
| Status bar | Left edge, full height | 3px wide, rounded right corners (1.5px). Allow=#34C759, Block=#FF3B30, Log=#5856D6, FWD=#007AFF |
| Status label | 12px from bar | 11px, SF Mono weight 600, uppercase, same color as bar. Fixed 52px width |
| Rule name | 8px from label | 14px, weight 500 (host rules) or 400 (group rules). Ports in parens |
| Pending dot | 4px after name | 6px circle, #FF9500. Appears with scale 0→1.2→1.0 animation (300ms) |
| Protocol | Below name, same x | 12px, weight 400, #86868B |
| Comment | After " · " separator | 12px, weight 400, #AEAEB2. Truncated with ellipsis |
| Source/Dest | Right-aligned, 140px | 13px. "Anyone" in regular, IPs in SF Mono |
| Origin tag | Right of source, 80px | 11px pill (group names) or plain text ("host") |
| Hit count | Right-aligned, 48px | 13px, weight 400, #86868B. "1.2k" format |
| Overflow menu | Right edge, hidden | `⋯` button appears on hover/focus. Tab-focusable, opens with Enter |

### Row Separator

1px line, #F2F2F7 (light) / #38383A (dark), **inset 15px from left** (starts after status bar gap, not full-width). Apple indents list separators.

### Row States

**Hover:** background #F5F5F7, overflow menu appears, 100ms transition
**Selected:** background rgba(0,122,255,0.10), 3px blue indicator bar on left (macOS Ventura style), side panel opens
**Disabled:** 40% opacity, rule name strikethrough
**Pending change:** orange dot (6px) after name
**Added:** subtle green tint rgba(52,199,89,0.04), orange dot
**Modified:** inline diff — old value strikethrough with red tint, new value with green tint
**Deleted:** 40% opacity, strikethrough, red tint rgba(255,59,48,0.04), still visible until applied

### Inline Comments

When a rule has a comment, it appears on the second line after the protocol, separated by " · ":

```
  ┃  ALLOW   SSH (22)                    Office IPs        web-svrs       3
  │          TCP · Allow office SSH — JIRA-1234
```

Comments are always visible — makes tribal knowledge accessible without expansion.

---

## Collapsible Origin Sections

```
  ── Web Servers ───────────────────────────────── 3 rules ── ▾ ──
```

- Section header: 12px, weight 600, uppercase, #86868B
- Horizontal rules extend to fill width (macOS "titled separator" pattern)
- Rule count: right-aligned, 12px, #AEAEB2
- Disclosure indicator: ▾ expanded / ▸ collapsed, #C7C7CC
- System Rules sections default collapsed with orange-tinted "Read-only" pill

### Connection Tracking Section

Visible at the top of the rule list. Shows auto-generated conntrack rules as configurable system rules. RELATED can be independently toggled. INVALID drop appears first (security best practice).

---

## Filter Bar

```
┌──────────────────────────┐
│ All │ Allow │ Block │    │    🔍 Filter rules...
└──────────────────────────┘
```

- Standard macOS segmented control with sliding capsule (150ms ease)
- "Log" segment only appears if LOG rules exist
- Search: filters by name, port, IP, comment. Shows "3 of 7 rules" count when filtered
- **Only appears at 5+ rules** — below that, filtering adds unnecessary chrome

---

## The "Everything Else" Row

Separated from other rules by a **dashed line** (2px dash, 4px gap). Visually distinct without adding a card.

- Status bar uses subtle gradient fade
- Second line always shows: "Default policy · Drop silently" / "Default policy · Allow all" / "Default policy · Reject with response"
- Cannot be reordered (no drag handle on hover)
- Clicking opens side panel with radio buttons for the 3 policy options

---

## Clicking a Rule — Side Panel

Opens a **420px side panel** on the right. Rule list stays visible — preserving spatial context.

### Animation

- Open: slide from right, 250ms ease-out. Rule list narrows simultaneously
- Close: reverse, 200ms. Escape key or ✕ button
- Switching rules: panel content cross-fades (150ms), panel stays in place
- **Narrow screens** (main content < 600px after panel): panel becomes a bottom sheet, max 70vh, with drag handle

### View Mode

```
│  SSH                            ✕    │
│  ──────────────────────────────────  │
│                                      │
│  Action        Allow                 │
│  Service       SSH                   │
│  Port          22                    │
│  Protocol      TCP                   │
│  Source         Office IPs           │
│                 83.12.44.0/24        │
│                 10.0.0.0/8           │
│  Direction      Incoming             │
│  Interface      Any                  │
│  Comment        Allow office SSH     │
│                                      │
│  ── Details ─────────────────────── │
│  Hits           3 (last 24h)         │
│  Added          March 15, 2026       │
│  Origin         Web Servers (group)   │
│                                      │
│  ▸ Show iptables command             │ ← disclosure, not always visible
│                                      │
│   Edit     Disable     Delete        │
```

Label-value pairs: label 13px #86868B in 100px column, value 13px weight 500.

The iptables command is behind a **disclosure triangle** — most users don't need Layer 1 info in a Layer 2 context. Power users click to reveal.

### Edit Mode

Clicking "Edit" or clicking a value inline transforms that field into an input. Apple pattern: click "Office IPs" next to Source → it becomes the combobox right there. Reduces mode switches.

Full edit mode available via the Edit button:

```
│  Edit Rule                      ✕    │
│  ──────────────────────────────────  │
│                                      │
│  Action                              │
│  ┌─────────────────────────────────┐ │
│  │ Allow │ Block │ Log │ Log+Block │ │
│  └─────────────────────────────────┘ │
│                                      │
│  Service                             │
│  ┌─────────────────────────────────┐ │
│  │ SSH                           ▾ │ │
│  └─────────────────────────────────┘ │
│                                      │
│  Source                              │
│  ┌─────────────────────────────────┐ │
│  │ Office IPs                    ▾ │ │
│  └─────────────────────────────────┘ │
│                                      │
│  Comment                             │
│  ┌─────────────────────────────────┐ │
│  │ Allow office SSH access         │ │
│  └─────────────────────────────────┘ │
│                                      │
│  More options...                     │
│                                      │
│            ┌────────┐ ┌──────────┐   │
│            │ Cancel │ │   Save   │   │
│            └────────┘ └──────────┘   │
```

Labels above inputs (not beside — panel too narrow for side-by-side). Input: 32px height, 8px radius, 2px blue ring on focus.

---

## Rule Reordering

### Drag and Drop

- Grab `↕` handle (visible on hover, right side)
- Rule lifts with shadow. Blue insertion line shows drop position
- Other rules animate (100ms ease)
- The "Everything Else" row is not draggable

### Keyboard

- `Alt+↑` / `Alt+↓` to move
- Screen reader: "SSH rule moved to position 2 of 4"

### Overflow Menu

`[⋯]` button (Tab-focusable, opens with Enter) with: Edit, Disable, Override (for group rules), Move to top/bottom/position, Delete.

---

## Pending Changes Bar

```
┌───────────────────────────────────────────────────────────────────────────┐
│  ●  2 pending changes  ▸ Show changes  ·        [Discard] [Apply ⌘S]    │
└───────────────────────────────────────────────────────────────────────────┘
```

- Fixed to bottom, 52px height. Orange dot (8px) left-aligned
- "Show changes" expands to list individual changes with per-change undo. Max 200px, scrollable
- Hover on "Apply" shows inline diff tooltip above the button (200ms slide-up)
- `⌘Z` / `⌘⇧Z` for undo/redo on the staged change stack

### Per-Host Independence

Staged changes are **per-host** and persisted to IndexedDB. Switching hosts preserves changes. Sidebar shows ⊙ indicator on hosts with pending changes.

---

## Sections

### Incoming / Outgoing (always visible)

### NAT Rules (always shown as link)

Port Forwarding and Source NAT are always visible as `+ Port Forwarding` and `+ Source NAT` links. Clicking when IP forwarding is disabled:

```
  Port forwarding requires IP forwarding.
  [Enable IP forwarding]  [Cancel]
```

### System Rules

Docker, fail2ban, wg-quick, CSF — auto-collapsed, read-only, with "Read-only" pill. K8s chains are detected but never displayed (too many rules).

```
  ── System Rules (Docker) ────────── 12 rules · Read-only ── ▸ ──
```

**DOCKER-USER chain rules are editable** through the GUI — this is the Docker-recommended place for user rules that interact with container traffic.

### Mangle/Raw Notice

When non-filter rules exist:

```
  3 additional rules in mangle/raw tables [view in Terminal]
```

---

## Split View

`[⊞ Split]` button opens Activity or Terminal as a resizable bottom panel:

```
┌──────────────────────────────────────────────┐
│  Rules                                       │
│  ┃ ALLOW Web Traffic (80,443)    Anyone      │
│  ┃ ALLOW SSH (22)                Office      │
│  ┃ BLOCK Everything Else        —            │
├──────────────────────────────── drag ────────┤
│  Activity (live)                    [Close]  │
│  🔴 3s ago  45.33.12.8  → :22   SSH         │
│  🔴 5s ago  91.240.11.2 → :3389 RDP         │
└──────────────────────────────────────────────┘
```

Resizable via drag handle. `⌘\` toggles.

---

## Empty States

### No Rules

```
  No traffic rules configured.
  All traffic is currently allowed.

  [Set up suggested rules]   [Add first rule]
```

### No Outgoing Rules

```
  Outgoing Traffic
  All outgoing traffic is allowed.
  Most servers don't need outgoing restrictions.
  [Add outgoing rule]
```
