# Visual Design Guidelines

Clean, spacious, purposeful. A **data-dense professional tool** that feels like a macOS system app.

## Design Principles

1. **Density with breathing room** — 52px table rows, 15px inset separators, generous padding in panels
2. **Typography carries hierarchy** — size and weight differentiate, not decoration
3. **Color for status only** — muted palette, strong status colors, shapes for accessibility
4. **Progressive revelation** — filter bar at 5+ rules, iptables behind disclosure, details on demand
5. **Motion with purpose** — 150-300ms transitions, cascade animations on setup, no flourishes
6. **Warmth over caution** — green progress bars, confidence statements, not warning language

## Color Palette

### Light Theme

```
Background:        #FFFFFF
Surface:           #F5F5F7
Sidebar:           #F0F0F2 (or semi-transparent with backdrop-blur for vibrancy)
Border:            #E5E5E7
Separator (rules): #F2F2F7 (inset 15px from left)
Text primary:      #1D1D1F
Text secondary:    #86868B
Text tertiary:     #AEAEB2

Status colors:
  Allow/Success:   #34C759
  Block/Error:     #FF3B30
  Warning:         #FF9500
  Info/Pending:    #007AFF
  Disabled:        #C7C7CC
  Log:             #5856D6

Diff highlights:
  Added:           rgba(52, 199, 89, 0.04) background, rgba(52, 199, 89, 0.08) on fields
  Removed:         rgba(255, 59, 48, 0.04) background, rgba(255, 59, 48, 0.08) on fields
```

### Dark Theme

```
Background:        #000000 (true black — OLED, matches macOS Sonoma)
Surface:           #1C1C1E
Sidebar:           #1C1C1E (or rgba(28,28,30,0.85) with backdrop-filter for vibrancy)
Elevated:          #2C2C2E (side panel, modals)
Super-elevated:    #3A3A3C (popovers, command palette)
Border:            #38383A
Separator (rules): #38383A (subtle — avoid spreadsheet effect)
Text primary:      #FFFFFF
Text secondary:    #98989D
Text tertiary:     #636366

Status colors (adjusted for dark):
  Allow/Success:   #30D158
  Block/Error:     #FF453A
  Warning:         #FF9F0A (warm orange, NOT #FFD60A yellow — maintain hue consistency)
  Info/Pending:    #0A84FF
  Disabled:        #48484A
  Log:             #5E5CE6

Diff highlights:
  Added:           rgba(50, 215, 75, 0.2)
  Removed:         rgba(255, 69, 58, 0.2)
```

**Important**: Dark warning is #FF9F0A, not yellow. Yellow reads as "highlight" not "caution." Keep orange hue consistent between modes.

## Typography

```
Font family:       -apple-system, BlinkMacSystemFont, "SF Pro",
                   "Segoe UI", system-ui, sans-serif

Sizes:
  Page title:      22px, weight 600 (reduced from 24px — Apple uses this for statement text)
  Section header:  12px, weight 600, uppercase, letter-spacing 1px (macOS titled separator)
  Rule name:       14px, weight 500 (host rules) / 400 (group rules)
  Rule protocol:   12px, weight 400, secondary color
  Rule comment:    12px, weight 400, tertiary color (after " · " separator)
  Status label:    11px, SF Mono weight 600, uppercase, letter-spacing 0.5px
  Caption/meta:    11px, weight 400, secondary color
  Filter count:    12px, weight 400, secondary ("3 of 7 rules")

Monospace (IPs/ports/code):
  "SF Mono", "Menlo", "Consolas", monospace
  12-13px, weight 400
  Use #98989D in dark mode — no syntax highlighting in tables (visual noise)
```

## Rule Table Styling

**Row height: 52px** (not 44px). Accommodates two-line content (name + protocol/comment) with breathing room. 44px is iOS tap minimum; 52px is macOS list view with dates (Finder pattern).

```
  Status bar:       3px wide, full height, rounded right corners (1.5px)
  Separator:        1px, inset 15px from left (Apple sidebar separator pattern)
  Hover:            #F5F5F7 (light) / #1C1C1E (dark), 100ms
  Selected:         rgba(0,122,255,0.10) (light) / rgba(10,132,255,0.20) (dark)
                    + 3px blue indicator bar on left (macOS Ventura selection)
  Rule row content: starts at 12px from status bar
```

### Status Label Column

Fixed 52px width, monospace:
```
  ALLOW   11px, SF Mono 600, #34C759
  BLOCK   11px, SF Mono 600, #FF3B30
  LOG     11px, SF Mono 600, #5856D6
  FWD     11px, SF Mono 600, #007AFF
  SNAT    11px, SF Mono 600, #007AFF
```

### Pending Change: Orange Dot

6px diameter, #FF9500, 4px after rule name. Appears with overshoot: scale 0→1.2→1.0, 300ms.

Apply button badge: `● 3 pending` in orange pill, same as iOS notification badge.

### Origin Tag

Group names: 11px pill — 1px border #E5E5EA, 4px radius, 2px 6px padding, text #8E8E93
"host": plain text, no pill (default state should be quiet)

Group-inherited rules: font-weight 400. Host-specific: 500.

### "Everything Else" Row

Separated by **dashed line** (2px dash, 4px gap, #E5E5E7). Status bar gradient fade. Cannot be dragged.

## Sidebar

**Width**: 220px default, resizable 180-320px (1px drag handle → 3px blue on drag). Collapses to 36px icon strip via `⌘0` or at <900px window.

### Status Indicators (SVG, not Unicode)

8px diameter. Each status has a **distinct shape**:

```
● Connected:     filled circle, #34C759
▲ Drifted:       filled equilateral triangle, #FF9500
⊗ Disconnected:  circle with X stroke, #FF3B30
○ Unreachable:   hollow circle, 1.5px stroke, #C7C7CC
◌ Connecting:    circle with 1.5px stroke, 90° arc rotating 1 rev/sec, #007AFF
⊙ Pending:       filled circle with concentric circle, #007AFF
```

Text label on hover/focus: "Connected", "Drifted", etc.

### Host Row

32px height. Status indicator (8px, 8px from left) → hostname (13px, 400, 8px gap) → chevron (on hover only, #C7C7CC).

Selected: rgba(0,122,255,0.15) bg + 3px blue left indicator bar.

### Section Headers

"HOSTS", "GROUPS", "IP LISTS" — 11px, weight 600, uppercase, letter-spacing 1px, #86868B. 20px top, 8px bottom, 12px left padding. Auto-collapsible at thresholds (50+ servers, 10+ groups).

### Scaling

| Hosts | Behavior |
|-------|----------|
| 1-10 | All visible, generous spacing |
| 11-30 | Groups primary, hosts collapsed within. "Ungrouped" section for loose hosts |
| 31-100 | Search primary. "RECENT" section (last 3). Status filter pill: "3 issues" |
| 100+ | Only: search, RECENT (5), GROUPS, "All Servers (147)" row → full-screen table. ⌘K as primary navigation |

## Component Styling

### Side Panel

```
Width:           420px
Background:      #FFFFFF / #2C2C2E (elevated in dark)
Border-left:     1px #E5E5E7
Animation:       Slide right, 250ms ease-out. Rule list narrows simultaneously
Narrow fallback: Bottom sheet at 70vh when (mainWidth - 420) < 400
Close:           ✕ button (12px, #86868B, 32px hit target) or Escape
```

### Safety Timer Banner

```
Position:        Top-center, 20px from tab bar
Width:           400px fixed
Background:      #1C1C1E (light mode) / #3A3A3C (dark mode)
Radius:          12px
Shadow:          0 8px 32px rgba(0,0,0,0.25). Dark mode: rgba(0,0,0,0.5)
Progress bar:    4px height, green (#34C759/#30D158), fills LEFT TO RIGHT
Text:            14px/13px white, "Confirming in 47 seconds"
Button:          "Revert Changes" — text-only, 80% white, centered below bar
Animation:       Slides down 300ms with slight overshoot
Compact mode:    After 5+ uses: single-line 44px: "Confirming... 47s [Revert]"
```

### Command Palette

```
Position:        Centered, 20% from top
Width:           680px max
Background:      #FFFFFF / #2C2C2E
Radius:          12px
Shadow:          0 24px 80px rgba(0,0,0,0.25)
Backdrop:        rgba(0,0,0,0.3), blur(20px) saturate(180%)
Search:          48px height, 17px text, auto-focused
Results:         44px rows, keyboard nav, first auto-selected
Animation:       Scale 0.95→1.0 + fade, 200ms
```

### Quick Block Dialog

```
Width:           380px
Position:        Centered, standard macOS sheet
Background:      Vibrancy material / standard panel
Button:          Blue primary (not red — blocks can't lock you out)
```

### Buttons

```
Primary:         #007AFF/#0A84FF bg, white text, 6px radius, 28px height
Secondary:       transparent, #007AFF text, 1px border
Destructive:     transparent, #FF3B30 text
Split button:    Primary left + dropdown arrow right, 1px separator
Disabled:        #F5F5F7 bg, #C7C7CC text
```

### Segmented Control

```
Container:       #F2F2F7/#1C1C1E bg, 8px radius, 2px padding
Selected:        white/#3A3A3C capsule, shadow 0 1px 3px rgba(0,0,0,0.08), 6px radius
Transition:      150ms slide
```

### Combobox Popover

```
Anchor:          Below trigger field
Width:           320px (narrower than panel to prevent overflow)
Radius:          8px
Shadow:          0 8px 24px rgba(0,0,0,0.15)
Search:          Sticky top, 13px
Categories:      12px uppercase, #86868B
Animation:       Fade + scale 0.97→1.0, 200ms ease
```

## Spacing System

8px grid:
```
4px   — tight (icon-to-label, pill padding)
8px   — compact (between related items)
12px  — default (inside components)
16px  — comfortable (between components)
20px  — section header top margin
24px  — spacious (sections, panel padding)
32px  — generous (page margins)
```

## Animations

| Element | Animation | Duration |
|---------|-----------|----------|
| Rule added | Fade in + slide down | 200ms ease-out |
| Rule deleted | Slide left + fade out | 200ms ease-in |
| Rule reordered | Lift with shadow, settle | 100ms ease |
| Tab switch | Content cross-fade | 150ms |
| Side panel open | Slide from right | 250ms ease-out |
| Side panel switch rule | Content cross-fade (panel stays) | 150ms |
| Safety banner | Slide down with overshoot | 300ms ease |
| Pending dot appear | Scale 0→1.2→1.0 | 300ms |
| First launch cascade | Icon→text→button | 400+200+200ms |
| Setup rules stagger | Each rule fades in | 100ms per rule |
| Packet tracer | Sequential chain reveal + traveling dot | ~2-3s total |
| Command palette | Scale 0.95→1.0 + fade | 200ms |

## Responsive

- **Desktop (>1024px)**: Full sidebar + main + side panel
- **Tablet (768-1024px)**: Sidebar collapses to 36px icons. Side panel → bottom sheet
- **Mobile (<768px)**: Full-screen navigation. Host list → rules → bottom sheet editing

## Icons

SF Symbols style (rounded, consistent weight). SVG only — no emoji in the actual UI. Text labels preferred over icon-only buttons. Minimal icon use — typography carries hierarchy.

## Empty States

Brief explanation (1-2 sentences) + single primary action. No illustrations. No mascots.

First launch gets the shield icon + confidence statement (see 01-overview.md). All other empty states are text-only with a call to action.
