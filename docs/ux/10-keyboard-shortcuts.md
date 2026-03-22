# Keyboard Shortcuts

The app is fully keyboard-navigable.

## Global

| Shortcut | Action |
|----------|--------|
| `Cmd/Ctrl + K` | Command palette (search, jump, actions) |
| `Cmd/Ctrl + Shift + B` | Quick Block IP |
| `Cmd/Ctrl + N` | Add new host |
| `Cmd/Ctrl + 0` | Toggle sidebar collapse |
| `Cmd/Ctrl + ,` | Open settings |
| `Cmd/Ctrl + S` | Apply pending changes |
| `Cmd/Ctrl + Z` | Undo last staged change |
| `Cmd/Ctrl + Shift + Z` | Redo |
| `Escape` | Close panel / dialog / cancel editing |

## Sidebar

| Shortcut | Action |
|----------|--------|
| `↑ / ↓` | Navigate host list |
| `Enter` | Select host |
| `Cmd/Ctrl + N` | Add new host |

## Rules View

| Shortcut | Action |
|----------|--------|
| `Tab` | Move focus between rules |
| `Enter` | Open focused rule in side panel |
| `E` | Edit focused rule |
| `D` | Disable/enable focused rule |
| `Delete / Backspace` | Delete focused rule (with confirmation) |
| `N` | Add new rule (opens builder in side panel) |
| `Alt + ↑` | Move focused rule up |
| `Alt + ↓` | Move focused rule down |
| `/` | Focus rule filter/search |

## Side Panel

| Shortcut | Action |
|----------|--------|
| `Tab` | Move between fields |
| `Enter` | Submit / save rule |
| `Escape` | Cancel and close panel |

## Tabs

| Shortcut | Action |
|----------|--------|
| `Cmd/Ctrl + 1` | Rules tab |
| `Cmd/Ctrl + 2` | Activity tab |
| `Cmd/Ctrl + 3` | Terminal tab |
| `Cmd/Ctrl + \` | Toggle split view |

## Accessibility

- All interactive elements are focusable via Tab
- ARIA live regions announce rule reordering: "Rule [name] moved to position [n] of [total]"
- All dialogs trap focus and return focus on close
- Status indicators use **distinct shapes** (not just color): ● ▲ ⊗ ○ ◌ ⊙
- Minimum contrast ratio: 4.5:1 for all text
- Every rule has a `[⋯]` overflow menu button (Tab-focusable, opens with Enter/Space) as an alternative to right-click context menus
- Combobox fields use `role="combobox"` with `aria-autocomplete="list"`
- Category headers in dropdowns use `role="group"` with `aria-label`
- Selected values announced via `aria-live="polite"`
