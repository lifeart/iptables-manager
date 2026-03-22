# Settings

Settings are minimal. The app should work well out of the box.

## Access

Settings icon (gear) in the top-right corner, or `Cmd+,` / `Ctrl+,`.

## Settings Layout

```
┌─────────────────────────────────────────────────────────┐
│  Settings                                            ×  │
│                                                         │
│  General                                                │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Theme              [System ▾]                          │
│                      ├ Light                            │
│                      ├ Dark                             │
│                      └ System (follow OS)               │
│                                                         │
│  Safety timeout     [60 seconds ▾]                      │
│                      ├ 30 seconds                       │
│                      ├ 60 seconds (recommended)         │
│                      ├ 120 seconds                      │
│                      └ Disabled (dangerous)             │
│                                                         │
│  Auto-refresh       [Every 30 seconds ▾]                │
│                                                         │
│  ─────────────────────────────────────────────────────  │
│  Advanced                                               │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  IP Version         ◉ IPv4 and IPv6 together            │
│                     ○ Manage separately                 │
│                                                         │
│  Default action     [Block ▾] for new "Everything Else" │
│                      ├ Block (recommended)              │
│                      └ Allow                            │
│                                                         │
│  System rules (Docker, K8s, fail2ban)                   │
│                     [☑ Hidden by default]                │
│                                                         │
│  SSH connection timeout  [10 seconds]                   │
│  Command timeout         [30 seconds]                   │
│                                                         │
│  Show SSH command log    [☑ Enabled]                     │
│  (Shows all commands sent to hosts in Terminal > SSH Log)│
│                                                         │
│  ─────────────────────────────────────────────────────  │
│  Data                                                   │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  Export all settings and hosts  [Export...]              │
│  Import from backup            [Import...]              │
│                                                         │
│  Staged changes are stored locally and persist          │
│  across app restarts.                                   │
│  [Clear all staged changes]                             │
│                                                         │
│  Snapshots: 47 snapshots (12 MB)                        │
│  [Manage snapshots]                                     │
│                                                         │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  About                                                  │
│  Traffic Rules v0.1.0                                   │
│  github.com/lifeart/iptables-manager                    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Corner Cases

### Disabling Safety Timeout

```
  ⚠️  Disabling the safety timeout is dangerous.

  If a rule change locks you out of a server,
  there will be no automatic rollback.

  You may permanently lose SSH access.

  [Keep safety timeout]  [Disable — I accept the risk]
```

### Changing IP Version Mode

```
  Switching to separate IPv4/IPv6 management will
  duplicate your rules into separate IPv4 and IPv6 tabs.

  Note: ICMPv6 neighbor discovery rules will always be
  auto-included when IPv6 is enabled.

  [Switch to separate]  [Keep combined]
```

### Export Format

Export creates a JSON file containing:
- All hosts (names, IPs, ports — NOT credentials)
- All groups with members
- All IP Lists
- All rule templates
- All snapshots

Credentials are NOT exported. On import, user must re-enter authentication.

### Import Conflict

```
  Import found 3 hosts. 1 already exists:

  ● web-01 — already managed (rules differ)
  ● db-02  — new host
  ● api-01 — new host

  For web-01:
  ○ Keep current rules
  ○ Replace with imported rules
  ○ Skip this host

  [Import]  [Cancel]
```

### Storage Full

```
  ⚠️  Cannot save snapshot: storage is full.

  You have 247 snapshots using 50MB.

  [Delete old snapshots (keep last 30)]  [Manage snapshots]
```
