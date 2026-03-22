# Architecture Overview

## Platform: Tauri 2.x

Chosen over Electron for security posture, binary size (~8MB), memory (~30MB), and native OS keychain access.

## SSH Library: `openssh` crate (subprocess-based)

Chosen over `russh` because:
- Inherits user's `~/.ssh/config`, `known_hosts`, SSH agent, ProxyJump — all free
- Host key verification delegated to battle-tested OpenSSH binary (critical for a firewall tool)
- Jump hosts work via `ssh -J` with no custom plumbing
- Keyboard-interactive auth handled natively
- Trade-off: one process per connection (fine for desktop app managing ≤50 hosts)

## Process Model

```
┌─────────────────────────────────────────────────────────┐
│  Tauri Main Process (Rust)                              │
│                                                         │
│  ┌─────────────────┐  ┌──────────────────────────────┐  │
│  │ SSH Pool         │  │ IptablesEngine               │  │
│  │ (openssh crate)  │  │ (parse, diff, generate)      │  │
│  └─────────────────┘  └──────────────────────────────┘  │
│  ┌─────────────────┐  ┌──────────────────────────────┐  │
│  │ Credential Store │  │ Safety Timer Manager         │  │
│  │ (keyring crate)  │  │ (tracks remote timers)       │  │
│  └─────────────────┘  └──────────────────────────────┘  │
│  ┌─────────────────┐  ┌──────────────────────────────┐  │
│  │ HMAC / Crypto    │  │ Command Builder              │  │
│  │ (ring crate)     │  │ (shell-escaped, validated)   │  │
│  └─────────────────┘  └──────────────────────────────┘  │
│                                                         │
│  Tauri IPC Commands (invoke / events)                   │
├─────────────────────────────────────────────────────────┤
│  WebView Process (Renderer)                             │
│                                                         │
│  ┌─────────────────┐  ┌──────────────────────────────┐  │
│  │ AppStore         │  │ UI Components (vanilla JS)   │  │
│  │ (selector-based) │  │ Sidebar, RuleTable, SidePanel│  │
│  └─────────────────┘  └──────────────────────────────┘  │
│  ┌─────────────────┐  ┌──────────────────────────────┐  │
│  │ IndexedDB Layer  │  │ CodeMirror 6, SortableJS,    │  │
│  │ (persistence)    │  │ @xyflow/vanilla (lazy-loaded) │  │
│  └─────────────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Security Boundary

The IPC layer IS the security boundary. The frontend requests operations but never constructs shell commands. All SSH, credential access, HMAC computation, iptables parsing, and **shell escaping** happens in Rust.

**Shell escaping**: SSH protocol's `exec` is always a single string passed to `$SHELL -c`. The Rust backend uses `shell_words::join()` to construct safe command strings from typed arguments. No raw string interpolation.

## Layer Architecture

```
Layer 4: UI Components (vanilla JS, DOM manipulation)
Layer 3: Application Services (rule merge, templates, shortcuts)
Layer 2: Tauri IPC Bridge (typed invoke/listen wrappers)
Layer 1: Core Services (Rust — SSH, iptables, safety, credentials)
Layer 0: OS Integration (keychain, filesystem, network)
```

## IPC Design

**Commands** (request/response via `invoke()`):

```
// Connection
host:connect(hostId) -> ConnectionResult
host:disconnect(hostId) -> void
host:test(connectionParams) -> TestResult
host:detect(hostId) -> stream of DetectionProgress events, final DetectionResult
host:provision(hostId) -> ProvisionResult  // creates dirs, installs revert script, checks sudo

// Rules
rules:fetch(hostId) -> RuleSet
rules:apply(hostId, changes[]) -> ApplyResult
rules:apply-multi(groupId, hostIds[], changes[], strategy) -> stream of MultiApplyProgress
rules:revert(hostId) -> void
rules:confirm(hostId) -> void
rules:trace(hostId, packet: TestPacket) -> TraceResult  // interactive packet tracer
rules:explain(ruleSpec) -> string  // plain English explanation
rules:export(hostId, format) -> string  // shell/ansible/iptables-save
rules:check-duplicate(hostId, rule) -> DuplicateCheckResult
rules:detect-conflicts(hostId) -> RuleConflict[]
rules:schedule-expiry(hostId, ruleId, expiresAt) -> void  // temporary rules
rules:cancel-expiry(hostId, ruleId) -> void

// Snapshots
snapshot:create(hostId) -> SnapshotMeta
snapshot:list(hostId) -> SnapshotMeta[]
snapshot:restore(hostId, snapshotId) -> ApplyResult

// IP Lists
iplist:sync(hostId, ipListId) -> void
iplist:delete(hostId, ipListId) -> void  // destroy remote ipset

// Hosts
host:delete(hostId, { removeRemoteData: boolean }) -> void

// Activity
activity:subscribe(hostId) -> streamId
activity:unsubscribe(streamId) -> void
activity:fetch-conntrack-table(hostId) -> ConntrackEntry[]
activity:fetch-bans(hostId) -> Fail2banBan[]

// Credentials
cred:store(hostId, credential) -> void
cred:retrieve(hostId) -> Credential
cred:delete(hostId) -> void

// System
sysctl:set(hostId, key, value, persistent) -> void
host:check-disk-space(hostId, path) -> DiskSpaceResult

// Terminal
terminal:exec(hostId, command) -> CommandResult
```

**Events** (push via `listen()`):

```
connection:status     — state changes
activity:hit-counters — periodic counter updates (30s)
activity:blocked      — real-time blocked log (rate-limited 10/sec)
activity:conntrack    — conntrack usage (60s)
safety:tick           — countdown timer updates (1/sec)
host:drift            — drift detection
host:detect-progress  — detection step progress during setup
```

**Typed Error Envelope**:

```rust
#[derive(Serialize, TS)]
#[serde(tag = "kind", content = "detail")]
enum IpcError {
    ConnectionFailed { host_id: String, reason: String },
    AuthFailed { host_id: String },
    LockoutDetected { trace: TraceResult },
    IptablesLocked { retry_after_ms: u64 },
    Timeout { operation: String },
    PartialApply { succeeded: usize, total: usize, error: String },
    DiskFull { path: String, available_bytes: u64 },
    QuotaExceeded { store: String },
}
```

## Authentication

For v1: **OS-level security only**. The app relies on macOS Keychain access prompts and OS login. Full app-level MFA is deferred to v2.

Rationale: MFA design (registration, login, recovery, enrollment) is a significant UX and backend effort that would delay v1. OS-level security (screen lock, Keychain) provides reasonable protection for a desktop app.

## `sudo` Strategy

For v1: **default to `root` user** in Quick Add. Document the recommended sudoers entry for security-conscious users:

```
# /etc/sudoers.d/traffic-rules
trafficrules ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/iptables-save, \
  /usr/sbin/iptables-restore, /usr/sbin/ip6tables, /usr/sbin/ip6tables-save, \
  /usr/sbin/ip6tables-restore, /usr/sbin/ipset, /usr/bin/at, /usr/bin/systemd-run, \
  /usr/bin/journalctl, /usr/bin/ss, /usr/bin/mkdir, /usr/bin/tee, /usr/bin/rm, \
  /usr/sbin/sysctl, /usr/sbin/iptables-apply
```

When sudo requires a password: write iptables-restore data to a temp file (`/tmp/tr-restore-XXXX`), then run `sudo iptables-restore < /tmp/tr-restore-XXXX` (avoids stdin conflict).

## Key Architecture Decisions

1. **`openssh` crate** for SSH — inherits user config, battle-tested host key verification
2. **Shell-escaped commands** via `shell_words::join()` — SSH exec is always a shell string, so we must escape properly
3. **App-managed chains prefixed `TR-`** with `:TR-CHAIN - [0:0]` reset lines in every restore
4. **Always `iptables-restore --noflush`** — even for single-rule changes. Atomicity > micro-optimization
5. **`-w 5` flag on all iptables commands** — wait for xtables lock (fail2ban/Docker contention)
6. **Selector-based subscriptions** — no path wildcards, memoized selectors only
7. **Effective ruleset is a memoized selector** — never stored in state
8. **Dual-layer safety timer** — local (UI countdown) + remote (at/systemd-run)
9. **Safety timer state persisted to IndexedDB** before scheduling remote revert
10. **Host provisioning step** on first connect — creates dirs, installs revert script, verifies sudo
