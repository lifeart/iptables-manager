# Traffic Rules

A desktop GUI for managing iptables firewall rules on remote Linux servers via SSH.

Built with Tauri 2.x (Rust backend + vanilla TypeScript frontend). Native on macOS and Linux.

**[Live Demo](https://lifeart.github.io/iptables-manager/)** (runs in browser, no install needed)

## What it does

- Connect to Linux servers via SSH (password or key auth)
- View, create, edit, delete, and reorder firewall rules through a visual GUI
- Apply changes with a 60-second safety timer (auto-reverts if connection drops)
- Dry-run preview — see exact iptables commands before applying
- Drift detection — alerts when rules change outside the tool, shows exactly what changed
- Audit log — persistent history of all rule changes
- Monitor traffic: real-time hit counters, blocked traffic log, connection tracking
- Port saturation warnings (conntrack capacity alerts)
- 16 built-in templates (web server, Kubernetes, VPN, database, monitoring, CI/CD, load balancer)
- 68 service presets with 110+ well-known port mappings
- Export rules as shell script, Ansible playbook, or iptables-save format
- Manage multiple hosts with groups and shared rules
- Bulk apply to host groups with canary, rolling, or parallel strategies
- Cross-host rule comparison (side-by-side diff)
- Import existing server rules as managed baseline
- Duplicate and conflict detection — shadow, redundant, and contradictory rule warnings
- Human-readable rule explanation in rule detail panel
- Advanced search filters (protocol, port, address)
- HMAC-signed backups for tamper detection
- Mixed-backend detection — warns when both legacy iptables and nf_tables rules exist, blocks unsafe apply
- xtables lock handling — detects lock holder, retries with backoff, shows actionable error
- Live traffic trace — insert kernel TRACE rules, collect real packet path, auto-cleanup
- ipset optimization — suggests compiling large rule groups into ipset for O(1) lookups
- Error explanations — maps 13 common iptables/SSH errors to human-readable remediation steps

## Screenshot

![Traffic Rules — iptables manager](docs/screenshot.png)

- **Sidebar**: hosts with status indicators, groups, IP lists
- **Rule table**: colored action badges (green=allow, red=drop), hit counts, drag-to-reorder
- **Side panel**: rule detail/edit, port forwarding, source NAT builders
- **Activity tab**: live hit counters with sparklines, blocked traffic log
- **Terminal tab**: raw iptables editor, packet tracer, live traffic trace, SSH command log

## Quick start

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (stable)
- [Node.js](https://nodejs.org/) 18+
- OpenSSH client on your machine

### Development

```bash
git clone https://github.com/lifeart/iptables-manager.git
cd iptables-manager
npm install
npm run tauri dev
```

This starts the Tauri app with hot-reload. The app loads demo data (3 hosts, rules, hit counters) so you can explore the UI without connecting to a real server.

### Browser-only mode (no Tauri)

```bash
npx vite --port 1420
```

Opens at `http://localhost:1420`. All IPC calls use mock data. Good for frontend development.

## Build

### macOS

```bash
npm run tauri build
```

Produces `src-tauri/target/release/bundle/dmg/Traffic Rules_0.1.0_aarch64.dmg` (Apple Silicon) or `x64.dmg` (Intel).

### Linux

```bash
npm run tauri build
```

Produces `.deb` and `.AppImage` in `src-tauri/target/release/bundle/`.

### Windows

```bash
npm run tauri build
```

Produces `.msi` in `src-tauri/target/release/bundle/msi/`.

## Project structure

```
├── src/                    # Frontend (TypeScript)
│   ├── components/         # UI components (sidebar, rule-table, dialogs, etc.)
│   ├── store/              # State management (actions, reducers, selectors)
│   ├── services/           # Rule merge, templates, theme, shortcuts
│   ├── ipc/                # Tauri IPC bridge with mock mode
│   ├── db/                 # IndexedDB persistence
│   ├── mock/               # Demo data
│   └── styles/             # CSS (BEM, dark mode)
│
├── src-tauri/              # Backend (Rust)
│   ├── src/
│   │   ├── iptables/       # Parser, generator, diff, tracer, conflict, live trace, lock, error catalog
│   │   ├── ssh/            # Connection pool, command builder, credentials
│   │   ├── safety/         # Timer, lockout detection, HMAC, drift detection
│   │   ├── host/           # Detection, persistence, auto-provision
│   │   ├── activity/       # Hit counters, blocked log, conntrack, audit log
│   │   ├── ipset/          # Atomic swap manager
│   │   ├── snapshot/       # Create, restore, list
│   │   ├── export/         # Shell, Ansible, iptables-save
│   │   └── ipc/            # Tauri command handlers
│   ├── scripts/            # revert.sh, expire-rule.sh
│   └── tests/              # 446 tests with fixtures
│
├── docs/
│   ├── ux/                 # 12 UX spec files
│   └── architecture/       # 6 architecture docs
│
├── test-server/            # Docker test environment
│   └── Dockerfile          # Ubuntu + iptables + SSH for testing
│
└── index.html              # Entry point
```

## Testing

### Rust tests

```bash
cd src-tauri
cargo test
```

446 tests covering: iptables parser (all match modules, system detection), generator (restore files, round-trip), diff engine, packet tracer, conflict detection, safety timer, SSH commands, ipset, export formats, serialization contracts, HMAC verification, drift detection, audit log, mixed-backend detection, xtables lock retry, live traffic trace (TRACE rule lifecycle, parsers), ipset optimization suggestions, error catalog (13 patterns).

### TypeScript type checking

```bash
npx tsc --noEmit
```

### Integration testing with Docker

```bash
# Start test server (Ubuntu + iptables + SSH)
cd test-server
podman machine start  # or docker
podman build -t iptables-test-server .
podman run -d --name iptables-test --cap-add=NET_ADMIN -p 2222:22 iptables-test-server

# Setup SSH key auth
sshpass -p testpassword ssh-copy-id -p 2222 root@localhost

# Test
ssh -p 2222 root@localhost "iptables-save"
```

Then connect to `root@localhost:2222` in the app.

## Connecting to a real server

1. Click **+ Add Host** in the sidebar
2. Type `root@your-server-ip` (or `user@host:port`)
3. Click **Connect**
4. The app connects via SSH, fetches iptables rules, and displays them

Requirements on the remote server:
- SSH access (key-based auth recommended)
- `iptables` and `iptables-save` available
- Root or sudo access for iptables commands

## Key features

### Safety timer (dead man's switch)
Every rule change includes a 60-second safety window. If the SSH connection drops after applying rules, they automatically revert via `at`/`systemd-run`/`nohup` — you can't lock yourself out. First-connect auto-provision deploys revert scripts and HMAC verification to the remote host.

### Dry-run preview
See the exact iptables commands that will run before applying any changes. Review the full diff of what will be added, removed, or modified.

### Drift detection
The app monitors for rule changes made outside the tool and alerts you when the live ruleset no longer matches the managed state. The drift banner shows exactly what changed — added, removed, or modified rules — with an expandable diff view.

### Audit log
Persistent history of all rule changes across sessions — who changed what, when, and why. Useful for compliance and troubleshooting.

### Rule builder
Sentence-style rule creation: pick action (Allow/Block/Log), service (SSH, Web, PostgreSQL, WireGuard...), source (Anyone, IP list, specific IP), and the rule is created. Progressive disclosure reveals advanced options (rate limiting, custom conditions, block type).

### Templates
16 built-in templates: Web Server, Database, Mail, Bastion, Docker Host, NAT Gateway, VPN (WireGuard/OpenVPN), IPSec, Kubernetes Node, Monitoring Stack, Load Balancer, CI/CD Server, Message Broker, Lockdown, Minimal. Each creates a complete working ruleset.

### Export
Export rules as:
- **Shell script** — standalone bash script with iptables commands
- **Ansible playbook** — ready for automation
- **iptables-save** — raw format for `iptables-restore`

### Multi-host management
Bulk apply rules to host groups with canary, rolling, or parallel deployment strategies. Compare rules across hosts with side-by-side diff. Import existing server rules as a managed baseline on first connect.

### Rule analysis
Duplicate detection with similarity scoring catches near-duplicates when adding or editing rules. Conflict detection identifies shadow, redundant, and contradictory rules and shows a warning banner. Each rule includes a human-readable explanation in its detail panel.

### Monitoring
Real-time hit counters with sparklines, blocked traffic log, and connection tracking. Port saturation warnings alert when conntrack capacity is nearing limits. SSH rate limiting (10 cmd/s per host) prevents overloading remote servers. Advanced search filters let you narrow rules by protocol, port, or address.

### Packet tracer
Test how a packet would be processed: enter source IP, destination, port, protocol — see which rule matches and why.

### Live traffic trace
Insert kernel TRACE rules on a remote host via SSH to trace real packets through the firewall. The app collects output via `xtables-monitor` (nft) or `dmesg` (legacy), auto-removes TRACE rules after a configurable timeout, and displays the packet path in the same format as the packet tracer.

### Mixed-backend detection
Detects when a host has both legacy iptables and nf_tables rules populated — a common source of "table is incompatible" errors. Shows a warning banner and blocks apply until resolved.

### xtables lock handling
When another process (Docker, fail2ban, ufw) holds the iptables lock, the app retries with exponential backoff (1s/2s/4s) and identifies the lock holder by PID and process name. Shows context-aware tips ("fail2ban is updating bans, try again shortly").

### ipset optimization
Analyzes rulesets for chains with many rules that differ only in source IP. Suggests compiling them into ipset hash:net sets for O(1) lookups instead of O(n) linear scans. One-click conversion creates the ipset and populates it.

### Error explanations
Maps 13 common iptables and SSH error patterns to human-readable explanations with context-aware remediation steps. Shows a popover with title, explanation, and actionable fix steps instead of raw stderr.

### Data integrity
HMAC-signed backups detect tampering. 20+ serialization contract tests prevent frontend/backend data mismatches. Credentials are stored on connect and deleted on host removal.

## Tech stack

| Layer | Technology | Lines |
|-------|-----------|-------|
| Frontend | Vanilla TypeScript, CSS | ~22k |
| Backend | Rust (Tauri 2.x) | ~14k |
| SSH | `openssh` crate (subprocess) | — |
| State | Custom store with selector subscriptions | — |
| Persistence | IndexedDB (browser) | — |
| Credentials | OS keychain via `keyring` crate | — |
| Drag & drop | SortableJS | — |

## Auto-updates

The app checks for updates on startup using the Tauri updater plugin. When a signed update is available, the user sees an "Update Now" button that downloads and installs in-place.

### Setting up auto-updates

1. Generate signing keys:
   ```bash
   cargo tauri signer generate -w ~/.tauri/traffic-rules.key
   ```
2. Copy the **public key** and add the updater plugin config to `src-tauri/tauri.conf.json`:
   ```json
   {
     "plugins": {
       "updater": {
         "endpoints": [
           "https://github.com/lifeart/iptables-manager/releases/latest/download/latest.json"
         ],
         "pubkey": "YOUR_PUBLIC_KEY_HERE"
       }
     }
   }
   ```
3. Add to GitHub repository secrets:
   - `TAURI_SIGNING_PRIVATE_KEY`: contents of `~/.tauri/traffic-rules.key`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`: the password you chose
4. Push a new tag to trigger a signed release

The `tauri-apps/tauri-action` in the release workflow will automatically sign update artifacts, generate `latest.json` with download URLs and signatures, and upload it as a release asset.

If the signing key is not configured (empty `pubkey`), the updater plugin is skipped gracefully and the app falls back to the GitHub API to check for new releases.

## Releasing

1. Bump the version in all three files:
   - `package.json` (`version`)
   - `src-tauri/Cargo.toml` (`version`)
   - `src-tauri/tauri.conf.json` (`version`)
2. Update `CHANGELOG.md` with the new version and changes
3. Commit and tag:
   ```bash
   git add -A && git commit -m "release: v0.2.0"
   git tag v0.2.0
   git push origin master --tags
   ```
4. The release workflow builds macOS (.dmg) and Linux (.deb, .AppImage) artifacts and creates a **draft** GitHub Release at [github.com/lifeart/iptables-manager/releases](https://github.com/lifeart/iptables-manager/releases)
5. Review the draft, edit release notes if needed, then publish

## License

MIT
