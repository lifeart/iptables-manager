# Project Structure

```
traffic-rules/
├── src-tauri/
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── capabilities/
│   │   └── default.json
│   ├── scripts/
│   │   ├── revert.sh                 # Safety timer revert (deployed during provisioning)
│   │   └── expire-rule.sh            # Temporary rule expiry (deployed during provisioning)
│   ├── data/
│   │   └── service-templates.json    # Service name → rule mapping
│   ├── src/
│   │   ├── main.rs
│   │   ├── lib.rs
│   │   ├── ipc/
│   │   │   ├── mod.rs
│   │   │   ├── commands.rs           # All #[tauri::command] handlers
│   │   │   ├── events.rs             # Event emission helpers
│   │   │   └── errors.rs             # IpcError enum with serde
│   │   ├── ssh/
│   │   │   ├── mod.rs
│   │   │   ├── pool.rs               # Connection pool with per-host Mutex
│   │   │   ├── session.rs            # ManagedSession wrapper
│   │   │   ├── command.rs            # Shell-escaped command construction
│   │   │   ├── credential.rs         # OS keychain (keyring crate)
│   │   │   └── provision.rs          # Remote host setup (dirs, revert script)
│   │   ├── iptables/
│   │   │   ├── mod.rs
│   │   │   ├── parser.rs             # iptables-save parser (winnow)
│   │   │   ├── generator.rs          # Restore file with :TR- reset lines
│   │   │   ├── diff.rs               # Ruleset diff
│   │   │   ├── system_detect.rs      # Chain ownership detection
│   │   │   ├── conflict.rs            # Shadow/redundancy/overlap detection
│   │   │   ├── tracer.rs             # Packet flow simulation (all 3 paths)
│   │   │   ├── explain.rs            # Plain-English rule explanation
│   │   │   ├── jump_rules.rs         # Idempotent jump rule management (v4 + v6)
│   │   │   ├── multi_apply.rs        # Canary/rolling/parallel orchestration
│   │   │   └── types.rs              # Core types with #[derive(TS)]
│   │   ├── ipset/
│   │   │   ├── mod.rs
│   │   │   └── manager.rs            # CRUD with atomic swap
│   │   ├── safety/
│   │   │   ├── mod.rs
│   │   │   ├── timer.rs              # Remote revert scheduling + atd check
│   │   │   ├── lockout.rs            # Pre-apply packet trace + VPN detection
│   │   │   └── hmac.rs               # Backup integrity (secret in file, not CLI)
│   │   ├── host/
│   │   │   ├── mod.rs
│   │   │   ├── detect.rs             # Capability detection with progress events
│   │   │   └── persist.rs            # Distro-specific rule persistence
│   │   ├── snapshot/
│   │   │   └── manager.rs            # Filtered backups (TR- chains only)
│   │   ├── activity/
│   │   │   └── monitor.rs            # Polling + streaming with rate limiting
│   │   ├── temporary/
│   │   │   ├── mod.rs
│   │   │   └── scheduler.rs          # Remote expiry scheduling (at/cron/systemd)
│   │   ├── export/
│   │   │   └── format.rs             # Shell, Ansible, iptables-save
│   │   └── sysctl/
│   │       └── mod.rs                # IP forwarding management + persistence
│   └── tests/
│       ├── parser_test.rs
│       ├── generator_test.rs
│       ├── diff_test.rs
│       ├── tracer_test.rs
│       ├── jump_rules_test.rs
│       ├── explain_test.rs
│       └── fixtures/                 # Real iptables-save output from Docker containers
│           ├── clean_server.txt
│           ├── docker_host.txt
│           ├── k8s_node.txt
│           ├── complex_mixed.txt
│           ├── wg_quick.txt
│           ├── fail2ban_active.txt
│           ├── iptables_nft.txt      # iptables-nft backend format
│           └── with_counters.txt     # Format with [packets:bytes]
│
├── src/
│   ├── index.html
│   ├── main.ts                       # Bootstrap sequence
│   ├── store/
│   │   ├── index.ts                  # Store with selector subscriptions
│   │   ├── actions.ts
│   │   ├── reducers.ts
│   │   ├── selectors.ts              # Memoized: effectiveRules, filteredRules, etc.
│   │   └── types.ts                  # AppState (with @persisted/@ephemeral annotations)
│   ├── ipc/
│   │   ├── bridge.ts                 # Typed invoke/listen with IpcError handling
│   │   └── types.generated.ts        # Auto-generated from Rust via ts-rs
│   ├── db/
│   │   ├── index.ts                  # IndexedDB setup with version migrations
│   │   ├── sync.ts                   # Batched + immediate write strategies
│   │   └── schema.ts
│   ├── components/
│   │   ├── base.ts                   # AbortController lifecycle base class
│   │   ├── reconciler.ts             # Keyed list reconciler for DOM updates
│   │   ├── sidebar/
│   │   ├── rule-table/
│   │   ├── side-panel/
│   │   ├── rule-builder/
│   │   ├── activity/
│   │   │   └── sparkline.ts          # Inline mini-charts for hit rates
│   │   ├── terminal/                 # Lazy-loaded (dynamic import)
│   │   ├── command-palette/
│   │   ├── safety-banner/
│   │   ├── dialogs/
│   │   │   └── first-setup.ts        # Service detection + suggested rules
│   │   └── settings/
│   ├── services/
│   │   ├── rule-merge.ts             # Effective ruleset computation (frontend-only)
│   │   ├── rule-label.ts             # Auto-labeling with service-templates.json
│   │   ├── shortcut.ts
│   │   ├── theme.ts
│   │   └── templates.ts
│   ├── utils/
│   │   ├── ip-validate.ts
│   │   ├── port-validate.ts
│   │   ├── format.ts
│   │   ├── animate.ts
│   │   ├── dom.ts
│   │   └── debounce.ts
│   └── styles/
│       ├── tokens.css                # CSS custom properties + dark mode
│       ├── reset.css
│       ├── base.css
│       └── components/               # BEM-named, layered via @layer
│           ├── sidebar.css
│           ├── rule-table.css
│           ├── side-panel.css
│           ├── rule-builder.css
│           ├── activity.css
│           ├── terminal.css
│           ├── dialogs.css
│           ├── command-palette.css
│           ├── safety-banner.css
│           └── settings.css
│
├── docs/
│   ├── ux/                           # 12 UX spec files
│   └── architecture/                 # Architecture docs
│
├── CONTRIBUTING.md                    # Developer setup guide
├── package.json
├── tsconfig.json
├── vite.config.ts
├── rust-toolchain.toml               # Pin Rust version
└── README.md
```

## Rust Dependencies

| Crate | Purpose |
|-------|---------|
| tauri 2.x | App framework |
| openssh | SSH client (subprocess-based) |
| keyring | OS keychain |
| ring | HMAC-SHA256 |
| winnow | Parser combinators for iptables-save |
| tokio | Async runtime |
| serde / serde_json | Serialization |
| ts-rs | Generate TypeScript types |
| shell-words | Safe shell command construction |
| dashmap | Concurrent per-host locks |
| tracing + tracing-subscriber + tracing-appender | Structured logging |
| thiserror | Error types |

## Frontend Dependencies

| Package | Purpose |
|---------|---------|
| @tauri-apps/api | Tauri IPC |
| sortablejs | Drag-and-drop (rule table) |
| codemirror 6 | Raw rules editor (lazy-loaded) |
| @xyflow/vanilla | Packet tracer visualization (lazy-loaded) |
| idb | IndexedDB wrapper |
| vite | Bundler |
| typescript | Type safety |

## Development

```bash
# Prerequisites
rustup install stable          # or version from rust-toolchain.toml
cargo install tauri-cli
npm install

# Development
npm run tauri dev              # Vite + Tauri hot reload

# Generate TypeScript types from Rust
cargo test export_bindings --manifest-path src-tauri/Cargo.toml

# Run Rust tests
cargo test --manifest-path src-tauri/Cargo.toml

# Create test fixtures (requires Docker)
docker run --rm --cap-add=NET_ADMIN -v ./fixtures:/out iptables-fixture-gen

# Build
npm run tauri build            # Platform-specific binary

# Lint
npm run lint                   # TypeScript + CSS (stylelint with BEM rules)
cargo clippy                   # Rust
```

## Testing Strategy

### Unit Tests (no SSH needed)
- Parser: test against fixture files (real iptables-save outputs)
- Generator: verify restore file format, `:TR-` reset lines, `-w` flag
- Diff: verify minimal changeset computation
- Tracer: verify packet flow against rulesets
- Explain: verify plain-English output
- Jump rules: verify idempotent insertion logic

### Integration Tests (Docker containers)
```yaml
# test-container/Dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y iptables ipset openssh-server at
```
- Connect via SSH, apply rules, verify with iptables-save
- Test safety timer (use `tokio::time::pause()` for time control)
- Test Docker coexistence (Docker-in-Docker)
- Test fail2ban coexistence

### Frontend Tests
- Store: action dispatch, selector memoization, subscription cleanup
- Reconciler: keyed list operations
- Validation: IP, port, CIDR
- Rule merge: effective ruleset computation

## Graceful Shutdown

```rust
.run(|app_handle, event| {
    if let tauri::RunEvent::ExitRequested { .. } = event {
        let pool = app_handle.state::<ConnectionPool>();
        tokio::runtime::Handle::current().block_on(async {
            // Cancel all background tasks
            pool.cancel_all().await;
            // Close SSH sessions
            pool.disconnect_all().await;
        });
    }
});
```

## Minimum Requirements

- iptables 1.6.0+ (for `-w` flag, conntrack module)
- Kernel 4.7+ (for conntrack helper changes)
- OpenSSH client on the user's machine
- macOS 12+, Ubuntu 20.04+, Windows 10+ (for Tauri WebView)
