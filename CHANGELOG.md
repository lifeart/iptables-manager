# Changelog

## [2.1.1] - 2026-03-27

### Added
- Structured logging via tracing-subscriber (27 instrumentation points)
- SSH pool: connect/disconnect/keepalive/rate-limit/timeout events
- Safety timer: armed/cancelled logging
- Backup: creation/HMAC/v6 failure warnings
- 14 silent error paths now log warnings instead of swallowing

### Removed
- Unused `winnow` dependency

## [2.1.0] - 2026-03-27

### Added
- ts-rs integration: 26 Rust structs auto-generate TypeScript bindings on `cargo test`
- 29 generated `.ts` files in `src/bindings/` replace manual type definitions
- Barrel export `src/bindings/index.ts` for clean imports

### Changed
- `bridge.ts` imports from generated `src/bindings/` instead of manual interfaces
- `store/types.ts` imports `RuleConflict`, `HitCounter` from bindings
- Edge cases handled: `u64→number`, `serde_json::Value→unknown`, `Option<T>→T|null`

### Removed
- 20+ manually maintained TypeScript interfaces (replaced by auto-generated)

## [2.0.0] - 2026-03-27

### Architecture Overhaul
- **Safety timer ordering**: Timer armed BEFORE rules apply; abort if timer fails (CRITICAL fix)
- **SSH keepalive**: 30s heartbeat per session, auto-detect dead connections
- **Backend split**: Monolithic commands.rs (2,415 lines) → 11 focused submodules (no file >618 lines)
- **Frontend split**: rule-table.ts (1,515 lines) → 5 sub-components + orchestrator (799 lines)
- **CSS split**: rule-table.css (1,558 lines) → 6 files aligned with component structure
- **Consolidated AppState**: Single managed state struct (pool + drift)

### Performance
- Shared `fetch_current_ruleset()` eliminates N+1 iptables-save SSH calls
- DashMap for drift state (lock-free concurrent access)
- Rate limiter race fix (holds mutex correctly)
- Conflict detection capped at 50 results with early termination
- Conflict detection frontend cache (60s TTL)
- Hit counter UI debounced to 1 render/second
- Reduced `.clone()` with Arc<String> in group apply
- SSH connect timeout (10s)

### Accessibility
- aria-label on all icon buttons (disconnect, refresh, export, close, etc.)
- aria-selected on tab buttons, role=dialog on preview modal

### Code Quality
- Extracted `exec_failed()` error helper (replaces 20+ patterns)
- Log non-quota IndexedDB write failures
- Documented intentionally permanent wireDbSync subscriptions

### Tests
- 9 new QA tests: timer ordering, keepalive, fetch helper, conflict capping,
  drift concurrency, rate limiter load (370 total)

## [1.0.1] - 2026-03-27

### Fixed
- Replace all hardcoded colors with CSS design tokens across new feature UIs
- Fix undefined CSS variables (`--color-window`, `--color-accent`, `--color-warning-bg`, `--radius-default`)
- Add dark mode support to conflicts banner, import banner, preview modal, drift banner, saturation warning

## [1.0.0] - 2026-03-27

### Added
- **Dry-run preview**: Preview exact iptables commands before applying
- **Bulk apply to host groups**: Canary, rolling, and parallel strategies with per-host progress
- **Drift detection**: Periodic polling detects rules changed outside the tool, amber warning banner
- **Audit log**: Persistent change history (IndexedDB, 500-entry cap) in Activity view
- **Cross-host rule comparison**: Side-by-side diff between any two connected hosts
- **Import existing rules**: One-click import of non-TR iptables rules as managed baseline
- **Port saturation warning**: Alert when conntrack usage exceeds 80%
- **SSH rate limiting**: 10 commands/second per host prevents overwhelming remote servers
- **Advanced search filters**: Filter rules by protocol, port number, source/destination address
- 8 new serialization contract tests (27 total), 1 rate limiter unit test (357 total)

### Fixed
- Parallel group-apply task failures now correctly report the failing host ID
- Import rules failure now shows error to user instead of silent swallow

## [0.5.1] - 2026-03-27

### Fixed
- TraceResult/TestPacket: serde camelCase, optional defaults, field names aligned with frontend
- SnapshotMeta: serde camelCase, replaced remote_path_v4 with ruleCount
- HitCounter: added ruleId + timestamp fields, serde camelCase
- Fail2banBan: restructured to per-IP entries with bannedAt/expiresAt timestamps
- ConntrackEntry: new struct for individual conntrack connections
- ConntrackUsage: serde camelCase
- activity_fetch_conntrack_table now returns ConntrackEntry[] (was ConntrackUsage)

### Added
- 20 serialization contract integration tests covering all IPC structs
  (prevents future FE/BE mismatches from going undetected)

## [0.5.0] - 2026-03-27

### Added
- Duplicate detection warning when adding rules (blocks at 80%+ similarity, warns at 50-80%)
- Automatic conflict detection after rules load with collapsible warning banner
- "Explain this rule" disclosure panel in rule detail with lazy loading and caching
- Credential lifecycle: store to OS keychain on connect, delete on host removal
- IP list editor: "Sync to Remote" and "Delete" buttons with feedback toasts

### Fixed
- RuleConflict serialization aligned with frontend (ruleIdA/ruleIdB, type, description)
- ConflictType enum serialized as lowercase to match frontend expectations
- Removed unused BUILTIN_CHAINS constant (zero Rust warnings)

## [0.4.0] - 2026-03-27

### Added
- State hydration from IndexedDB on app startup (hosts, groups, settings persist across reloads)
- Auto-reconnect to last active host on app launch
- `fetchActivity` single-call activity polling (replaces two separate SSH round-trips)
- 18 new QA tests for safety timer, duplicate detection, and conflict detection (328 total)

### Fixed
- `lastActiveHostId` now persisted in settings on host selection
- `activity_subscribe` returns stream ID (was void, caused runtime mismatch)
- `activity_unsubscribe` accepts correct parameter name
- Bootstrap guard prevents double-hydration on page reload

### Removed
- Unused event listener exports (`onConnectionStatus`, `onSafetyTick`, `onDrift`, `onDetectProgress`)
- `tracer_test.rs` stub (tracer has internal unit tests)

## [0.3.1] - 2026-03-27

### Fixed
- Conflict detection now accounts for negated addresses/protocols (prevents false negatives)
- Conflict detection now checks interface fields (prevents false positives on different interfaces)
- Duplicate detection handles protocol as number (e.g., 6 → tcp)
- Duplicate detection respects negation flags on addresses and protocols
- Duplicate detection compares interface fields (8-field comparison, up from 6)
- Credential store frontend schema matches Rust `Credential` enum (discriminated union)
- `cred_delete` is now idempotent (ignores not-found errors)
- Safety timer revert failure distinguished from success in error messages
- Force-apply warns instead of auto-reverting on timer scheduling failure
- `at` job cancellation verified via `atq` after `atrm`

## [0.3.0] - 2026-03-27

### Added
- Rule duplicate detection with 6-field similarity scoring (chain, protocol, port, source, dest, action)
- Rule conflict detection: shadow, redundant, and contradictory rule analysis
- Auto-provision hosts on first connect (deploys revert scripts, HMAC secret)
- Credential store commands (`cred_store`, `cred_delete`) wired to OS keychain

### Fixed
- Safety timer now fully wired end-to-end (was previously UI-only countdown with no server-side rollback)
- Safety timer auto-reverts rules if scheduling fails (no more unprotected fake countdown)
- Force-apply path now schedules safety timer (was missing revert protection entirely)
- `at` time format uses POSIX-portable minutes instead of GNU-only seconds
- Unparseable `at` job ID returns error instead of silent "unknown" success
- `revert.sh` refuses to restore if HMAC file missing on provisioned hosts
- `systemd-run` and `nohup` cancel now check exit codes
- Parser fix: implicit `--dport`/`--sport` flags no longer silently dropped

### Changed
- `SafetyTimerState` includes `mechanism` field for proper job cancellation
- `confirmChanges` IPC accepts optional `jobId` and `mechanism` parameters
- `filter_tr_chains` made public for reuse across modules
- `PortSpec` now derives `PartialEq`/`Eq` for comparison support

## [0.1.0] - 2026-03-26

### Added
- SSH connection management with password and key-based authentication
- Firewall rule CRUD (create, read, update, delete) via iptables
- Visual rule builder with protocol, port, and address fields
- Safety timer — auto-reverts rule changes if not confirmed within timeout
- Real-time traffic monitoring with packet/byte counters
- Rule templates for common configurations (SSH, HTTP, DNS, etc.)
- Export rules to iptables-save, shell script, and JSON formats
- Multi-host management with connection profiles
- Packet tracer for testing rule matches
- Chain and table management (filter, nat, mangle, raw)
- Rule reordering via drag-and-drop
- Demo mode for exploring the UI without a server connection
- Cross-platform desktop app (macOS, Linux, Windows)
