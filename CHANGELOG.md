# Changelog

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
