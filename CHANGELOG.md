# Changelog

## [0.2.0] - 2026-03-27

### Fixed
- Safety timer now fully wired end-to-end (was previously UI-only countdown with no server-side rollback)
- `rules_apply` creates HMAC-signed backup of current rules before applying changes
- `rules_confirm` cancels scheduled revert job and cleans up backup files (was a no-op stub)
- Frontend calls `set_safety_timer` IPC to schedule actual remote revert via at/systemd-run/nohup
- Revert button cancels scheduled job before reverting rules

### Changed
- `SafetyTimerState` now includes `mechanism` field for proper job cancellation
- `confirmChanges` IPC accepts optional `jobId` and `mechanism` parameters
- `filter_tr_chains` made public for reuse across modules

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
