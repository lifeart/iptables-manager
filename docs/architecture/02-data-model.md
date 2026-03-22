# Data Model

## Host

```typescript
interface Host {
  id: string;
  name: string;
  connection: {
    hostname: string;
    port: number;                // default 22
    username: string;            // default "root" for v1
    authMethod: 'key' | 'password';
    keyPath?: string;
    jumpHost?: {
      hostname: string;
      port: number;
      username: string;
      keyPath?: string;
    };
  };
  capabilities: HostCapabilities | null;  // null until detection completes
  status: HostStatus;
  groupIds: string[];
  groupOrder: string[];          // priority order
  lastConnected?: number;
  lastSyncedRuleHash?: string;
  provisioned: boolean;          // true after dirs + revert script installed
  createdAt: number;
  updatedAt: number;
}

type HostStatus = 'connected' | 'connecting' | 'disconnected' | 'unreachable' | 'drifted' | 'pending';

interface HostCapabilities {
  iptablesVariant: 'iptables-legacy' | 'iptables-nft';
  // 'nft' (native, no compat) is UNSUPPORTED in v1 — host is rejected with clear message
  iptablesVersion: string;       // e.g. "1.8.7"
  safetyMechanism: 'iptables-apply' | 'at' | 'systemd-run' | 'background';
  atdRunning: boolean;           // checked separately from `at` binary existence
  ipsetAvailable: boolean;
  ip6tablesAvailable: boolean;
  detectedTools: DetectedTool[];
  cloudEnvironment?: 'aws' | 'gcp' | 'azure' | null;
  distro: { name: string; family: 'debian' | 'rhel' | 'arch' | 'alpine' | 'other' };
  interfaces: NetworkInterface[];
  runningServices: DetectedService[];
  persistenceMethod: 'iptables-persistent' | 'iptables-services' | 'manual';
  managementInterface?: string;  // interface SSH arrives on
  managementIsVpn: boolean;      // true if SSH comes through wg0/tun0
}

interface DetectedTool {
  type: 'docker' | 'fail2ban' | 'kubernetes' | 'wg-quick' | 'csf' | 'firewalld' | 'ufw';
  chains: string[];
  ruleCount: number;
}

interface NetworkInterface {
  name: string;
  type: 'physical' | 'vlan' | 'bridge' | 'bond' | 'tunnel' | 'wireguard' | 'loopback';
  addresses: string[];
  isUp: boolean;
}

interface DetectedService {
  name: string;                  // "nginx", "sshd", etc.
  ports: number[];               // [80, 443] — services can listen on multiple ports
  protocol: 'tcp' | 'udp';
  suggestedRule?: ServiceTemplate;  // auto-mapped from service-templates.json
}
```

### Service-to-Rule Mapping

A JSON mapping file defines how detected services map to suggested rules:

```json
{
  "nginx": { "label": "Web Traffic", "ports": [80, 443], "protocol": "tcp" },
  "apache2": { "label": "Web Traffic", "ports": [80, 443], "protocol": "tcp" },
  "sshd": { "label": "SSH", "ports": [22], "protocol": "tcp", "restrictToManagementIp": true },
  "node_exporter": { "label": "Monitoring", "ports": [9100], "protocol": "tcp", "restrictToLocalNet": true },
  "postgres": { "label": "PostgreSQL", "ports": [5432], "protocol": "tcp", "restrictToLocalNet": true }
}
```

## Rule

Lossless abstraction above iptables.

```typescript
interface Rule {
  id: string;

  // Layer 3 (Intent)
  label: string;
  action: 'allow' | 'block' | 'block-reject' | 'log' | 'log-block' | 'dnat' | 'snat' | 'masquerade';

  // Layer 2 (Details)
  protocol?: 'tcp' | 'udp' | 'icmp' | 'icmpv6' | 'gre' | 'esp' | 'ah' | 'sctp' | number;
  ports?: PortSpec;
  source: AddressSpec;
  destination: AddressSpec;
  direction: 'incoming' | 'outgoing' | 'forwarded';
  addressFamily: 'v4' | 'v6' | 'both';  // determines iptables vs ip6tables
  interfaceIn?: string;
  interfaceOut?: string;

  // Advanced
  conntrackStates?: ('new' | 'established' | 'related' | 'invalid')[];
  rateLimit?: { rate: number; per: 'second' | 'minute' | 'hour'; perSource: boolean; burst?: number };
  logPrefix?: string;
  logRateLimit?: { rate: number; per: 'second' | 'minute'; burst: number };  // default: 5/min burst 10
  tcpFlags?: { mask: string[]; set: string[] };
  ipsecPolicy?: { direction: 'in' | 'out'; policy: 'ipsec' | 'none' };
  conntrackHelper?: string;      // e.g. "ftp" — generates raw table CT rule
  customMatches?: RawMatch[];    // escape hatch for lossless round-trip

  // NAT targets
  dnat?: { targetIp: string; targetPort: number; hairpinNat: boolean };
  snat?: { sourceIp: string };
  // MASQUERADE has no extra fields (uses outbound interface)

  // Metadata
  comment?: string;
  origin: RuleOrigin;
  position: number;
  enabled: boolean;
  temporary?: { expiresAt: number };
  raw?: string;                  // original iptables line (authoritative for unmodified rules)
  createdAt: number;
  updatedAt: number;
}
```

### Address Family Logic

- `source: { type: 'cidr', value: '10.0.0.0/8' }` → `addressFamily: 'v4'` (auto-detected)
- `source: { type: 'cidr', value: '2001:db8::/32' }` → `addressFamily: 'v6'`
- `source: { type: 'anyone' }` → `addressFamily: 'both'`
- `source: { type: 'iplist', ipListId }` → depends on IP List content (may need two ipsets)

When `addressFamily: 'both'`, the generator emits the rule into BOTH iptables and ip6tables restore files.

### Round-Trip Fidelity

When a rule is **unmodified** (imported from the host), the `raw` field is authoritative — emit it verbatim. When a rule is **modified** through the UI, regenerate from structured fields and discard `raw`.

## Other Entities

```typescript
interface HostGroup {
  id: string;
  name: string;
  memberHostIds: string[];
  rules: Rule[];
  position: number;              // sidebar order = priority
  createdAt: number;
  updatedAt: number;
}

interface IpList {
  id: string;
  name: string;
  slug: string;                  // ASCII only, max 25 bytes (TR- prefix 3 + slug 25 + -v6 suffix 3 = 31 = ipset max)
  entries: IpListEntry[];
  usedInRuleIds: string[];
  createdAt: number;
  updatedAt: number;
}

interface Snapshot {
  id: string;
  hostId: string;
  iptablesSaveV4: string;       // filtered to TR- chains only
  iptablesSaveV6?: string;
  ipsetState?: string;
  parsedRules: Rule[];
  timestamp: number;
  description?: string;
  remotePathV4?: string;
  remotePathV6?: string;
}

interface StagedChangeset {
  hostId: string;
  changes: StagedChange[];
  undoStack: StagedChange[][];
  redoStack: StagedChange[][];
  createdAt: number;
  updatedAt: number;
}

type StagedChange = {
  correlationId?: string;       // links cross-host operations for unified undo
} & (
  | { type: 'add'; rule: Rule; position: number }
  | { type: 'delete'; ruleId: string }
  | { type: 'modify'; ruleId: string; before: Partial<Rule>; after: Partial<Rule> }
  | { type: 'reorder'; ruleId: string; fromPosition: number; toPosition: number }
  | { type: 'policy'; direction: string; policy: string }
  | { type: 'iplist-update'; ipListId: string; before: IpListEntry[]; after: IpListEntry[] }
);
```

## Host Status Transitions

```
INITIAL → connecting           (on host:connect)
connecting → connected         (SSH + detect + provision success)
connecting → unreachable       (failure, no prior connection)
connecting → disconnected      (failure, had prior connection)
connected → drifted            (rule hash mismatch on periodic check)
connected → pending            (staged change created locally)
connected → disconnected       (connection lost)
drifted → connected            (drift resolved by user)
pending → connected            (changes applied or discarded)
disconnected → connecting      (auto-reconnect or manual retry)
unreachable → connecting       (manual "Retry Connection")
```

Priority for display: `disconnected` > `connecting` > `drifted` > `pending` > `connected` > `unreachable`

## Additional Data Types

```typescript
interface BlockedEntry {
  id: string;
  timestamp: number;
  sourceIp: string;
  destPort: number;
  protocol: string;
  serviceName?: string;          // auto-labeled from port via service-templates
  interfaceIn: string;
  count: number;                 // for aggregation at high volume
}

interface ConntrackEntry {
  protocol: string;
  sourceIp: string;
  sourcePort?: number;
  destIp: string;
  destPort?: number;
  state: string;                 // ESTABLISHED, TIME_WAIT, SYN_SENT, etc.
  timeoutSec: number;
}

interface RuleConflict {
  type: 'shadow' | 'redundancy' | 'overlap' | 'contradiction';
  ruleIds: string[];
  reason: string;
}

interface MultiApplyState {
  groupId: string;
  strategy: 'canary' | 'rolling' | 'parallel';
  hostResults: Map<string, 'pending' | 'applying' | 'confirming' | 'confirmed' | 'failed' | 'skipped'>;
  phase: 'canary' | 'remaining' | 'complete';
}

interface ScheduledExpiry {
  ruleId: string;
  hostId: string;
  expiresAt: number;
  remoteJobId: string;           // at job ID or systemd timer name
}
```

## Effective Ruleset

**Always computed via memoized selector. Never stored in state.**

```typescript
// Per-host memoization keyed on inputs
const selectEffectiveRules = createMemoizedSelector(
  (state, hostId) => state.hosts.get(hostId),
  (state, hostId) => relevantGroups(state, hostId),
  (state, hostId) => state.hostStates.get(hostId)?.rules,
  (host, groups, rules) => computeEffectiveRuleset(host, groups, rules)
);
```

Merge order:
1. Loopback allow (`-i lo -j ACCEPT`, auto-included, not user-visible)
2. Connection Tracking (INVALID drop → ESTABLISHED → RELATED)
3. Group rules (in priority order, skip overridden)
4. Per-host overrides
5. Host-specific rules
6. Rate-limited LOG before "Everything Else" (for blocked log functionality)
7. Default policy ("Everything Else")
8. System rules (separate collapsed section, read-only)

## IndexedDB Schema

```
Database: "traffic-rules" v1

Object Stores:
  hosts           keyPath: "id"       indexes: [name, status]
  groups          keyPath: "id"       indexes: [name]
  ipLists         keyPath: "id"       indexes: [name]
  stagedChanges   keyPath: "hostId"   // immediate writes, no debounce
  snapshots       keyPath: "id"       indexes: [hostId, timestamp]
  settings        keyPath: "key"
  sshLog          keyPath: "id"       indexes: [hostId, timestamp]  autoIncrement
  safetyTimers    keyPath: "hostId"   // persisted BEFORE scheduling remote revert
```

### Persistence Annotations

```
@persisted (IndexedDB):  hosts, groups, ipLists, stagedChanges, snapshots, settings, safetyTimers
@ephemeral (in-memory):  hitCounters, blockedLog, conntrackUsage, sshCommandLog, operations
```

Write strategies:
- `stagedChanges`: immediate (data loss prevention)
- `safetyTimers`: immediate (must survive force-quit)
- `hosts`, `groups`, `ipLists`: batched per-tick via `queueMicrotask`
- `snapshots`: after successful apply
- `sshLog`: append, prune to last 1000/host

Error handling: catch `QuotaExceededError` on write. Warn user. Offer to delete old snapshots.
