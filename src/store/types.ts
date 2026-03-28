// App State — central state shape for the Traffic Rules application.
// Fields annotated @persisted are synced to IndexedDB.
// Fields annotated @ephemeral are in-memory only.

import type { RuleConflict, DiffEntry } from '../bindings';
export type { RuleConflict, DiffEntry };

// ─── Domain Types ───────────────────────────────────────────────

export type HostStatus =
  | 'connected'
  | 'connecting'
  | 'disconnected'
  | 'unreachable'
  | 'drifted'
  | 'pending';

export interface HostCapabilities {
  iptablesVariant: 'iptables-legacy' | 'iptables-nft';
  iptablesVersion: string;
  safetyMechanism: 'iptables-apply' | 'at' | 'systemd-run' | 'background';
  atdRunning: boolean;
  ipsetAvailable: boolean;
  ip6tablesAvailable: boolean;
  detectedTools: DetectedTool[];
  cloudEnvironment?: 'aws' | 'gcp' | 'azure' | null;
  distro: { name: string; family: 'debian' | 'rhel' | 'arch' | 'alpine' | 'other' };
  interfaces: NetworkInterface[];
  runningServices: DetectedService[];
  persistenceMethod: 'iptables-persistent' | 'iptables-services' | 'manual';
  managementInterface?: string;
  managementIsVpn: boolean;
}

export interface DetectedTool {
  type: 'docker' | 'fail2ban' | 'kubernetes' | 'wg-quick' | 'csf' | 'firewalld' | 'ufw';
  chains: string[];
  ruleCount: number;
}

export interface NetworkInterface {
  name: string;
  type: 'physical' | 'vlan' | 'bridge' | 'bond' | 'tunnel' | 'wireguard' | 'loopback';
  addresses: string[];
  isUp: boolean;
}

export interface ServiceTemplate {
  label: string;
  ports: number[];
  protocol: 'tcp' | 'udp';
  restrictToManagementIp?: boolean;
  restrictToLocalNet?: boolean;
}

export interface DetectedService {
  name: string;
  ports: number[];
  protocol: 'tcp' | 'udp';
  suggestedRule?: ServiceTemplate;
}

export interface Host {
  id: string;
  name: string;
  connection: {
    hostname: string;
    port: number;
    username: string;
    authMethod: 'key' | 'password';
    keyPath?: string;
    jumpHost?: {
      hostname: string;
      port: number;
      username: string;
      keyPath?: string;
    };
  };
  capabilities: HostCapabilities | null;
  status: HostStatus;
  groupIds: string[];
  groupOrder: string[];
  lastConnected?: number;
  lastSyncedRuleHash?: string;
  provisioned: boolean;
  createdAt: number;
  updatedAt: number;
}

export type PortSpec =
  | { type: 'single'; port: number }
  | { type: 'range'; from: number; to: number }
  | { type: 'multi'; ports: number[] };

export type AddressSpec =
  | { type: 'anyone' }
  | { type: 'cidr'; value: string }
  | { type: 'iplist'; ipListId: string };

export type RuleOrigin =
  | { type: 'user' }
  | { type: 'imported' }
  | { type: 'group'; groupId: string }
  | { type: 'system'; owner: string };

export interface RawMatch {
  module: string;
  args: string;
}

export interface Rule {
  id: string;
  label: string;
  action: 'allow' | 'block' | 'block-reject' | 'log' | 'log-block' | 'dnat' | 'snat' | 'masquerade';
  protocol?: 'tcp' | 'udp' | 'icmp' | 'icmpv6' | 'gre' | 'esp' | 'ah' | 'sctp' | number;
  ports?: PortSpec;
  source: AddressSpec;
  destination: AddressSpec;
  direction: 'incoming' | 'outgoing' | 'forwarded';
  addressFamily: 'v4' | 'v6' | 'both';
  interfaceIn?: string;
  interfaceOut?: string;
  conntrackStates?: ('new' | 'established' | 'related' | 'invalid')[];
  rateLimit?: { rate: number; per: 'second' | 'minute' | 'hour'; perSource: boolean; burst?: number };
  logPrefix?: string;
  logRateLimit?: { rate: number; per: 'second' | 'minute'; burst: number };
  tcpFlags?: { mask: string[]; set: string[] };
  ipsecPolicy?: { direction: 'in' | 'out'; policy: 'ipsec' | 'none' };
  conntrackHelper?: string;
  customMatches?: RawMatch[];
  dnat?: { targetIp: string; targetPort: number; hairpinNat: boolean };
  snat?: { sourceIp: string };
  comment?: string;
  origin: RuleOrigin;
  position: number;
  enabled: boolean;
  temporary?: { expiresAt: number };
  raw?: string;
  createdAt: number;
  updatedAt: number;
}

export interface HostGroup {
  id: string;
  name: string;
  memberHostIds: string[];
  rules: Rule[];
  position: number;
  createdAt: number;
  updatedAt: number;
}

export interface IpListEntry {
  address: string;
  comment?: string;
}

export interface IpList {
  id: string;
  name: string;
  slug: string;
  entries: IpListEntry[];
  usedInRuleIds: string[];
  createdAt: number;
  updatedAt: number;
}

export interface Snapshot {
  id: string;
  hostId: string;
  iptablesSaveV4: string;
  iptablesSaveV6?: string;
  ipsetState?: string;
  parsedRules: Rule[];
  timestamp: number;
  description?: string;
  remotePathV4?: string;
  remotePathV6?: string;
}

export type StagedChange = {
  correlationId?: string;
} & (
  | { type: 'add'; rule: Rule; position: number }
  | { type: 'delete'; ruleId: string }
  | { type: 'modify'; ruleId: string; before: Partial<Rule>; after: Partial<Rule> }
  | { type: 'reorder'; ruleId: string; fromPosition: number; toPosition: number }
  | { type: 'policy'; direction: string; policy: string }
  | { type: 'iplist-update'; ipListId: string; before: IpListEntry[]; after: IpListEntry[] }
);

export interface StagedChangeset {
  hostId: string;
  changes: StagedChange[];
  undoStack: StagedChange[][];
  redoStack: StagedChange[][];
  createdAt: number;
  updatedAt: number;
}

export interface SafetyTimerState {
  hostId: string;
  expiresAt: number;
  remoteJobId: string;
  mechanism: string;
  startedAt: number;
}

export interface HitCounter {
  ruleId: string;
  packets: number;
  bytes: number;
  timestamp: number;
  chain: string;
  ruleNum: number;
  target: string;
  protocol: string;
  source: string;
  destination: string;
}

export interface BlockedEntry {
  id: string;
  timestamp: number;
  sourceIp: string;
  destPort: number;
  protocol: string;
  serviceName?: string;
  interfaceIn: string;
  count: number;
}

export interface SshLogEntry {
  id?: number;
  hostId: string;
  command: string;
  output: string;
  exitCode: number;
  timestamp: number;
}

export interface AuditEntry {
  id: string;
  timestamp: number;
  hostId: string;
  hostName: string;
  action: 'apply' | 'revert' | 'confirm' | 'snapshot-restore' | 'group-apply';
  changeCount: number;
  details: string;
}

export interface AppSettings {
  theme: 'light' | 'dark' | 'system';
  lastActiveHostId?: string;
  defaultSafetyTimeout: number;
  pollIntervalMs: number;
  autoReconnect: boolean;
  showSystemRules: boolean;
  confirmBeforeApply: boolean;
}

export type SidePanelContent =
  | { type: 'rule-detail'; ruleId: string }
  | { type: 'rule-edit'; ruleId: string }
  | { type: 'rule-new' }
  | { type: 'snapshot-history' }
  | { type: 'port-forward' }
  | { type: 'source-nat' }
  | { type: 'settings' }
  | { type: 'host-settings' }
  | { type: 'group-edit'; groupId: string }
  | { type: 'iplist-edit'; ipListId: string };

export type DialogType =
  | 'add-host'
  | 'quick-block'
  | 'create-group'
  | 'create-iplist'
  | 'first-setup'
  | 'multi-apply'
  | 'compare-hosts'
  | null;

export interface DriftInfo {
  hostId: string;
  addedRules: number;
  removedRules: number;
  modifiedRules: number;
  detectedAt: number;
  changes: DiffEntry[];
}

export interface OperationState {
  type: string;
  hostId?: string;
  status: 'pending' | 'success' | 'error';
  error?: string;
  startedAt: number;
}

export interface HostState {
  rules: Rule[];
  hitCounters: Map<string, HitCounter>;
  prevHitCounters: Map<string, HitCounter>;
  blockedLog: BlockedEntry[];
  conntrackUsage: { current: number; max: number };
  sshCommandLog: SshLogEntry[];
  ruleConflicts: RuleConflict[];
}

// ─── Effective Rule (computed, never stored) ───────────────────

export interface EffectiveRule extends Rule {
  sourceType: 'host' | 'group' | 'system' | 'auto';
  groupName?: string;
  overridden: boolean;
  section:
    | 'loopback'
    | 'conntrack'
    | 'group'
    | 'host-override'
    | 'host'
    | 'log-catchall'
    | 'default-policy'
    | 'system';
}

// ─── App State ─────────────────────────────────────────────────

export interface AppState {
  // Navigation
  activeHostId: string | null;
  activeTab: 'rules' | 'activity' | 'terminal';
  activeTerminalSubTab: 'raw' | 'tracer' | 'sshlog';
  sidePanelOpen: boolean;
  sidePanelContent: SidePanelContent | null;
  splitPanelOpen: boolean;
  splitPanelContent: 'activity' | 'terminal';
  sidebarCollapsed: boolean;
  commandPaletteOpen: boolean;
  quickBlockOpen: boolean;
  openDialog: DialogType;
  ruleFilter: {
    tab: 'all' | 'allow' | 'block' | 'log';
    search: string;
    protocol: '' | 'tcp' | 'udp' | 'icmp';
    port: string;
    address: string;
  };

  // @persisted — synced to IndexedDB
  hosts: Map<string, Host>;
  groups: Map<string, HostGroup>;
  ipLists: Map<string, IpList>;
  settings: AppSettings;

  // @persisted (immediate writes)
  stagedChanges: Map<string, StagedChangeset>;
  safetyTimers: Map<string, SafetyTimerState>;

  // @persisted — audit trail of rule changes
  auditLog: AuditEntry[];

  // @ephemeral — re-fetched on connect, never persisted
  hostStates: Map<string, HostState>;

  // Async operation tracking
  operations: Map<string, OperationState>;

  // @ephemeral — drift detection alerts per host
  driftAlerts: Map<string, DriftInfo>;

  // Storage
  storageQuotaExceeded: boolean;
}

// ─── Initial State ─────────────────────────────────────────────

export function createInitialState(): AppState {
  return {
    activeHostId: null,
    activeTab: 'rules',
    activeTerminalSubTab: 'raw',
    sidePanelOpen: false,
    sidePanelContent: null,
    splitPanelOpen: false,
    splitPanelContent: 'activity',
    sidebarCollapsed: false,
    commandPaletteOpen: false,
    quickBlockOpen: false,
    openDialog: null,
    ruleFilter: { tab: 'all', search: '', protocol: '', port: '', address: '' },

    hosts: new Map(),
    groups: new Map(),
    ipLists: new Map(),
    settings: {
      theme: 'system',
      defaultSafetyTimeout: 60,
      pollIntervalMs: 30000,
      autoReconnect: true,
      showSystemRules: false,
      confirmBeforeApply: true,
    },

    stagedChanges: new Map(),
    safetyTimers: new Map(),
    auditLog: [],
    hostStates: new Map(),
    operations: new Map(),
    driftAlerts: new Map(),
    storageQuotaExceeded: false,
  };
}
