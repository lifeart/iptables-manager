/**
 * Typed IPC bridge for Tauri commands and events.
 *
 * When running outside Tauri (dev mode in browser), mock implementations
 * are used so the frontend can be developed independently.
 */

import type {
  Rule,
  StagedChange,
  HostStatus,
  HitCounter,
  BlockedEntry,
} from '../store/types';

import type {
  ActivityData,
  ApplyResult,
  ChainOwnerGroup,
  ChainTraversal,
  CoexistenceProfile,
  CompareHostsResult,
  ConnectionResult,
  ConvertToIpsetResult,
  ConntrackEntry,
  DetectionResult,
  DriftCheckResult,
  DualStackDivergence,
  DuplicateCheckResult,
  Fail2banBan,
  GroupApplyResult,
  HostApplyResult,
  ImportExistingRulesResult,
  IpsetSuggestion,
  LiveTraceRequest,
  LiveTraceResult,
  MixedBackendCheckResult,
  PreviewResult,
  ProvisionResult,
  RuleConflict,
  RuleSetResult,
  SafetyTimerResult,
  SnapshotMeta,
  TestConnectionResult,
  TestPacket,
  TraceResult,
} from '../bindings';

// Re-export generated types so existing consumers keep working.
export type {
  ActivityData,
  ApplyResult,
  ChainOwnerGroup,
  ChainTraversal,
  CoexistenceProfile,
  CompareHostsResult,
  ConnectionResult,
  ConvertToIpsetResult,
  ConntrackEntry,
  DetectionResult,
  DriftCheckResult,
  DualStackDivergence,
  DuplicateCheckResult,
  Fail2banBan,
  GroupApplyResult,
  HostApplyResult,
  ImportExistingRulesResult,
  IpsetSuggestion,
  LiveTraceRequest,
  LiveTraceResult,
  MixedBackendCheckResult,
  PreviewResult,
  ProvisionResult,
  RuleConflict,
  RuleSetResult,
  SafetyTimerResult,
  SnapshotMeta,
  TestPacket,
  TraceResult,
};

// Aliases for names that differ between old bridge and generated bindings.
export type TestResult = TestConnectionResult;
export type RuleSet = RuleSetResult;

// ─── Error Type ──────────────────────────────────────────────

export class IpcError extends Error {
  constructor(
    public readonly kind: string,
    public readonly detail: string,
  ) {
    super(`${kind}: ${detail}`);
    this.name = 'IpcError';
  }
}

// ─── Frontend-only types ─────────────────────────────────────

export interface DetectionProgress {
  step: string;
  progress: number;
  total: number;
  message: string;
}

export interface ConnectionStatusEvent {
  hostId: string;
  status: HostStatus;
  latencyMs?: number;
  error?: string;
}

export interface DriftEvent {
  hostId: string;
  addedRules: number;
  removedRules: number;
  modifiedRules: number;
}

export interface SafetyTickEvent {
  hostId: string;
  remainingMs: number;
  totalMs: number;
}

export interface ConntrackEvent {
  hostId: string;
  current: number;
  max: number;
}

// ─── Tauri Detection ─────────────────────────────────────────

const IS_TAURI = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

// ─── Mock Layer ──────────────────────────────────────────────

const MOCK_DELAY = 200;

async function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function mockCall<T>(cmd: string, _args?: Record<string, unknown>): Promise<T> {
  await delay(MOCK_DELAY);

  switch (cmd) {
    case 'host:connect':
      return { hostId: _args?.hostId ?? '', status: 'connected', latencyMs: 23 } as T;
    case 'host:disconnect':
      return undefined as T;
    case 'host:test':
      return {
        success: true, latencyMs: 23, iptablesAvailable: true,
        rootAccess: true, dockerDetected: false, fail2banDetected: false,
        nftablesBackend: false,
      } as T;
    case 'host:detect':
      return { completed: true, capabilities: null } as T;
    case 'host:provision':
      return { success: true, dirsCreated: [], revertScriptInstalled: true, sudoVerified: true } as T;
    case 'host:delete':
      return undefined as T;
    case 'rules:fetch':
      return { rules: [], defaultPolicy: 'drop', rawIptablesSave: '' } as T;
    case 'rules:apply':
      return { success: true, safetyTimerActive: true, safetyTimerExpiry: Date.now() + 60000 } as T;
    case 'rules:apply-group': {
      const hostIds = (_args?.hostIds as string[]) ?? [];
      return {
        results: hostIds.map(id => ({ hostId: id, success: true, error: undefined })),
        strategy: (_args?.strategy as string) ?? 'rolling',
        total: hostIds.length,
        succeeded: hostIds.length,
        failed: 0,
      } as T;
    }
    case 'rules:preview':
      return {
        restoreContent: (_args?.changesJson as string) || '# No changes to preview',
        restoreCommand: 'sudo iptables-restore -w 5 --noflush --counters',
      } as T;
    case 'rules:revert':
      return undefined as T;
    case 'rules:confirm':
      return undefined as T;
    case 'safety:set-timer':
      return { jobId: 'mock-job-1', mechanism: 'At' } as T;
    case 'safety:clear-timer':
      return undefined as T;
    case 'rules:trace':
      return { matched: false, chain: [], verdict: 'DROP', explanation: 'No matching rule (mock)' } as T;
    case 'rules:live-trace':
      await delay(2000);
      return {
        events: [
          { timestamp: '[12345.678]', table: 'raw', chain: 'PREROUTING', ruleNum: 1, verdict: 'policy', packetInfo: 'IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP DPT=22' },
          { timestamp: '[12345.679]', table: 'filter', chain: 'INPUT', ruleNum: 3, verdict: 'rule', packetInfo: 'IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP DPT=22' },
        ],
        traceRuleInserted: true,
        traceRuleRemoved: true,
        collectionMethod: 'xtables-monitor',
      } as T;
    case 'rules:explain':
      return 'This rule allows traffic matching the specified criteria. (mock)' as T;
    case 'rules:export':
      return '# Mock export\n' as T;
    case 'rules:check-duplicate':
      return { isDuplicate: false, similarity: 0 } as T;
    case 'rules:detect-conflicts':
      return [
        {
          ruleIdA: 'demo-rule-web-http',
          ruleIdB: 'demo-rule-web-block-all',
          type: 'shadow',
          description: 'The block-all rule shadows port 80/443 traffic that is already explicitly allowed by the HTTP rule.',
        },
        {
          ruleIdA: 'demo-rule-web-ssh',
          ruleIdB: 'demo-rule-web-monitoring',
          type: 'redundant',
          description: 'Both rules allow traffic from the same source network on overlapping port ranges.',
        },
      ] as T;
    case 'snapshot:create':
      return { id: crypto.randomUUID(), hostId: _args?.hostId ?? '', timestamp: Date.now(), ruleCount: 0 } as T;
    case 'snapshot:list':
      return [] as T;
    case 'snapshot:restore':
      return { success: true, safetyTimerActive: false } as T;
    case 'iplist:sync':
      return undefined as T;
    case 'iplist:delete':
      return undefined as T;
    case 'cred:store':
      return undefined as T;
    case 'cred:delete':
      return undefined as T;
    case 'activity:subscribe':
      return 'mock-stream-id' as T;
    case 'activity:unsubscribe':
      return undefined as T;
    case 'activity:fetch-conntrack-table':
      return [] as T;
    case 'activity:fetch-bans':
      return [] as T;
    case 'activity:fetch-hit-counters':
      return [] as T;
    case 'activity:fetch-conntrack':
      return { current: 0, max: 0 } as T;
    case 'activity:fetch':
      return { hitCounters: [], conntrackCurrent: 0, conntrackMax: 0 } as T;
    case 'mixed-backend:check':
      return { isMixed: false, legacyRuleCount: 0, nftRuleCount: 0, remediation: '' } as T;
    case 'drift:check':
      return { drifted: false, addedRules: 0, removedRules: 0, modifiedRules: 0, changes: [] } as T;
    case 'drift:reset':
      return undefined as T;
    case 'ipset:analyze':
      return [] as T;
    case 'ipset:convert':
      return { ipsetCreated: true, ipsetName: 'TR-mock-blocklist', entriesAdded: 0, rulesReplaced: 0 } as T;
    case 'hosts:compare':
      return { onlyInA: [], onlyInB: [], different: [], identical: 0 } as T;
    case 'rules:import-existing':
      return { rules: { tables: {} }, rawIptablesSave: '', nonTrRuleCount: 0 } as T;
    case 'dualstack:check-divergence':
      return {
        diverged: false,
        v4OnlyChains: [],
        v6OnlyChains: [],
        ruleCountV4: 0,
        ruleCountV6: 0,
      } as T;
    case 'coexistence:profile':
      return {
        owners: [
          { owner: 'Docker', chains: ['DOCKER', 'DOCKER-USER'], ruleCount: 8, isAppManaged: false },
          { owner: 'fail2ban', chains: ['f2b-sshd'], ruleCount: 3, isAppManaged: false },
          { owner: 'App', chains: ['TR-INPUT', 'TR-CONNTRACK'], ruleCount: 5, isAppManaged: true },
          { owner: 'Built-in', chains: ['INPUT', 'FORWARD', 'OUTPUT'], ruleCount: 0, isAppManaged: false },
        ],
        totalChains: 8,
        appManagedChains: 2,
        externalChains: 3,
      } as T;
    default:
      return undefined as T;
  }
}

// ─── Command Name Mapping ────────────────────────────────────
// Maps frontend colon-separated command names to Rust snake_case fn names.
// Commands not in this map are converted by replacing colons with underscores.
const COMMAND_NAME_MAP: Record<string, string> = {
  'host:connect': 'host_connect',
  'host:disconnect': 'host_disconnect',
  'host:test': 'host_test',
  'host:detect': 'host_detect',
  'host:delete': 'host_delete',
  'host:provision': 'host_provision',
  'rules:fetch': 'fetch_rules',
  'rules:apply': 'rules_apply',
  'rules:apply-group': 'rules_apply_group',
  'rules:preview': 'rules_preview',
  'rules:revert': 'rules_revert',
  'rules:confirm': 'rules_confirm',
  'rules:explain': 'explain_rule_cmd',
  'rules:export': 'export_rules',
  'rules:trace': 'rules_trace',
  'rules:live-trace': 'rules_live_trace',
  'rules:check-duplicate': 'rules_check_duplicate',
  'rules:detect-conflicts': 'rules_detect_conflicts',
  'snapshot:create': 'snapshot_create',
  'snapshot:list': 'snapshot_list',
  'snapshot:restore': 'snapshot_restore',
  'iplist:sync': 'iplist_sync',
  'iplist:delete': 'iplist_delete',
  'cred:store': 'cred_store',
  'cred:delete': 'cred_delete',
  'activity:subscribe': 'activity_subscribe',
  'activity:unsubscribe': 'activity_unsubscribe',
  'activity:fetch-conntrack-table': 'activity_fetch_conntrack_table',
  'activity:fetch-bans': 'activity_fetch_bans',
  'activity:fetch-hit-counters': 'activity_fetch_hit_counters',
  'activity:fetch-conntrack': 'activity_fetch_conntrack',
  'activity:fetch': 'fetch_activity',
  'safety:set-timer': 'set_safety_timer',
  'safety:clear-timer': 'clear_safety_timer',
  'mixed-backend:check': 'check_mixed_backend',
  'drift:check': 'check_drift',
  'drift:reset': 'reset_drift',
  'hosts:compare': 'compare_hosts',
  'rules:import-existing': 'import_existing_rules',
  'ipset:analyze': 'analyze_ipset_opportunities',
  'ipset:convert': 'convert_to_ipset',
  'dualstack:check-divergence': 'check_v4_v6_divergence',
  'coexistence:profile': 'get_coexistence_profile',
};

function mapCommandName(cmd: string): string {
  return COMMAND_NAME_MAP[cmd] ?? cmd.replace(/[:-]/g, '_');
}

// ─── Core IPC Call ────────────────────────────────────────────

async function ipcCall<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!IS_TAURI) return mockCall<T>(cmd, args);
  const { invoke } = await import('@tauri-apps/api/core');
  // Tauri 2.x derives command names from Rust fn names (snake_case).
  // Frontend uses colon-separated names (e.g. 'host:connect') for readability,
  // so we convert: 'host:connect' -> 'host_connect', 'rules:fetch' -> 'fetch_rules', etc.
  const tauriCmd = mapCommandName(cmd);
  try {
    return await invoke<T>(tauriCmd, args);
  } catch (e) {
    let err: Record<string, unknown>;
    if (typeof e === 'string') {
      try {
        err = JSON.parse(e);
      } catch {
        throw new IpcError('Unknown', e);
      }
    } else {
      err = e as Record<string, unknown>;
    }
    const kind = typeof err.kind === 'string' ? err.kind : 'Unknown';
    const detail = typeof err.detail === 'string'
      ? err.detail
      : typeof err.detail === 'object' && err.detail !== null
        ? JSON.stringify(err.detail)
        : String(e);
    throw new IpcError(kind, detail);
  }
}

// ─── Typed Command Exports ───────────────────────────────────

// Connection
export const connectHost = (
  hostId: string,
  hostname?: string,
  port?: number,
  username?: string,
  authMethod?: string,
  keyPath?: string,
) =>
  ipcCall<ConnectionResult>('host:connect', {
    hostId,
    hostname: hostname ?? '',
    port: port ?? 22,
    username: username ?? 'root',
    authMethod: authMethod ?? 'key',
    keyPath: keyPath ?? null,
  });

export const disconnectHost = (hostId: string) =>
  ipcCall<void>('host:disconnect', { hostId });

export const testConnection = (params: { hostname: string; port: number; username: string; authMethod: string; keyPath?: string }) =>
  ipcCall<TestResult>('host:test', { params });

export const detectHost = (hostId: string) =>
  ipcCall<DetectionResult>('host:detect', { hostId });

export const provisionHost = (hostId: string) =>
  ipcCall<ProvisionResult>('host:provision', { hostId });

export const deleteHost = (hostId: string, removeRemoteData: boolean) =>
  ipcCall<void>('host:delete', { hostId, removeRemoteData: removeRemoteData });

// Rules
export const fetchRules = (hostId: string) =>
  ipcCall<RuleSet>('rules:fetch', { hostId: hostId });

export const applyChanges = (hostId: string, changes: StagedChange[], safetyTimeoutSecs?: number) =>
  ipcCall<ApplyResult>('rules:apply', { hostId, changesJson: JSON.stringify(changes), safetyTimeoutSecs: safetyTimeoutSecs ?? null });

export const applyToGroup = (
  hostIds: string[],
  changesJson: string,
  strategy: 'canary' | 'rolling' | 'parallel',
) =>
  ipcCall<GroupApplyResult>('rules:apply-group', { hostIds, changesJson, strategy });

export const previewChanges = (hostId: string, changes: StagedChange[]) =>
  ipcCall<PreviewResult>('rules:preview', { hostId, changesJson: JSON.stringify(changes) });

export const revertChanges = (hostId: string) =>
  ipcCall<void>('rules:revert', { hostId });

export const setSafetyTimer = (hostId: string, timeoutSecs: number) =>
  ipcCall<SafetyTimerResult>('safety:set-timer', { hostId, timeoutSecs });

export const clearSafetyTimer = (hostId: string, jobId: string, mechanism?: string) =>
  ipcCall<void>('safety:clear-timer', { hostId, jobId, mechanism: mechanism ?? null });

export const confirmChanges = (hostId: string, jobId?: string, mechanism?: string) =>
  ipcCall<void>('rules:confirm', { hostId, jobId: jobId ?? null, mechanism: mechanism ?? null });

export const tracePacket = (hostId: string, packet: TestPacket) =>
  ipcCall<TraceResult>('rules:trace', { hostId, packet });

export const liveTrace = (hostId: string, request: LiveTraceRequest) =>
  ipcCall<LiveTraceResult>('rules:live-trace', { hostId, request });

export const explainRule = (ruleSpec: string) =>
  ipcCall<string>('rules:explain', { ruleJson: ruleSpec });

export const exportRules = (hostId: string, format: 'shell' | 'ansible' | 'iptables-save') =>
  ipcCall<string>('rules:export', { hostId, format });

export const checkDuplicate = (hostId: string, rule: Partial<Rule>) =>
  ipcCall<DuplicateCheckResult>('rules:check-duplicate', { hostId, rule });

export const detectConflicts = (hostId: string) =>
  ipcCall<RuleConflict[]>('rules:detect-conflicts', { hostId });

// Snapshots
export const createSnapshot = (hostId: string, description?: string) =>
  ipcCall<SnapshotMeta>('snapshot:create', { hostId, description });

export const listSnapshots = (hostId: string) =>
  ipcCall<SnapshotMeta[]>('snapshot:list', { hostId });

export const restoreSnapshot = (hostId: string, snapshotId: string) =>
  ipcCall<ApplyResult>('snapshot:restore', { hostId, snapshotId });

// IP Lists
export const syncIpList = (hostId: string, ipListId: string) =>
  ipcCall<void>('iplist:sync', { hostId, ipListId });

export const deleteIpList = (hostId: string, ipListId: string) =>
  ipcCall<void>('iplist:delete', { hostId, ipListId });

// Credentials
export type CredentialPayload =
  | { type: 'Password'; username: string; password: string }
  | { type: 'KeyFile'; username: string; key_path: string; passphrase?: string | null }
  | { type: 'Agent'; username: string };

export const storeCredential = (hostId: string, credential: CredentialPayload) =>
  ipcCall<void>('cred:store', { hostId, credential });

export const deleteCredential = (hostId: string) =>
  ipcCall<void>('cred:delete', { hostId });

// Activity
export const subscribeActivity = (hostId: string) =>
  ipcCall<string>('activity:subscribe', { hostId });

export const unsubscribeActivity = (streamId: string) =>
  ipcCall<void>('activity:unsubscribe', { streamId });

export const fetchConntrackTable = (hostId: string) =>
  ipcCall<ConntrackEntry[]>('activity:fetch-conntrack-table', { hostId });

export const fetchBans = (hostId: string) =>
  ipcCall<Fail2banBan[]>('activity:fetch-bans', { hostId });

export const fetchHitCounters = (hostId: string) =>
  ipcCall<HitCounter[]>('activity:fetch-hit-counters', { hostId });

export const fetchConntrack = (hostId: string) =>
  ipcCall<{ current: number; max: number }>('activity:fetch-conntrack', { hostId });

export const fetchActivity = (hostId: string) =>
  ipcCall<ActivityData>('activity:fetch', { hostId });

// Mixed Backend Detection
export const checkMixedBackend = (hostId: string) =>
  ipcCall<MixedBackendCheckResult>('mixed-backend:check', { hostId });

// Drift Detection
export const checkDrift = (hostId: string) =>
  ipcCall<DriftCheckResult>('drift:check', { hostId });

export const resetDrift = (hostId: string) =>
  ipcCall<void>('drift:reset', { hostId });

// Cross-host comparison
export const compareHosts = (hostIdA: string, hostIdB: string) =>
  ipcCall<CompareHostsResult>('hosts:compare', { hostIdA, hostIdB });

// Import existing (non-TR) rules as baseline
export const importExistingRules = (hostId: string) =>
  ipcCall<ImportExistingRulesResult>('rules:import-existing', { hostId });

// Ipset optimization
export const analyzeIpsetOpportunities = (hostId: string) =>
  ipcCall<IpsetSuggestion[]>('ipset:analyze', { hostId });

export const convertToIpset = (hostId: string, suggestion: string) =>
  ipcCall<ConvertToIpsetResult>('ipset:convert', { hostId, suggestionJson: suggestion });

// Dual-stack divergence check
export const checkDualStackDivergence = (hostId: string) =>
  ipcCall<DualStackDivergence>('dualstack:check-divergence', { hostId });

// Coexistence profile
export const getCoexistenceProfile = (hostId: string) =>
  ipcCall<CoexistenceProfile>('coexistence:profile', { hostId });

// ─── Event Listeners ─────────────────────────────────────────

type UnlistenFn = () => void;

/**
 * Create an event listener that respects an AbortSignal for cleanup.
 * Returns a cleanup function for manual use.
 */
async function listenEvent<T>(
  eventName: string,
  handler: (payload: T) => void,
  signal?: AbortSignal,
): Promise<UnlistenFn> {
  if (!IS_TAURI) {
    // In mock mode, return a no-op unlisten
    return () => {};
  }

  const { listen } = await import('@tauri-apps/api/event');
  const unlisten = await listen<T>(eventName, (e) => handler(e.payload));

  if (signal) {
    if (signal.aborted) {
      unlisten();
      return () => {};
    }
    signal.addEventListener('abort', () => unlisten());
  }

  return unlisten;
}

export const onHitCounters = (handler: (payload: { hostId: string; counters: HitCounter[] }) => void, signal?: AbortSignal) =>
  listenEvent<{ hostId: string; counters: HitCounter[] }>('activity:hit-counters', handler, signal);

export const onBlockedEntry = (handler: (payload: { hostId: string; entry: BlockedEntry }) => void, signal?: AbortSignal) =>
  listenEvent<{ hostId: string; entry: BlockedEntry }>('activity:blocked', handler, signal);

export const onConntrack = (handler: (payload: ConntrackEvent) => void, signal?: AbortSignal) =>
  listenEvent<ConntrackEvent>('activity:conntrack', handler, signal);

