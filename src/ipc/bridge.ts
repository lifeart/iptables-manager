/**
 * Typed IPC bridge for Tauri commands and events.
 *
 * When running outside Tauri (dev mode in browser), mock implementations
 * are used so the frontend can be developed independently.
 */

import type {
  Rule,
  StagedChange,
  Host,
  HostStatus,
  HitCounter,
  BlockedEntry,
  Snapshot,
} from '../store/types';

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

// ─── IPC Result Types ────────────────────────────────────────

export interface ConnectionResult {
  hostId: string;
  status: HostStatus;
  latencyMs: number;
}

export interface TestResult {
  success: boolean;
  latencyMs: number;
  iptablesAvailable: boolean;
  rootAccess: boolean;
  dockerDetected: boolean;
  fail2banDetected: boolean;
  nftablesBackend: boolean;
  error?: string;
}

export interface DetectionResult {
  completed: boolean;
  capabilities: Host['capabilities'];
}

export interface DetectionProgress {
  step: string;
  progress: number;
  total: number;
  message: string;
}

export interface ProvisionResult {
  success: boolean;
  dirsCreated: string[];
  revertScriptInstalled: boolean;
  sudoVerified: boolean;
}

export interface RuleSet {
  rules: Rule[];
  defaultPolicy: string;
  rawIptablesSave: string;
}

export interface ApplyResult {
  success: boolean;
  safetyTimerActive: boolean;
  safetyTimerExpiry?: number;
  remoteJobId?: string;
}

export interface TraceResult {
  matched: boolean;
  matchedRuleId?: string;
  chain: string[];
  verdict: string;
  explanation: string;
}

export interface TestPacket {
  sourceIp: string;
  destIp: string;
  destPort: number;
  protocol: 'tcp' | 'udp' | 'icmp';
  interfaceIn?: string;
}

export interface DuplicateCheckResult {
  isDuplicate: boolean;
  existingRuleId?: string;
  similarity: number;
}

export interface RuleConflict {
  ruleIdA: string;
  ruleIdB: string;
  type: 'shadow' | 'contradiction' | 'redundant';
  description: string;
}

export interface SnapshotMeta {
  id: string;
  hostId: string;
  timestamp: number;
  description?: string;
  ruleCount: number;
}

export interface ConntrackEntry {
  protocol: string;
  sourceIp: string;
  destIp: string;
  sourcePort: number;
  destPort: number;
  state: string;
  ttl: number;
}

export interface Fail2banBan {
  jail: string;
  ip: string;
  bannedAt: number;
  expiresAt: number | null;
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
    case 'rules:revert':
      return undefined as T;
    case 'rules:confirm':
      return undefined as T;
    case 'rules:trace':
      return { matched: false, chain: [], verdict: 'DROP', explanation: 'No matching rule (mock)' } as T;
    case 'rules:explain':
      return 'This rule allows traffic matching the specified criteria. (mock)' as T;
    case 'rules:export':
      return '# Mock export\n' as T;
    case 'rules:check-duplicate':
      return { isDuplicate: false, similarity: 0 } as T;
    case 'rules:detect-conflicts':
      return [] as T;
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
    default:
      console.warn(`[IPC Mock] Unknown command: ${cmd}`);
      return undefined as T;
  }
}

// ─── Core IPC Call ────────────────────────────────────────────

async function ipcCall<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!IS_TAURI) return mockCall<T>(cmd, args);
  const { invoke } = await import('@tauri-apps/api/core');
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    const err = typeof e === 'string' ? JSON.parse(e) : e;
    throw new IpcError(err.kind ?? 'Unknown', err.detail ?? String(e));
  }
}

// ─── Typed Command Exports ───────────────────────────────────

// Connection
export const connectHost = (hostId: string) =>
  ipcCall<ConnectionResult>('host:connect', { hostId });

export const disconnectHost = (hostId: string) =>
  ipcCall<void>('host:disconnect', { hostId });

export const testConnection = (params: { hostname: string; port: number; username: string; authMethod: string; keyPath?: string }) =>
  ipcCall<TestResult>('host:test', { params });

export const detectHost = (hostId: string) =>
  ipcCall<DetectionResult>('host:detect', { hostId });

export const provisionHost = (hostId: string) =>
  ipcCall<ProvisionResult>('host:provision', { hostId });

export const deleteHost = (hostId: string, removeRemoteData: boolean) =>
  ipcCall<void>('host:delete', { hostId, removeRemoteData });

// Rules
export const fetchRules = (hostId: string) =>
  ipcCall<RuleSet>('rules:fetch', { hostId });

export const applyChanges = (hostId: string, changes: StagedChange[]) =>
  ipcCall<ApplyResult>('rules:apply', { hostId, changes });

export const revertChanges = (hostId: string) =>
  ipcCall<void>('rules:revert', { hostId });

export const confirmChanges = (hostId: string) =>
  ipcCall<void>('rules:confirm', { hostId });

export const tracePacket = (hostId: string, packet: TestPacket) =>
  ipcCall<TraceResult>('rules:trace', { hostId, packet });

export const explainRule = (ruleSpec: string) =>
  ipcCall<string>('rules:explain', { ruleSpec });

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
export const storeCredential = (hostId: string, credential: { type: string; value: string }) =>
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

export const onConnectionStatus = (handler: (payload: ConnectionStatusEvent) => void, signal?: AbortSignal) =>
  listenEvent<ConnectionStatusEvent>('connection:status', handler, signal);

export const onHitCounters = (handler: (payload: { hostId: string; counters: HitCounter[] }) => void, signal?: AbortSignal) =>
  listenEvent<{ hostId: string; counters: HitCounter[] }>('activity:hit-counters', handler, signal);

export const onBlockedEntry = (handler: (payload: { hostId: string; entry: BlockedEntry }) => void, signal?: AbortSignal) =>
  listenEvent<{ hostId: string; entry: BlockedEntry }>('activity:blocked', handler, signal);

export const onConntrack = (handler: (payload: ConntrackEvent) => void, signal?: AbortSignal) =>
  listenEvent<ConntrackEvent>('activity:conntrack', handler, signal);

export const onSafetyTick = (handler: (payload: SafetyTickEvent) => void, signal?: AbortSignal) =>
  listenEvent<SafetyTickEvent>('safety:tick', handler, signal);

export const onDrift = (handler: (payload: DriftEvent) => void, signal?: AbortSignal) =>
  listenEvent<DriftEvent>('host:drift', handler, signal);

export const onDetectProgress = (handler: (payload: DetectionProgress) => void, signal?: AbortSignal) =>
  listenEvent<DetectionProgress>('host:detect-progress', handler, signal);
