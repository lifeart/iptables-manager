import type { AppState, EffectiveRule, Host, HostGroup, HostState, StagedChangeset } from './types';
import { computeEffectiveRuleset } from '../services/rule-merge';

// ─── createSelector with memoization ─────────────────────────

// 1 input selector
export function createSelector<S, A, R>(
  selectorA: (s: S) => A,
  combiner: (a: A) => R,
): (s: S) => R;

// 2 input selectors
export function createSelector<S, A, B, R>(
  selectorA: (s: S) => A,
  selectorB: (s: S) => B,
  combiner: (a: A, b: B) => R,
): (s: S) => R;

// 3 input selectors
export function createSelector<S, A, B, C, R>(
  selectorA: (s: S) => A,
  selectorB: (s: S) => B,
  selectorC: (s: S) => C,
  combiner: (a: A, b: B, c: C) => R,
): (s: S) => R;

// 4 input selectors
export function createSelector<S, A, B, C, D, R>(
  selectorA: (s: S) => A,
  selectorB: (s: S) => B,
  selectorC: (s: S) => C,
  selectorD: (s: S) => D,
  combiner: (a: A, b: B, c: C, d: D) => R,
): (s: S) => R;

// 5 input selectors
export function createSelector<S, A, B, C, D, E, R>(
  selectorA: (s: S) => A,
  selectorB: (s: S) => B,
  selectorC: (s: S) => C,
  selectorD: (s: S) => D,
  selectorE: (s: S) => E,
  combiner: (a: A, b: B, c: C, d: D, e: E) => R,
): (s: S) => R;

// Implementation
export function createSelector(...args: Array<(...a: unknown[]) => unknown>): (s: unknown) => unknown {
  const inputSelectors = args.slice(0, -1) as Array<(s: unknown) => unknown>;
  const combiner = args[args.length - 1] as (...vals: unknown[]) => unknown;

  let lastInputs: unknown[] | null = null;
  let lastResult: unknown = undefined;

  return (state: unknown): unknown => {
    const inputs = inputSelectors.map(sel => sel(state));

    // Check if any input changed (=== reference equality)
    if (lastInputs !== null && inputs.length === lastInputs.length) {
      let allSame = true;
      for (let i = 0; i < inputs.length; i++) {
        if (inputs[i] !== lastInputs[i]) {
          allSame = false;
          break;
        }
      }
      if (allSame) return lastResult;
    }

    lastInputs = inputs;
    lastResult = combiner(...inputs);
    return lastResult;
  };
}

// ─── App Selectors ───────────────────────────────────────────

/**
 * Select the active host object.
 */
export const selectActiveHost = createSelector(
  (s: AppState) => s.activeHostId,
  (s: AppState) => s.hosts,
  (activeId, hosts): Host | null => {
    if (!activeId) return null;
    return hosts.get(activeId) ?? null;
  },
);

/**
 * Select the ephemeral state for the active host.
 */
export const selectActiveHostState = createSelector(
  (s: AppState) => s.activeHostId,
  (s: AppState) => s.hostStates,
  (activeId, hostStates): HostState | null => {
    if (!activeId) return null;
    return hostStates.get(activeId) ?? null;
  },
);

/**
 * Compute effective rules for the active host.
 * This is the primary memoized selector — never stored in state.
 */
export const selectEffectiveRules = createSelector(
  (s: AppState): Host | undefined => s.activeHostId ? s.hosts.get(s.activeHostId) : undefined,
  (s: AppState) => s.groups,
  (s: AppState): HostState | undefined => s.activeHostId ? s.hostStates.get(s.activeHostId) : undefined,
  (s: AppState): StagedChangeset | undefined => s.activeHostId ? s.stagedChanges.get(s.activeHostId) : undefined,
  (activeHost: Host | undefined, groups: Map<string, HostGroup>, hostState: HostState | undefined, staged: StagedChangeset | undefined): EffectiveRule[] | null => {
    if (!activeHost) return null;
    // Reconstruct minimal maps for computeEffectiveRuleset
    const hosts = new Map([[activeHost.id, activeHost]]);
    const hostStates = hostState ? new Map([[activeHost.id, hostState]]) : new Map<string, HostState>();
    const stagedChanges = staged ? new Map([[activeHost.id, staged]]) : new Map<string, StagedChangeset>();
    return computeEffectiveRuleset(activeHost.id, hosts, groups, hostStates, stagedChanges);
  },
);

/**
 * Filter effective rules by current filter settings.
 */
export const selectFilteredRules = createSelector(
  selectEffectiveRules as (s: AppState) => EffectiveRule[] | null,
  (s: AppState) => s.ruleFilter,
  (rules, filter): EffectiveRule[] | null => {
    if (!rules) return null;

    let filtered = rules;

    // Filter by tab
    if (filter.tab !== 'all') {
      filtered = filtered.filter(r => {
        switch (filter.tab) {
          case 'allow':
            return r.action === 'allow';
          case 'block':
            return r.action === 'block' || r.action === 'block-reject';
          case 'log':
            return r.action === 'log' || r.action === 'log-block';
          default:
            return true;
        }
      });
    }

    // Filter by search text (label, comment, ports, source/dest addresses)
    if (filter.search) {
      const searchLower = filter.search.toLowerCase();
      filtered = filtered.filter(r => {
        // Match label
        if (r.label.toLowerCase().includes(searchLower)) return true;
        // Match comment
        if (r.comment && r.comment.toLowerCase().includes(searchLower)) return true;
        // Match port numbers
        if (r.ports) {
          if (r.ports.type === 'single' && String(r.ports.port).includes(searchLower)) return true;
          if (r.ports.type === 'range' && (`${r.ports.from}-${r.ports.to}`).includes(searchLower)) return true;
          if (r.ports.type === 'multi' && r.ports.ports.some(p => String(p).includes(searchLower))) return true;
        }
        // Match source address
        if (r.source.type === 'cidr' && r.source.value.toLowerCase().includes(searchLower)) return true;
        if (r.source.type === 'iplist' && r.source.ipListId.toLowerCase().includes(searchLower)) return true;
        // Match destination address
        if (r.destination.type === 'cidr' && r.destination.value.toLowerCase().includes(searchLower)) return true;
        if (r.destination.type === 'iplist' && r.destination.ipListId.toLowerCase().includes(searchLower)) return true;
        return false;
      });
    }

    // Filter by protocol
    if (filter.protocol) {
      filtered = filtered.filter(r => r.protocol === filter.protocol);
    }

    // Filter by port number
    if (filter.port) {
      const portNum = parseInt(filter.port, 10);
      if (!isNaN(portNum)) {
        filtered = filtered.filter(r => {
          if (!r.ports) return false;
          if (r.ports.type === 'single') return r.ports.port === portNum;
          if (r.ports.type === 'range') return portNum >= r.ports.from && portNum <= r.ports.to;
          if (r.ports.type === 'multi') return r.ports.ports.includes(portNum);
          return false;
        });
      }
    }

    // Filter by source/destination IP address
    if (filter.address) {
      const addrLower = filter.address.toLowerCase();
      filtered = filtered.filter(r => {
        if (r.source.type === 'cidr' && r.source.value.toLowerCase().includes(addrLower)) return true;
        if (r.destination.type === 'cidr' && r.destination.value.toLowerCase().includes(addrLower)) return true;
        if (r.source.type === 'iplist' && r.source.ipListId.toLowerCase().includes(addrLower)) return true;
        if (r.destination.type === 'iplist' && r.destination.ipListId.toLowerCase().includes(addrLower)) return true;
        return false;
      });
    }

    return filtered;
  },
);

/**
 * Count pending changes for the active host.
 */
export const selectPendingChangeCount = createSelector(
  (s: AppState) => s.activeHostId,
  (s: AppState) => s.stagedChanges,
  (activeId, stagedChanges): number => {
    if (!activeId) return 0;
    const changeset = stagedChanges.get(activeId);
    return changeset ? changeset.changes.length : 0;
  },
);
