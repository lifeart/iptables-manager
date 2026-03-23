import type { Action } from './actions';
import type {
  AppState,
  HostState,
  StagedChangeset,
  HitCounter,
} from './types';

const BLOCKED_LOG_CAP = 500;
const SSH_LOG_CAP = 1000;

function cloneMap<K, V>(map: Map<K, V>): Map<K, V> {
  return new Map(map);
}

function ensureHostState(state: AppState, hostId: string): HostState {
  const existing = state.hostStates.get(hostId);
  if (existing) return existing;
  return {
    rules: [],
    hitCounters: new Map(),
    prevHitCounters: new Map(),
    blockedLog: [],
    conntrackUsage: { current: 0, max: 0 },
    sshCommandLog: [],
  };
}

export function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    // ─── Hydration ───────────────────────────────────────
    case 'HYDRATE': {
      const { hosts, groups, ipLists, stagedChanges, safetyTimers, settings } = action.payload;
      const newState = { ...state };

      if (hosts) {
        newState.hosts = new Map(hosts.map(h => [h.id, h]));
      }
      if (groups) {
        newState.groups = new Map(groups.map(g => [g.id, g]));
      }
      if (ipLists) {
        newState.ipLists = new Map(ipLists.map(l => [l.id, l]));
      }
      if (stagedChanges) {
        newState.stagedChanges = new Map(stagedChanges.map(s => [s.hostId, s]));
      }
      if (safetyTimers) {
        newState.safetyTimers = new Map(safetyTimers.map(t => [t.hostId, t]));
      }
      if (settings) {
        newState.settings = { ...state.settings, ...settings };
      }
      return newState;
    }

    // ─── Navigation ──────────────────────────────────────
    case 'SET_ACTIVE_HOST':
      return { ...state, activeHostId: action.hostId };

    case 'SET_ACTIVE_TAB':
      return { ...state, activeTab: action.tab };

    case 'SET_TERMINAL_SUB_TAB':
      return { ...state, activeTerminalSubTab: action.subTab };

    case 'TOGGLE_SIDE_PANEL':
      return {
        ...state,
        sidePanelOpen: action.open !== undefined ? action.open : !state.sidePanelOpen,
      };

    case 'SET_SIDE_PANEL_CONTENT':
      return {
        ...state,
        sidePanelContent: action.content,
        sidePanelOpen: action.content !== null,
      };

    case 'TOGGLE_SPLIT_PANEL':
      return {
        ...state,
        splitPanelOpen: action.open !== undefined ? action.open : !state.splitPanelOpen,
      };

    case 'SET_SPLIT_PANEL_CONTENT':
      return { ...state, splitPanelContent: action.content };

    case 'TOGGLE_SIDEBAR':
      return {
        ...state,
        sidebarCollapsed: action.collapsed !== undefined ? action.collapsed : !state.sidebarCollapsed,
      };

    case 'TOGGLE_COMMAND_PALETTE':
      return {
        ...state,
        commandPaletteOpen: action.open !== undefined ? action.open : !state.commandPaletteOpen,
      };

    case 'TOGGLE_QUICK_BLOCK':
      return {
        ...state,
        quickBlockOpen: action.open !== undefined ? action.open : !state.quickBlockOpen,
      };

    case 'SET_RULE_FILTER': {
      const newFilter = { ...state.ruleFilter, ...action.filter };
      if (
        newFilter.tab === state.ruleFilter.tab &&
        newFilter.search === state.ruleFilter.search
      ) {
        return state;
      }
      return { ...state, ruleFilter: newFilter };
    }

    case 'OPEN_DIALOG':
      return { ...state, openDialog: action.dialog };

    case 'CLOSE_DIALOG':
      return { ...state, openDialog: null };

    // ─── Host Management ─────────────────────────────────
    case 'ADD_HOST': {
      const hosts = cloneMap(state.hosts);
      hosts.set(action.host.id, action.host);
      return { ...state, hosts };
    }

    case 'UPDATE_HOST': {
      const existing = state.hosts.get(action.hostId);
      if (!existing) return state;
      const hosts = cloneMap(state.hosts);
      hosts.set(action.hostId, { ...existing, ...action.changes, updatedAt: Date.now() });
      return { ...state, hosts };
    }

    case 'REMOVE_HOST': {
      const hosts = cloneMap(state.hosts);
      hosts.delete(action.hostId);

      const hostStates = cloneMap(state.hostStates);
      hostStates.delete(action.hostId);

      const stagedChanges = cloneMap(state.stagedChanges);
      stagedChanges.delete(action.hostId);

      const safetyTimers = cloneMap(state.safetyTimers);
      safetyTimers.delete(action.hostId);

      const activeHostId = state.activeHostId === action.hostId ? null : state.activeHostId;

      // Cascade: remove hostId from all groups' memberHostIds
      const groups = cloneMap(state.groups);
      for (const [groupId, group] of groups) {
        if (group.memberHostIds.includes(action.hostId)) {
          groups.set(groupId, {
            ...group,
            memberHostIds: group.memberHostIds.filter(id => id !== action.hostId),
            updatedAt: Date.now(),
          });
        }
      }

      // Cascade: remove operations with matching hostId
      const operations = cloneMap(state.operations);
      for (const [opId, op] of operations) {
        if (op.hostId === action.hostId) {
          operations.delete(opId);
        }
      }

      return { ...state, hosts, hostStates, stagedChanges, safetyTimers, activeHostId, groups, operations };
    }

    case 'SET_HOST_STATUS': {
      const existing = state.hosts.get(action.hostId);
      if (!existing) return state;
      const hosts = cloneMap(state.hosts);
      hosts.set(action.hostId, { ...existing, status: action.status, updatedAt: Date.now() });
      return { ...state, hosts };
    }

    // ─── Group Management ────────────────────────────────
    case 'ADD_GROUP': {
      const groups = cloneMap(state.groups);
      groups.set(action.group.id, action.group);
      return { ...state, groups };
    }

    case 'UPDATE_GROUP': {
      const existing = state.groups.get(action.groupId);
      if (!existing) return state;
      const groups = cloneMap(state.groups);
      groups.set(action.groupId, { ...existing, ...action.changes, updatedAt: Date.now() });
      return { ...state, groups };
    }

    case 'REMOVE_GROUP': {
      const groups = cloneMap(state.groups);
      groups.delete(action.groupId);

      // Cascade: remove groupId from all hosts' groupIds and groupOrder
      const hosts = cloneMap(state.hosts);
      for (const [hostId, host] of hosts) {
        if (host.groupIds.includes(action.groupId) || host.groupOrder.includes(action.groupId)) {
          hosts.set(hostId, {
            ...host,
            groupIds: host.groupIds.filter(id => id !== action.groupId),
            groupOrder: host.groupOrder.filter(id => id !== action.groupId),
            updatedAt: Date.now(),
          });
        }
      }

      return { ...state, groups, hosts };
    }

    // ─── IP List Management ──────────────────────────────
    case 'ADD_IP_LIST': {
      const ipLists = cloneMap(state.ipLists);
      ipLists.set(action.ipList.id, action.ipList);
      return { ...state, ipLists };
    }

    case 'UPDATE_IP_LIST': {
      const existing = state.ipLists.get(action.ipListId);
      if (!existing) return state;
      const ipLists = cloneMap(state.ipLists);
      ipLists.set(action.ipListId, { ...existing, ...action.changes, updatedAt: Date.now() });
      return { ...state, ipLists };
    }

    case 'REMOVE_IP_LIST': {
      const ipLists = cloneMap(state.ipLists);
      ipLists.delete(action.ipListId);
      return { ...state, ipLists };
    }

    case 'SET_IP_LIST_ENTRIES': {
      const existing = state.ipLists.get(action.ipListId);
      if (!existing) return state;
      const ipLists = cloneMap(state.ipLists);
      ipLists.set(action.ipListId, { ...existing, entries: action.entries, updatedAt: Date.now() });
      return { ...state, ipLists };
    }

    // ─── Host State (ephemeral) ──────────────────────────
    case 'SET_HOST_RULES': {
      const hostStates = cloneMap(state.hostStates);
      const hs = ensureHostState(state, action.hostId);
      hostStates.set(action.hostId, { ...hs, rules: action.rules });
      return { ...state, hostStates };
    }

    case 'UPDATE_HIT_COUNTERS': {
      const hostStates = cloneMap(state.hostStates);
      const hs = ensureHostState(state, action.hostId);
      const newHitCounters = new Map<string, HitCounter>();
      for (const counter of action.counters) {
        newHitCounters.set(counter.ruleId, counter);
      }
      hostStates.set(action.hostId, {
        ...hs,
        prevHitCounters: hs.hitCounters,
        hitCounters: newHitCounters,
      });
      return { ...state, hostStates };
    }

    case 'ADD_BLOCKED_ENTRY': {
      const hostStates = cloneMap(state.hostStates);
      const hs = ensureHostState(state, action.hostId);
      const blockedLog = [action.entry, ...hs.blockedLog].slice(0, BLOCKED_LOG_CAP);
      hostStates.set(action.hostId, { ...hs, blockedLog });
      return { ...state, hostStates };
    }

    case 'SET_CONNTRACK_USAGE': {
      const hostStates = cloneMap(state.hostStates);
      const hs = ensureHostState(state, action.hostId);
      hostStates.set(action.hostId, {
        ...hs,
        conntrackUsage: { current: action.current, max: action.max },
      });
      return { ...state, hostStates };
    }

    case 'ADD_SSH_LOG_ENTRY': {
      const hostStates = cloneMap(state.hostStates);
      const hs = ensureHostState(state, action.hostId);
      const sshCommandLog = [...hs.sshCommandLog, action.entry].slice(-SSH_LOG_CAP);
      hostStates.set(action.hostId, { ...hs, sshCommandLog });
      return { ...state, hostStates };
    }

    case 'CLEAR_HOST_STATE': {
      const hostStates = cloneMap(state.hostStates);
      hostStates.delete(action.hostId);
      return { ...state, hostStates };
    }

    // ─── Staged Changes ─────────────────────────────────
    case 'ADD_STAGED_CHANGE': {
      const stagedChanges = cloneMap(state.stagedChanges);
      const existing = stagedChanges.get(action.hostId);
      const now = Date.now();
      if (existing) {
        stagedChanges.set(action.hostId, {
          ...existing,
          changes: [...existing.changes, action.change],
          undoStack: [...existing.undoStack, existing.changes],
          redoStack: [],
          updatedAt: now,
        });
      } else {
        stagedChanges.set(action.hostId, {
          hostId: action.hostId,
          changes: [action.change],
          undoStack: [[]],
          redoStack: [],
          createdAt: now,
          updatedAt: now,
        });
      }
      return { ...state, stagedChanges };
    }

    case 'UNDO_STAGED_CHANGE': {
      const existing = state.stagedChanges.get(action.hostId);
      if (!existing || existing.undoStack.length === 0) return state;
      const stagedChanges = cloneMap(state.stagedChanges);
      const undoStack = [...existing.undoStack];
      const prevChanges = undoStack.pop()!;
      stagedChanges.set(action.hostId, {
        ...existing,
        changes: prevChanges,
        undoStack,
        redoStack: [...existing.redoStack, existing.changes],
        updatedAt: Date.now(),
      });
      return { ...state, stagedChanges };
    }

    case 'REDO_STAGED_CHANGE': {
      const existing = state.stagedChanges.get(action.hostId);
      if (!existing || existing.redoStack.length === 0) return state;
      const stagedChanges = cloneMap(state.stagedChanges);
      const redoStack = [...existing.redoStack];
      const nextChanges = redoStack.pop()!;
      stagedChanges.set(action.hostId, {
        ...existing,
        changes: nextChanges,
        undoStack: [...existing.undoStack, existing.changes],
        redoStack,
        updatedAt: Date.now(),
      });
      return { ...state, stagedChanges };
    }

    case 'CLEAR_STAGED_CHANGES': {
      const stagedChanges = cloneMap(state.stagedChanges);
      stagedChanges.delete(action.hostId);
      return { ...state, stagedChanges };
    }

    // ─── Safety Timer ────────────────────────────────────
    case 'SET_SAFETY_TIMER': {
      const safetyTimers = cloneMap(state.safetyTimers);
      safetyTimers.set(action.timer.hostId, action.timer);
      return { ...state, safetyTimers };
    }

    case 'CLEAR_SAFETY_TIMER': {
      const safetyTimers = cloneMap(state.safetyTimers);
      safetyTimers.delete(action.hostId);
      return { ...state, safetyTimers };
    }

    // ─── Settings ────────────────────────────────────────
    case 'UPDATE_SETTINGS':
      return {
        ...state,
        settings: { ...state.settings, ...action.changes },
      };

    // ─── Operations ──────────────────────────────────────
    case 'START_OPERATION': {
      const operations = cloneMap(state.operations);
      operations.set(action.operationId, {
        type: action.operationType,
        hostId: action.hostId,
        status: 'pending',
        startedAt: Date.now(),
      });
      return { ...state, operations };
    }

    case 'COMPLETE_OPERATION': {
      const existing = state.operations.get(action.operationId);
      if (!existing) return state;
      const operations = cloneMap(state.operations);
      operations.set(action.operationId, { ...existing, status: 'success' });
      return { ...state, operations };
    }

    case 'FAIL_OPERATION': {
      const existing = state.operations.get(action.operationId);
      if (!existing) return state;
      const operations = cloneMap(state.operations);
      operations.set(action.operationId, { ...existing, status: 'error', error: action.error });
      return { ...state, operations };
    }

    case 'CLEAR_OPERATION': {
      const operations = cloneMap(state.operations);
      operations.delete(action.operationId);
      return { ...state, operations };
    }

    // ─── Storage ─────────────────────────────────────────
    case 'STORAGE_QUOTA_EXCEEDED':
      return { ...state, storageQuotaExceeded: true };

    default:
      return state;
  }
}
