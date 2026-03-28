import type {
  Host,
  HostGroup,
  IpList,
  Rule,
  StagedChange,
  StagedChangeset,
  SafetyTimerState,
  HitCounter,
  BlockedEntry,
  SshLogEntry,
  AppSettings,
  HostStatus,
  SidePanelContent,
  AppState,
  IpListEntry,
  DialogType,
  RuleConflict,
  AuditEntry,
  DriftInfo,
  CoexistenceProfile,
} from './types';

// ─── Hydration ─────────────────────────────────────────────────

export interface HydrateAction {
  type: 'HYDRATE';
  payload: {
    hosts?: Array<Host>;
    groups?: Array<HostGroup>;
    ipLists?: Array<IpList>;
    stagedChanges?: Array<StagedChangeset>;
    safetyTimers?: Array<SafetyTimerState>;
    settings?: Partial<AppSettings>;
    auditLog?: Array<AuditEntry>;
  };
}

// ─── Navigation ────────────────────────────────────────────────

export interface SetActiveHostAction {
  type: 'SET_ACTIVE_HOST';
  hostId: string | null;
}

export interface SetActiveTabAction {
  type: 'SET_ACTIVE_TAB';
  tab: AppState['activeTab'];
}

export interface SetTerminalSubTabAction {
  type: 'SET_TERMINAL_SUB_TAB';
  subTab: AppState['activeTerminalSubTab'];
}

export interface ToggleSidePanelAction {
  type: 'TOGGLE_SIDE_PANEL';
  open?: boolean;
}

export interface SetSidePanelContentAction {
  type: 'SET_SIDE_PANEL_CONTENT';
  content: SidePanelContent | null;
}

export interface ToggleSplitPanelAction {
  type: 'TOGGLE_SPLIT_PANEL';
  open?: boolean;
}

export interface SetSplitPanelContentAction {
  type: 'SET_SPLIT_PANEL_CONTENT';
  content: 'activity' | 'terminal';
}

export interface ToggleSidebarAction {
  type: 'TOGGLE_SIDEBAR';
  collapsed?: boolean;
}

export interface ToggleCommandPaletteAction {
  type: 'TOGGLE_COMMAND_PALETTE';
  open?: boolean;
}

export interface ToggleQuickBlockAction {
  type: 'TOGGLE_QUICK_BLOCK';
  open?: boolean;
}

export interface SetRuleFilterAction {
  type: 'SET_RULE_FILTER';
  filter: Partial<AppState['ruleFilter']>;
}

export interface OpenDialogAction {
  type: 'OPEN_DIALOG';
  dialog: DialogType;
}

export interface CloseDialogAction {
  type: 'CLOSE_DIALOG';
}

// ─── Host Management ──────────────────────────────────────────

export interface AddHostAction {
  type: 'ADD_HOST';
  host: Host;
}

export interface UpdateHostAction {
  type: 'UPDATE_HOST';
  hostId: string;
  changes: Partial<Host>;
}

export interface RemoveHostAction {
  type: 'REMOVE_HOST';
  hostId: string;
}

export interface SetHostStatusAction {
  type: 'SET_HOST_STATUS';
  hostId: string;
  status: HostStatus;
}

// ─── Group Management ─────────────────────────────────────────

export interface AddGroupAction {
  type: 'ADD_GROUP';
  group: HostGroup;
}

export interface UpdateGroupAction {
  type: 'UPDATE_GROUP';
  groupId: string;
  changes: Partial<HostGroup>;
}

export interface RemoveGroupAction {
  type: 'REMOVE_GROUP';
  groupId: string;
}

// ─── IP List Management ───────────────────────────────────────

export interface AddIpListAction {
  type: 'ADD_IP_LIST';
  ipList: IpList;
}

export interface UpdateIpListAction {
  type: 'UPDATE_IP_LIST';
  ipListId: string;
  changes: Partial<IpList>;
}

export interface RemoveIpListAction {
  type: 'REMOVE_IP_LIST';
  ipListId: string;
}

// ─── Host State (ephemeral) ───────────────────────────────────

export interface SetHostRulesAction {
  type: 'SET_HOST_RULES';
  hostId: string;
  rules: Rule[];
}

export interface UpdateHitCountersAction {
  type: 'UPDATE_HIT_COUNTERS';
  hostId: string;
  counters: HitCounter[];
}

export interface AddBlockedEntryAction {
  type: 'ADD_BLOCKED_ENTRY';
  hostId: string;
  entry: BlockedEntry;
}

export interface SetConntrackUsageAction {
  type: 'SET_CONNTRACK_USAGE';
  hostId: string;
  current: number;
  max: number;
}

export interface AddSshLogEntryAction {
  type: 'ADD_SSH_LOG_ENTRY';
  hostId: string;
  entry: SshLogEntry;
}

export interface ClearHostStateAction {
  type: 'CLEAR_HOST_STATE';
  hostId: string;
}

export interface SetRuleConflictsAction {
  type: 'SET_RULE_CONFLICTS';
  hostId: string;
  conflicts: RuleConflict[];
}

// ─── Staged Changes ──────────────────────────────────────────

export interface AddStagedChangeAction {
  type: 'ADD_STAGED_CHANGE';
  hostId: string;
  change: StagedChange;
}

export interface UndoStagedChangeAction {
  type: 'UNDO_STAGED_CHANGE';
  hostId: string;
}

export interface RedoStagedChangeAction {
  type: 'REDO_STAGED_CHANGE';
  hostId: string;
}

export interface ClearStagedChangesAction {
  type: 'CLEAR_STAGED_CHANGES';
  hostId: string;
}

// ─── Safety Timer ─────────────────────────────────────────────

export interface SetSafetyTimerAction {
  type: 'SET_SAFETY_TIMER';
  timer: SafetyTimerState;
}

export interface ClearSafetyTimerAction {
  type: 'CLEAR_SAFETY_TIMER';
  hostId: string;
}

// ─── Settings ─────────────────────────────────────────────────

export interface UpdateSettingsAction {
  type: 'UPDATE_SETTINGS';
  changes: Partial<AppSettings>;
}

// ─── Operations ───────────────────────────────────────────────

export interface StartOperationAction {
  type: 'START_OPERATION';
  operationId: string;
  operationType: string;
  hostId?: string;
}

export interface CompleteOperationAction {
  type: 'COMPLETE_OPERATION';
  operationId: string;
}

export interface FailOperationAction {
  type: 'FAIL_OPERATION';
  operationId: string;
  error: string;
}

export interface ClearOperationAction {
  type: 'CLEAR_OPERATION';
  operationId: string;
}

// ─── Storage ──────────────────────────────────────────────────

export interface StorageQuotaExceededAction {
  type: 'STORAGE_QUOTA_EXCEEDED';
}

// ─── Audit Log ────────────────────────────────────────────────

export interface AddAuditEntryAction {
  type: 'ADD_AUDIT_ENTRY';
  entry: AuditEntry;
}

// ─── IP List Entries ──────────────────────────────────────────

export interface SetIpListEntriesAction {
  type: 'SET_IP_LIST_ENTRIES';
  ipListId: string;
  entries: IpListEntry[];
}

// ─── Coexistence Profile ──────────────────────────────────────

export interface SetCoexistenceProfileAction {
  type: 'SET_COEXISTENCE_PROFILE';
  hostId: string;
  profile: CoexistenceProfile;
}

// ─── Drift Detection ──────────────────────────────────────────

export interface SetDriftDetectedAction {
  type: 'SET_DRIFT_DETECTED';
  drift: DriftInfo;
}

export interface ClearDriftAction {
  type: 'CLEAR_DRIFT';
  hostId: string;
}

// ─── Discriminated Union ──────────────────────────────────────

export type Action =
  | HydrateAction
  | SetActiveHostAction
  | SetActiveTabAction
  | SetTerminalSubTabAction
  | ToggleSidePanelAction
  | SetSidePanelContentAction
  | ToggleSplitPanelAction
  | SetSplitPanelContentAction
  | ToggleSidebarAction
  | ToggleCommandPaletteAction
  | ToggleQuickBlockAction
  | SetRuleFilterAction
  | OpenDialogAction
  | CloseDialogAction
  | AddHostAction
  | UpdateHostAction
  | RemoveHostAction
  | SetHostStatusAction
  | AddGroupAction
  | UpdateGroupAction
  | RemoveGroupAction
  | AddIpListAction
  | UpdateIpListAction
  | RemoveIpListAction
  | SetHostRulesAction
  | UpdateHitCountersAction
  | AddBlockedEntryAction
  | SetConntrackUsageAction
  | AddSshLogEntryAction
  | ClearHostStateAction
  | SetRuleConflictsAction
  | AddStagedChangeAction
  | UndoStagedChangeAction
  | RedoStagedChangeAction
  | ClearStagedChangesAction
  | SetSafetyTimerAction
  | ClearSafetyTimerAction
  | UpdateSettingsAction
  | StartOperationAction
  | CompleteOperationAction
  | FailOperationAction
  | ClearOperationAction
  | StorageQuotaExceededAction
  | SetIpListEntriesAction
  | AddAuditEntryAction
  | SetCoexistenceProfileAction
  | SetDriftDetectedAction
  | ClearDriftAction;
