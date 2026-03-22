import type {
  Host,
  HostGroup,
  HostState,
  Rule,
  StagedChangeset,
  EffectiveRule,
  StagedChange,
} from '../store/types';

/**
 * Compute the effective ruleset for a host.
 *
 * This is a pure function — it takes all inputs and produces
 * the merged, ordered list of effective rules. Never stored in state.
 *
 * Merge order:
 * 1. Loopback allow (-i lo -j ACCEPT, auto-included)
 * 2. Connection Tracking (INVALID drop, ESTABLISHED, RELATED)
 * 3. Group rules (in priority order, skip overridden)
 * 4. Per-host overrides
 * 5. Host-specific rules
 * 6. Rate-limited LOG before default policy
 * 7. Default policy ("Everything Else")
 * 8. System rules (separate collapsed section, read-only)
 */
export function computeEffectiveRuleset(
  hostId: string,
  hosts: Map<string, Host>,
  groups: Map<string, HostGroup>,
  hostStates: Map<string, HostState>,
  stagedChanges: Map<string, StagedChangeset>,
): EffectiveRule[] {
  const host = hosts.get(hostId);
  if (!host) return [];

  const hostState = hostStates.get(hostId);
  const remoteRules = hostState?.rules ?? [];
  const staged = stagedChanges.get(hostId);

  // Apply staged changes to get working ruleset
  const workingRules = applyStagedChanges(remoteRules, staged);

  // Separate system rules from user/imported rules
  const systemRules: Rule[] = [];
  const userRules: Rule[] = [];
  for (const rule of workingRules) {
    if (rule.origin.type === 'system') {
      systemRules.push(rule);
    } else {
      userRules.push(rule);
    }
  }

  // Collect group rules in priority order
  const groupRules: Array<{ rule: Rule; groupName: string }> = [];
  const overriddenGroupRuleIds = new Set<string>();

  // Get groups this host belongs to, sorted by priority (groupOrder on host)
  const hostGroupIds = host.groupOrder.length > 0 ? host.groupOrder : host.groupIds;
  for (const groupId of hostGroupIds) {
    const group = groups.get(groupId);
    if (!group) continue;
    for (const rule of group.rules) {
      // Check if host has an override for this rule
      const hasOverride = userRules.some(
        ur => ur.origin.type === 'user' && isRuleOverride(ur, rule),
      );
      if (hasOverride) {
        overriddenGroupRuleIds.add(rule.id);
      }
      groupRules.push({ rule, groupName: group.name });
    }
  }

  // Build effective rule list in merge order
  const effective: EffectiveRule[] = [];
  let position = 0;

  // 1. Loopback allow (auto-generated)
  effective.push(makeEffective({
    id: '__loopback__',
    label: 'Allow Local Traffic',
    action: 'allow',
    source: { type: 'anyone' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'both',
    interfaceIn: 'lo',
    origin: { type: 'user' },
    position: position++,
    enabled: true,
    createdAt: 0,
    updatedAt: 0,
  }, 'loopback', 'auto'));

  // 2. Connection Tracking
  effective.push(makeEffective({
    id: '__ct_invalid__',
    label: 'Drop Invalid Packets',
    action: 'block',
    source: { type: 'anyone' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'both',
    conntrackStates: ['invalid'],
    origin: { type: 'user' },
    position: position++,
    enabled: true,
    createdAt: 0,
    updatedAt: 0,
  }, 'conntrack', 'auto'));

  effective.push(makeEffective({
    id: '__ct_established__',
    label: 'Allow Return Traffic',
    action: 'allow',
    source: { type: 'anyone' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'both',
    conntrackStates: ['established', 'related'],
    origin: { type: 'user' },
    position: position++,
    enabled: true,
    createdAt: 0,
    updatedAt: 0,
  }, 'conntrack', 'auto'));

  // 3. Group rules (in priority order, marking overridden ones)
  for (const { rule, groupName } of groupRules) {
    const overridden = overriddenGroupRuleIds.has(rule.id);
    const er = makeEffective(
      { ...rule, position: position++ },
      'group',
      'group',
    );
    er.groupName = groupName;
    er.overridden = overridden;
    effective.push(er);
  }

  // 4 & 5. Host-specific rules (user + imported)
  for (const rule of userRules) {
    const isOverride = groupRules.some(gr => isRuleOverride(rule, gr.rule));
    effective.push(makeEffective(
      { ...rule, position: position++ },
      isOverride ? 'host-override' : 'host',
      'host',
    ));
  }

  // 6. Log catch-all (auto-generated for blocked log functionality)
  effective.push(makeEffective({
    id: '__log_catchall__',
    label: 'Log Blocked Attempts',
    action: 'log',
    source: { type: 'anyone' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'both',
    logPrefix: 'BLOCKED: ',
    comment: 'Logs blocked traffic so you can review it in the Activity tab',
    logRateLimit: { rate: 5, per: 'minute', burst: 10 },
    origin: { type: 'user' },
    position: position++,
    enabled: true,
    createdAt: 0,
    updatedAt: 0,
  }, 'log-catchall', 'auto'));

  // 7. Default policy
  effective.push(makeEffective({
    id: '__default_policy__',
    label: 'Drop Everything Else',
    action: 'block',
    source: { type: 'anyone' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'both',
    origin: { type: 'user' },
    position: position++,
    enabled: true,
    createdAt: 0,
    updatedAt: 0,
  }, 'default-policy', 'auto'));

  // 8. System rules (read-only)
  for (const rule of systemRules) {
    effective.push(makeEffective(
      { ...rule, position: position++ },
      'system',
      'system',
    ));
  }

  return effective;
}

// ─── Helpers ────────────────────────────────────────────────

function makeEffective(
  rule: Omit<Rule, 'position'> & { position: number },
  section: EffectiveRule['section'],
  sourceType: EffectiveRule['sourceType'],
): EffectiveRule {
  return {
    ...rule,
    section,
    sourceType,
    overridden: false,
  } as EffectiveRule;
}

/**
 * Check if ruleA is an override of ruleB (same ports/protocol/direction).
 */
function isRuleOverride(ruleA: Rule, ruleB: Rule): boolean {
  return (
    ruleA.direction === ruleB.direction &&
    ruleA.protocol === ruleB.protocol &&
    portsMatch(ruleA.ports, ruleB.ports) &&
    JSON.stringify(ruleA.source) === JSON.stringify(ruleB.source) &&
    JSON.stringify(ruleA.destination) === JSON.stringify(ruleB.destination)
  );
}

function portsMatch(a: Rule['ports'], b: Rule['ports']): boolean {
  if (!a && !b) return true;
  if (!a || !b) return false;
  if (a.type !== b.type) return false;
  switch (a.type) {
    case 'single':
      return b.type === 'single' && a.port === b.port;
    case 'range':
      return b.type === 'range' && a.from === b.from && a.to === b.to;
    case 'multi':
      if (b.type !== 'multi') return false;
      if (a.ports.length !== b.ports.length) return false;
      return a.ports.every((p, i) => b.type === 'multi' && p === b.ports[i]);
    default:
      return false;
  }
}

/**
 * Apply staged changes to the remote rules to get the working ruleset.
 */
function applyStagedChanges(
  rules: Rule[],
  staged: StagedChangeset | undefined,
): Rule[] {
  if (!staged || staged.changes.length === 0) return rules;

  let result = [...rules];

  for (const change of staged.changes) {
    result = applySingleChange(result, change);
  }

  return result;
}

function applySingleChange(rules: Rule[], change: StagedChange): Rule[] {
  switch (change.type) {
    case 'add': {
      const newRules = [...rules];
      newRules.splice(change.position, 0, change.rule);
      return newRules;
    }
    case 'delete':
      return rules.filter(r => r.id !== change.ruleId);
    case 'modify':
      return rules.map(r =>
        r.id === change.ruleId ? { ...r, ...change.after } : r,
      );
    case 'reorder': {
      const newRules = [...rules];
      const idx = newRules.findIndex(r => r.id === change.ruleId);
      if (idx === -1) return rules;
      const [moved] = newRules.splice(idx, 1);
      newRules.splice(change.toPosition, 0, moved);
      return newRules;
    }
    case 'policy':
    case 'iplist-update':
      // These don't directly affect the rule array
      return rules;
    default:
      return rules;
  }
}
