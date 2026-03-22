/**
 * Convert a parsed ruleset from the Rust backend (RuleSet) into
 * the frontend Rule[] format.
 *
 * The backend returns RuleSet { rules: Rule[], defaultPolicy, rawIptablesSave }.
 * When the backend returns pre-parsed Rule objects, we pass them through
 * with origin and direction normalization. When it returns raw iptables data,
 * we parse it into Rule objects.
 */

import type { Rule, PortSpec, AddressSpec, RuleOrigin } from '../store/types';
import type { RuleSet } from '../ipc/bridge';
import { generateRuleLabel } from './rule-label';

/**
 * Map an iptables target string to the app's action type.
 */
function mapTarget(target: string): Rule['action'] {
  switch (target.toUpperCase()) {
    case 'ACCEPT': return 'allow';
    case 'DROP': return 'block';
    case 'REJECT': return 'block-reject';
    case 'LOG': return 'log';
    case 'DNAT': return 'dnat';
    case 'SNAT': return 'snat';
    case 'MASQUERADE': return 'masquerade';
    default: return 'allow';
  }
}

/**
 * Map a chain name to a direction.
 */
function mapChainToDirection(chain: string): Rule['direction'] {
  const upper = chain.toUpperCase();
  if (upper === 'INPUT' || upper.startsWith('INPUT')) return 'incoming';
  if (upper === 'OUTPUT' || upper.startsWith('OUTPUT')) return 'outgoing';
  if (upper === 'FORWARD' || upper.startsWith('FORWARD')) return 'forwarded';
  // NAT chains
  if (upper === 'PREROUTING') return 'incoming';
  if (upper === 'POSTROUTING') return 'outgoing';
  return 'incoming';
}

/**
 * Parse a port specification string into a PortSpec.
 */
function parsePortSpec(portStr: string): PortSpec | undefined {
  if (!portStr) return undefined;
  if (portStr.includes(':')) {
    const [from, to] = portStr.split(':').map(Number);
    if (!isNaN(from) && !isNaN(to)) {
      return { type: 'range', from, to };
    }
  }
  if (portStr.includes(',')) {
    const ports = portStr.split(',').map(Number).filter(p => !isNaN(p));
    if (ports.length > 0) return { type: 'multi', ports };
  }
  const port = Number(portStr);
  if (!isNaN(port)) return { type: 'single', port };
  return undefined;
}

/**
 * Parse an address string into an AddressSpec.
 */
function parseAddressSpec(addr: string | undefined | null): AddressSpec {
  if (!addr || addr === '0.0.0.0/0' || addr === '::/0' || addr === 'anywhere') {
    return { type: 'anyone' };
  }
  return { type: 'cidr', value: addr };
}

/**
 * Convert a RuleSet from the backend into frontend Rule[] objects.
 *
 * If the backend already returns parsed Rule objects (with id, label, etc.),
 * those are used directly. Otherwise, raw iptables-save lines are parsed.
 */
export function convertRuleSet(ruleSet: RuleSet): Rule[] {
  // If the backend returned pre-parsed rules, use them directly
  if (ruleSet.rules && ruleSet.rules.length > 0) {
    return ruleSet.rules.map((rule, index) => ({
      ...rule,
      position: rule.position ?? index,
      origin: rule.origin ?? { type: 'imported' as const },
    }));
  }

  // Fall back to parsing rawIptablesSave
  if (!ruleSet.rawIptablesSave) return [];

  return parseIptablesSave(ruleSet.rawIptablesSave);
}

/**
 * Parse raw iptables-save output into Rule[] objects.
 */
function parseIptablesSave(raw: string): Rule[] {
  const rules: Rule[] = [];
  const lines = raw.split('\n');
  let currentTable = 'filter';
  let position = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    // Table header: *filter, *nat, *mangle, etc.
    if (trimmed.startsWith('*')) {
      currentTable = trimmed.slice(1);
      continue;
    }

    // Skip comments, empty lines, COMMIT, chain policy lines
    if (!trimmed || trimmed.startsWith('#') || trimmed === 'COMMIT' || trimmed.startsWith(':')) {
      continue;
    }

    // Rule lines start with -A
    if (trimmed.startsWith('-A ')) {
      const rule = parseIptablesRule(trimmed, currentTable, position);
      if (rule) {
        rules.push(rule);
        position++;
      }
    }
  }

  return rules;
}

/**
 * Parse a single iptables rule line (e.g., "-A INPUT -p tcp --dport 22 -j ACCEPT").
 */
function parseIptablesRule(line: string, _table: string, position: number): Rule | null {
  const args = tokenize(line);

  let chain = '';
  let protocol: Rule['protocol'] | undefined;
  let ports: PortSpec | undefined;
  let sourceAddr: string | undefined;
  let destAddr: string | undefined;
  let target = '';
  let interfaceIn: string | undefined;
  let interfaceOut: string | undefined;
  let comment: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];

    switch (arg) {
      case '-A':
        chain = next ?? '';
        i++;
        break;
      case '-p':
        protocol = (next ?? 'tcp') as Rule['protocol'];
        i++;
        break;
      case '--dport':
        ports = parsePortSpec(next ?? '');
        i++;
        break;
      case '--sport':
        // Source port - store as dport for simplicity
        if (!ports) ports = parsePortSpec(next ?? '');
        i++;
        break;
      case '-s':
        sourceAddr = next;
        i++;
        break;
      case '-d':
        destAddr = next;
        i++;
        break;
      case '-j':
        target = next ?? '';
        i++;
        break;
      case '-i':
        interfaceIn = next;
        i++;
        break;
      case '-o':
        interfaceOut = next;
        i++;
        break;
      case '--comment':
        comment = next;
        i++;
        break;
      case '-m':
        // Skip module name, handle specific module args
        if (next === 'comment') {
          // next arg after 'comment' should be '--comment'
        }
        i++;
        break;
      case '--dports':
      case '--destination-ports':
        ports = parsePortSpec(next ?? '');
        i++;
        break;
    }
  }

  if (!chain) return null;

  const action = mapTarget(target);
  const direction = mapChainToDirection(chain);
  const source = parseAddressSpec(sourceAddr);
  const destination = parseAddressSpec(destAddr);
  const origin: RuleOrigin = { type: 'imported' };
  const now = Date.now();

  const rule: Rule = {
    id: crypto.randomUUID(),
    label: '',
    action,
    protocol,
    ports,
    source,
    destination,
    direction,
    addressFamily: 'v4',
    interfaceIn,
    interfaceOut,
    comment,
    origin,
    position,
    enabled: true,
    raw: line,
    createdAt: now,
    updatedAt: now,
  };

  // Generate label from comment or rule properties
  rule.label = comment || generateRuleLabel(rule);

  return rule;
}

/**
 * Tokenize an iptables command line, respecting quoted strings.
 */
function tokenize(line: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inQuote = false;
  let quoteChar = '';

  for (const ch of line) {
    if (inQuote) {
      if (ch === quoteChar) {
        inQuote = false;
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      inQuote = true;
      quoteChar = ch;
    } else if (ch === ' ' || ch === '\t') {
      if (current) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);

  return tokens;
}
