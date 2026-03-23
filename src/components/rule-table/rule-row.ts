/**
 * Rule row — stateless render functions for a single rule in the table.
 *
 * 52px height, 3px left status bar, two-line content.
 */

import type { EffectiveRule, AddressSpec, PortSpec } from '../../store/types';
import { h } from '../../utils/dom';

// ─── Helpers ─────────────────────────────────────────────────

type ActionDisplay = 'ALLOW' | 'BLOCK' | 'LOG' | 'FWD' | 'SNAT';

function getActionDisplay(action: EffectiveRule['action']): ActionDisplay {
  switch (action) {
    case 'allow': return 'ALLOW';
    case 'block':
    case 'block-reject': return 'BLOCK';
    case 'log':
    case 'log-block': return 'LOG';
    case 'dnat':
    case 'masquerade': return 'FWD';
    case 'snat': return 'SNAT';
    default: return 'ALLOW';
  }
}

function getActionColorClass(action: EffectiveRule['action']): string {
  switch (action) {
    case 'allow': return 'rule-table__row-bar--allow';
    case 'block':
    case 'block-reject': return 'rule-table__row-bar--block';
    case 'log':
    case 'log-block': return 'rule-table__row-bar--log';
    case 'dnat':
    case 'snat':
    case 'masquerade': return 'rule-table__row-bar--fwd';
    default: return 'rule-table__row-bar--allow';
  }
}

function getStatusLabelClass(action: EffectiveRule['action']): string {
  switch (action) {
    case 'allow': return 'rule-table__status-label--allow';
    case 'block':
    case 'block-reject': return 'rule-table__status-label--block';
    case 'log':
    case 'log-block': return 'rule-table__status-label--log';
    case 'dnat':
    case 'snat':
    case 'masquerade': return 'rule-table__status-label--fwd';
    default: return 'rule-table__status-label--allow';
  }
}

function formatAddress(addr: AddressSpec, ipListName?: string): string {
  switch (addr.type) {
    case 'anyone': return 'Anyone';
    case 'cidr': return addr.value;
    case 'iplist': return ipListName ?? addr.ipListId;
    default: return '';
  }
}

function formatPorts(ports: PortSpec | undefined): string {
  if (!ports) return '';
  switch (ports.type) {
    case 'single': return String(ports.port);
    case 'range': return `${ports.from}-${ports.to}`;
    case 'multi': return ports.ports.join(', ');
    default: return '';
  }
}

// ─── Create / Update ─────────────────────────────────────────

export function createRuleRow(rule: EffectiveRule, hasPendingChange = false, ipListNames?: Map<string, string>): HTMLElement {
  const row = h('div', {
    className: 'rule-table__row',
    tabindex: '0',
    role: 'listitem',
    'aria-label': `${getActionDisplay(rule.action)} ${rule.label}`,
    dataset: { ruleId: rule.id },
  });

  // Drag handle (visible on hover)
  const dragHandle = h('span', { className: 'rule-table__drag-handle' }, '\u2807');
  row.appendChild(dragHandle);

  // Status bar (left edge)
  const bar = h('div', { className: `rule-table__row-bar ${getActionColorClass(rule.action)}` });
  row.appendChild(bar);

  // Content area
  const content = h('div', { className: 'rule-table__row-content' });

  // First line: status label + name + pending dot
  const firstLine = h('div', { className: 'rule-table__row-first-line' });

  const statusLabel = h('span', {
    className: `rule-table__status-label ${getStatusLabelClass(rule.action)}`,
  }, getActionDisplay(rule.action));
  firstLine.appendChild(statusLabel);

  const nameText = rule.label + (rule.ports ? ` (${formatPorts(rule.ports)})` : '');
  const fontWeightClass = rule.sourceType === 'group' ? 'rule-table__rule-name--group' : '';
  const nameEl = h('span', {
    className: `rule-table__rule-name ${fontWeightClass}`.trim(),
  }, nameText);
  firstLine.appendChild(nameEl);

  // Pending dot (shown when rule has staged changes)
  const pendingDot = h('span', { className: 'rule-table__pending-dot' });
  pendingDot.style.display = hasPendingChange ? '' : 'none';
  firstLine.appendChild(pendingDot);

  content.appendChild(firstLine);

  // Second line: protocol + comment (always show something for conntrack/auto rules)
  const secondLine = h('div', { className: 'rule-table__row-second-line' });
  const protocolText = rule.protocol ? String(rule.protocol).toUpperCase() : '';
  const commentText = rule.comment ? ` \u00B7 ${rule.comment}` : '';

  // For auto-generated rules without protocol, show a descriptive subtitle
  const autoSubtitle = getAutoRuleSubtitle(rule);

  if (protocolText || commentText) {
    if (protocolText) {
      const protocolEl = h('span', { className: 'rule-table__protocol' }, protocolText);
      secondLine.appendChild(protocolEl);
    }
    if (rule.comment) {
      const commentEl = h('span', { className: 'rule-table__comment' }, ` \u00B7 ${rule.comment}`);
      secondLine.appendChild(commentEl);
    }
  } else if (autoSubtitle) {
    const subtitleEl = h('span', { className: 'rule-table__comment' }, autoSubtitle);
    secondLine.appendChild(subtitleEl);
  }
  content.appendChild(secondLine);

  row.appendChild(content);

  // Right section: source/dest, origin tag, hit count
  const rightSection = h('div', { className: 'rule-table__row-right' });

  // Source
  const ipListName = rule.source.type === 'iplist' && ipListNames
    ? ipListNames.get(rule.source.ipListId) : undefined;
  const sourceText = formatAddress(rule.source, ipListName);
  const sourceEl = h('span', {
    className: 'rule-table__source' + (rule.source.type === 'cidr' ? ' rule-table__source--mono' : ''),
  }, sourceText);
  rightSection.appendChild(sourceEl);

  // Origin tag
  if (rule.sourceType === 'group' && rule.groupName) {
    const originTag = h('span', { className: 'rule-table__origin-tag rule-table__origin-tag--pill' },
      rule.groupName);
    rightSection.appendChild(originTag);
  } else if (rule.sourceType === 'host') {
    const originTag = h('span', { className: 'rule-table__origin-tag' }, 'host');
    rightSection.appendChild(originTag);
  }

  // Hit count
  const hitCountEl = h('span', { className: 'rule-table__hit-count' }, '');
  rightSection.appendChild(hitCountEl);

  row.appendChild(rightSection);

  // Overflow menu (hidden, shown on hover)
  const overflowBtn = h('button', {
    className: 'rule-table__overflow-btn',
    'aria-label': 'Rule actions',
    tabindex: '0',
  }, '\u22EF');
  row.appendChild(overflowBtn);

  return row;
}

function getAutoRuleSubtitle(rule: EffectiveRule): string {
  if (rule.section === 'loopback') return 'Allows the server to talk to itself (required for local services)';
  if (rule.section === 'conntrack' && rule.id === '__ct_invalid__') return 'Drops broken or malformed packets that don\'t belong to any connection';
  if (rule.section === 'conntrack' && rule.id === '__ct_established__') return 'Allows response traffic for connections you already started';
  if (rule.section === 'log-catchall') return 'Records blocked traffic for review (rate limited to 5/min)';
  if (rule.section === 'default-policy') return 'Blocks all traffic not matched by rules above';
  return '';
}

export function updateRuleRow(el: HTMLElement, rule: EffectiveRule, hasPendingChange = false, ipListNames?: Map<string, string>): void {
  el.setAttribute('aria-label', `${getActionDisplay(rule.action)} ${rule.label}`);
  el.dataset.ruleId = rule.id;

  // Update status bar color
  const bar = el.querySelector('.rule-table__row-bar');
  if (bar) {
    bar.className = `rule-table__row-bar ${getActionColorClass(rule.action)}`;
  }

  // Update status label
  const statusLabel = el.querySelector('.rule-table__status-label');
  if (statusLabel) {
    const actionText = getActionDisplay(rule.action);
    if (statusLabel.textContent !== actionText) {
      statusLabel.textContent = actionText;
    }
    statusLabel.className = `rule-table__status-label ${getStatusLabelClass(rule.action)}`;
  }

  // Update rule name
  const nameEl = el.querySelector('.rule-table__rule-name');
  if (nameEl) {
    const nameText = rule.label + (rule.ports ? ` (${formatPorts(rule.ports)})` : '');
    if (nameEl.textContent !== nameText) {
      nameEl.textContent = nameText;
    }
    const isGroup = rule.sourceType === 'group';
    nameEl.classList.toggle('rule-table__rule-name--group', isGroup);
  }

  // Update protocol line
  const protocolEl = el.querySelector('.rule-table__protocol');
  if (protocolEl) {
    const protocolText = rule.protocol ? String(rule.protocol).toUpperCase() : '';
    if (protocolEl.textContent !== protocolText) {
      protocolEl.textContent = protocolText;
    }
  }

  // Update comment
  const commentEl = el.querySelector('.rule-table__comment');
  if (commentEl) {
    const commentText = rule.comment ? ` \u00B7 ${rule.comment}` : '';
    if (commentEl.textContent !== commentText) {
      commentEl.textContent = commentText;
    }
  }

  // Update source
  const sourceEl = el.querySelector('.rule-table__source');
  if (sourceEl) {
    const ipListName = rule.source.type === 'iplist' && ipListNames
      ? ipListNames.get(rule.source.ipListId) : undefined;
    const sourceText = formatAddress(rule.source, ipListName);
    if (sourceEl.textContent !== sourceText) {
      sourceEl.textContent = sourceText;
    }
    sourceEl.classList.toggle('rule-table__source--mono', rule.source.type === 'cidr');
  }

  // Update origin tag
  const originTag = el.querySelector('.rule-table__origin-tag');
  if (originTag) {
    if (rule.sourceType === 'group' && rule.groupName) {
      originTag.textContent = rule.groupName;
      originTag.classList.add('rule-table__origin-tag--pill');
    } else if (rule.sourceType === 'host') {
      originTag.textContent = 'host';
      originTag.classList.remove('rule-table__origin-tag--pill');
    }
  }

  // Update pending dot visibility
  const pendingDot = el.querySelector<HTMLElement>('.rule-table__pending-dot');
  if (pendingDot) {
    pendingDot.style.display = hasPendingChange ? '' : 'none';
  }
}
