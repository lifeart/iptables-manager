/**
 * Rule detail view — shows label-value pairs for a selected rule.
 *
 * Sections:
 *   - Main: Action, Service, Port, Protocol, Source (expanded IPs), Direction, Interface, Comment
 *   - Details: Hits, Added date, Origin
 *   - Disclosure triangle for iptables command
 *   - Action buttons: Edit, Disable, Delete
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { Rule, AddressSpec, PortSpec, IpList } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';

// ─── Helpers ─────────────────────────────────────────────────

function formatAction(action: Rule['action']): string {
  switch (action) {
    case 'allow': return 'Allow';
    case 'block': return 'Block (Drop)';
    case 'block-reject': return 'Block (Reject)';
    case 'log': return 'Log';
    case 'log-block': return 'Log + Block';
    case 'dnat': return 'Port Forward';
    case 'snat': return 'Source NAT';
    case 'masquerade': return 'Masquerade';
    default: return String(action);
  }
}

function formatProtocol(protocol: Rule['protocol']): string {
  if (!protocol) return 'Any';
  if (typeof protocol === 'number') return `Protocol ${protocol}`;
  return protocol.toUpperCase();
}

function formatPorts(ports: PortSpec | undefined): string {
  if (!ports) return 'Any';
  switch (ports.type) {
    case 'single': return String(ports.port);
    case 'range': return `${ports.from}-${ports.to}`;
    case 'multi': return ports.ports.join(', ');
    default: return 'Any';
  }
}

function formatAddress(addr: AddressSpec, ipLists: Map<string, IpList>): string {
  switch (addr.type) {
    case 'anyone': return 'Anyone';
    case 'cidr': return addr.value;
    case 'iplist': {
      const list = ipLists.get(addr.ipListId);
      return list ? list.name : addr.ipListId;
    }
    default: return '';
  }
}

function formatDate(ts: number): string {
  if (!ts) return 'Unknown';
  return new Date(ts).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

function formatOrigin(rule: Rule): string {
  switch (rule.origin.type) {
    case 'user': return 'User-created';
    case 'imported': return 'Imported';
    case 'group': return `Group: ${rule.origin.groupId}`;
    case 'system': return `System (${rule.origin.owner})`;
    default: return 'Unknown';
  }
}

// ─── Component ───────────────────────────────────────────────

export class RuleDetail extends Component {
  private ruleId: string;
  private containerEl: HTMLElement;

  constructor(container: HTMLElement, store: Store, ruleId: string) {
    super(container, store);
    this.ruleId = ruleId;

    this.containerEl = h('div', { className: 'rule-detail' });
    this.el.appendChild(this.containerEl);

    this.render();

    // Re-render when host rules change
    this.subscribe(
      (s) => s.activeHostId ? s.hostStates.get(s.activeHostId)?.rules : undefined,
      () => this.render(),
    );
  }

  private findRule(): Rule | null {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return null;
    const hostState = state.hostStates.get(hostId);
    if (!hostState) return null;
    return hostState.rules.find((r) => r.id === this.ruleId) ?? null;
  }

  private render(): void {
    clearChildren(this.containerEl);

    const rule = this.findRule();
    if (!rule) {
      this.containerEl.appendChild(
        h('p', { className: 'rule-detail__empty' }, 'Rule not found.'),
      );
      return;
    }

    const ipLists = this.store.getState().ipLists;

    // Title
    this.containerEl.appendChild(
      h('h2', { className: 'rule-detail__title' }, rule.label),
    );

    // Divider
    this.containerEl.appendChild(h('hr', { className: 'rule-detail__divider' }));

    // Label-value pairs
    const fields = h('div', { className: 'rule-detail__fields' });

    fields.appendChild(this.createField('Action', formatAction(rule.action)));
    fields.appendChild(this.createField('Service', rule.label));
    fields.appendChild(this.createField('Port', formatPorts(rule.ports)));
    fields.appendChild(this.createField('Protocol', formatProtocol(rule.protocol)));

    // Source with expanded IPs
    const sourceText = formatAddress(rule.source, ipLists);
    const sourceField = this.createField('Source', sourceText);
    if (rule.source.type === 'iplist') {
      const ipList = ipLists.get(rule.source.ipListId);
      if (ipList && ipList.entries.length > 0) {
        const expandedIps = h('div', { className: 'rule-detail__expanded-ips' });
        for (const entry of ipList.entries) {
          expandedIps.appendChild(
            h('span', { className: 'rule-detail__ip-entry' }, entry.address),
          );
        }
        sourceField.appendChild(expandedIps);
      }
    }
    fields.appendChild(sourceField);

    fields.appendChild(this.createField('Direction', rule.direction.charAt(0).toUpperCase() + rule.direction.slice(1)));
    fields.appendChild(this.createField('Interface', rule.interfaceIn ?? 'Any'));

    if (rule.comment) {
      fields.appendChild(this.createField('Comment', rule.comment));
    }

    this.containerEl.appendChild(fields);

    // Details section
    const detailsSection = h('div', { className: 'rule-detail__section' });
    detailsSection.appendChild(
      h('div', { className: 'rule-detail__section-header' }, 'Details'),
    );

    const detailFields = h('div', { className: 'rule-detail__fields' });

    // Hit count
    const state = this.store.getState();
    const hostId = state.activeHostId;
    let hitCount = 0;
    if (hostId) {
      const hostState = state.hostStates.get(hostId);
      if (hostState) {
        const counter = hostState.hitCounters.get(this.ruleId);
        if (counter) hitCount = counter.packets;
      }
    }
    detailFields.appendChild(this.createField('Hits', hitCount > 0 ? `${hitCount.toLocaleString()} (last 24h)` : '0'));
    detailFields.appendChild(this.createField('Added', formatDate(rule.createdAt)));
    detailFields.appendChild(this.createField('Origin', formatOrigin(rule)));

    detailsSection.appendChild(detailFields);
    this.containerEl.appendChild(detailsSection);

    // Disclosure triangle for iptables command
    if (rule.raw) {
      const disclosure = h('details', { className: 'rule-detail__disclosure' });
      const summary = h('summary', { className: 'rule-detail__disclosure-summary' },
        'Show iptables command');
      disclosure.appendChild(summary);
      const codeBlock = h('pre', { className: 'rule-detail__code' },
        h('code', {}, rule.raw),
      );
      disclosure.appendChild(codeBlock);
      this.containerEl.appendChild(disclosure);
    }

    // Action buttons
    const actions = h('div', { className: 'rule-detail__actions' });

    const editBtn = h('button', {
      className: 'rule-detail__action-btn rule-detail__action-btn--edit',
      type: 'button',
    }, 'Edit');
    this.listen(editBtn, 'click', () => {
      this.store.dispatch({
        type: 'SET_SIDE_PANEL_CONTENT',
        content: { type: 'rule-edit', ruleId: this.ruleId },
      });
    });

    const disableBtn = h('button', {
      className: 'rule-detail__action-btn rule-detail__action-btn--disable',
      type: 'button',
    }, rule.enabled ? 'Disable' : 'Enable');
    this.listen(disableBtn, 'click', () => {
      const activeHostId = this.store.getState().activeHostId;
      if (activeHostId) {
        this.store.dispatch({
          type: 'ADD_STAGED_CHANGE',
          hostId: activeHostId,
          change: {
            type: 'modify',
            ruleId: this.ruleId,
            before: { enabled: rule.enabled },
            after: { enabled: !rule.enabled },
          },
        });
      }
    });

    const deleteBtn = h('button', {
      className: 'rule-detail__action-btn rule-detail__action-btn--delete',
      type: 'button',
    }, 'Delete');
    this.listen(deleteBtn, 'click', () => {
      const activeHostId = this.store.getState().activeHostId;
      if (activeHostId) {
        this.store.dispatch({
          type: 'ADD_STAGED_CHANGE',
          hostId: activeHostId,
          change: { type: 'delete', ruleId: this.ruleId },
        });
        this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: false });
        this.store.dispatch({ type: 'SET_SIDE_PANEL_CONTENT', content: null });
      }
    });

    actions.appendChild(editBtn);
    actions.appendChild(disableBtn);
    actions.appendChild(deleteBtn);
    this.containerEl.appendChild(actions);
  }

  private createField(label: string, value: string): HTMLElement {
    const field = h('div', { className: 'rule-detail__field' });
    field.appendChild(h('span', { className: 'rule-detail__label' }, label));
    field.appendChild(h('span', { className: 'rule-detail__value' }, value));
    return field;
  }
}
