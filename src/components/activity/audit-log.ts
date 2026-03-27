/**
 * Audit log panel — shows a reverse-chronological list of rule changes.
 *
 * Each entry displays: timestamp, host name, action badge, and details.
 * Rendered as a section within the activity view.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, AuditEntry } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';
import { formatTimeAgo } from '../../utils/format';

const ACTION_LABELS: Record<AuditEntry['action'], string> = {
  'apply': 'Applied',
  'revert': 'Reverted',
  'confirm': 'Confirmed',
  'snapshot-restore': 'Restored',
  'group-apply': 'Group Apply',
};

const ACTION_CLASSES: Record<AuditEntry['action'], string> = {
  'apply': 'audit-log__badge--apply',
  'revert': 'audit-log__badge--revert',
  'confirm': 'audit-log__badge--confirm',
  'snapshot-restore': 'audit-log__badge--restore',
  'group-apply': 'audit-log__badge--group-apply',
};

export class AuditLog extends Component {
  private listEl: HTMLElement;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);

    this.listEl = h('div', { className: 'audit-log__list' });
    this.el.appendChild(this.listEl);

    this.subscribe(
      (s: AppState) => s.auditLog,
      () => this.renderEntries(),
    );

    this.renderEntries();
  }

  private renderEntries(): void {
    clearChildren(this.listEl);

    const state = this.store.getState();
    const entries = state.auditLog;

    if (entries.length === 0) {
      this.listEl.appendChild(
        h('div', { className: 'audit-log__empty' }, 'No changes recorded yet.'),
      );
      return;
    }

    for (const entry of entries) {
      this.listEl.appendChild(this.createEntryRow(entry));
    }
  }

  private createEntryRow(entry: AuditEntry): HTMLElement {
    const row = h('div', { className: 'audit-log__row' });

    // Timestamp
    const date = new Date(entry.timestamp);
    const timeStr = date.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
    const timeEl = h('span', { className: 'audit-log__time' }, timeStr);
    timeEl.title = date.toISOString();
    row.appendChild(timeEl);

    // Action badge
    const badgeClass = ACTION_CLASSES[entry.action] ?? '';
    const badge = h('span', {
      className: `audit-log__badge ${badgeClass}`,
    }, ACTION_LABELS[entry.action] ?? entry.action);
    row.appendChild(badge);

    // Host name
    row.appendChild(h('span', { className: 'audit-log__host' }, entry.hostName));

    // Details
    row.appendChild(h('span', { className: 'audit-log__details' }, entry.details));

    // Relative time
    row.appendChild(h('span', { className: 'audit-log__ago' }, formatTimeAgo(entry.timestamp)));

    return row;
  }
}
