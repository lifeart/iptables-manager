/**
 * Snapshot history panel — renders a list of snapshots for the active host.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import { h, clearChildren } from '../../utils/dom';
import { demoSnapshots } from '../../mock/demo-data';
import { selectActiveHost } from '../../store/selectors';
import type { AppState, Snapshot } from '../../store/types';
import * as ipc from '../../ipc/bridge';
import type { SnapshotMeta } from '../../ipc/bridge';

export class SnapshotHistory extends Component {
  private listEl: HTMLElement;
  private ipcSnapshots: SnapshotMeta[] | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);

    const wrapper = h('div', { className: 'side-panel__snapshot-history' });
    wrapper.appendChild(h('h3', { className: 'side-panel__section-title' }, 'Snapshot History'));

    this.listEl = h('div', { className: 'side-panel__snapshot-list' });
    wrapper.appendChild(this.listEl);

    this.el.appendChild(wrapper);

    this.subscribe(
      (s: AppState) => s.activeHostId,
      () => this.loadSnapshots(),
    );

    this.loadSnapshots();
  }

  private async loadSnapshots(): Promise<void> {
    const host = this.store.select(selectActiveHost);
    if (!host) {
      this.ipcSnapshots = null;
      this.renderSnapshots();
      return;
    }

    try {
      const snapshots = await ipc.listSnapshots(host.id);
      this.ipcSnapshots = snapshots.length > 0 ? snapshots : null;
    } catch {
      this.ipcSnapshots = null;
    }

    this.renderSnapshots();
  }

  private renderSnapshots(): void {
    clearChildren(this.listEl);

    const host = this.store.select(selectActiveHost);
    if (!host) {
      this.listEl.appendChild(
        h('p', { className: 'side-panel__empty-text' }, 'No host selected.'),
      );
      return;
    }

    // Use IPC snapshots if available, otherwise fall back to demo data
    if (this.ipcSnapshots && this.ipcSnapshots.length > 0) {
      const sorted = [...this.ipcSnapshots].sort((a, b) => b.timestamp - a.timestamp);
      for (const snap of sorted) {
        const item = this.createSnapshotMetaItem(snap);
        this.listEl.appendChild(item);
      }
      return;
    }

    // Fall back to demo data
    const snapshots = demoSnapshots.filter(s => s.hostId === host.id);

    if (snapshots.length === 0) {
      this.listEl.appendChild(
        h('p', { className: 'side-panel__empty-text' }, 'No snapshots yet.'),
      );
      return;
    }

    const sorted = [...snapshots].sort((a, b) => b.timestamp - a.timestamp);
    for (const snapshot of sorted) {
      const item = this.createSnapshotItem(snapshot);
      this.listEl.appendChild(item);
    }
  }

  private createSnapshotMetaItem(snapshot: SnapshotMeta): HTMLElement {
    const date = new Date(snapshot.timestamp);
    const timeStr = date.toLocaleString();

    const item = h('div', { className: 'side-panel__snapshot-item' });

    const header = h('div', { className: 'side-panel__snapshot-item-header' });
    header.appendChild(
      h('span', { className: 'side-panel__snapshot-item-time' }, timeStr),
    );

    const restoreBtn = h('button', {
      className: 'dialog-btn dialog-btn--secondary side-panel__snapshot-restore-btn',
      type: 'button',
    }, 'Restore');
    this.listen(restoreBtn, 'click', () => this.handleRestore(snapshot.id));
    header.appendChild(restoreBtn);

    item.appendChild(header);

    if (snapshot.description) {
      item.appendChild(
        h('p', { className: 'side-panel__snapshot-item-desc' }, snapshot.description),
      );
    }

    item.appendChild(
      h('span', { className: 'side-panel__snapshot-item-meta' },
        `${snapshot.ruleCount} rule${snapshot.ruleCount !== 1 ? 's' : ''}`),
    );

    return item;
  }

  private createSnapshotItem(snapshot: Snapshot): HTMLElement {
    const date = new Date(snapshot.timestamp);
    const timeStr = date.toLocaleString();

    const item = h('div', { className: 'side-panel__snapshot-item' });

    const header = h('div', { className: 'side-panel__snapshot-item-header' });
    header.appendChild(
      h('span', { className: 'side-panel__snapshot-item-time' }, timeStr),
    );

    const restoreBtn = h('button', {
      className: 'dialog-btn dialog-btn--secondary side-panel__snapshot-restore-btn',
      type: 'button',
    }, 'Restore');
    this.listen(restoreBtn, 'click', () => this.handleRestore(snapshot.id));
    header.appendChild(restoreBtn);

    item.appendChild(header);

    if (snapshot.description) {
      item.appendChild(
        h('p', { className: 'side-panel__snapshot-item-desc' }, snapshot.description),
      );
    }

    const ruleCount = snapshot.parsedRules.length;
    item.appendChild(
      h('span', { className: 'side-panel__snapshot-item-meta' },
        `${ruleCount} rule${ruleCount !== 1 ? 's' : ''}`),
    );

    return item;
  }

  private async handleRestore(snapshotId: string): Promise<void> {
    const host = this.store.select(selectActiveHost);
    if (!host) return;

    try {
      await ipc.restoreSnapshot(host.id, snapshotId);
      // Re-fetch rules after restore
      const ruleSet = await ipc.fetchRules(host.id);
      // Import convertRuleSet dynamically to avoid circular deps
      const { convertRuleSet } = await import('../../services/rule-converter');
      const rules = convertRuleSet(ruleSet);
      this.store.dispatch({ type: 'SET_HOST_RULES', hostId: host.id, rules });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Restore failed';
      window.alert(`Snapshot restore failed: ${errorMsg}`);
    }
  }
}
