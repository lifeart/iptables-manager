/**
 * Snapshot history panel — renders a list of snapshots for the active host.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { Snapshot } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';
import { demoSnapshots } from '../../mock/demo-data';
import { selectActiveHost } from '../../store/selectors';
import type { AppState } from '../../store/types';

export class SnapshotHistory extends Component {
  private listEl: HTMLElement;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);

    const wrapper = h('div', { className: 'side-panel__snapshot-history' });
    wrapper.appendChild(h('h3', { className: 'side-panel__section-title' }, 'Snapshot History'));

    this.listEl = h('div', { className: 'side-panel__snapshot-list' });
    wrapper.appendChild(this.listEl);

    this.el.appendChild(wrapper);

    this.subscribe(
      (s: AppState) => s.activeHostId,
      () => this.renderSnapshots(),
    );

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

    const snapshots = demoSnapshots.filter(s => s.hostId === host.id);

    if (snapshots.length === 0) {
      this.listEl.appendChild(
        h('p', { className: 'side-panel__empty-text' }, 'No snapshots yet.'),
      );
      return;
    }

    // Sort by timestamp descending (most recent first)
    const sorted = [...snapshots].sort((a, b) => b.timestamp - a.timestamp);

    for (const snapshot of sorted) {
      const item = this.createSnapshotItem(snapshot);
      this.listEl.appendChild(item);
    }
  }

  private createSnapshotItem(snapshot: Snapshot): HTMLElement {
    const date = new Date(snapshot.timestamp);
    const timeStr = date.toLocaleString();

    const item = h('div', { className: 'side-panel__snapshot-item' });

    const header = h('div', { className: 'side-panel__snapshot-item-header' });
    header.appendChild(
      h('span', { className: 'side-panel__snapshot-item-time' }, timeStr),
    );
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
}
