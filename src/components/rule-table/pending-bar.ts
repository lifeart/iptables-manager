/**
 * Pending changes bar — fixed to bottom of rule table.
 *
 * Shows change count, Discard button, Apply button with keyboard shortcut hint.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState } from '../../store/types';
import { selectPendingChangeCount } from '../../store/selectors';
import { formatCount } from '../../utils/format';
import { h } from '../../utils/dom';
import * as ipc from '../../ipc/bridge';

export class PendingBar extends Component {
  private countEl!: HTMLElement;
  private discardBtn!: HTMLButtonElement;
  private applyBtn!: HTMLButtonElement;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindEvents();
    this.bindSubscriptions();
  }

  private render(): void {
    this.el.innerHTML = '';
    this.el.className = 'rule-table__pending-bar';

    // Dot indicator
    const dot = h('span', { className: 'rule-table__pending-bar-dot' });
    this.el.appendChild(dot);

    // Count label
    this.countEl = h('span', { className: 'rule-table__pending-bar-count' });
    this.el.appendChild(this.countEl);

    // Spacer
    this.el.appendChild(h('span', { className: 'rule-table__pending-bar-spacer' }));

    // Discard button
    this.discardBtn = document.createElement('button');
    this.discardBtn.className = 'rule-table__pending-bar-discard';
    this.discardBtn.textContent = 'Discard';
    this.el.appendChild(this.discardBtn);

    // Apply button
    this.applyBtn = document.createElement('button');
    this.applyBtn.className = 'rule-table__pending-bar-apply';
    this.applyBtn.innerHTML = 'Apply <kbd>\u2318S</kbd>';
    this.el.appendChild(this.applyBtn);
  }

  private bindEvents(): void {
    this.listen(this.discardBtn, 'click', () => {
      const hostId = this.store.getState().activeHostId;
      if (hostId) {
        this.store.dispatch({ type: 'CLEAR_STAGED_CHANGES', hostId });
      }
    });

    this.listen(this.applyBtn, 'click', () => {
      this.applyChanges();
    });

    // Keyboard shortcut: Cmd+S / Ctrl+S
    this.listen(document, 'keydown', (e) => {
      const ke = e as KeyboardEvent;
      if ((ke.metaKey || ke.ctrlKey) && ke.key === 's') {
        ke.preventDefault();
        const count = this.store.select(selectPendingChangeCount);
        if (count > 0) {
          this.applyChanges();
        }
      }
    });
  }

  private async applyChanges(): Promise<void> {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return;

    const changeset = state.stagedChanges.get(hostId);
    if (!changeset || changeset.changes.length === 0) return;

    try {
      this.applyBtn.disabled = true;
      this.applyBtn.textContent = 'Applying...';
      await ipc.applyChanges(hostId, changeset.changes);
      this.store.dispatch({ type: 'CLEAR_STAGED_CHANGES', hostId });
    } catch (err) {
      console.error('Apply failed:', err);
      // Error handling will be done via operations tracking in a future iteration
    } finally {
      this.applyBtn.disabled = false;
      this.applyBtn.innerHTML = 'Apply <kbd>\u2318S</kbd>';
    }
  }

  private bindSubscriptions(): void {
    this.subscribe(
      selectPendingChangeCount,
      (count) => {
        this.countEl.textContent = formatCount(count, 'pending change', 'pending changes');
        this.el.classList.toggle('rule-table__pending-bar--visible', count > 0);
      },
    );
  }
}
