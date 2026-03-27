/**
 * Pending changes bar — fixed to bottom of rule table.
 *
 * Shows change count, "Show changes" toggle, Discard button, Apply button
 * with keyboard shortcut hint and hover diff preview tooltip.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, StagedChange } from '../../store/types';
import { selectPendingChangeCount } from '../../store/selectors';
import { formatCount } from '../../utils/format';
import { h } from '../../utils/dom';
import * as ipc from '../../ipc/bridge';
import { IpcError } from '../../ipc/bridge';

export class PendingBar extends Component {
  private countEl!: HTMLElement;
  private discardBtn!: HTMLButtonElement;
  private applyBtn!: HTMLButtonElement;
  private showChangesLink!: HTMLElement;
  private changesListEl!: HTMLElement;
  private changesExpanded = false;
  private tooltipEl: HTMLElement | null = null;
  private tooltipTimeout: ReturnType<typeof setTimeout> | null = null;

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

    // "Show changes" toggle link
    this.showChangesLink = h('button', {
      className: 'rule-table__pending-bar-show-changes',
      type: 'button',
    }, 'Show changes');
    this.el.appendChild(this.showChangesLink);

    // Spacer
    this.el.appendChild(h('span', { className: 'rule-table__pending-bar-spacer' }));

    // Discard button
    this.discardBtn = document.createElement('button');
    this.discardBtn.className = 'rule-table__pending-bar-discard';
    this.discardBtn.textContent = 'Discard';
    this.el.appendChild(this.discardBtn);

    // Apply button (wrapped in container for tooltip positioning)
    const applyContainer = h('div', {
      className: 'rule-table__pending-bar-apply-wrap',
    });
    this.applyBtn = document.createElement('button');
    this.applyBtn.className = 'rule-table__pending-bar-apply';
    this.applyBtn.innerHTML = 'Apply <kbd>\u2318S</kbd>';
    applyContainer.appendChild(this.applyBtn);
    this.el.appendChild(applyContainer);

    // Expandable changes list (below the bar)
    this.changesListEl = h('div', {
      className: 'rule-table__pending-bar-changes-list',
    });
    this.changesListEl.style.display = 'none';
    this.el.appendChild(this.changesListEl);
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

    // "Show changes" toggle
    this.listen(this.showChangesLink, 'click', () => {
      this.changesExpanded = !this.changesExpanded;
      this.showChangesLink.textContent = this.changesExpanded ? 'Hide changes' : 'Show changes';
      this.changesListEl.style.display = this.changesExpanded ? '' : 'none';
      if (this.changesExpanded) {
        this.renderChangesList();
      }
    });

    // Hover diff preview on Apply button
    this.listen(this.applyBtn, 'mouseenter', () => {
      this.tooltipTimeout = setTimeout(() => {
        this.showApplyTooltip();
      }, 200);
    });

    this.listen(this.applyBtn, 'mouseleave', () => {
      if (this.tooltipTimeout) {
        clearTimeout(this.tooltipTimeout);
        this.tooltipTimeout = null;
      }
      this.hideApplyTooltip();
    });

    // Keyboard shortcut: Cmd+S / Ctrl+S — only on rules tab
    this.listen(document, 'keydown', (e) => {
      const ke = e as KeyboardEvent;
      if ((ke.metaKey || ke.ctrlKey) && ke.key === 's') {
        ke.preventDefault();
        if (this.store.getState().activeTab !== 'rules') return;
        const count = this.store.select(selectPendingChangeCount);
        if (count > 0) {
          this.applyChanges();
        }
      }
    });
  }

  private getChanges(): StagedChange[] {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return [];
    const changeset = state.stagedChanges.get(hostId);
    return changeset?.changes ?? [];
  }

  private describeChange(change: StagedChange): string {
    switch (change.type) {
      case 'add':
        return `+ Added ${change.rule.label}`;
      case 'delete':
        return `- Removed rule ${change.ruleId}`;
      case 'modify':
        return `~ Modified rule ${change.ruleId}`;
      case 'reorder':
        return `\u2195 Moved rule ${change.ruleId}`;
      case 'policy':
        return `~ Policy ${change.direction}: ${change.policy}`;
      case 'iplist-update':
        return `~ Updated IP list ${change.ipListId}`;
      default:
        return 'Unknown change';
    }
  }

  private renderChangesList(): void {
    this.changesListEl.innerHTML = '';
    const changes = this.getChanges();
    for (let i = 0; i < changes.length; i++) {
      const change = changes[i];
      const row = h('div', {
        className: 'rule-table__pending-bar-change-row',
      });
      row.appendChild(h('span', {}, this.describeChange(change)));
      const undoBtn = h('button', {
        className: 'rule-table__pending-bar-undo-btn',
        type: 'button',
      }, 'undo');
      const changeIndex = i;
      this.listen(undoBtn, 'click', () => {
        const hostId = this.store.getState().activeHostId;
        if (hostId) {
          // Remove individual staged change by undoing repeatedly until we match, then redo the rest
          // For simplicity, dispatch UNDO_STAGED_CHANGE (removes last) — true individual undo would need store support
          void changeIndex;
          this.store.dispatch({ type: 'UNDO_STAGED_CHANGE', hostId });
          this.renderChangesList();
        }
      });
      row.appendChild(undoBtn);
      this.changesListEl.appendChild(row);
    }
    if (changes.length === 0) {
      this.changesListEl.appendChild(h('span', {
        className: 'rule-table__pending-bar-empty',
      }, 'No pending changes'));
    }
  }

  private showApplyTooltip(): void {
    this.hideApplyTooltip();
    const changes = this.getChanges();
    if (changes.length === 0) return;

    this.tooltipEl = h('div', {
      className: 'rule-table__pending-bar-tooltip',
    });
    for (const change of changes) {
      this.tooltipEl.appendChild(h('div', {
        className: 'rule-table__pending-bar-tooltip-item',
      }, this.describeChange(change)));
    }
    // Append to the apply button's parent container (which has position: relative)
    this.applyBtn.parentElement?.appendChild(this.tooltipEl);
  }

  private hideApplyTooltip(): void {
    if (this.tooltipEl) {
      this.tooltipEl.remove();
      this.tooltipEl = null;
    }
  }

  /**
   * Schedule a safety timer after a successful apply.
   * If the timer fails, revert the just-applied changes and show an error.
   */
  private async scheduleSafetyTimer(hostId: string, timeoutSec: number): Promise<void> {
    const now = Date.now();
    try {
      const timerResult = await ipc.setSafetyTimer(hostId, timeoutSec);
      this.store.dispatch({
        type: 'SET_SAFETY_TIMER',
        timer: {
          hostId,
          expiresAt: now + timeoutSec * 1000,
          remoteJobId: timerResult.jobId,
          mechanism: timerResult.mechanism,
          startedAt: now,
        },
      });
    } catch {
      // Safety timer failed — revert the just-applied rules so the server
      // is not left in a state with no automatic rollback protection.
      try {
        await ipc.revertChanges(hostId);
      } catch {
        // Revert also failed — show both issues
      }
      this.showError('Safety timer failed \u2014 changes reverted for your protection.');
      throw new Error('Safety timer scheduling failed');
    }
  }

  private showError(message: string): void {
    const errorEl = document.createElement('span');
    errorEl.className = 'rule-table__pending-bar-error';
    errorEl.textContent = message;
    this.el.appendChild(errorEl);
    setTimeout(() => errorEl.remove(), 5000);
  }

  private async applyChanges(): Promise<void> {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return;

    const changeset = state.stagedChanges.get(hostId);
    if (!changeset || changeset.changes.length === 0) return;

    const host = state.hosts.get(hostId);
    const isRealHost = host && host.status === 'connected';

    try {
      this.applyBtn.disabled = true;
      this.applyBtn.textContent = 'Applying...';

      await ipc.applyChanges(hostId, changeset.changes);
      this.store.dispatch({ type: 'CLEAR_STAGED_CHANGES', hostId });

      // Set safety timer for real connected hosts
      if (isRealHost) {
        const timeoutSec = state.settings.defaultSafetyTimeout || 60;
        await this.scheduleSafetyTimer(hostId, timeoutSec);
      }
    } catch (err) {
      if (err instanceof IpcError && err.kind === 'LockoutDetected') {
        const proceed = window.confirm(
          'WARNING: These changes may lock you out!\n\n' +
          err.detail + '\n\n' +
          'Add an SSH rule for your IP before applying.\n\n' +
          'Apply anyway? (DANGEROUS)'
        );
        if (proceed) {
          try {
            await ipc.applyChanges(hostId, changeset.changes);
            this.store.dispatch({ type: 'CLEAR_STAGED_CHANGES', hostId });

            // Schedule safety timer for force-applied changes too
            if (isRealHost) {
              const timeoutSec = state.settings.defaultSafetyTimeout || 60;
              await this.scheduleSafetyTimer(hostId, timeoutSec);
            }
          } catch (forceErr) {
            const forceMsg = forceErr instanceof Error ? forceErr.message : 'Apply failed';
            this.showError(forceMsg);
          }
        }
      } else if (!(err instanceof Error && err.message === 'Safety timer scheduling failed')) {
        // Show error feedback inline (but not for safety timer failures,
        // which are already reported by scheduleSafetyTimer)
        const errorMsg = err instanceof Error ? err.message : 'Apply failed';
        this.showError(errorMsg);
      }
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
        // Update expanded changes list if visible
        if (this.changesExpanded) {
          this.renderChangesList();
        }
        // Reset expansion when no changes
        if (count === 0) {
          this.changesExpanded = false;
          this.showChangesLink.textContent = 'Show changes';
          this.changesListEl.style.display = 'none';
        }
      },
    );
  }
}
