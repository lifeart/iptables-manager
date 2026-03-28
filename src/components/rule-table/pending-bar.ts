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
import { addAuditEntry } from '../../store/audit';

export class PendingBar extends Component {
  private countEl!: HTMLElement;
  private discardBtn!: HTMLButtonElement;
  private previewBtn!: HTMLButtonElement;
  private applyBtn!: HTMLButtonElement;
  private groupApplyBtn!: HTMLButtonElement;
  private showChangesLink!: HTMLElement;
  private changesListEl!: HTMLElement;
  private changesExpanded = false;
  private tooltipEl: HTMLElement | null = null;
  private tooltipTimeout: ReturnType<typeof setTimeout> | null = null;
  private previewModalEl: HTMLElement | null = null;

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

    // Preview button
    this.previewBtn = document.createElement('button');
    this.previewBtn.className = 'rule-table__pending-bar-preview';
    this.previewBtn.textContent = 'Preview';
    this.el.appendChild(this.previewBtn);

    // Apply to Group button (only shown when host is in a group)
    this.groupApplyBtn = document.createElement('button');
    this.groupApplyBtn.className = 'rule-table__pending-bar-group-apply';
    this.groupApplyBtn.textContent = 'Apply to Group';
    this.groupApplyBtn.style.display = 'none';
    this.el.appendChild(this.groupApplyBtn);

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

    this.listen(this.previewBtn, 'click', () => {
      this.showPreview();
    });

    this.listen(this.applyBtn, 'click', () => {
      this.applyChanges();
    });

    this.listen(this.groupApplyBtn, 'click', () => {
      this.store.dispatch({ type: 'OPEN_DIALOG', dialog: 'multi-apply' });
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
        this.showError('Safety timer failed \u2014 changes reverted for your protection.');
      } catch (revertErr) {
        // Revert also failed — this is critical
        const revertDetail = revertErr instanceof Error ? revertErr.message : String(revertErr);
        this.showError(
          'CRITICAL: Safety timer AND revert both failed. Rules applied with NO rollback protection. Verify server access immediately.'
        );
        console.error('Revert failed after safety timer failure:', revertDetail);
      }
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

      const timeoutSec = isRealHost ? (state.settings.defaultSafetyTimeout || 60) : undefined;
      const applyResult = await ipc.applyChanges(hostId, changeset.changes, timeoutSec);
      const changeCount = changeset.changes.length;
      this.store.dispatch({ type: 'CLEAR_STAGED_CHANGES', hostId });
      addAuditEntry(hostId, host?.name ?? hostId, 'apply', changeCount, `Applied ${changeCount} change${changeCount !== 1 ? 's' : ''}`);

      // Dispatch safety timer state from the apply result (timer was armed server-side before rules were applied)
      if (applyResult.safetyTimerActive && applyResult.remoteJobId) {
        const now = Date.now();
        this.store.dispatch({
          type: 'SET_SAFETY_TIMER',
          timer: {
            hostId,
            expiresAt: applyResult.safetyTimerExpiry ?? (now + (timeoutSec ?? 60) * 1000),
            remoteJobId: applyResult.remoteJobId,
            mechanism: applyResult.safetyTimerMechanism ?? 'At',
            startedAt: now,
          },
        });
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
            const forceTimeoutSec = isRealHost ? (state.settings.defaultSafetyTimeout || 60) : undefined;
            const forceResult = await ipc.applyChanges(hostId, changeset.changes, forceTimeoutSec);
            const forceChangeCount = changeset.changes.length;
            this.store.dispatch({ type: 'CLEAR_STAGED_CHANGES', hostId });
            addAuditEntry(hostId, host?.name ?? hostId, 'apply', forceChangeCount, `Force-applied ${forceChangeCount} change${forceChangeCount !== 1 ? 's' : ''} (lockout warning overridden)`);

            // Dispatch safety timer state from the force-apply result
            if (forceResult.safetyTimerActive && forceResult.remoteJobId) {
              const now = Date.now();
              this.store.dispatch({
                type: 'SET_SAFETY_TIMER',
                timer: {
                  hostId,
                  expiresAt: forceResult.safetyTimerExpiry ?? (now + (forceTimeoutSec ?? 60) * 1000),
                  remoteJobId: forceResult.remoteJobId,
                  mechanism: forceResult.safetyTimerMechanism ?? 'At',
                  startedAt: now,
                },
              });
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

  private async showPreview(): Promise<void> {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return;

    const changeset = state.stagedChanges.get(hostId);
    if (!changeset || changeset.changes.length === 0) return;

    try {
      this.previewBtn.disabled = true;
      this.previewBtn.textContent = 'Loading...';

      const result = await ipc.previewChanges(hostId, changeset.changes);
      this.renderPreviewModal(result.restoreContent, result.restoreCommand);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Preview failed';
      this.showError(msg);
    } finally {
      this.previewBtn.disabled = false;
      this.previewBtn.textContent = 'Preview';
    }
  }

  private renderPreviewModal(restoreContent: string, restoreCommand: string): void {
    this.closePreviewModal();

    // Backdrop
    const backdrop = h('div', { className: 'preview-modal__backdrop' });

    // Modal
    const modal = h('div', { className: 'preview-modal' });

    // Header
    const header = h('div', { className: 'preview-modal__header' });
    header.appendChild(h('h3', { className: 'preview-modal__title' }, 'Preview: iptables-restore'));
    const closeBtn = h('button', { className: 'preview-modal__close', type: 'button' }, '\u00D7');
    header.appendChild(closeBtn);
    modal.appendChild(header);

    // Command line
    const cmdSection = h('div', { className: 'preview-modal__section' });
    cmdSection.appendChild(h('label', { className: 'preview-modal__label' }, 'Command'));
    const cmdPre = h('pre', { className: 'preview-modal__code preview-modal__code--cmd' });
    cmdPre.appendChild(h('code', {}, restoreCommand));
    cmdSection.appendChild(cmdPre);
    modal.appendChild(cmdSection);

    // Restore content (stdin)
    const contentSection = h('div', { className: 'preview-modal__section' });
    const contentHeader = h('div', { className: 'preview-modal__section-header' });
    contentHeader.appendChild(h('label', { className: 'preview-modal__label' }, 'Stdin content'));
    const copyBtn = h('button', { className: 'preview-modal__copy', type: 'button' }, 'Copy');
    contentHeader.appendChild(copyBtn);
    contentSection.appendChild(contentHeader);

    const contentPre = h('pre', { className: 'preview-modal__code' });
    contentPre.appendChild(h('code', {}, restoreContent));
    contentSection.appendChild(contentPre);
    modal.appendChild(contentSection);

    backdrop.appendChild(modal);
    document.body.appendChild(backdrop);
    this.previewModalEl = backdrop;

    // Events
    const close = () => this.closePreviewModal();
    closeBtn.addEventListener('click', close);
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) close();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') close();
    }, { once: true });

    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(restoreContent).then(() => {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      }).catch(() => {
        copyBtn.textContent = 'Failed';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      });
    });
  }

  private closePreviewModal(): void {
    if (this.previewModalEl) {
      this.previewModalEl.remove();
      this.previewModalEl = null;
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

    // Show/hide "Apply to Group" button based on whether active host belongs to a group
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return false;
        const host = s.hosts.get(hostId);
        return !!(host && host.groupIds.length > 0);
      },
      (hasGroup) => {
        this.groupApplyBtn.style.display = hasGroup ? '' : 'none';
      },
    );
  }
}
