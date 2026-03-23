/**
 * Multi-Apply dialog — apply staged changes to multiple hosts
 * in a group with configurable deployment strategy.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, Host, HostGroup } from '../../store/types';
import { applyChanges } from '../../ipc/bridge';
import { h, trapFocus } from '../../utils/dom';

type Strategy = 'canary' | 'rolling' | 'parallel';
type HostApplyStatus = 'pending' | 'applying' | 'confirmed' | 'failed';

interface HostProgress {
  hostId: string;
  status: HostApplyStatus;
  error?: string;
}

export class MultiApplyDialog extends Component {
  private overlay!: HTMLElement;
  private strategy: Strategy = 'rolling';
  private hostProgresses: HostProgress[] = [];
  private applyBtn!: HTMLButtonElement;
  private progressContainer!: HTMLElement;
  private isApplying = false;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
  }

  private getGroupAndHosts(): { group: HostGroup | null; hosts: Host[] } {
    const state = this.store.getState();
    const activeHostId = state.activeHostId;
    if (!activeHostId) return { group: null, hosts: [] };

    const activeHost = state.hosts.get(activeHostId);
    if (!activeHost) return { group: null, hosts: [] };

    // Find first group
    for (const groupId of activeHost.groupIds) {
      const group = state.groups.get(groupId);
      if (group) {
        const hosts: Host[] = [];
        for (const memberId of group.memberHostIds) {
          const h = state.hosts.get(memberId);
          if (h) hosts.push(h);
        }
        return { group, hosts };
      }
    }

    // No group — just the active host
    return { group: null, hosts: activeHost ? [activeHost] : [] };
  }

  private render(): void {
    const { group, hosts } = this.getGroupAndHosts();

    this.overlay = h('div', { className: 'dialog-overlay' });
    const titleId = 'multiapply-dialog-title';
    const dialog = h('div', {
      className: 'dialog-card',
      role: 'dialog',
      'aria-modal': 'true',
      'aria-labelledby': titleId,
    });

    // Header
    const header = h('div', { className: 'dialog-header' },
      h('span', { className: 'dialog-title', id: titleId },
        group ? `Apply to ${group.name}` : 'Multi-Host Apply'),
      h('button', { className: 'dialog-close', 'aria-label': 'Close' }, '\u00D7'),
    );
    dialog.appendChild(header);

    // Body
    const body = h('div', { className: 'dialog-body' });

    // Host list with status
    const hostList = h('div', { className: 'dialog-members-list' });
    this.hostProgresses = [];
    for (const host of hosts) {
      const progress: HostProgress = { hostId: host.id, status: 'pending' };
      this.hostProgresses.push(progress);

      const statusText = host.status === 'connected' ? 'Connected' : host.status;
      const row = h('div', { className: 'dialog-member-row' },
        h('span', { className: 'dialog-member-label' }, host.name),
        h('span', {
          className: `rule-table__host-status rule-table__host-status--${host.status}`,
          dataset: { hostProgressId: host.id },
        }, statusText),
      );
      hostList.appendChild(row);
    }
    body.appendChild(hostList);

    // Strategy selector
    const strategyField = h('div', { className: 'dialog-field', style: { marginTop: '16px' } });
    strategyField.appendChild(h('label', { className: 'dialog-label' }, 'Deployment Strategy'));
    const strategyGroup = h('div', { className: 'dialog-radio-group' });

    const strategies: Array<{ value: Strategy; label: string }> = [
      { value: 'canary', label: 'Canary' },
      { value: 'rolling', label: 'Rolling' },
      { value: 'parallel', label: 'Parallel' },
    ];

    for (const s of strategies) {
      const radio = document.createElement('input');
      radio.type = 'radio';
      radio.name = 'strategy';
      radio.value = s.value;
      radio.id = `strategy-${s.value}`;
      radio.checked = s.value === this.strategy;
      this.listen(radio, 'change', () => {
        this.strategy = s.value;
      });
      strategyGroup.appendChild(radio);
      strategyGroup.appendChild(h('label', { for: `strategy-${s.value}` }, s.label));
    }
    strategyField.appendChild(strategyGroup);
    body.appendChild(strategyField);

    // Progress display
    this.progressContainer = h('div', { className: 'dialog-test-status' });
    body.appendChild(this.progressContainer);

    dialog.appendChild(body);

    // Footer
    const footer = h('div', { className: 'dialog-footer' });
    const spacer = h('div', { className: 'dialog-footer-spacer' });
    const cancelBtn = h('button', { className: 'dialog-btn dialog-btn--secondary' }, 'Cancel');
    this.applyBtn = document.createElement('button');
    this.applyBtn.className = 'dialog-btn dialog-btn--primary';
    this.applyBtn.textContent = 'Apply';
    this.applyBtn.disabled = hosts.filter(h => h.status === 'connected').length === 0;

    footer.appendChild(spacer);
    footer.appendChild(cancelBtn);
    footer.appendChild(this.applyBtn);
    dialog.appendChild(footer);

    this.overlay.appendChild(dialog);
    this.el.appendChild(this.overlay);

    trapFocus(dialog, this.ac.signal);

    // Events
    this.listen(document, 'keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Escape') this.close();
    });
    this.listen(cancelBtn, 'click', () => this.close());
    this.listen(header.querySelector('.dialog-close')!, 'click', () => this.close());
    this.listen(this.overlay, 'click', (e) => {
      if (e.target === this.overlay) this.close();
    });
    this.listen(this.applyBtn, 'click', () => this.handleApply());
  }

  private async handleApply(): Promise<void> {
    if (this.isApplying) return;
    this.isApplying = true;
    this.applyBtn.disabled = true;
    this.applyBtn.textContent = 'Applying...';

    const state = this.store.getState();
    const connectedHosts = this.hostProgresses.filter(hp => {
      const host = state.hosts.get(hp.hostId);
      return host && host.status === 'connected';
    });

    if (this.strategy === 'parallel') {
      await Promise.all(connectedHosts.map(hp => this.applyToHost(hp, state)));
    } else {
      // canary: apply to first, then wait; rolling: apply sequentially
      for (const hp of connectedHosts) {
        await this.applyToHost(hp, state);
        if (hp.status === 'failed' && this.strategy === 'canary') {
          break;
        }
      }
    }

    this.isApplying = false;
    this.applyBtn.textContent = 'Done';
  }

  private async applyToHost(hp: HostProgress, state: AppState): Promise<void> {
    hp.status = 'applying';
    this.updateProgressDisplay(hp);

    const changeset = state.stagedChanges.get(hp.hostId);
    const changes = changeset?.changes ?? [];

    try {
      await applyChanges(hp.hostId, changes);
      hp.status = 'confirmed';
    } catch (err) {
      hp.status = 'failed';
      hp.error = err instanceof Error ? err.message : 'Apply failed';
    }
    this.updateProgressDisplay(hp);
  }

  private updateProgressDisplay(hp: HostProgress): void {
    const state = this.store.getState();
    const host = state.hosts.get(hp.hostId);
    const hostName = host?.name ?? hp.hostId;

    const statusMap: Record<HostApplyStatus, string> = {
      pending: 'Pending',
      applying: 'Applying...',
      confirmed: 'Confirmed',
      failed: `Failed${hp.error ? ': ' + hp.error : ''}`,
    };

    const statusEl = this.overlay.querySelector<HTMLElement>(`[data-host-progress-id="${hp.hostId}"]`);
    if (statusEl) {
      statusEl.textContent = statusMap[hp.status];
    }

    // Also update progress container
    let entry = this.progressContainer.querySelector(`[data-progress-host="${hp.hostId}"]`);
    if (!entry) {
      const isOk = hp.status === 'confirmed';
      const isError = hp.status === 'failed';
      entry = h('div', {
        className: `dialog-test-item ${isOk ? 'dialog-test-item--ok' : ''} ${isError ? 'dialog-test-item--error' : ''}`,
        dataset: { progressHost: hp.hostId },
      }, `${hostName}: ${statusMap[hp.status]}`);
      this.progressContainer.appendChild(entry);
    } else {
      const isOk = hp.status === 'confirmed';
      const isError = hp.status === 'failed';
      entry.className = `dialog-test-item ${isOk ? 'dialog-test-item--ok' : ''} ${isError ? 'dialog-test-item--error' : ''}`;
      entry.textContent = `${hostName}: ${statusMap[hp.status]}`;
    }
  }

  private close(): void {
    this.overlay.remove();
    this.store.dispatch({ type: 'CLOSE_DIALOG' });
    this.destroy();
  }
}
