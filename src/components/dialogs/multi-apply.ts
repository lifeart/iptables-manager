/**
 * Multi-Apply dialog — apply staged changes to multiple hosts
 * in a group with configurable deployment strategy.
 *
 * Uses the rules:apply-group IPC command which delegates to the
 * backend multi_apply module for canary/rolling/parallel strategies.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { Host, HostGroup } from '../../store/types';
import { applyToGroup } from '../../ipc/bridge';
import type { GroupApplyResult } from '../../ipc/bridge';
import { h, trapFocus } from '../../utils/dom';
import { addAuditEntry } from '../../store/audit';

type Strategy = 'canary' | 'rolling' | 'parallel';
type HostApplyStatus = 'pending' | 'applying' | 'confirmed' | 'failed' | 'skipped';

interface HostProgress {
  hostId: string;
  status: HostApplyStatus;
  error?: string;
}

const STRATEGY_DESCRIPTIONS: Record<Strategy, string> = {
  canary: 'Apply to first host, then all remaining if it succeeds.',
  rolling: 'Apply one host at a time, stopping on first failure.',
  parallel: 'Apply to all hosts concurrently.',
};

export class MultiApplyDialog extends Component {
  private overlay!: HTMLElement;
  private strategy: Strategy = 'rolling';
  private selectedGroupId: string | null = null;
  private hostProgresses: HostProgress[] = [];
  private applyBtn!: HTMLButtonElement;
  private progressContainer!: HTMLElement;
  private hostListEl!: HTMLElement;
  private strategyDescEl!: HTMLElement;
  private summaryEl!: HTMLElement;
  private isApplying = false;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    // Pick initial group from active host or first available
    const state = this.store.getState();
    const activeHostId = state.activeHostId;
    if (activeHostId) {
      const activeHost = state.hosts.get(activeHostId);
      if (activeHost && activeHost.groupIds.length > 0) {
        this.selectedGroupId = activeHost.groupIds[0];
      }
    }
    if (!this.selectedGroupId) {
      const groups = this.getAvailableGroups();
      if (groups.length > 0) {
        this.selectedGroupId = groups[0].id;
      }
    }
    this.render();
  }

  private getAvailableGroups(): HostGroup[] {
    const state = this.store.getState();
    const result: HostGroup[] = [];
    for (const [, group] of state.groups) {
      if (group.memberHostIds.length > 0) {
        result.push(group);
      }
    }
    return result;
  }

  private getSelectedHosts(): Host[] {
    const state = this.store.getState();
    if (this.selectedGroupId) {
      const group = state.groups.get(this.selectedGroupId);
      if (group) {
        const hosts: Host[] = [];
        for (const memberId of group.memberHostIds) {
          const host = state.hosts.get(memberId);
          if (host) hosts.push(host);
        }
        return hosts;
      }
    }

    // Fallback: active host only
    const activeHostId = state.activeHostId;
    if (!activeHostId) return [];
    const activeHost = state.hosts.get(activeHostId);
    return activeHost ? [activeHost] : [];
  }

  private render(): void {
    const hosts = this.getSelectedHosts();
    const groups = this.getAvailableGroups();

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
      h('span', { className: 'dialog-title', id: titleId }, 'Apply to Group'),
      h('button', { className: 'dialog-close', 'aria-label': 'Close' }, '\u00D7'),
    );
    dialog.appendChild(header);

    // Body
    const body = h('div', { className: 'dialog-body' });

    // Group selector (if multiple groups)
    if (groups.length > 1) {
      const groupField = h('div', { className: 'dialog-field' });
      groupField.appendChild(h('label', { className: 'dialog-label' }, 'Host Group'));
      const groupSelect = document.createElement('select');
      groupSelect.className = 'dialog-input';
      for (const group of groups) {
        const opt = document.createElement('option');
        opt.value = group.id;
        opt.textContent = `${group.name} (${group.memberHostIds.length} hosts)`;
        opt.selected = group.id === this.selectedGroupId;
        groupSelect.appendChild(opt);
      }
      this.listen(groupSelect, 'change', () => {
        this.selectedGroupId = groupSelect.value;
        this.refreshHostList();
      });
      groupField.appendChild(groupSelect);
      body.appendChild(groupField);
    } else if (groups.length === 1) {
      body.appendChild(h('div', { className: 'dialog-field' },
        h('label', { className: 'dialog-label' }, `Group: ${groups[0].name}`),
      ));
    }

    // Host list with status
    this.hostListEl = h('div', { className: 'dialog-members-list' });
    this.buildHostList(hosts);
    body.appendChild(this.hostListEl);

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
        this.strategyDescEl.textContent = STRATEGY_DESCRIPTIONS[s.value];
      });
      strategyGroup.appendChild(radio);
      strategyGroup.appendChild(h('label', { for: `strategy-${s.value}` }, s.label));
    }
    strategyField.appendChild(strategyGroup);

    this.strategyDescEl = h('div', { className: 'dialog-help-text' },
      STRATEGY_DESCRIPTIONS[this.strategy]);
    strategyField.appendChild(this.strategyDescEl);

    body.appendChild(strategyField);

    // Summary (shown after apply)
    this.summaryEl = h('div', { className: 'dialog-test-status' });
    this.summaryEl.style.display = 'none';
    body.appendChild(this.summaryEl);

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
    const connectedCount = hosts.filter(host => host.status === 'connected').length;
    this.applyBtn.disabled = connectedCount === 0;

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

  private buildHostList(hosts: Host[]): void {
    this.hostListEl.innerHTML = '';
    this.hostProgresses = [];
    for (const host of hosts) {
      const progress: HostProgress = { hostId: host.id, status: 'pending' };
      this.hostProgresses.push(progress);

      const statusText = host.status === 'connected' ? 'Ready' :
                         host.status === 'disconnected' ? 'Disconnected' : host.status;
      const row = h('div', { className: 'dialog-member-row' },
        h('span', { className: 'dialog-member-label' }, host.name),
        h('span', {
          className: `rule-table__host-status rule-table__host-status--${host.status}`,
          dataset: { hostProgressId: host.id },
        }, statusText),
      );
      this.hostListEl.appendChild(row);
    }
  }

  private refreshHostList(): void {
    const hosts = this.getSelectedHosts();
    this.buildHostList(hosts);
    const connectedCount = hosts.filter(host => host.status === 'connected').length;
    this.applyBtn.disabled = connectedCount === 0;
  }

  private async handleApply(): Promise<void> {
    if (this.isApplying) return;
    this.isApplying = true;
    this.applyBtn.disabled = true;
    this.applyBtn.textContent = 'Applying...';
    this.progressContainer.innerHTML = '';
    this.summaryEl.style.display = 'none';

    const state = this.store.getState();
    const hosts = this.getSelectedHosts();
    const connectedHostIds = hosts
      .filter(host => host.status === 'connected')
      .map(host => host.id);

    if (connectedHostIds.length === 0) {
      this.isApplying = false;
      this.applyBtn.textContent = 'Apply';
      this.applyBtn.disabled = false;
      return;
    }

    // Mark all connected hosts as applying, others as skipped
    for (const hp of this.hostProgresses) {
      const host = state.hosts.get(hp.hostId);
      if (host && host.status === 'connected') {
        hp.status = 'applying';
      } else {
        hp.status = 'skipped';
      }
      this.updateProgressDisplay(hp);
    }

    // Get changes from the active host's staged changeset
    const activeHostId = state.activeHostId;
    let changesJson = '';
    let changeCount = 0;
    if (activeHostId) {
      const changeset = state.stagedChanges.get(activeHostId);
      if (changeset) {
        changesJson = JSON.stringify(changeset.changes);
        changeCount = changeset.changes.length;
      }
    }

    try {
      const result: GroupApplyResult = await applyToGroup(
        connectedHostIds,
        changesJson,
        this.strategy,
      );

      // Update per-host status from results
      for (const hostResult of result.results) {
        const hp = this.hostProgresses.find(p => p.hostId === hostResult.hostId);
        if (hp) {
          hp.status = hostResult.success ? 'confirmed' : 'failed';
          hp.error = hostResult.error ?? undefined;
          this.updateProgressDisplay(hp);

          // Audit successful applies
          if (hostResult.success) {
            const host = state.hosts.get(hostResult.hostId);
            addAuditEntry(
              hostResult.hostId,
              host?.name ?? hostResult.hostId,
              'group-apply',
              changeCount,
              `Group apply (${this.strategy}): ${changeCount} change${changeCount !== 1 ? 's' : ''}`,
            );
          }
        }
      }

      // Mark hosts that were not in results (e.g., skipped due to canary failure)
      for (const hp of this.hostProgresses) {
        if (hp.status === 'applying') {
          hp.status = 'skipped';
          this.updateProgressDisplay(hp);
        }
      }

      // Show summary
      this.showSummary(result);

    } catch (err) {
      // Mark all applying hosts as failed
      for (const hp of this.hostProgresses) {
        if (hp.status === 'applying') {
          hp.status = 'failed';
          hp.error = err instanceof Error ? err.message : 'Apply failed';
          this.updateProgressDisplay(hp);
        }
      }
    }

    this.isApplying = false;
    this.applyBtn.textContent = 'Done';
  }

  private showSummary(result: GroupApplyResult): void {
    this.summaryEl.innerHTML = '';
    this.summaryEl.style.display = '';

    const strategyLabel = result.strategy.charAt(0).toUpperCase() + result.strategy.slice(1);
    const allOk = result.failed === 0;
    const className = allOk ? 'dialog-test-item dialog-test-item--ok' : 'dialog-test-item dialog-test-item--error';

    const summary = h('div', { className },
      `${strategyLabel}: ${result.succeeded}/${result.total} succeeded` +
      (result.failed > 0 ? `, ${result.failed} failed` : ''),
    );
    this.summaryEl.appendChild(summary);
  }

  private updateProgressDisplay(hp: HostProgress): void {
    const state = this.store.getState();
    const host = state.hosts.get(hp.hostId);
    const hostName = host?.name ?? hp.hostId;

    const statusMap: Record<HostApplyStatus, string> = {
      pending: 'Pending',
      applying: 'Applying...',
      confirmed: 'Success',
      failed: `Failed${hp.error ? ': ' + hp.error : ''}`,
      skipped: 'Skipped',
    };

    // Update inline host status badge
    const statusEl = this.overlay.querySelector<HTMLElement>(`[data-host-progress-id="${hp.hostId}"]`);
    if (statusEl) {
      statusEl.textContent = statusMap[hp.status];
      statusEl.className = 'rule-table__host-status';
      if (hp.status === 'confirmed') {
        statusEl.classList.add('rule-table__host-status--connected');
      } else if (hp.status === 'failed') {
        statusEl.classList.add('rule-table__host-status--unreachable');
      } else if (hp.status === 'applying') {
        statusEl.classList.add('rule-table__host-status--connecting');
      } else if (hp.status === 'skipped') {
        statusEl.classList.add('rule-table__host-status--disconnected');
      }
    }

    // Update progress container log
    let entry = this.progressContainer.querySelector(`[data-progress-host="${hp.hostId}"]`);
    if (!entry) {
      if (hp.status === 'pending') return;
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
