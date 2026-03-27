/**
 * Activity view — live traffic monitoring with hit counters,
 * blocked log, fail2ban bans, and connection tracking.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState } from '../../store/types';
import { selectActiveHost } from '../../store/selectors';
import { onHitCounters, onBlockedEntry, onConntrack, subscribeActivity, unsubscribeActivity, fetchBans, fetchActivity } from '../../ipc/bridge';
import type { Fail2banBan } from '../../ipc/bridge';
import { h } from '../../utils/dom';
import { formatTimeAgo } from '../../utils/format';
import { HitCounters } from './hit-counters';
import { BlockedLog } from './blocked-log';
import { ConntrackBar } from './conntrack';
import { AuditLog } from './audit-log';

export class Activity extends Component {
  private hitCountersEl!: HTMLElement;
  private blockedLogEl!: HTMLElement;
  private bansSection!: HTMLElement;
  private conntrackEl!: HTMLElement;
  private pauseBtn!: HTMLButtonElement;
  private refreshBtn!: HTMLButtonElement;
  private saturationBanner: HTMLElement | null = null;

  private hitCounters: HitCounters | null = null;
  private blockedLog: BlockedLog | null = null;
  private conntrackBar: ConntrackBar | null = null;
  private auditLogComponent: AuditLog | null = null;

  private paused = false;
  private streamId: string | null = null;
  private pollInterval: ReturnType<typeof setInterval> | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindSubscriptions();
    this.setupIpcListeners();
  }

  private render(): void {
    this.el.innerHTML = '';
    this.el.className = 'activity-view';

    // Controls bar
    const controls = h('div', { className: 'activity-view__controls' });
    this.pauseBtn = document.createElement('button');
    this.pauseBtn.className = 'dialog-btn dialog-btn--secondary dialog-btn--small';
    this.pauseBtn.textContent = 'Pause';

    this.refreshBtn = document.createElement('button');
    this.refreshBtn.className = 'dialog-btn dialog-btn--secondary dialog-btn--small';
    this.refreshBtn.textContent = 'Refresh';

    controls.appendChild(this.pauseBtn);
    controls.appendChild(this.refreshBtn);
    this.el.appendChild(controls);

    this.listen(this.pauseBtn, 'click', () => this.togglePause());
    this.listen(this.refreshBtn, 'click', () => this.refresh());

    // Rule Hits section
    this.el.appendChild(h('h2', { className: 'activity-view__section-title' }, 'Rule Hits (live)'));
    this.hitCountersEl = h('div', { className: 'activity-view__hit-counters' });
    this.el.appendChild(this.hitCountersEl);

    // Blocked traffic section
    this.el.appendChild(h('h2', { className: 'activity-view__section-title' }, 'Recent Blocked'));
    this.blockedLogEl = h('div', { className: 'activity-view__blocked-log' });
    this.el.appendChild(this.blockedLogEl);

    // Automated Bans section (hidden when not detected)
    this.bansSection = h('div', { className: 'activity-view__bans-section', style: { display: 'none' } });
    this.bansSection.appendChild(h('h2', { className: 'activity-view__section-title' }, 'Automated Bans (fail2ban)'));
    this.el.appendChild(this.bansSection);

    // Connection Tracking section
    this.el.appendChild(h('h2', { className: 'activity-view__section-title' }, 'Connection Tracking'));
    this.conntrackEl = h('div', { className: 'activity-view__conntrack' });
    this.el.appendChild(this.conntrackEl);

    // Initialize child components
    this.hitCounters = new HitCounters(this.hitCountersEl, this.store);
    this.addChild(this.hitCounters);

    this.blockedLog = new BlockedLog(this.blockedLogEl, this.store);
    this.addChild(this.blockedLog);

    this.conntrackBar = new ConntrackBar(this.conntrackEl, this.store);
    this.addChild(this.conntrackBar);

    // Audit Log section
    this.el.appendChild(h('h2', { className: 'activity-view__section-title' }, 'Change Log'));
    const auditLogEl = h('div', { className: 'activity-view__audit-log' });
    this.el.appendChild(auditLogEl);

    this.auditLogComponent = new AuditLog(auditLogEl, this.store);
    this.addChild(this.auditLogComponent);
  }

  private bindSubscriptions(): void {
    // Show/hide fail2ban section based on detection
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return false;
        const host = s.hosts.get(hostId);
        if (!host?.capabilities) return false;
        return host.capabilities.detectedTools.some(t => t.type === 'fail2ban');
      },
      (hasFail2ban) => {
        this.bansSection.style.display = hasFail2ban ? '' : 'none';
        if (hasFail2ban) this.loadBans();
      },
    );

    // Port saturation warning when conntrack > 80%
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hostStates.get(hostId)?.conntrackUsage ?? null;
      },
      (usage) => this.updateSaturationBanner(usage),
    );

    // Re-subscribe on host change
    this.subscribe(
      (s: AppState) => s.activeHostId,
      () => this.onHostChanged(),
    );
  }

  private async setupIpcListeners(): Promise<void> {
    const signal = this.ac.signal;

    await onHitCounters((payload) => {
      if (this.paused) return;
      this.store.dispatch({
        type: 'UPDATE_HIT_COUNTERS',
        hostId: payload.hostId,
        counters: payload.counters,
      });
    }, signal);

    await onBlockedEntry((payload) => {
      if (this.paused) return;
      this.store.dispatch({
        type: 'ADD_BLOCKED_ENTRY',
        hostId: payload.hostId,
        entry: payload.entry,
      });
    }, signal);

    await onConntrack((payload) => {
      if (this.paused) return;
      this.store.dispatch({
        type: 'SET_CONNTRACK_USAGE',
        hostId: payload.hostId,
        current: payload.current,
        max: payload.max,
      });
    }, signal);
  }

  private async onHostChanged(): Promise<void> {
    // Clean up previous polling
    this.stopPolling();

    // Unsubscribe from old stream
    if (this.streamId) {
      try {
        await unsubscribeActivity(this.streamId);
      } catch {
        // Unsubscribe failure is non-critical
      }
      this.streamId = null;
    }

    // Subscribe to new host
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return;

    const host = state.hosts.get(hostId);
    if (!host) return;

    try {
      this.streamId = await subscribeActivity(hostId);
    } catch {
      this.showActivityError('Unable to load activity data');
    }

    // For real connected hosts (not demo), poll for activity data
    if (host.status === 'connected') {
      this.fetchActivityData(hostId);
      const pollMs = state.settings.pollIntervalMs || 30000;
      this.pollInterval = setInterval(() => {
        if (!this.paused) {
          this.fetchActivityData(hostId);
        }
      }, pollMs);
    }
  }

  private async fetchActivityData(hostId: string): Promise<void> {
    try {
      const data = await fetchActivity(hostId);
      this.store.dispatch({
        type: 'UPDATE_HIT_COUNTERS',
        hostId,
        counters: data.hitCounters,
      });
      this.store.dispatch({
        type: 'SET_CONNTRACK_USAGE',
        hostId,
        current: data.conntrackCurrent,
        max: data.conntrackMax,
      });
    } catch {
      // Polling failure is non-critical — next poll will retry
    }
  }

  private stopPolling(): void {
    if (this.pollInterval !== null) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  private async loadBans(): Promise<void> {
    const hostId = this.store.getState().activeHostId;
    if (!hostId) return;

    try {
      const bans = await fetchBans(hostId);
      this.renderBans(bans);
    } catch {
      const existingList = this.bansSection.querySelector('.activity-view__bans-list');
      if (existingList) existingList.remove();
      const errorEl = h('div', { className: 'activity-view__bans-list' },
        h('div', { className: 'activity-view__bans-empty activity-view__bans-empty--error' },
          'Unable to load activity data'),
      );
      this.bansSection.appendChild(errorEl);
    }
  }

  private renderBans(bans: Fail2banBan[]): void {
    // Clear existing ban entries (keep the section title)
    const existingList = this.bansSection.querySelector('.activity-view__bans-list');
    if (existingList) existingList.remove();

    const list = h('div', { className: 'activity-view__bans-list' });

    if (bans.length === 0) {
      list.appendChild(h('div', { className: 'activity-view__bans-empty' }, 'No active bans.'));
    } else {
      for (const ban of bans) {
        list.appendChild(
          h('div', { className: 'activity-view__ban-row' },
            h('span', { className: 'activity-view__ban-icon' }, '\uD83D\uDEE1\uFE0F'),
            h('span', { className: 'activity-view__ban-ip' }, ban.ip),
            h('span', { className: 'activity-view__ban-time' }, `banned ${formatTimeAgo(ban.bannedAt)}`),
            h('span', { className: 'activity-view__ban-jail' }, ban.jail),
          ),
        );
      }
    }

    this.bansSection.appendChild(list);
  }

  private updateSaturationBanner(usage: { current: number; max: number } | null): void {
    if (!usage || usage.max === 0) {
      this.removeSaturationBanner();
      return;
    }

    const ratio = usage.current / usage.max;
    if (ratio > 0.8) {
      const percent = Math.round(ratio * 100);
      if (!this.saturationBanner) {
        this.saturationBanner = h('div', { className: 'activity-view__saturation-banner' });
        // Insert at the top of the view, after the controls
        const controls = this.el.querySelector('.activity-view__controls');
        if (controls && controls.nextSibling) {
          this.el.insertBefore(this.saturationBanner, controls.nextSibling);
        } else {
          this.el.prepend(this.saturationBanner);
        }
      }
      this.saturationBanner.textContent =
        `Connection tracking at ${percent}% capacity (${usage.current.toLocaleString()}/${usage.max.toLocaleString()})`;
    } else {
      this.removeSaturationBanner();
    }
  }

  private removeSaturationBanner(): void {
    if (this.saturationBanner) {
      this.saturationBanner.remove();
      this.saturationBanner = null;
    }
  }

  private showActivityError(message: string): void {
    // Display error message in the hit counters area
    this.hitCountersEl.innerHTML = '';
    this.hitCountersEl.appendChild(
      h('div', { className: 'activity-view__error' }, message),
    );
  }

  private togglePause(): void {
    this.paused = !this.paused;
    this.pauseBtn.textContent = this.paused ? 'Resume' : 'Pause';
  }

  private refresh(): void {
    this.paused = false;
    this.pauseBtn.textContent = 'Pause';
    this.onHostChanged();
  }

  override destroy(): void {
    this.stopPolling();
    if (this.streamId) {
      unsubscribeActivity(this.streamId).catch(() => {});
    }
    super.destroy();
  }
}
