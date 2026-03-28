/**
 * Drift detection banner component.
 *
 * Periodically polls the backend to check if remote iptables rules
 * have changed outside of Traffic Rules. When drift is detected,
 * shows a warning banner with a "Refresh" button.
 *
 * - Polls every 60 seconds (configurable via store settings)
 * - Only polls when a host is connected
 * - Banner slides down from top, similar to SafetyBanner
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { DriftInfo } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';

const DRIFT_POLL_INTERVAL_MS = 60_000;

export class DriftBanner extends Component {
  private bannerEl: HTMLElement;
  private contentEl: HTMLElement;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private currentHostId: string | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);

    this.bannerEl = h('div', { className: 'drift-banner' });
    this.bannerEl.style.display = 'none';

    this.contentEl = h('div', { className: 'drift-banner__content' });
    this.bannerEl.appendChild(this.contentEl);

    this.el.appendChild(this.bannerEl);

    // Subscribe to active host changes to start/stop polling
    this.subscribe(
      (s) => s.activeHostId,
      (hostId) => this.onActiveHostChanged(hostId),
    );

    // Subscribe to drift alerts to update the banner
    this.subscribe(
      (s) => s.driftAlerts,
      (alerts) => this.onDriftAlertsChanged(alerts),
    );

    // Initial check
    const state = this.store.getState();
    if (state.activeHostId) {
      this.onActiveHostChanged(state.activeHostId);
    }
  }

  private onActiveHostChanged(hostId: string | null): void {
    this.stopPolling();
    this.currentHostId = hostId;

    if (!hostId) {
      this.hide();
      return;
    }

    // Check if host is connected
    const host = this.store.getState().hosts.get(hostId);
    if (!host || host.status !== 'connected') {
      return;
    }

    // Start polling for drift
    this.startPolling(hostId);
  }

  private startPolling(hostId: string): void {
    this.stopPolling();

    // Initial check after a short delay (let rules load first)
    const initialDelay = setTimeout(() => {
      this.checkDrift(hostId);
    }, 5000);
    this.ac.signal.addEventListener('abort', () => clearTimeout(initialDelay));

    // Periodic checks
    this.pollTimer = setInterval(() => {
      // Re-check that host is still active and connected
      const state = this.store.getState();
      if (state.activeHostId !== hostId) {
        this.stopPolling();
        return;
      }
      const host = state.hosts.get(hostId);
      if (!host || host.status !== 'connected') {
        this.stopPolling();
        return;
      }
      this.checkDrift(hostId);
    }, DRIFT_POLL_INTERVAL_MS);
  }

  private stopPolling(): void {
    if (this.pollTimer !== null) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private async checkDrift(hostId: string): Promise<void> {
    try {
      const { checkDrift: checkDriftIpc } = await import('../../ipc/bridge');
      const result = await checkDriftIpc(hostId);

      if (result.drifted) {
        this.store.dispatch({
          type: 'SET_DRIFT_DETECTED',
          drift: {
            hostId,
            addedRules: result.addedRules,
            removedRules: result.removedRules,
            modifiedRules: result.modifiedRules,
            detectedAt: Date.now(),
          },
        });
      }
    } catch (err) {
      // Drift check failure is non-critical; log and continue polling
      console.warn('Drift check failed:', err);
    }
  }

  private onDriftAlertsChanged(alerts: Map<string, DriftInfo>): void {
    const hostId = this.currentHostId;
    if (!hostId) {
      this.hide();
      return;
    }

    const drift = alerts.get(hostId);
    if (!drift) {
      this.hide();
      return;
    }

    this.showDrift(drift);
  }

  private showDrift(drift: DriftInfo): void {
    this.bannerEl.style.display = '';
    this.bannerEl.classList.add('drift-banner--visible');

    clearChildren(this.contentEl);

    // Warning icon
    const icon = h('span', { className: 'drift-banner__icon' }, '\u26A0');

    // Build description text
    const parts: string[] = [];
    if (drift.addedRules > 0) parts.push(`+${drift.addedRules} added`);
    if (drift.removedRules > 0) parts.push(`-${drift.removedRules} removed`);
    if (drift.modifiedRules > 0) parts.push(`${drift.modifiedRules} changed`);

    const description = parts.length > 0
      ? `Rules changed outside Traffic Rules: ${parts.join(', ')}. Click to refresh.`
      : 'Rules changed outside Traffic Rules. Click to refresh.';

    const textEl = h('span', { className: 'drift-banner__text' }, description);

    // Refresh button
    const refreshBtn = document.createElement('button');
    refreshBtn.className = 'drift-banner__refresh-btn';
    refreshBtn.type = 'button';
    refreshBtn.textContent = 'Refresh';
    refreshBtn.setAttribute('aria-label', 'Refresh rules');
    this.listen(refreshBtn, 'click', () => this.handleRefresh(drift.hostId));

    // Dismiss button
    const dismissBtn = document.createElement('button');
    dismissBtn.className = 'drift-banner__dismiss-btn';
    dismissBtn.type = 'button';
    dismissBtn.textContent = '\u00D7';
    dismissBtn.title = 'Dismiss';
    dismissBtn.setAttribute('aria-label', 'Dismiss');
    this.listen(dismissBtn, 'click', () => this.handleDismiss(drift.hostId));

    this.contentEl.appendChild(icon);
    this.contentEl.appendChild(textEl);
    this.contentEl.appendChild(refreshBtn);
    this.contentEl.appendChild(dismissBtn);
  }

  private hide(): void {
    this.bannerEl.classList.remove('drift-banner--visible');
    this.bannerEl.classList.add('drift-banner--hiding');

    setTimeout(() => {
      this.bannerEl.style.display = 'none';
      this.bannerEl.classList.remove('drift-banner--hiding');
    }, 300);
  }

  private async handleRefresh(hostId: string): Promise<void> {
    // Clear the drift alert
    this.store.dispatch({ type: 'CLEAR_DRIFT', hostId });

    try {
      // Re-fetch rules
      const { fetchRules, resetDrift: resetDriftIpc } = await import('../../ipc/bridge');
      const result = await fetchRules(hostId);

      // Update rules in the store
      this.store.dispatch({
        type: 'SET_HOST_RULES',
        hostId,
        rules: result.rules as unknown as import('../../store/types').Rule[],
      });

      // Reset drift baseline
      await resetDriftIpc(hostId);
    } catch (err) {
      console.warn('Failed to refresh rules after drift:', err);
    }
  }

  private handleDismiss(hostId: string): void {
    this.store.dispatch({ type: 'CLEAR_DRIFT', hostId });
  }

  destroy(): void {
    this.stopPolling();
    super.destroy();
  }
}
