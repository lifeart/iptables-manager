/**
 * Mixed backend detection banner component.
 *
 * When a host has both legacy iptables and nf_tables rules populated,
 * this banner warns the user that apply is blocked until the conflict
 * is resolved.
 *
 * - Checks on host connect / active host change
 * - Banner slides down from top, similar to DriftBanner
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { MixedBackendInfo } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';

export class MixedBackendBanner extends Component {
  private bannerEl: HTMLElement;
  private contentEl: HTMLElement;
  private currentHostId: string | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);

    this.bannerEl = h('div', { className: 'mixed-backend-banner' });
    this.bannerEl.style.display = 'none';

    this.contentEl = h('div', { className: 'mixed-backend-banner__content' });
    this.bannerEl.appendChild(this.contentEl);

    this.el.appendChild(this.bannerEl);

    // Subscribe to active host changes to trigger checks
    this.subscribe(
      (s) => s.activeHostId,
      (hostId) => this.onActiveHostChanged(hostId),
    );

    // Subscribe to mixed backend alerts to update the banner
    this.subscribe(
      (s) => s.mixedBackendAlerts,
      (alerts) => this.onAlertsChanged(alerts),
    );

    // Initial check
    const state = this.store.getState();
    if (state.activeHostId) {
      this.onActiveHostChanged(state.activeHostId);
    }
  }

  private onActiveHostChanged(hostId: string | null): void {
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

    // Run a mixed backend check
    this.checkMixedBackend(hostId);
  }

  private async checkMixedBackend(hostId: string): Promise<void> {
    try {
      const { checkMixedBackend: checkMixedBackendIpc } = await import('../../ipc/bridge');
      const result = await checkMixedBackendIpc(hostId);

      if (result.isMixed) {
        this.store.dispatch({
          type: 'SET_MIXED_BACKEND',
          info: {
            hostId,
            legacyRuleCount: result.legacyRuleCount,
            nftRuleCount: result.nftRuleCount,
            detectedAt: Date.now(),
          },
        });
      } else {
        // Clear any stale alert
        this.store.dispatch({ type: 'CLEAR_MIXED_BACKEND', hostId });
      }
    } catch (err) {
      // Mixed backend check failure is non-critical; log and continue
      console.warn('Mixed backend check failed:', err);
    }
  }

  private onAlertsChanged(alerts: Map<string, MixedBackendInfo>): void {
    const hostId = this.currentHostId;
    if (!hostId) {
      this.hide();
      return;
    }

    const info = alerts.get(hostId);
    if (!info) {
      this.hide();
      return;
    }

    this.showBanner(info);
  }

  private showBanner(info: MixedBackendInfo): void {
    this.bannerEl.style.display = '';
    this.bannerEl.classList.add('mixed-backend-banner--visible');

    clearChildren(this.contentEl);

    // Warning icon
    const icon = h('span', { className: 'mixed-backend-banner__icon' }, '\u26A0');

    // Description text
    const description = `Mixed iptables backend detected: ${info.legacyRuleCount} legacy rules, ${info.nftRuleCount} nft rules. Apply is blocked until resolved.`;
    const textEl = h('span', { className: 'mixed-backend-banner__text' }, description);

    // Learn More button
    const learnMoreBtn = document.createElement('button');
    learnMoreBtn.className = 'mixed-backend-banner__action-btn';
    learnMoreBtn.type = 'button';
    learnMoreBtn.textContent = 'Learn More';
    learnMoreBtn.setAttribute('aria-label', 'Learn more about mixed backend');
    this.listen(learnMoreBtn, 'click', () => this.handleLearnMore());

    // Dismiss button
    const dismissBtn = document.createElement('button');
    dismissBtn.className = 'mixed-backend-banner__dismiss-btn';
    dismissBtn.type = 'button';
    dismissBtn.textContent = '\u00D7';
    dismissBtn.title = 'Dismiss';
    dismissBtn.setAttribute('aria-label', 'Dismiss');
    this.listen(dismissBtn, 'click', () => this.handleDismiss(info.hostId));

    this.contentEl.appendChild(icon);
    this.contentEl.appendChild(textEl);
    this.contentEl.appendChild(learnMoreBtn);
    this.contentEl.appendChild(dismissBtn);
  }

  private hide(): void {
    this.bannerEl.classList.remove('mixed-backend-banner--visible');
    this.bannerEl.classList.add('mixed-backend-banner--hiding');

    setTimeout(() => {
      this.bannerEl.style.display = 'none';
      this.bannerEl.classList.remove('mixed-backend-banner--hiding');
    }, 300);
  }

  private handleLearnMore(): void {
    // Open documentation or show explanation
    window.open(
      'https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_iptables_to_nftables',
      '_blank',
    );
  }

  private handleDismiss(hostId: string): void {
    this.store.dispatch({ type: 'CLEAR_MIXED_BACKEND', hostId });
  }

  destroy(): void {
    super.destroy();
  }
}
