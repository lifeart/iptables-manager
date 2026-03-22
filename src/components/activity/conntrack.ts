/**
 * Conntrack usage bar — compact progress bar showing nf_conntrack usage.
 *
 * 4px height bar. Color coded: green (<50%), orange (50-75%), red (>75%).
 * Shows warning with action buttons when usage exceeds 75%.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState } from '../../store/types';
import { h } from '../../utils/dom';
import { formatCount } from '../../utils/format';

export class ConntrackBar extends Component {
  private container: HTMLElement;
  private barFill!: HTMLElement;
  private labelEl!: HTMLElement;
  private warningEl: HTMLElement | null = null;
  private warningDismissed = false;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.container = container;
    this.container.className = 'conntrack';
    this.render();
    this.bindSubscriptions();
  }

  private render(): void {
    this.container.innerHTML = '';

    const header = h('div', { className: 'conntrack__header' },
      h('span', { className: 'conntrack__title' }, 'Active Connections'),
    );
    this.labelEl = h('span', { className: 'conntrack__label' });
    header.appendChild(this.labelEl);
    this.container.appendChild(header);

    const barTrack = h('div', { className: 'conntrack__bar-track' });
    this.barFill = h('div', { className: 'conntrack__bar-fill' });
    barTrack.appendChild(this.barFill);
    this.container.appendChild(barTrack);
  }

  private bindSubscriptions(): void {
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hostStates.get(hostId)?.conntrackUsage ?? null;
      },
      () => this.update(),
    );

    this.update();
  }

  private update(): void {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) {
      this.labelEl.textContent = '';
      this.barFill.style.width = '0%';
      this.removeWarning();
      return;
    }

    const hostState = state.hostStates.get(hostId);
    const usage = hostState?.conntrackUsage ?? { current: 0, max: 0 };

    const percent = usage.max > 0 ? (usage.current / usage.max) * 100 : 0;

    this.labelEl.textContent = `${formatCount(usage.current)} / ${formatCount(usage.max)} (${percent.toFixed(1)}%)`;
    this.barFill.style.width = `${Math.min(percent, 100)}%`;

    // Color code
    let color: string;
    if (percent > 75) {
      color = 'var(--color-block, #FF3B30)';
    } else if (percent > 50) {
      color = 'var(--color-warning, #FF9500)';
    } else {
      color = 'var(--color-allow, #34C759)';
    }
    this.barFill.style.backgroundColor = color;

    // Show/hide warning for >75%
    if (percent > 75 && !this.warningDismissed) {
      this.showWarning(percent, usage.max);
    } else if (percent <= 75) {
      this.removeWarning();
      this.warningDismissed = false;
    }
  }

  private showWarning(percent: number, currentMax: number): void {
    if (this.warningEl) {
      // Update existing warning text
      const textEl = this.warningEl.querySelector('.conntrack__warning-text');
      if (textEl) {
        textEl.textContent = `\u26A0\uFE0F Connection tracking table is ${Math.round(percent)}% full.`;
      }
      return;
    }

    this.warningEl = h('div', { className: 'conntrack__warning' });

    const textEl = h('span', { className: 'conntrack__warning-text' },
      `\u26A0\uFE0F Connection tracking table is ${Math.round(percent)}% full.`);
    this.warningEl.appendChild(textEl);

    const actions = h('div', { className: 'conntrack__warning-actions' });

    const increaseBtn = h('button', {
      className: 'conntrack__warning-btn conntrack__warning-btn--primary',
      type: 'button',
    }, 'Increase to recommended');
    this.listen(increaseBtn, 'click', () => {
      const recommended = currentMax * 2;
      alert(`Would run: sysctl -w net.netfilter.nf_conntrack_max=${recommended}\n\nThis is a demo — no changes were made.`);
    });
    actions.appendChild(increaseBtn);

    const dismissBtn = h('button', {
      className: 'conntrack__warning-btn conntrack__warning-btn--secondary',
      type: 'button',
    }, 'Dismiss');
    this.listen(dismissBtn, 'click', () => {
      this.warningDismissed = true;
      this.removeWarning();
    });
    actions.appendChild(dismissBtn);

    this.warningEl.appendChild(actions);
    this.container.appendChild(this.warningEl);
  }

  private removeWarning(): void {
    if (this.warningEl) {
      this.warningEl.remove();
      this.warningEl = null;
    }
  }
}
