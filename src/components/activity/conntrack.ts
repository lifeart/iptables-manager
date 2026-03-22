/**
 * Conntrack usage bar — compact progress bar showing nf_conntrack usage.
 *
 * 4px height bar. Color coded: green (<50%), orange (50-75%), red (>75%).
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
  }
}
