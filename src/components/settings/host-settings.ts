/**
 * Host-specific settings panel — per-host configuration options.
 *
 * Currently supports:
 *   - Enable dual-stack mode (IPv4 + IPv6 unified policy)
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, Host } from '../../store/types';
import { selectActiveHost } from '../../store/selectors';
import { h } from '../../utils/dom';

export class HostSettings extends Component {
  private dualStackCheckbox: HTMLInputElement | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindSubscriptions();
  }

  private render(): void {
    this.el.innerHTML = '';
    this.el.className = 'settings-panel';

    const host = this.store.select(selectActiveHost);
    if (!host) {
      this.el.appendChild(h('p', {}, 'No host selected.'));
      return;
    }

    // Header
    this.el.appendChild(h('div', { className: 'settings-panel__header' },
      h('h1', { className: 'settings-panel__title' }, `Host Settings: ${host.name}`),
    ));

    const body = h('div', { className: 'settings-panel__body' });

    // --- IPv6 / Dual-stack Section ---
    body.appendChild(this.renderSectionHeader('IPv6 / Dual-stack'));

    const dualStackField = h('div', { className: 'settings-panel__field settings-panel__field--checkbox' });
    this.dualStackCheckbox = document.createElement('input');
    this.dualStackCheckbox.type = 'checkbox';
    this.dualStackCheckbox.id = 'settings-dualStack';
    this.dualStackCheckbox.checked = host.dualStackEnabled ?? false;

    this.listen(this.dualStackCheckbox, 'change', () => {
      if (!this.dualStackCheckbox) return;
      const hostObj = this.store.select(selectActiveHost);
      if (!hostObj) return;
      this.store.dispatch({
        type: 'SET_HOST_DUAL_STACK',
        hostId: hostObj.id,
        enabled: this.dualStackCheckbox.checked,
      });
    });

    dualStackField.appendChild(this.dualStackCheckbox);
    dualStackField.appendChild(h('label', { for: 'settings-dualStack' },
      h('span', {}, 'Enable dual-stack mode'),
      h('span', { className: 'settings-panel__checkbox-desc' },
        'Generate both IPv4 and IPv6 rules from a single rule definition'),
    ));
    body.appendChild(dualStackField);

    body.appendChild(h('p', { className: 'settings-panel__hint' },
      'When enabled, each rule can target IPv4 only, IPv6 only, or both address families. ' +
      'Rules without IP-specific content are applied to both stacks automatically.',
    ));

    this.el.appendChild(body);
  }

  private bindSubscriptions(): void {
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hosts.get(hostId) ?? null;
      },
      (host: Host | null) => {
        if (host && this.dualStackCheckbox) {
          this.dualStackCheckbox.checked = host.dualStackEnabled ?? false;
        }
      },
    );
  }

  private renderSectionHeader(title: string): HTMLElement {
    return h('div', { className: 'settings-panel__section-header' }, title);
  }
}
