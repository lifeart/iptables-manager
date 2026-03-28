/**
 * External Chains component — displays chains owned by external tools
 * (Docker, fail2ban, Kubernetes, etc.) as read-only, grouped by owner.
 *
 * Starts collapsed by default.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, CoexistenceProfile } from '../../store/types';
import type { ChainOwnerGroup } from '../../bindings';
import { h } from '../../utils/dom';

const OWNER_ICONS: Record<string, string> = {
  Docker: '[Docker]',
  'fail2ban': '[f2b]',
  Kubernetes: '[K8s]',
  CSF: '[CSF]',
  WireGuard: '[WG]',
  UFW: '[UFW]',
  firewalld: '[fwd]',
  'Built-in': '[sys]',
  Unknown: '[?]',
};

export class ExternalChains extends Component {
  private collapsed = true;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return undefined;
        return s.hostStates.get(hostId)?.coexistenceProfile;
      },
      () => this.renderProfile(),
    );
    this.renderProfile();
  }

  private renderProfile(): void {
    this.el.innerHTML = '';

    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return;

    const profile = state.hostStates.get(hostId)?.coexistenceProfile;
    if (!profile) return;

    // Filter to only external (non-app, non-builtin, non-unknown) groups
    const externalGroups = profile.owners.filter(
      (g) => !g.isAppManaged && g.owner !== 'Built-in' && g.owner !== 'Unknown',
    );

    if (externalGroups.length === 0) return;

    const totalExternalChains = externalGroups.reduce((acc, g) => acc + g.chains.length, 0);
    const totalExternalRules = externalGroups.reduce((acc, g) => acc + g.ruleCount, 0);

    const wrapper = h('div', {
      className: `external-chains${this.collapsed ? ' external-chains--collapsed' : ''}`,
    });

    // Header
    const header = h('div', { className: 'external-chains__header' });
    const chevron = h('span', { className: 'external-chains__chevron' }, '\u25BC');
    const title = h('span', {}, 'External Chains');
    const count = h('span', { className: 'external-chains__count' },
      `${totalExternalChains} chains, ${totalExternalRules} rules`);

    header.appendChild(chevron);
    header.appendChild(title);
    header.appendChild(count);

    this.listen(header, 'click', () => {
      this.collapsed = !this.collapsed;
      this.renderProfile();
    });

    wrapper.appendChild(header);

    // Body
    const body = h('div', { className: 'external-chains__body' });

    for (const group of externalGroups) {
      body.appendChild(this.renderGroup(group));
    }

    wrapper.appendChild(body);
    this.el.appendChild(wrapper);
  }

  private renderGroup(group: ChainOwnerGroup): HTMLElement {
    const groupEl = h('div', { className: 'external-chains__group' });

    const headerEl = h('div', { className: 'external-chains__group-header' });

    const icon = h('span', { className: 'external-chains__group-icon' },
      OWNER_ICONS[group.owner] ?? `[${group.owner}]`);
    const name = h('span', { className: 'external-chains__group-name' }, group.owner);
    const stats = h('span', { className: 'external-chains__group-stats' },
      `${group.chains.length} chain${group.chains.length !== 1 ? 's' : ''}, ${group.ruleCount} rule${group.ruleCount !== 1 ? 's' : ''}`);

    headerEl.appendChild(icon);
    headerEl.appendChild(name);
    headerEl.appendChild(stats);

    groupEl.appendChild(headerEl);

    // Chain list
    const chainList = h('div', { className: 'external-chains__chain-list' });
    for (const chain of group.chains) {
      chainList.appendChild(h('span', { className: 'external-chains__chain' }, chain));
    }
    groupEl.appendChild(chainList);

    return groupEl;
  }
}
