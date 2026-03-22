/**
 * Sidebar component — primary navigation showing hosts, groups, and IP lists.
 *
 * Subscribes to: hosts, groups, ipLists, activeHostId.
 * Dispatches: SET_ACTIVE_HOST.
 * Features: search filtering, keyboard navigation, status indicators.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, Host, HostGroup, IpList } from '../../store/types';
import { reconcileList } from '../reconciler';
import { createHostRow, updateHostRow } from './host-row';
import { createGroupRow, updateGroupRow } from './group-row';
import { h } from '../../utils/dom';

export class Sidebar extends Component {
  private searchInput!: HTMLInputElement;
  private hostsContainer!: HTMLElement;
  private groupsContainer!: HTMLElement;
  private ipListsContainer!: HTMLElement;
  private searchTerm = '';
  private expandedGroups = new Set<string>();
  private focusedIndex = -1;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindEvents();
    this.bindSubscriptions();
  }

  private render(): void {
    this.el.innerHTML = '';
    this.el.className = 'sidebar';

    // Search field
    const searchWrap = h('div', { className: 'sidebar__search' });
    this.searchInput = document.createElement('input');
    this.searchInput.type = 'text';
    this.searchInput.placeholder = 'Search hosts...';
    this.searchInput.className = 'sidebar__search-input';
    this.searchInput.setAttribute('aria-label', 'Search hosts');
    searchWrap.appendChild(this.searchInput);
    this.el.appendChild(searchWrap);

    // Hosts section
    const hostsSection = h('div', { className: 'sidebar__section' });
    const hostsHeader = h('div', { className: 'sidebar__section-header' }, 'HOSTS');
    hostsSection.appendChild(hostsHeader);
    this.hostsContainer = h('div', { className: 'sidebar__host-list', role: 'listbox' });
    hostsSection.appendChild(this.hostsContainer);
    this.el.appendChild(hostsSection);

    // Groups section
    const groupsSection = h('div', { className: 'sidebar__section' });
    const groupsHeader = h('div', { className: 'sidebar__section-header' }, 'GROUPS');
    groupsSection.appendChild(groupsHeader);
    this.groupsContainer = h('div', { className: 'sidebar__group-list', role: 'listbox' });
    groupsSection.appendChild(this.groupsContainer);
    this.el.appendChild(groupsSection);

    // IP Lists section
    const ipListsSection = h('div', { className: 'sidebar__section' });
    const ipListsHeader = h('div', { className: 'sidebar__section-header' }, 'IP LISTS');
    ipListsSection.appendChild(ipListsHeader);
    this.ipListsContainer = h('div', { className: 'sidebar__iplist-list', role: 'listbox' });
    ipListsSection.appendChild(this.ipListsContainer);
    this.el.appendChild(ipListsSection);

    // Add button
    const addBtn = h('button', {
      className: 'sidebar__add-btn',
      'aria-label': 'Add host',
    }, '+ Add Host');
    this.el.appendChild(addBtn);
  }

  private bindEvents(): void {
    // Search input
    this.listen(this.searchInput, 'input', () => {
      this.searchTerm = this.searchInput.value.trim().toLowerCase();
      this.renderHosts();
    });

    // Click delegation for host rows
    this.listen(this.hostsContainer, 'click', (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>('.sidebar__host-row');
      if (row?.dataset.hostId) {
        this.store.dispatch({ type: 'SET_ACTIVE_HOST', hostId: row.dataset.hostId });
      }
    });

    // Click delegation for group rows
    this.listen(this.groupsContainer, 'click', (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>('.sidebar__group-row');
      if (row?.dataset.groupId) {
        const groupId = row.dataset.groupId;
        if (this.expandedGroups.has(groupId)) {
          this.expandedGroups.delete(groupId);
        } else {
          this.expandedGroups.add(groupId);
        }
        this.renderGroups();
      }
    });

    // Click delegation for IP list rows
    this.listen(this.ipListsContainer, 'click', (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>('.sidebar__iplist-row');
      if (row?.dataset.iplistId) {
        // IP lists don't set active host, but could open a panel in the future
      }
    });

    // Keyboard navigation
    this.listen(this.el, 'keydown', (e) => {
      const ke = e as KeyboardEvent;
      if (ke.key === 'ArrowDown' || ke.key === 'ArrowUp') {
        ke.preventDefault();
        this.navigateKeyboard(ke.key === 'ArrowDown' ? 1 : -1);
      } else if (ke.key === 'Enter') {
        this.selectFocused();
      }
    });
  }

  private bindSubscriptions(): void {
    // Subscribe to hosts
    this.subscribe(
      (s: AppState) => s.hosts,
      () => this.renderHosts(),
    );

    // Subscribe to activeHostId
    this.subscribe(
      (s: AppState) => s.activeHostId,
      () => this.renderHosts(),
    );

    // Subscribe to groups
    this.subscribe(
      (s: AppState) => s.groups,
      () => this.renderGroups(),
    );

    // Subscribe to ipLists
    this.subscribe(
      (s: AppState) => s.ipLists,
      () => this.renderIpLists(),
    );

    // Subscribe to sidebar collapsed state
    this.subscribe(
      (s: AppState) => s.sidebarCollapsed,
      (collapsed) => {
        this.el.classList.toggle('sidebar--collapsed', collapsed);
      },
    );

    // Initial render
    this.renderHosts();
    this.renderGroups();
    this.renderIpLists();
  }

  private getFilteredHosts(): Host[] {
    const state = this.store.getState();
    const hosts = Array.from(state.hosts.values());

    if (!this.searchTerm) return hosts;

    return hosts.filter(host =>
      host.name.toLowerCase().includes(this.searchTerm) ||
      host.connection.hostname.toLowerCase().includes(this.searchTerm),
    );
  }

  private renderHosts(): void {
    const state = this.store.getState();
    const activeHostId = state.activeHostId;
    const hosts = this.getFilteredHosts();

    reconcileList(
      this.hostsContainer,
      hosts,
      (host) => host.id,
      (host) => createHostRow(host, host.id === activeHostId),
      (el, host) => updateHostRow(el, host, host.id === activeHostId),
    );
  }

  private renderGroups(): void {
    const state = this.store.getState();
    const groups = Array.from(state.groups.values());

    reconcileList(
      this.groupsContainer,
      groups,
      (group) => group.id,
      (group) => createGroupRow(group, this.expandedGroups.has(group.id)),
      (el, group) => updateGroupRow(el, group, this.expandedGroups.has(group.id)),
    );
  }

  private renderIpLists(): void {
    const state = this.store.getState();
    const ipLists = Array.from(state.ipLists.values());

    reconcileList(
      this.ipListsContainer,
      ipLists,
      (list) => list.id,
      (list) => this.createIpListRow(list),
      (el, list) => this.updateIpListRow(el, list),
    );
  }

  private createIpListRow(list: IpList): HTMLElement {
    const row = h('div', {
      className: 'sidebar__iplist-row',
      tabindex: '0',
      role: 'button',
      'aria-label': `${list.name} - ${list.entries.length} entries`,
      dataset: { iplistId: list.id },
    });

    const nameEl = h('span', { className: 'sidebar__iplist-name' }, list.name);
    row.appendChild(nameEl);

    const countEl = h('span', { className: 'sidebar__iplist-count' },
      String(list.entries.length));
    row.appendChild(countEl);

    return row;
  }

  private updateIpListRow(el: HTMLElement, list: IpList): void {
    el.dataset.iplistId = list.id;
    el.setAttribute('aria-label', `${list.name} - ${list.entries.length} entries`);

    const nameEl = el.querySelector('.sidebar__iplist-name');
    if (nameEl && nameEl.textContent !== list.name) {
      nameEl.textContent = list.name;
    }

    const countEl = el.querySelector('.sidebar__iplist-count');
    const countStr = String(list.entries.length);
    if (countEl && countEl.textContent !== countStr) {
      countEl.textContent = countStr;
    }
  }

  private getAllFocusableRows(): HTMLElement[] {
    return Array.from(this.el.querySelectorAll<HTMLElement>(
      '.sidebar__host-row, .sidebar__group-row, .sidebar__iplist-row',
    ));
  }

  private navigateKeyboard(direction: number): void {
    const rows = this.getAllFocusableRows();
    if (rows.length === 0) return;

    this.focusedIndex += direction;
    if (this.focusedIndex < 0) this.focusedIndex = rows.length - 1;
    if (this.focusedIndex >= rows.length) this.focusedIndex = 0;

    rows[this.focusedIndex].focus();
  }

  private selectFocused(): void {
    const rows = this.getAllFocusableRows();
    if (this.focusedIndex < 0 || this.focusedIndex >= rows.length) return;

    const row = rows[this.focusedIndex];
    if (row.dataset.hostId) {
      this.store.dispatch({ type: 'SET_ACTIVE_HOST', hostId: row.dataset.hostId });
    } else if (row.dataset.groupId) {
      const groupId = row.dataset.groupId;
      if (this.expandedGroups.has(groupId)) {
        this.expandedGroups.delete(groupId);
      } else {
        this.expandedGroups.add(groupId);
      }
      this.renderGroups();
    }
  }
}
