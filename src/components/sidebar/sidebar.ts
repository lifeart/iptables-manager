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
  private focusedId: string | null = null;
  private resizeHandle!: HTMLElement;
  private isResizing = false;

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
    const searchClearBtn = h('button', {
      className: 'sidebar__search-clear',
      type: 'button',
      'aria-label': 'Clear search',
      style: { display: 'none' },
    }, '\u00D7');
    searchWrap.appendChild(searchClearBtn);
    this.el.appendChild(searchWrap);

    // Hosts section
    const hostsSection = h('div', { className: 'sidebar__section' });
    const hostsHeader = h('div', { className: 'sidebar__section-header' }, 'HOSTS');
    hostsSection.appendChild(hostsHeader);
    this.hostsContainer = h('div', { className: 'sidebar__host-list', role: 'list' });
    hostsSection.appendChild(this.hostsContainer);
    this.el.appendChild(hostsSection);

    // Groups section
    const groupsSection = h('div', { className: 'sidebar__section' });
    const groupsHeader = h('div', { className: 'sidebar__section-header' }, 'GROUPS');
    groupsSection.appendChild(groupsHeader);
    this.groupsContainer = h('div', { className: 'sidebar__group-list', role: 'list' });
    groupsSection.appendChild(this.groupsContainer);
    this.el.appendChild(groupsSection);

    // IP Lists section
    const ipListsSection = h('div', { className: 'sidebar__section' });
    const ipListsHeader = h('div', { className: 'sidebar__section-header' }, 'IP LISTS');
    ipListsSection.appendChild(ipListsHeader);
    this.ipListsContainer = h('div', { className: 'sidebar__iplist-list', role: 'list' });
    ipListsSection.appendChild(this.ipListsContainer);
    this.el.appendChild(ipListsSection);

    // Add button
    const addBtn = h('button', {
      className: 'sidebar__add-btn',
      'aria-label': 'Add host',
    }, '+ Add Host');
    this.el.appendChild(addBtn);

    // Resize handle
    this.resizeHandle = h('div', {
      className: 'sidebar__resize-handle',
      style: {
        position: 'absolute',
        top: '0',
        right: '0',
        width: '4px',
        height: '100%',
        cursor: 'col-resize',
        zIndex: '10',
      },
    });
    this.el.style.position = 'relative';
    this.el.appendChild(this.resizeHandle);
  }

  private bindEvents(): void {
    // Search input
    const clearBtn = this.el.querySelector<HTMLElement>('.sidebar__search-clear');
    this.listen(this.searchInput, 'input', () => {
      this.searchTerm = this.searchInput.value.trim().toLowerCase();
      if (clearBtn) clearBtn.style.display = this.searchTerm ? '' : 'none';
      this.renderHosts();
    });
    if (clearBtn) {
      this.listen(clearBtn, 'click', () => {
        this.searchInput.value = '';
        this.searchTerm = '';
        clearBtn.style.display = 'none';
        this.renderHosts();
        this.searchInput.focus();
      });
    }

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
        // Select the first host in the group, if any
        const state = this.store.getState();
        const group = state.groups.get(groupId);
        if (group && group.memberHostIds.length > 0) {
          this.store.dispatch({ type: 'SET_ACTIVE_HOST', hostId: group.memberHostIds[0] });
        }
        this.renderGroups();
      }
    });

    // Click delegation for IP list rows — highlight and show toast
    this.listen(this.ipListsContainer, 'click', (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>('.sidebar__iplist-row');
      if (row?.dataset.iplistId) {
        // Briefly highlight the clicked row to give visual feedback
        const allRows = this.ipListsContainer.querySelectorAll('.sidebar__iplist-row');
        for (const r of allRows) {
          r.classList.remove('sidebar__iplist-row--selected');
        }
        row.classList.add('sidebar__iplist-row--selected');

        // Show the IP list entries in a tooltip-like detail
        const ipListId = row.dataset.iplistId;
        const state = this.store.getState();
        const ipList = state.ipLists.get(ipListId);
        if (ipList) {
          // Remove any existing detail popover
          const existing = this.el.querySelector('.sidebar__iplist-detail');
          if (existing) existing.remove();

          const detail = h('div', { className: 'sidebar__iplist-detail' });
          detail.appendChild(h('div', { className: 'sidebar__iplist-detail-title' }, ipList.name));
          for (const entry of ipList.entries) {
            const entryEl = h('div', { className: 'sidebar__iplist-detail-entry' });
            entryEl.appendChild(h('span', { className: 'sidebar__iplist-detail-addr' }, entry.address));
            if (entry.comment) {
              entryEl.appendChild(h('span', { className: 'sidebar__iplist-detail-comment' }, entry.comment));
            }
            detail.appendChild(entryEl);
          }
          if (ipList.entries.length === 0) {
            detail.appendChild(h('div', { className: 'sidebar__iplist-detail-empty' }, 'No addresses in this list.'));
          }
          const closeBtn = h('button', {
            className: 'sidebar__iplist-detail-close',
            type: 'button',
            'aria-label': 'Close',
          }, '\u00D7');
          this.listen(closeBtn, 'click', () => {
            detail.remove();
            row.classList.remove('sidebar__iplist-row--selected');
          });
          detail.insertBefore(closeBtn, detail.firstChild);
          row.parentElement?.appendChild(detail);
        }
      }
    });

    // Add Host button
    const addBtn = this.el.querySelector<HTMLElement>('.sidebar__add-btn');
    if (addBtn) {
      this.listen(addBtn, 'click', () => {
        this.store.dispatch({ type: 'OPEN_DIALOG', dialog: 'add-host' });
      });
    }

    // Resize handle drag
    this.listen(this.resizeHandle, 'mousedown', (e) => {
      e.preventDefault();
      this.isResizing = true;
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    });

    this.listen(document, 'mousemove', (e) => {
      if (!this.isResizing) return;
      const me = e as MouseEvent;
      const newWidth = Math.min(320, Math.max(180, me.clientX));
      this.el.style.width = `${newWidth}px`;
      document.documentElement.style.setProperty('--sidebar-width', `${newWidth}px`);
    });

    this.listen(document, 'mouseup', () => {
      if (this.isResizing) {
        this.isResizing = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
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
      role: 'listitem',
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

  private getRowId(row: HTMLElement): string | null {
    return row.dataset.hostId ?? row.dataset.groupId ?? row.dataset.iplistId ?? null;
  }

  private navigateKeyboard(direction: number): void {
    const rows = this.getAllFocusableRows();
    if (rows.length === 0) return;

    // Recompute current index from stored ID
    let currentIndex = -1;
    if (this.focusedId) {
      currentIndex = rows.findIndex(r => this.getRowId(r) === this.focusedId);
    }

    let nextIndex = currentIndex + direction;
    if (nextIndex < 0) nextIndex = rows.length - 1;
    if (nextIndex >= rows.length) nextIndex = 0;

    const nextRow = rows[nextIndex];
    this.focusedId = this.getRowId(nextRow);
    nextRow.focus();
  }

  private selectFocused(): void {
    const rows = this.getAllFocusableRows();
    if (!this.focusedId) return;

    const row = rows.find(r => this.getRowId(r) === this.focusedId);
    if (!row) return;

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
