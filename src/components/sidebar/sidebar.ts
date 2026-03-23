/**
 * Sidebar component — primary navigation showing hosts, groups, and IP lists.
 *
 * Subscribes to: hosts, groups, ipLists, activeHostId.
 * Dispatches: SET_ACTIVE_HOST.
 * Features: search filtering, keyboard navigation, status indicators,
 *           scaling behavior (30+/100+ hosts), group expand with nested hosts.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, Host, HostGroup, IpList } from '../../store/types';
import { reconcileList } from '../reconciler';
import { createHostRow, updateHostRow } from './host-row';
import { createGroupRow, updateGroupRow } from './group-row';
import { h } from '../../utils/dom';
import { fetchRules } from '../../ipc/bridge';
import { convertRuleSet } from '../../services/rule-converter';

type ScaleMode = 'all' | 'medium' | 'large';

export class Sidebar extends Component {
  private searchInput!: HTMLInputElement;
  private hostsContainer!: HTMLElement;
  private recentContainer!: HTMLElement;
  private recentSection!: HTMLElement;
  private statusFilterPill!: HTMLElement;
  private allHostsRow!: HTMLElement;
  private allHostsSection!: HTMLElement;
  private allHostsExpanded = false;
  private groupsContainer!: HTMLElement;
  private ipListsContainer!: HTMLElement;
  private searchTerm = '';
  private expandedGroups = new Set<string>();
  private focusedId: string | null = null;
  private resizeHandle!: HTMLElement;
  private isResizing = false;
  private statusFilterActive = false;
  private recentHostIds: string[] = [];

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindEvents();
    this.bindSubscriptions();
  }

  private getScaleMode(): ScaleMode {
    const state = this.store.getState();
    const hostCount = state.hosts.size;
    if (hostCount > 100) return 'large';
    if (hostCount > 30) return 'medium';
    return 'all';
  }

  private trackRecentHost(hostId: string): void {
    this.recentHostIds = [hostId, ...this.recentHostIds.filter(id => id !== hostId)];
  }

  private getRecentHosts(count: number): Host[] {
    const state = this.store.getState();
    const result: Host[] = [];
    for (const id of this.recentHostIds) {
      const host = state.hosts.get(id);
      if (host) {
        result.push(host);
        if (result.length >= count) break;
      }
    }
    return result;
  }

  private getIssueCount(): number {
    const state = this.store.getState();
    let count = 0;
    for (const host of state.hosts.values()) {
      if (host.status === 'drifted' || host.status === 'disconnected') {
        count++;
      }
    }
    return count;
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

    // Recent section (hidden by default, shown at 31+ hosts)
    this.recentSection = h('div', { className: 'sidebar__section sidebar__section--recent', style: { display: 'none' } });
    const recentHeader = h('div', { className: 'sidebar__section-header' }, 'RECENT');
    this.recentSection.appendChild(recentHeader);
    this.recentContainer = h('div', { className: 'sidebar__host-list sidebar__host-list--recent', role: 'list' });
    this.recentSection.appendChild(this.recentContainer);
    this.el.appendChild(this.recentSection);

    // Status filter pill (hidden by default, shown at 31+ hosts when issues exist)
    this.statusFilterPill = h('button', {
      className: 'sidebar__status-filter-pill',
      type: 'button',
      style: { display: 'none' },
    });
    this.el.appendChild(this.statusFilterPill);

    // Hosts section
    const hostsSection = h('div', { className: 'sidebar__section' });
    const hostsHeader = h('div', { className: 'sidebar__section-header' }, 'HOSTS');
    hostsSection.appendChild(hostsHeader);
    this.hostsContainer = h('div', { className: 'sidebar__host-list', role: 'list' });
    hostsSection.appendChild(this.hostsContainer);
    this.el.appendChild(hostsSection);

    // All Hosts row (hidden by default, shown at 100+ hosts)
    this.allHostsSection = h('div', { className: 'sidebar__section sidebar__section--all-hosts', style: { display: 'none' } });
    this.allHostsRow = h('button', {
      className: 'sidebar__all-hosts-row',
      type: 'button',
    }, 'All Hosts (0)');
    this.allHostsSection.appendChild(this.allHostsRow);
    this.el.appendChild(this.allHostsSection);

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
    });
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

    // Click delegation for host rows (in both hosts and recent containers)
    const handleHostClick = (e: Event) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>('.sidebar__host-row');
      if (row?.dataset.hostId) {
        const hostId = row.dataset.hostId;
        this.trackRecentHost(hostId);
        this.store.dispatch({ type: 'SET_ACTIVE_HOST', hostId });
        this.fetchRulesIfConnected(hostId);
      }
    };
    this.listen(this.hostsContainer, 'click', handleHostClick);
    this.listen(this.recentContainer, 'click', handleHostClick);

    // Click delegation for group rows and nested member hosts
    this.listen(this.groupsContainer, 'click', (e) => {
      // Check if a member host row was clicked
      const memberRow = (e.target as HTMLElement).closest<HTMLElement>('.sidebar__host-row');
      if (memberRow?.dataset.hostId) {
        this.trackRecentHost(memberRow.dataset.hostId);
        this.store.dispatch({ type: 'SET_ACTIVE_HOST', hostId: memberRow.dataset.hostId });
        return;
      }

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

    // Status filter pill
    this.listen(this.statusFilterPill, 'click', () => {
      this.statusFilterActive = !this.statusFilterActive;
      this.statusFilterPill.classList.toggle('sidebar__status-filter-pill--active', this.statusFilterActive);
      this.renderHosts();
    });

    // All Hosts row (100+ mode)
    this.listen(this.allHostsRow, 'click', () => {
      this.allHostsExpanded = !this.allHostsExpanded;
      this.renderHosts();
    });

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
      (hostId) => {
        if (hostId) this.trackRecentHost(hostId);
        this.renderHosts();
      },
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

  private fetchRulesIfConnected(hostId: string): void {
    const state = this.store.getState();
    const host = state.hosts.get(hostId);
    if (host && host.status === 'connected') {
      fetchRules(hostId)
        .then((ruleSet) => {
          const rules = convertRuleSet(ruleSet);
          this.store.dispatch({ type: 'SET_HOST_RULES', hostId, rules });
        })
        .catch(() => {
          // Rule fetch failure is handled by the empty state UI
        });
    }
  }

  private getFilteredHosts(): Host[] {
    const state = this.store.getState();
    let hosts = Array.from(state.hosts.values());

    // Status filter (for medium/large modes)
    if (this.statusFilterActive) {
      hosts = hosts.filter(host =>
        host.status === 'drifted' || host.status === 'disconnected',
      );
    }

    if (!this.searchTerm) return hosts;

    return hosts.filter(host =>
      host.name.toLowerCase().includes(this.searchTerm) ||
      host.connection.hostname.toLowerCase().includes(this.searchTerm),
    );
  }

  private renderHosts(): void {
    const state = this.store.getState();
    const activeHostId = state.activeHostId;
    const scaleMode = this.getScaleMode();

    // Update status filter pill
    const issueCount = this.getIssueCount();
    if (scaleMode !== 'all' && issueCount > 0) {
      this.statusFilterPill.style.display = '';
      this.statusFilterPill.textContent = `${issueCount} issue${issueCount !== 1 ? 's' : ''}`;
    } else {
      this.statusFilterPill.style.display = 'none';
      if (scaleMode === 'all') {
        this.statusFilterActive = false;
      }
    }

    // Recent section
    if (scaleMode === 'medium' || scaleMode === 'large') {
      this.recentSection.style.display = '';
      const recentCount = scaleMode === 'large' ? 5 : 3;
      const recentHosts = this.getRecentHosts(recentCount);
      reconcileList(
        this.recentContainer,
        recentHosts,
        (host) => `recent-${host.id}`,
        (host) => {
          const row = createHostRow(host, host.id === activeHostId);
          row.dataset.key = `recent-${host.id}`;
          return row;
        },
        (el, host) => updateHostRow(el, host, host.id === activeHostId),
      );
    } else {
      this.recentSection.style.display = 'none';
    }

    // All Hosts expandable row (100+ mode)
    if (scaleMode === 'large') {
      this.allHostsSection.style.display = '';
      this.allHostsRow.textContent = `All Hosts (${state.hosts.size})`;
    } else {
      this.allHostsSection.style.display = 'none';
      this.allHostsExpanded = false;
    }

    // Main hosts list
    const hosts = this.getFilteredHosts();
    const shouldShowHosts = scaleMode === 'all'
      || scaleMode === 'medium'
      || this.allHostsExpanded
      || this.searchTerm.length > 0;

    if (shouldShowHosts) {
      // In medium mode, collapse groups by default (handled in renderGroups)
      this.hostsContainer.parentElement!.style.display = '';
      reconcileList(
        this.hostsContainer,
        hosts,
        (host) => host.id,
        (host) => createHostRow(host, host.id === activeHostId),
        (el, host) => updateHostRow(el, host, host.id === activeHostId),
      );
    } else {
      // Large mode with all-hosts collapsed and no search: hide main host list
      this.hostsContainer.parentElement!.style.display = 'none';
    }
  }

  private renderGroups(): void {
    const state = this.store.getState();
    const groups = Array.from(state.groups.values());
    const activeHostId = state.activeHostId;
    const scaleMode = this.getScaleMode();

    // Clear and rebuild to handle nested member hosts
    this.groupsContainer.innerHTML = '';

    for (const group of groups) {
      const isExpanded = this.expandedGroups.has(group.id);

      // In medium mode, groups are collapsed by default (expandedGroups tracks explicit toggles)
      const effectiveExpanded = scaleMode === 'medium' ? isExpanded : isExpanded;

      const groupRow = createGroupRow(group, effectiveExpanded);
      groupRow.dataset.key = group.id;
      this.groupsContainer.appendChild(groupRow);

      // If expanded, render member hosts as indented rows
      if (effectiveExpanded) {
        for (const memberId of group.memberHostIds) {
          const host = state.hosts.get(memberId);
          if (host) {
            const memberRow = createHostRow(host, host.id === activeHostId);
            memberRow.classList.add('sidebar__host-row--indented');
            memberRow.dataset.key = `group-member-${group.id}-${host.id}`;
            this.groupsContainer.appendChild(memberRow);
          }
        }
      }
    }
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
