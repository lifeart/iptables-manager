/**
 * Command palette component.
 *
 * - Triggered by Cmd+K (registered in shortcut service)
 * - Centered at 20% from top, 680px wide, blur backdrop
 * - Search field (48px, 17px text, auto-focused)
 * - Results: RECENT hosts, ACTIONS, search results
 * - Keyboard navigable (up/down/Enter)
 * - First result auto-selected
 * - Escape or click outside to close
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { Host } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';

interface PaletteItem {
  id: string;
  label: string;
  detail?: string;
  category: string;
  action: () => void;
}

export class CommandPalette extends Component {
  private overlayEl: HTMLElement;
  private dialogEl: HTMLElement;
  private searchInput: HTMLInputElement;
  private resultsEl: HTMLElement;
  private items: PaletteItem[] = [];
  private selectedIndex = 0;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);

    // Backdrop overlay
    this.overlayEl = h('div', { className: 'command-palette__overlay' });
    this.overlayEl.style.display = 'none';

    // Dialog
    this.dialogEl = h('div', {
      className: 'command-palette__dialog',
      role: 'dialog',
      'aria-label': 'Command palette',
    });

    // Search field
    this.searchInput = document.createElement('input');
    this.searchInput.type = 'text';
    this.searchInput.className = 'command-palette__search';
    this.searchInput.placeholder = 'Search hosts, actions...';
    this.searchInput.setAttribute('aria-label', 'Search');
    this.dialogEl.appendChild(this.searchInput);

    // Results
    this.resultsEl = h('div', {
      className: 'command-palette__results',
      role: 'listbox',
    });
    this.dialogEl.appendChild(this.resultsEl);

    this.overlayEl.appendChild(this.dialogEl);
    this.el.appendChild(this.overlayEl);

    // Event listeners
    this.listen(this.searchInput, 'input', () => this.onSearchInput());
    this.listen(this.searchInput, 'keydown', (e) => this.onKeyDown(e as KeyboardEvent));
    this.listen(this.overlayEl, 'click', (e) => {
      if (e.target === this.overlayEl) {
        this.close();
      }
    });

    // Subscribe to open state
    this.subscribe(
      (s) => s.commandPaletteOpen,
      (open) => {
        if (open) {
          this.open();
        } else {
          this.hide();
        }
      },
    );
  }

  private open(): void {
    this.overlayEl.style.display = '';
    this.dialogEl.classList.add('command-palette__dialog--open');
    this.searchInput.value = '';
    this.selectedIndex = 0;
    this.buildItems('');
    this.renderResults();

    // Auto-focus search
    requestAnimationFrame(() => {
      this.searchInput.focus();
    });
  }

  private hide(): void {
    this.dialogEl.classList.remove('command-palette__dialog--open');
    this.overlayEl.style.display = 'none';
  }

  private close(): void {
    this.store.dispatch({ type: 'TOGGLE_COMMAND_PALETTE', open: false });
  }

  private onSearchInput(): void {
    const query = this.searchInput.value.trim();
    this.buildItems(query);
    this.selectedIndex = 0;
    this.renderResults();
  }

  private onKeyDown(e: KeyboardEvent): void {
    switch (e.key) {
      case 'Escape':
        e.preventDefault();
        this.close();
        break;
      case 'ArrowDown':
        e.preventDefault();
        this.selectedIndex = Math.min(this.selectedIndex + 1, this.items.length - 1);
        this.renderResults();
        break;
      case 'ArrowUp':
        e.preventDefault();
        this.selectedIndex = Math.max(this.selectedIndex - 1, 0);
        this.renderResults();
        break;
      case 'Enter':
        e.preventDefault();
        if (this.items[this.selectedIndex]) {
          this.items[this.selectedIndex].action();
          this.close();
        }
        break;
    }
  }

  private buildItems(query: string): void {
    this.items = [];
    const queryLower = query.toLowerCase();
    const state = this.store.getState();

    // RECENT hosts
    const recentHosts = this.getRecentHosts(state.hosts);
    for (const host of recentHosts) {
      if (queryLower && !host.name.toLowerCase().includes(queryLower)) continue;
      this.items.push({
        id: `host-${host.id}`,
        label: host.name,
        detail: host.connection.hostname,
        category: 'RECENT',
        action: () => {
          this.store.dispatch({ type: 'SET_ACTIVE_HOST', hostId: host.id });
        },
      });
    }

    // ACTIONS
    const actions: Array<{ label: string; detail: string; action: () => void }> = [
      {
        label: 'Quick Block',
        detail: 'Block an IP address',
        action: () => {
          this.store.dispatch({ type: 'TOGGLE_QUICK_BLOCK', open: true });
        },
      },
      {
        label: 'Add Host',
        detail: 'Connect to a new server',
        action: () => {
          // Will be handled by host setup flow
        },
      },
      {
        label: 'Apply Changes',
        detail: 'Apply pending changes to host',
        action: () => {
          // Will be handled by apply action
        },
      },
    ];

    for (const act of actions) {
      if (queryLower && !act.label.toLowerCase().includes(queryLower)) continue;
      this.items.push({
        id: `action-${act.label}`,
        label: act.label,
        detail: act.detail,
        category: 'ACTIONS',
        action: act.action,
      });
    }

    // All hosts (search results)
    if (queryLower) {
      for (const [, host] of state.hosts) {
        // Skip if already in recent
        if (recentHosts.some(rh => rh.id === host.id)) continue;
        if (!host.name.toLowerCase().includes(queryLower) &&
            !host.connection.hostname.toLowerCase().includes(queryLower)) continue;

        this.items.push({
          id: `search-host-${host.id}`,
          label: host.name,
          detail: host.connection.hostname,
          category: 'HOSTS',
          action: () => {
            this.store.dispatch({ type: 'SET_ACTIVE_HOST', hostId: host.id });
          },
        });
      }
    }
  }

  private getRecentHosts(hosts: Map<string, Host>): Host[] {
    return Array.from(hosts.values())
      .filter(h => h.lastConnected)
      .sort((a, b) => (b.lastConnected ?? 0) - (a.lastConnected ?? 0))
      .slice(0, 5);
  }

  private renderResults(): void {
    clearChildren(this.resultsEl);

    let currentCategory = '';

    for (let i = 0; i < this.items.length; i++) {
      const item = this.items[i];

      // Category header
      if (item.category !== currentCategory) {
        currentCategory = item.category;
        this.resultsEl.appendChild(
          h('div', { className: 'command-palette__category' }, currentCategory),
        );
      }

      const row = h('div', {
        className: 'command-palette__result' +
          (i === this.selectedIndex ? ' command-palette__result--selected' : ''),
        role: 'option',
        'aria-selected': String(i === this.selectedIndex),
      });

      row.appendChild(h('span', { className: 'command-palette__result-label' }, item.label));
      if (item.detail) {
        row.appendChild(h('span', { className: 'command-palette__result-detail' }, item.detail));
      }

      this.listen(row, 'click', () => {
        item.action();
        this.close();
      });

      this.listen(row, 'mouseenter', () => {
        this.selectedIndex = i;
        this.renderResults();
      });

      this.resultsEl.appendChild(row);
    }

    if (this.items.length === 0) {
      this.resultsEl.appendChild(
        h('div', { className: 'command-palette__empty' }, 'No results found.'),
      );
    }
  }
}
