/**
 * Rule table component — the primary rules interface.
 *
 * Subscribes to: selectEffectiveRules, selectFilteredRules, ruleFilter, activeTab.
 * Shows rules organized by direction (Incoming / Outgoing / NAT) with
 * collapsible sections grouped by origin.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, EffectiveRule } from '../../store/types';
import {
  selectActiveHost,
  selectEffectiveRules,
  selectFilteredRules,
} from '../../store/selectors';
import { reconcileList } from '../reconciler';
import { createRuleRow, updateRuleRow } from './rule-row';
import { createSectionHeader, updateSectionHeader } from './section-header';
import { FilterBar } from './filter-bar';
import { PendingBar } from './pending-bar';
import { h } from '../../utils/dom';

interface RuleSection {
  title: string;
  rules: EffectiveRule[];
}

export class RuleTable extends Component {
  private headerEl!: HTMLElement;
  private tabsEl!: HTMLElement;
  private filterBarContainer!: HTMLElement;
  private sectionsContainer!: HTMLElement;
  private pendingBarContainer!: HTMLElement;

  private filterBar: FilterBar | null = null;
  private pendingBar!: PendingBar;
  private collapsedSections = new Set<string>();

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindEvents();
    this.bindSubscriptions();
  }

  private render(): void {
    this.el.innerHTML = '';
    this.el.className = 'rule-table';

    // Header: host name + connection status
    this.headerEl = h('div', { className: 'rule-table__header' });
    this.el.appendChild(this.headerEl);

    // Tabs: Rules | Activity | Terminal
    this.tabsEl = h('div', { className: 'rule-table__tabs', role: 'tablist' });
    const tabs: Array<{ id: AppState['activeTab']; label: string }> = [
      { id: 'rules', label: 'Rules' },
      { id: 'activity', label: 'Activity' },
      { id: 'terminal', label: 'Terminal' },
    ];
    for (const tab of tabs) {
      const btn = h('button', {
        className: 'rule-table__tab',
        role: 'tab',
        dataset: { tab: tab.id },
      }, tab.label);
      this.tabsEl.appendChild(btn);
    }
    this.el.appendChild(this.tabsEl);

    // Filter bar container (conditionally rendered)
    this.filterBarContainer = h('div', { className: 'rule-table__filter-bar-container' });
    this.el.appendChild(this.filterBarContainer);

    // Sections container (scrollable)
    this.sectionsContainer = h('div', { className: 'rule-table__sections' });
    this.el.appendChild(this.sectionsContainer);

    // Pending bar at bottom
    this.pendingBarContainer = h('div', { className: 'rule-table__pending-bar-container' });
    this.el.appendChild(this.pendingBarContainer);
    this.pendingBar = new PendingBar(this.pendingBarContainer, this.store);
    this.addChild(this.pendingBar);
  }

  private bindEvents(): void {
    // Tab switching
    this.listen(this.tabsEl, 'click', (e) => {
      const btn = (e.target as HTMLElement).closest<HTMLElement>('.rule-table__tab');
      if (!btn?.dataset.tab) return;
      const tab = btn.dataset.tab as AppState['activeTab'];
      this.store.dispatch({ type: 'SET_ACTIVE_TAB', tab });
    });

    // Section header click — toggle collapse
    this.listen(this.sectionsContainer, 'click', (e) => {
      const header = (e.target as HTMLElement).closest<HTMLElement>('.rule-table__section-header');
      if (header?.dataset.sectionTitle) {
        const title = header.dataset.sectionTitle;
        if (this.collapsedSections.has(title)) {
          this.collapsedSections.delete(title);
        } else {
          this.collapsedSections.add(title);
        }
        this.renderRules();
        return;
      }

      // Rule row click — open side panel with rule detail
      const row = (e.target as HTMLElement).closest<HTMLElement>('.rule-table__row');
      if (row?.dataset.ruleId) {
        // Don't open panel for overflow button clicks
        if ((e.target as HTMLElement).closest('.rule-table__overflow-btn')) return;

        this.store.dispatch({
          type: 'SET_SIDE_PANEL_CONTENT',
          content: { type: 'rule-detail', ruleId: row.dataset.ruleId },
        });
      }
    });
  }

  private bindSubscriptions(): void {
    // Active host changed — update header
    this.subscribe(
      selectActiveHost,
      (host) => {
        if (host) {
          this.headerEl.innerHTML = '';
          const nameEl = h('span', { className: 'rule-table__host-name' }, host.name);
          this.headerEl.appendChild(nameEl);
          const statusEl = h('span', {
            className: `rule-table__host-status rule-table__host-status--${host.status}`,
          }, host.status.charAt(0).toUpperCase() + host.status.slice(1));
          this.headerEl.appendChild(statusEl);
        } else {
          this.headerEl.innerHTML = '';
        }
      },
    );

    // Active tab changed — update tab styling
    this.subscribe(
      (s: AppState) => s.activeTab,
      (tab) => {
        const tabBtns = this.tabsEl.querySelectorAll('.rule-table__tab');
        for (const btn of tabBtns) {
          const el = btn as HTMLElement;
          const isActive = el.dataset.tab === tab;
          el.classList.toggle('rule-table__tab--active', isActive);
          el.setAttribute('aria-selected', String(isActive));
        }
      },
    );

    // Rules changed — re-render rule rows
    this.subscribe(
      selectFilteredRules as (s: AppState) => EffectiveRule[] | null,
      () => this.renderRules(),
    );

    // Effective rules (unfiltered) — update filter bar info
    this.subscribe(
      selectEffectiveRules as (s: AppState) => EffectiveRule[] | null,
      () => this.updateFilterBar(),
    );

    // Filter changed
    this.subscribe(
      (s: AppState) => s.ruleFilter,
      () => this.updateFilterBar(),
    );

    // Initial renders
    this.updateTabStyling();
    this.renderRules();
    this.updateFilterBar();
  }

  private updateTabStyling(): void {
    const tab = this.store.getState().activeTab;
    const tabBtns = this.tabsEl.querySelectorAll('.rule-table__tab');
    for (const btn of tabBtns) {
      const el = btn as HTMLElement;
      const isActive = el.dataset.tab === tab;
      el.classList.toggle('rule-table__tab--active', isActive);
      el.setAttribute('aria-selected', String(isActive));
    }
  }

  private updateFilterBar(): void {
    const state = this.store.getState();
    const allRules = this.store.select(selectEffectiveRules as (s: AppState) => EffectiveRule[] | null);
    const filteredRules = this.store.select(selectFilteredRules as (s: AppState) => EffectiveRule[] | null);
    const ruleCount = allRules?.length ?? 0;

    // Show/hide filter bar based on rule count (5+ threshold)
    if (ruleCount >= 5 && !this.filterBar) {
      this.filterBar = new FilterBar(this.filterBarContainer, this.store);
      this.addChild(this.filterBar);
    } else if (ruleCount < 5 && this.filterBar) {
      this.removeChild(this.filterBar);
      this.filterBar = null;
      this.filterBarContainer.innerHTML = '';
    }

    // Update filter bar info
    this.filterBar?.updateRuleInfo(allRules, filteredRules);
  }

  private renderRules(): void {
    const state = this.store.getState();
    const filteredRules = this.store.select(selectFilteredRules as (s: AppState) => EffectiveRule[] | null);

    if (!filteredRules || filteredRules.length === 0) {
      this.renderEmptyState();
      return;
    }

    // Group rules by direction
    const sections = this.groupRulesByDirection(filteredRules);

    // Build section DOM
    this.sectionsContainer.innerHTML = '';

    for (const section of sections) {
      const sectionEl = h('div', {
        className: 'rule-table__section',
        dataset: { section: section.title },
      });

      const isCollapsed = this.collapsedSections.has(section.title);

      // Section header
      const header = createSectionHeader(section.title, section.rules.length, isCollapsed);
      sectionEl.appendChild(header);

      // Rule rows (hidden if collapsed)
      if (!isCollapsed) {
        const rowsContainer = h('div', { className: 'rule-table__rows' });

        // Group by origin within section
        const originGroups = this.groupRulesByOrigin(section.rules);

        for (const group of originGroups) {
          // Origin sub-header (if not the only group)
          if (originGroups.length > 1 && group.title) {
            const subHeader = createSectionHeader(
              group.title,
              group.rules.length,
              this.collapsedSections.has(`${section.title}:${group.title}`),
            );
            subHeader.classList.add('rule-table__section-header--sub');
            rowsContainer.appendChild(subHeader);

            if (this.collapsedSections.has(`${section.title}:${group.title}`)) {
              continue;
            }
          }

          // Render rule rows
          for (const rule of group.rules) {
            const rowEl = createRuleRow(rule);
            rowEl.dataset.key = rule.id;
            rowsContainer.appendChild(rowEl);
          }
        }

        sectionEl.appendChild(rowsContainer);
      }

      this.sectionsContainer.appendChild(sectionEl);
    }
  }

  private groupRulesByDirection(rules: EffectiveRule[]): RuleSection[] {
    const incoming: EffectiveRule[] = [];
    const outgoing: EffectiveRule[] = [];
    const nat: EffectiveRule[] = [];

    for (const rule of rules) {
      if (rule.action === 'dnat' || rule.action === 'snat' || rule.action === 'masquerade') {
        nat.push(rule);
      } else if (rule.direction === 'outgoing') {
        outgoing.push(rule);
      } else {
        incoming.push(rule);
      }
    }

    const sections: RuleSection[] = [];
    if (incoming.length > 0) {
      sections.push({ title: 'Incoming Traffic', rules: incoming });
    }
    if (outgoing.length > 0) {
      sections.push({ title: 'Outgoing Traffic', rules: outgoing });
    }
    if (nat.length > 0) {
      sections.push({ title: 'NAT Rules', rules: nat });
    }

    return sections;
  }

  private groupRulesByOrigin(rules: EffectiveRule[]): Array<{ title: string; rules: EffectiveRule[] }> {
    const groups: Array<{ title: string; rules: EffectiveRule[] }> = [];
    const groupMap = new Map<string, EffectiveRule[]>();

    for (const rule of rules) {
      let key: string;
      if (rule.section === 'conntrack' || rule.section === 'loopback') {
        key = 'Connection Tracking';
      } else if (rule.section === 'system') {
        key = `System Rules (${rule.origin.type === 'system' ? (rule.origin as { type: 'system'; owner: string }).owner : 'system'})`;
      } else if (rule.section === 'group' && rule.groupName) {
        key = rule.groupName;
      } else if (rule.section === 'default-policy') {
        key = '';
      } else {
        key = 'Host';
      }

      const existing = groupMap.get(key);
      if (existing) {
        existing.push(rule);
      } else {
        groupMap.set(key, [rule]);
      }
    }

    for (const [title, groupRules] of groupMap) {
      groups.push({ title, rules: groupRules });
    }

    return groups;
  }

  private renderEmptyState(): void {
    this.sectionsContainer.innerHTML = '';
    const empty = h('div', { className: 'rule-table__empty' });
    empty.appendChild(h('p', { className: 'rule-table__empty-title' }, 'No traffic rules configured.'));
    empty.appendChild(h('p', { className: 'rule-table__empty-subtitle' }, 'All traffic is currently allowed.'));

    const actions = h('div', { className: 'rule-table__empty-actions' });
    actions.appendChild(h('button', { className: 'rule-table__empty-btn rule-table__empty-btn--primary' },
      'Set up suggested rules'));
    actions.appendChild(h('button', { className: 'rule-table__empty-btn' }, 'Add first rule'));
    empty.appendChild(actions);

    this.sectionsContainer.appendChild(empty);
  }
}
