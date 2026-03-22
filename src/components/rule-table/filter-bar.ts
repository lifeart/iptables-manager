/**
 * Filter bar component — segmented control + search input.
 *
 * Only rendered when there are 5+ rules.
 * Segmented control: All | Allow | Block (+ Log if LOG rules exist).
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, EffectiveRule } from '../../store/types';
import { h } from '../../utils/dom';

type FilterTab = AppState['ruleFilter']['tab'];

export class FilterBar extends Component {
  private segmentedControl!: HTMLElement;
  private searchInput!: HTMLInputElement;
  private filterCountEl!: HTMLElement;
  private hasLogRules = false;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindEvents();
    this.bindSubscriptions();
  }

  private render(): void {
    this.el.innerHTML = '';
    this.el.className = 'rule-table__filter-bar';

    // Segmented control
    this.segmentedControl = h('div', { className: 'filter-bar__segmented', role: 'tablist' });
    this.renderSegments();
    this.el.appendChild(this.segmentedControl);

    // Search
    const searchWrap = h('div', { className: 'filter-bar__search-wrap' });
    this.searchInput = document.createElement('input');
    this.searchInput.type = 'text';
    this.searchInput.placeholder = 'Filter rules...';
    this.searchInput.className = 'filter-bar__search-input';
    this.searchInput.setAttribute('aria-label', 'Filter rules');
    searchWrap.appendChild(this.searchInput);

    // Filter count
    this.filterCountEl = h('span', { className: 'filter-bar__count' });
    searchWrap.appendChild(this.filterCountEl);

    this.el.appendChild(searchWrap);
  }

  private renderSegments(): void {
    this.segmentedControl.innerHTML = '';
    const state = this.store.getState();
    const activeTab = state.ruleFilter.tab;

    const tabs: Array<{ id: FilterTab; label: string }> = [
      { id: 'all', label: 'All' },
      { id: 'allow', label: 'Allow' },
      { id: 'block', label: 'Block' },
    ];

    if (this.hasLogRules) {
      tabs.push({ id: 'log', label: 'Log' });
    }

    for (const tab of tabs) {
      const btn = h('button', {
        className: 'filter-bar__segment' + (activeTab === tab.id ? ' filter-bar__segment--active' : ''),
        role: 'tab',
        'aria-selected': String(activeTab === tab.id),
        dataset: { filterTab: tab.id },
      }, tab.label);
      this.segmentedControl.appendChild(btn);
    }
  }

  private bindEvents(): void {
    // Segmented control clicks
    this.listen(this.segmentedControl, 'click', (e) => {
      const btn = (e.target as HTMLElement).closest<HTMLElement>('.filter-bar__segment');
      if (!btn?.dataset.filterTab) return;
      const tab = btn.dataset.filterTab as FilterTab;
      this.store.dispatch({ type: 'SET_RULE_FILTER', filter: { tab } });
    });

    // Search input
    this.listen(this.searchInput, 'input', () => {
      this.store.dispatch({
        type: 'SET_RULE_FILTER',
        filter: { search: this.searchInput.value },
      });
    });
  }

  private bindSubscriptions(): void {
    // Update active segment on filter change
    this.subscribe(
      (s: AppState) => s.ruleFilter,
      (filter) => {
        // Update segments
        const segments = this.segmentedControl.querySelectorAll('.filter-bar__segment');
        for (const seg of segments) {
          const el = seg as HTMLElement;
          const isActive = el.dataset.filterTab === filter.tab;
          el.classList.toggle('filter-bar__segment--active', isActive);
          el.setAttribute('aria-selected', String(isActive));
        }

        // Sync search input if changed externally
        if (this.searchInput.value !== filter.search) {
          this.searchInput.value = filter.search;
        }
      },
    );
  }

  /**
   * Update the filter bar with current rule information.
   * Called by the parent RuleTable component.
   */
  updateRuleInfo(allRules: EffectiveRule[] | null, filteredRules: EffectiveRule[] | null): void {
    // Check if LOG rules exist
    const prevHasLog = this.hasLogRules;
    this.hasLogRules = allRules?.some(r => r.action === 'log' || r.action === 'log-block') ?? false;
    if (this.hasLogRules !== prevHasLog) {
      this.renderSegments();
    }

    // Update filter count
    if (allRules && filteredRules && filteredRules.length !== allRules.length) {
      this.filterCountEl.textContent = `${filteredRules.length} of ${allRules.length} rules`;
      this.filterCountEl.style.display = '';
    } else {
      this.filterCountEl.textContent = '';
      this.filterCountEl.style.display = 'none';
    }
  }
}
