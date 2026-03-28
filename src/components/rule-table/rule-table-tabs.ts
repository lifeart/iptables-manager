/**
 * Rule table tabs sub-component.
 *
 * Renders the tab bar (Rules / Activity / Terminal) with proper
 * ARIA attributes and handles tab switching via store dispatch.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState } from '../../store/types';
import { h } from '../../utils/dom';

export class RuleTableTabs extends Component {
  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindEvents();
    this.bindSubscriptions();
  }

  private render(): void {
    this.el.setAttribute('role', 'tablist');

    const tabs: Array<{ id: AppState['activeTab']; label: string }> = [
      { id: 'rules', label: 'Rules' },
      { id: 'activity', label: 'Activity' },
      { id: 'terminal', label: 'Terminal' },
    ];

    for (const tab of tabs) {
      const panelId = `tabpanel-${tab.id}`;
      const tabId = `tab-${tab.id}`;
      const btn = h(
        'button',
        {
          className: 'rule-table__tab',
          id: tabId,
          role: 'tab',
          'aria-controls': panelId,
          dataset: { tab: tab.id },
        },
        tab.label,
      );
      this.el.appendChild(btn);
    }

    // Apply initial styling
    this.updateTabStyling(this.store.getState().activeTab);
  }

  private bindEvents(): void {
    this.listen(this.el, 'click', (e) => {
      const btn = (e.target as HTMLElement).closest<HTMLElement>(
        '.rule-table__tab',
      );
      if (!btn?.dataset.tab) return;
      const tab = btn.dataset.tab as AppState['activeTab'];
      this.store.dispatch({ type: 'SET_ACTIVE_TAB', tab });
    });
  }

  private bindSubscriptions(): void {
    this.subscribe(
      (s: AppState) => s.activeTab,
      (tab) => this.updateTabStyling(tab),
    );
  }

  private updateTabStyling(tab: AppState['activeTab']): void {
    const tabBtns = this.el.querySelectorAll('.rule-table__tab');
    for (const btn of tabBtns) {
      const el = btn as HTMLElement;
      const isActive = el.dataset.tab === tab;
      el.classList.toggle('rule-table__tab--active', isActive);
      el.setAttribute('aria-selected', String(isActive));
    }
  }
}
