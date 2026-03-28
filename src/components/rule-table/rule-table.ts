/**
 * Rule table component — the primary rules interface.
 *
 * Orchestrates sub-components (header, tabs, banners) and handles
 * rule rendering organized by direction (Incoming / Outgoing / NAT)
 * with collapsible sections grouped by origin.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, EffectiveRule, HitCounter, OperationState } from '../../store/types';
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
import { RuleTableHeader } from './rule-table-header';
import { RuleTableTabs } from './rule-table-tabs';
import { ConflictBanner } from './conflict-banner';
import { ImportBanner } from './import-banner';
import { IpsetSuggestionCard } from './ipset-suggestion-card';
import { TerminalTab } from './terminal-tab';
import { h } from '../../utils/dom';
import { Activity } from '../activity/activity';
import { generateFromTemplate } from '../../services/templates';
import Sortable from 'sortablejs';

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
  private addRuleBtnContainer!: HTMLElement;
  private collapsedSections = new Set<string>();
  private loadingOverlay: HTMLElement | null = null;
  private errorBanner: HTMLElement | null = null;

  // Sub-components
  private headerComponent!: RuleTableHeader;
  private tabsComponent!: RuleTableTabs;
  private conflictBanner!: ConflictBanner;
  private importBannerComponent!: ImportBanner;
  private ipsetSuggestionCard!: IpsetSuggestionCard;

  // Tab content panels
  private activityPanel: HTMLElement | null = null;
  private terminalPanel: HTMLElement | null = null;
  private activityComponent: Activity | null = null;
  private terminalTabComponent: TerminalTab | null = null;

  // Split view
  private splitContainer: HTMLElement | null = null;
  private splitDivider: HTMLElement | null = null;
  private splitBottomPanel: HTMLElement | null = null;
  private splitActivityComponent: Activity | null = null;
  private isDraggingSplit = false;
  private splitRatio = 0.6;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindEvents();
    this.bindSubscriptions();
  }

  private render(): void {
    this.el.innerHTML = '';
    this.el.className = 'rule-table';

    // Header: host name + connection status (delegated to sub-component)
    this.headerEl = h('div', { className: 'rule-table__header' });
    this.el.appendChild(this.headerEl);
    this.headerComponent = new RuleTableHeader(this.headerEl, this.store);
    this.headerComponent.onNoActiveHost = () => this.renderWelcomeScreen();
    this.headerComponent.onActiveHost = () => {
      this.tabsEl.style.display = '';
    };
    this.addChild(this.headerComponent);

    // Tabs: Rules | Activity | Terminal (delegated to sub-component)
    this.tabsEl = h('div', { className: 'rule-table__tabs' });
    this.el.appendChild(this.tabsEl);
    this.tabsComponent = new RuleTableTabs(this.tabsEl, this.store);
    this.addChild(this.tabsComponent);

    // Filter bar container (conditionally rendered)
    this.filterBarContainer = h('div', { className: 'rule-table__filter-bar-container' });
    this.el.appendChild(this.filterBarContainer);

    // Standalone "+ Add Rule" button (shown when filter bar is hidden, i.e. < 5 rules)
    this.addRuleBtnContainer = h('div', { className: 'rule-table__add-rule-container' });
    const addRuleBtn = h('button', {
      className: 'rule-table__add-rule-btn',
      type: 'button',
    }, '+ Add Rule');
    this.listen(addRuleBtn, 'click', () => {
      this.store.dispatch({
        type: 'SET_SIDE_PANEL_CONTENT',
        content: { type: 'rule-new' },
      });
    });
    this.addRuleBtnContainer.appendChild(addRuleBtn);
    this.el.appendChild(this.addRuleBtnContainer);

    // Sections container (scrollable) — serves as the rules tab panel
    this.sectionsContainer = h('div', {
      className: 'rule-table__sections',
      id: 'tabpanel-rules',
      role: 'tabpanel',
      'aria-labelledby': 'tab-rules',
    });
    this.el.appendChild(this.sectionsContainer);

    // Conflict, import, and ipset suggestion banners (delegated to sub-components)
    this.conflictBanner = new ConflictBanner(this.el, this.store, this.sectionsContainer);
    this.addChild(this.conflictBanner);
    this.importBannerComponent = new ImportBanner(this.el, this.store, this.sectionsContainer);
    this.addChild(this.importBannerComponent);
    this.ipsetSuggestionCard = new IpsetSuggestionCard(this.el, this.store, this.sectionsContainer);
    this.addChild(this.ipsetSuggestionCard);

    // Activity tab panel (hidden by default)
    this.activityPanel = h('div', {
      className: 'rule-table__sections',
      id: 'tabpanel-activity',
      role: 'tabpanel',
      'aria-labelledby': 'tab-activity',
    });
    this.activityPanel.style.display = 'none';
    this.el.appendChild(this.activityPanel);

    // Terminal tab panel (hidden by default)
    this.terminalPanel = h('div', {
      className: 'rule-table__sections',
      id: 'tabpanel-terminal',
      role: 'tabpanel',
      'aria-labelledby': 'tab-terminal',
    });
    this.terminalPanel.style.display = 'none';
    this.el.appendChild(this.terminalPanel);

    // Pending bar at bottom
    this.pendingBarContainer = h('div', { className: 'rule-table__pending-bar-container' });
    this.el.appendChild(this.pendingBarContainer);
    this.pendingBar = new PendingBar(this.pendingBarContainer, this.store);
    this.addChild(this.pendingBar);
  }

  private bindEvents(): void {
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
        if ((e.target as HTMLElement).closest('.rule-table__overflow-btn')) return;

        this.store.dispatch({
          type: 'SET_SIDE_PANEL_CONTENT',
          content: { type: 'rule-detail', ruleId: row.dataset.ruleId },
        });
      }
    });
  }

  private bindSubscriptions(): void {
    // Active tab changed — switch content
    this.subscribe(
      (s: AppState) => s.activeTab,
      (tab) => this.switchTabContent(tab),
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

    // Hit counters changed — re-render to update counts
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hostStates.get(hostId)?.hitCounters ?? null;
      },
      () => this.renderRules(),
    );

    // Operations — show loading/error states for fetchRules
    this.subscribe(
      (s: AppState) => s.operations,
      (ops) => this.updateOperationState(ops),
    );

    // Split panel toggle (Cmd+\)
    this.subscribe(
      (s: AppState) => s.splitPanelOpen,
      (open) => this.updateSplitPanel(open, this.store.getState().splitPanelContent),
    );

    this.subscribe(
      (s: AppState) => s.splitPanelContent,
      (content) => {
        if (this.store.getState().splitPanelOpen) {
          this.updateSplitPanel(true, content);
        }
      },
    );

    // Initial renders
    this.renderRules();
    this.updateFilterBar();
  }

  private updateOperationState(operations: Map<string, OperationState>): void {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    let fetchOp: OperationState | null = null;

    for (const op of operations.values()) {
      if (op.type === 'fetchRules' && op.hostId === hostId) {
        if (!fetchOp || op.startedAt > fetchOp.startedAt) {
          fetchOp = op;
        }
      }
    }

    if (fetchOp?.status === 'pending') {
      if (!this.loadingOverlay) {
        this.loadingOverlay = h('div', { className: 'rule-table__loading-overlay' },
          h('div', { className: 'rule-table__loading-spinner' }),
          h('span', {}, 'Loading rules...'),
        );
        this.sectionsContainer.appendChild(this.loadingOverlay);
      }
    } else {
      if (this.loadingOverlay) {
        this.loadingOverlay.remove();
        this.loadingOverlay = null;
      }
    }

    if (fetchOp?.status === 'error') {
      if (!this.errorBanner) {
        this.errorBanner = h('div', { className: 'rule-table__error-banner' });
        this.sectionsContainer.insertBefore(this.errorBanner, this.sectionsContainer.firstChild);
      }
      this.errorBanner.textContent = fetchOp.error ?? 'Failed to load rules';
    } else {
      if (this.errorBanner) {
        this.errorBanner.remove();
        this.errorBanner = null;
      }
    }
  }

  private updateFilterBar(): void {
    const allRules = this.store.select(selectEffectiveRules as (s: AppState) => EffectiveRule[] | null);
    const filteredRules = this.store.select(selectFilteredRules as (s: AppState) => EffectiveRule[] | null);
    const ruleCount = allRules?.length ?? 0;

    if (ruleCount >= 5 && !this.filterBar) {
      this.filterBar = new FilterBar(this.filterBarContainer, this.store);
      this.addChild(this.filterBar);
    } else if (ruleCount < 5 && this.filterBar) {
      this.removeChild(this.filterBar);
      this.filterBar = null;
      this.filterBarContainer.innerHTML = '';
    }

    const showStandaloneAddBtn = ruleCount > 0 && ruleCount < 5;
    this.addRuleBtnContainer.style.display = showStandaloneAddBtn ? '' : 'none';

    this.filterBar?.updateRuleInfo(allRules, filteredRules);
  }

  private renderRules(): void {
    const filteredRules = this.store.select(selectFilteredRules as (s: AppState) => EffectiveRule[] | null);

    if (!filteredRules || filteredRules.length === 0) {
      this.renderEmptyState();
      return;
    }

    const sections = this.groupRulesByDirection(filteredRules);

    const expectedSectionKeys = new Set(sections.map(s => s.title));

    const existingSections = Array.from(
      this.sectionsContainer.querySelectorAll<HTMLElement>(':scope > .rule-table__section'),
    );
    for (const existingEl of existingSections) {
      const key = existingEl.dataset.section;
      if (key && !expectedSectionKeys.has(key)) {
        this.sectionsContainer.removeChild(existingEl);
      }
    }

    const emptyEl = this.sectionsContainer.querySelector('.rule-table__empty');
    if (emptyEl) emptyEl.remove();

    let nextSibling: Element | null = this.sectionsContainer.firstElementChild;

    for (const section of sections) {
      const isCollapsed = this.collapsedSections.has(section.title);

      let sectionEl = this.sectionsContainer.querySelector<HTMLElement>(
        `.rule-table__section[data-section="${CSS.escape(section.title)}"]`,
      );

      if (!sectionEl) {
        sectionEl = h('div', {
          className: 'rule-table__section',
          dataset: { section: section.title },
        });
        this.sectionsContainer.insertBefore(sectionEl, nextSibling);
      } else if (sectionEl !== nextSibling) {
        this.sectionsContainer.insertBefore(sectionEl, nextSibling);
      }
      nextSibling = sectionEl.nextElementSibling;

      let header = sectionEl.querySelector<HTMLElement>('.rule-table__section-header');
      if (header) {
        updateSectionHeader(header, section.title, section.rules.length, isCollapsed);
      } else {
        header = createSectionHeader(section.title, section.rules.length, isCollapsed);
        sectionEl.insertBefore(header, sectionEl.firstChild);
      }

      let rowsContainer = sectionEl.querySelector<HTMLElement>('.rule-table__rows');
      if (isCollapsed) {
        if (rowsContainer) rowsContainer.remove();
      } else {
        if (!rowsContainer) {
          rowsContainer = h('div', { className: 'rule-table__rows', role: 'list' });
          sectionEl.appendChild(rowsContainer);
        }

        if (section.rules.length === 0) {
          rowsContainer.innerHTML = '';
          if (section.title === 'NAT Rules') {
            const natActions = h('div', { className: 'rule-table__nat-actions' });
            const portFwdLink = h('button', {
              className: 'rule-table__nat-link',
              type: 'button',
            }, '+ Port Forwarding');
            const snatLink = h('button', {
              className: 'rule-table__nat-link',
              type: 'button',
            }, '+ Source NAT');
            this.listen(portFwdLink, 'click', () => {
              this.store.dispatch({
                type: 'SET_SIDE_PANEL_CONTENT',
                content: { type: 'port-forward' },
              });
              this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: true });
            });
            this.listen(snatLink, 'click', () => {
              this.store.dispatch({
                type: 'SET_SIDE_PANEL_CONTENT',
                content: { type: 'source-nat' },
              });
              this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: true });
            });
            natActions.appendChild(portFwdLink);
            natActions.appendChild(snatLink);
            natActions.appendChild(h('p', {
              className: 'rule-table__nat-hint',
            }, 'Set up port forwarding or source NAT for this host'));
            rowsContainer.appendChild(natActions);
          } else {
            const emptyText = h('p', { className: 'rule-table__section-empty' },
              'No rules in this section.');
            rowsContainer.appendChild(emptyText);
          }
        } else {
          const emptyP = rowsContainer.querySelector('.rule-table__section-empty');
          if (emptyP) emptyP.remove();

          const allSectionRules: EffectiveRule[] = [];
          const originGroups = this.groupRulesByOrigin(section.rules);
          for (const group of originGroups) {
            if (this.collapsedSections.has(`${section.title}:${group.title}`)) {
              continue;
            }
            allSectionRules.push(...group.rules);
          }

          const state = this.store.getState();
          const activeHostId = state.activeHostId;
          const pendingRuleIds = new Set<string>();
          if (activeHostId) {
            const changeset = state.stagedChanges.get(activeHostId);
            if (changeset) {
              for (const change of changeset.changes) {
                if ('ruleId' in change && change.ruleId) {
                  pendingRuleIds.add(change.ruleId);
                }
                if (change.type === 'add') {
                  pendingRuleIds.add(change.rule.id);
                }
              }
            }
          }

          const hitCounters = activeHostId
            ? state.hostStates.get(activeHostId)?.hitCounters
            : undefined;

          const ipListNames = new Map<string, string>();
          for (const [id, list] of state.ipLists) {
            ipListNames.set(id, list.name);
          }

          reconcileList(
            rowsContainer,
            allSectionRules,
            (rule) => rule.id,
            (rule) => {
              const rowEl = createRuleRow(rule, pendingRuleIds.has(rule.id), ipListNames);
              if (rule.section === 'default-policy') {
                rowEl.classList.add('rule-table__row--default-policy');
                if (rule.action === 'allow') {
                  rowEl.classList.add('rule-table__row--default-policy-accept');
                }
              }
              this.updateRowHitCount(rowEl, rule.id, hitCounters);
              return rowEl;
            },
            (el, rule) => {
              updateRuleRow(el, rule, pendingRuleIds.has(rule.id), ipListNames);
              el.classList.toggle('rule-table__row--default-policy', rule.section === 'default-policy');
              el.classList.toggle('rule-table__row--default-policy-accept', rule.section === 'default-policy' && rule.action === 'allow');
              this.updateRowHitCount(el, rule.id, hitCounters);
            },
          );

          if (activeHostId && !(rowsContainer as HTMLElement & { _sortableInit?: boolean })._sortableInit) {
            const hostId = activeHostId;
            new Sortable(rowsContainer, {
              handle: '.rule-table__drag-handle',
              animation: 150,
              ghostClass: 'rule-table__row--ghost',
              onEnd: (evt) => {
                if (evt.oldIndex !== undefined && evt.newIndex !== undefined) {
                  const ruleId = evt.item.dataset.ruleId;
                  if (ruleId) {
                    this.store.dispatch({
                      type: 'ADD_STAGED_CHANGE',
                      hostId,
                      change: { type: 'reorder', ruleId, fromPosition: evt.oldIndex, toPosition: evt.newIndex },
                    });
                  }
                }
              },
            });
            (rowsContainer as HTMLElement & { _sortableInit?: boolean })._sortableInit = true;
          }
        }
      }
    }
  }

  private updateRowHitCount(
    rowEl: HTMLElement,
    ruleId: string,
    hitCounters: Map<string, HitCounter> | undefined,
  ): void {
    const hitCountEl = rowEl.querySelector('.rule-table__hit-count');
    if (!hitCountEl) return;
    const counter = hitCounters?.get(ruleId);
    const count = counter?.packets ?? 0;
    const text = count > 0 ? this.formatHitCount(count) : '';
    if (hitCountEl.textContent !== text) {
      hitCountEl.textContent = text;
      if (text) {
        hitCountEl.classList.add('rule-table__hit-count--updating');
        setTimeout(() => {
          hitCountEl.classList.remove('rule-table__hit-count--updating');
        }, 500);
      }
    }
  }

  private formatHitCount(count: number): string {
    if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M`;
    if (count >= 1_000) return `${(count / 1_000).toFixed(1)}k`;
    return String(count);
  }

  private switchTabContent(tab: AppState['activeTab']): void {
    this.sectionsContainer.style.display = tab === 'rules' ? '' : 'none';
    this.filterBarContainer.style.display = tab === 'rules' ? '' : 'none';
    if (tab !== 'rules') {
      this.addRuleBtnContainer.style.display = 'none';
    }
    if (this.activityPanel) this.activityPanel.style.display = tab === 'activity' ? '' : 'none';
    if (this.terminalPanel) this.terminalPanel.style.display = tab === 'terminal' ? '' : 'none';

    if (tab === 'activity' && this.activityPanel) {
      if (!this.activityComponent) {
        this.activityComponent = new Activity(this.activityPanel, this.store);
        this.addChild(this.activityComponent);
      }
    }

    if (tab === 'terminal' && this.terminalPanel) {
      if (!this.terminalTabComponent) {
        this.terminalTabComponent = new TerminalTab(this.terminalPanel, this.store);
        this.addChild(this.terminalTabComponent);
      }
      this.terminalTabComponent.renderContent();
    }
  }

  private updateSplitPanel(open: boolean, content: 'activity' | 'terminal'): void {
    if (!open) {
      if (this.splitContainer) {
        if (this.splitContainer.parentElement) {
          this.splitContainer.parentElement.insertBefore(this.sectionsContainer, this.splitContainer);
        }
        if (this.splitActivityComponent) {
          this.removeChild(this.splitActivityComponent);
          this.splitActivityComponent = null;
        }
        this.splitContainer.remove();
        this.splitContainer = null;
        this.splitDivider = null;
        this.splitBottomPanel = null;
      }
      this.sectionsContainer.style.height = '';
      return;
    }

    if (!this.splitContainer) {
      this.splitContainer = h('div', { className: 'rule-table__split-container' });
      this.splitContainer.style.display = 'flex';
      this.splitContainer.style.flexDirection = 'column';
      this.splitContainer.style.flex = '1';
      this.splitContainer.style.overflow = 'hidden';

      this.sectionsContainer.parentElement?.insertBefore(this.splitContainer, this.sectionsContainer);

      this.sectionsContainer.style.height = `${this.splitRatio * 100}%`;
      this.sectionsContainer.style.overflow = 'auto';
      this.splitContainer.appendChild(this.sectionsContainer);

      this.splitDivider = h('div', { className: 'rule-table__split-divider' });
      this.splitDivider.style.height = '4px';
      this.splitDivider.style.cursor = 'row-resize';
      this.splitDivider.style.background = 'var(--border-color, #ccc)';
      this.splitDivider.style.flexShrink = '0';
      this.splitContainer.appendChild(this.splitDivider);

      this.splitBottomPanel = h('div', { className: 'rule-table__split-bottom' });
      this.splitBottomPanel.style.height = `${(1 - this.splitRatio) * 100}%`;
      this.splitBottomPanel.style.overflow = 'auto';
      this.splitContainer.appendChild(this.splitBottomPanel);

      this.listen(this.splitDivider, 'mousedown', (e) => {
        e.preventDefault();
        this.isDraggingSplit = true;
        const onMove = (me: MouseEvent) => {
          if (!this.isDraggingSplit || !this.splitContainer) return;
          const rect = this.splitContainer.getBoundingClientRect();
          const ratio = (me.clientY - rect.top) / rect.height;
          this.splitRatio = Math.max(0.2, Math.min(0.8, ratio));
          this.sectionsContainer.style.height = `${this.splitRatio * 100}%`;
          if (this.splitBottomPanel) {
            this.splitBottomPanel.style.height = `${(1 - this.splitRatio) * 100}%`;
          }
        };
        const onUp = () => {
          this.isDraggingSplit = false;
          document.removeEventListener('mousemove', onMove);
          document.removeEventListener('mouseup', onUp);
        };
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
      });
    }

    if (this.splitBottomPanel) {
      this.splitBottomPanel.innerHTML = '';
      if (this.splitActivityComponent) {
        this.removeChild(this.splitActivityComponent);
        this.splitActivityComponent = null;
      }

      if (content === 'activity') {
        this.splitActivityComponent = new Activity(this.splitBottomPanel, this.store);
        this.addChild(this.splitActivityComponent);
      } else {
        this.splitBottomPanel.appendChild(
          h('div', { className: 'rule-table__split-terminal-placeholder' },
            h('p', {}, 'Terminal panel — connect to a real server to use the terminal.')),
        );
      }
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

    const showNat = nat.length > 0 || this.hostHasNatCapability();
    if (showNat) {
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
        key = 'Auto-Generated (Essential)';
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

  private hostHasNatCapability(): boolean {
    const host = this.store.select(selectActiveHost);
    if (!host?.capabilities) return false;
    const ifaces = host.capabilities.interfaces;
    return ifaces != null && ifaces.length >= 2;
  }

  private renderEmptyState(): void {
    this.sectionsContainer.innerHTML = '';
    this.conflictBanner.clearBanner();
    this.importBannerComponent.clearBanner();
    this.ipsetSuggestionCard.clearCard();

    const activeHost = this.store.select(selectActiveHost);
    if (activeHost && activeHost.status === 'unreachable') {
      const empty = h('div', { className: 'rule-table__empty' });
      empty.appendChild(h('p', { className: 'rule-table__empty-title' }, 'Host Unreachable'));
      empty.appendChild(h('p', { className: 'rule-table__empty-subtitle' },
        `Cannot connect to ${activeHost.name} (${activeHost.connection.hostname}). ` +
        'The server may be offline or the network connection may be down.'));
      if (activeHost.lastConnected) {
        const lastSeen = new Date(activeHost.lastConnected).toLocaleString();
        empty.appendChild(h('p', { className: 'rule-table__empty-subtitle' },
          `Last connected: ${lastSeen}`));
      }
      this.sectionsContainer.appendChild(empty);
      return;
    }

    const empty = h('div', { className: 'rule-table__empty' });
    empty.appendChild(h('p', { className: 'rule-table__empty-title' }, 'No traffic rules configured.'));
    empty.appendChild(h('p', { className: 'rule-table__empty-subtitle' }, 'All traffic is currently allowed.'));

    const actions = h('div', { className: 'rule-table__empty-actions' });

    const suggestedBtn = h('button', { className: 'rule-table__empty-btn rule-table__empty-btn--primary' },
      'Set up suggested rules');
    this.listen(suggestedBtn, 'click', () => this.handleSetupSuggestedRules());
    actions.appendChild(suggestedBtn);

    const addFirstBtn = h('button', { className: 'rule-table__empty-btn' }, 'Add first rule');
    this.listen(addFirstBtn, 'click', () => {
      this.store.dispatch({
        type: 'SET_SIDE_PANEL_CONTENT',
        content: { type: 'rule-new' },
      });
    });
    actions.appendChild(addFirstBtn);

    empty.appendChild(actions);
    this.sectionsContainer.appendChild(empty);
  }

  private renderWelcomeScreen(): void {
    this.sectionsContainer.innerHTML = '';
    this.conflictBanner.clearBanner();
    this.importBannerComponent.clearBanner();
    this.ipsetSuggestionCard.clearCard();
    this.filterBarContainer.style.display = 'none';
    this.addRuleBtnContainer.style.display = 'none';
    this.tabsEl.style.display = 'none';

    const welcome = h('div', { className: 'rule-table__empty' });
    welcome.appendChild(h('p', { className: 'rule-table__empty-title' }, 'Welcome to Traffic Rules'));
    welcome.appendChild(h('p', { className: 'rule-table__empty-subtitle' },
      'Connect to a Linux server to manage its firewall, or explore the demo.'));

    const actions = h('div', { className: 'rule-table__empty-actions' });

    const addHostBtn = h('button', {
      className: 'rule-table__empty-btn rule-table__empty-btn--primary',
    }, 'Connect to Server');
    this.listen(addHostBtn, 'click', () => {
      this.store.dispatch({ type: 'OPEN_DIALOG', dialog: 'add-host' });
    });
    actions.appendChild(addHostBtn);

    const demoBtn = h('button', { className: 'rule-table__empty-btn' }, 'Try Demo');
    this.listen(demoBtn, 'click', () => {
      import('../../mock/demo-data').then(({ loadDemoData }) => {
        loadDemoData(this.store);
      });
    });
    actions.appendChild(demoBtn);

    welcome.appendChild(actions);
    this.sectionsContainer.appendChild(welcome);
  }

  private handleSetupSuggestedRules(): void {
    const activeHostId = this.store.getState().activeHostId;
    if (!activeHostId) return;

    const rules = generateFromTemplate('web-server');
    for (let i = 0; i < rules.length; i++) {
      this.store.dispatch({
        type: 'ADD_STAGED_CHANGE',
        hostId: activeHostId,
        change: { type: 'add', rule: rules[i], position: i },
      });
    }
  }
}
