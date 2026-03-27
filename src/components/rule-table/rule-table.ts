/**
 * Rule table component — the primary rules interface.
 *
 * Subscribes to: selectEffectiveRules, selectFilteredRules, ruleFilter, activeTab.
 * Shows rules organized by direction (Incoming / Outgoing / NAT) with
 * collapsible sections grouped by origin.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, EffectiveRule, HitCounter, Host, OperationState, Rule } from '../../store/types';
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
import { Activity } from '../activity/activity';
import { generateFromTemplate } from '../../services/templates';
import { disconnectHost, connectHost, fetchRules, exportRules, tracePacket, provisionHost, detectConflicts, importExistingRules } from '../../ipc/bridge';
import type { TestPacket, RuleConflict } from '../../ipc/bridge';
import { convertRuleSet } from '../../services/rule-converter';
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
  private currentHeaderHostId: string | null = null;
  private loadingOverlay: HTMLElement | null = null;
  private errorBanner: HTMLElement | null = null;
  private conflictsBanner: HTMLElement | null = null;
  private conflictsExpanded = false;
  private importBanner: HTMLElement | null = null;
  private importDismissed = new Set<string>();

  // Tab content panels
  private activityPanel: HTMLElement | null = null;
  private terminalPanel: HTMLElement | null = null;
  private activityComponent: Activity | null = null;

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
      const panelId = `tabpanel-${tab.id}`;
      const tabId = `tab-${tab.id}`;
      const btn = h('button', {
        className: 'rule-table__tab',
        id: tabId,
        role: 'tab',
        'aria-controls': panelId,
        dataset: { tab: tab.id },
      }, tab.label);
      this.tabsEl.appendChild(btn);
    }
    this.el.appendChild(this.tabsEl);

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

  private currentHeaderStatus: string | null = null;

  private bindSubscriptions(): void {
    // Active host changed — rebuild header when host ID or status changes
    this.subscribe(
      selectActiveHost,
      (host) => {
        if (host) {
          // Show tabs (welcome screen may have hidden them)
          this.tabsEl.style.display = '';

          const needsRebuild = this.currentHeaderHostId !== host.id
            || this.currentHeaderStatus !== host.status;

          if (needsRebuild) {
            this.currentHeaderHostId = host.id;
            this.currentHeaderStatus = host.status;
            this.rebuildHeader(host);
          } else {
            // Just update name if it changed
            const nameEl = this.headerEl.querySelector('.rule-table__host-name');
            if (nameEl && nameEl.textContent !== host.name) {
              nameEl.textContent = host.name;
            }
          }
        } else {
          this.currentHeaderHostId = null;
          this.currentHeaderStatus = null;
          this.headerEl.innerHTML = '';
          this.renderWelcomeScreen();
        }
      },
    );

    // Active tab changed — update tab styling and switch content
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
        this.switchTabContent(tab);
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

    // Hit counters changed — re-render to update counts
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hostStates.get(hostId)?.hitCounters ?? null;
      },
      () => this.renderRules(),
    );

    // Rules changed — trigger conflict detection
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hostStates.get(hostId)?.rules ?? null;
      },
      (rules) => {
        const hostId = this.store.getState().activeHostId;
        if (hostId && rules && rules.length > 1) {
          this.runConflictDetection(hostId);
        } else if (hostId) {
          // Clear conflicts when there are 0-1 rules
          this.store.dispatch({ type: 'SET_RULE_CONFLICTS', hostId, conflicts: [] });
        }
      },
    );

    // Rule conflicts changed — update the conflicts banner
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hostStates.get(hostId)?.ruleConflicts ?? null;
      },
      (conflicts) => this.renderConflictsBanner(conflicts ?? []),
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

    // Check for non-TR rules when rules load (for import-as-baseline banner)
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hostStates.get(hostId)?.rules ?? null;
      },
      (rules) => {
        const hostId = this.store.getState().activeHostId;
        if (hostId && rules && rules.length > 0) {
          this.checkImportBanner(hostId);
        } else {
          this.removeImportBanner();
        }
      },
    );

    // Initial renders
    this.updateTabStyling();
    this.renderRules();
    this.updateFilterBar();
  }

  private updateOperationState(operations: Map<string, OperationState>): void {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    let fetchOp: OperationState | null = null;

    // Find the most recent fetchRules operation for the active host
    for (const op of operations.values()) {
      if (op.type === 'fetchRules' && op.hostId === hostId) {
        if (!fetchOp || op.startedAt > fetchOp.startedAt) {
          fetchOp = op;
        }
      }
    }

    // Loading spinner
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

    // Error banner
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

  private runConflictDetection(hostId: string): void {
    detectConflicts(hostId)
      .then((conflicts) => {
        // Only dispatch if still viewing the same host
        if (this.store.getState().activeHostId === hostId) {
          this.store.dispatch({ type: 'SET_RULE_CONFLICTS', hostId, conflicts });
        }
      })
      .catch((err) => {
        console.warn('Conflict detection failed:', err);
      });
  }

  private renderConflictsBanner(conflicts: RuleConflict[]): void {
    if (conflicts.length === 0) {
      if (this.conflictsBanner) {
        this.conflictsBanner.remove();
        this.conflictsBanner = null;
      }
      return;
    }

    if (!this.conflictsBanner) {
      this.conflictsBanner = h('div', { className: 'rule-table__conflicts-banner' });
      this.sectionsContainer.insertBefore(this.conflictsBanner, this.sectionsContainer.firstChild);
    }

    const conflictTypeLabel = (type: RuleConflict['type']): string => {
      switch (type) {
        case 'shadow': return 'Shadow';
        case 'contradiction': return 'Contradiction';
        case 'redundant': return 'Redundancy';
        default: return type;
      }
    };

    this.conflictsBanner.innerHTML = '';

    // Summary row (clickable to expand/collapse)
    const summary = h('button', {
      className: 'rule-table__conflicts-summary',
      type: 'button',
      'aria-expanded': String(this.conflictsExpanded),
    });
    const chevron = h('span', {
      className: 'rule-table__conflicts-chevron' + (this.conflictsExpanded ? ' rule-table__conflicts-chevron--open' : ''),
    }, '\u25B6');
    summary.appendChild(chevron);
    summary.appendChild(h('span', {}, `${conflicts.length} potential conflict${conflicts.length === 1 ? '' : 's'} detected`));

    this.listen(summary, 'click', () => {
      this.conflictsExpanded = !this.conflictsExpanded;
      this.renderConflictsBanner(conflicts);
    });

    this.conflictsBanner.appendChild(summary);

    // Expandable detail list
    if (this.conflictsExpanded) {
      const list = h('div', { className: 'rule-table__conflicts-list' });
      for (const conflict of conflicts) {
        const item = h('div', { className: 'rule-table__conflicts-item' });
        const badge = h('span', {
          className: `rule-table__conflicts-badge rule-table__conflicts-badge--${conflict.type}`,
        }, conflictTypeLabel(conflict.type));
        const rules = h('span', { className: 'rule-table__conflicts-rules' },
          `Rules: ${conflict.ruleIdA.slice(0, 8)} \u2194 ${conflict.ruleIdB.slice(0, 8)}`);
        const desc = h('span', { className: 'rule-table__conflicts-desc' }, conflict.description);

        item.appendChild(badge);
        item.appendChild(rules);
        item.appendChild(desc);
        list.appendChild(item);
      }
      this.conflictsBanner.appendChild(list);
    }
  }

  private checkImportBanner(hostId: string): void {
    if (this.importDismissed.has(hostId)) {
      this.removeImportBanner();
      return;
    }

    const state = this.store.getState();
    const hostState = state.hostStates.get(hostId);
    if (!hostState) return;

    const importedCount = hostState.rules.filter(
      r => r.origin?.type === 'imported' || r.origin?.type === 'system',
    ).length;

    if (importedCount > 0 && !this.importBanner) {
      this.importBanner = h('div', { className: 'rule-table__import-banner' });

      const text = h('span', { className: 'rule-table__import-text' },
        `This host has ${importedCount} existing iptables rule${importedCount === 1 ? '' : 's'} not managed by Traffic Rules. Import them?`);
      this.importBanner.appendChild(text);

      const importBtn = h('button', {
        className: 'rule-table__import-btn',
        type: 'button',
      }, 'Import');
      this.listen(importBtn, 'click', () => this.handleImportRules(hostId));
      this.importBanner.appendChild(importBtn);

      const dismissBtn = h('button', {
        className: 'rule-table__import-dismiss',
        type: 'button',
        'aria-label': 'Dismiss',
      }, '\u00D7');
      this.listen(dismissBtn, 'click', () => {
        this.importDismissed.add(hostId);
        this.removeImportBanner();
      });
      this.importBanner.appendChild(dismissBtn);

      this.sectionsContainer.insertBefore(this.importBanner, this.sectionsContainer.firstChild);
    } else if (importedCount === 0) {
      this.removeImportBanner();
    }
  }

  private removeImportBanner(): void {
    if (this.importBanner) {
      this.importBanner.remove();
      this.importBanner = null;
    }
  }

  private async handleImportRules(hostId: string): Promise<void> {
    try {
      const result = await importExistingRules(hostId);
      if (result.nonTrRuleCount === 0) {
        this.removeImportBanner();
        return;
      }

      const ruleSet = {
        rules: [] as Rule[],
        defaultPolicy: 'drop',
        rawIptablesSave: result.rawIptablesSave,
      };
      const allRules = convertRuleSet(ruleSet);

      for (let i = 0; i < allRules.length; i++) {
        const rule = allRules[i];
        rule.origin = { type: 'imported' };
        this.store.dispatch({
          type: 'ADD_STAGED_CHANGE',
          hostId,
          change: { type: 'add', rule, position: i },
        });
      }

      this.importDismissed.add(hostId);
      this.removeImportBanner();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Import failed';
      const errorEl = h('div', { className: 'rule-table__import-error' }, msg);
      this.importBanner?.appendChild(errorEl);
      setTimeout(() => errorEl.remove(), 5000);
    }
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

    // Show standalone "+ Add Rule" button when filter bar is hidden and rules exist (1-4 rules)
    const showStandaloneAddBtn = ruleCount > 0 && ruleCount < 5;
    this.addRuleBtnContainer.style.display = showStandaloneAddBtn ? '' : 'none';

    // Update filter bar info
    this.filterBar?.updateRuleInfo(allRules, filteredRules);
  }

  private renderRules(): void {
    const filteredRules = this.store.select(selectFilteredRules as (s: AppState) => EffectiveRule[] | null);

    if (!filteredRules || filteredRules.length === 0) {
      this.renderEmptyState();
      return;
    }

    // Group rules by direction
    const sections = this.groupRulesByDirection(filteredRules);

    // Build a set of section keys we expect
    const expectedSectionKeys = new Set(sections.map(s => s.title));

    // Remove sections that no longer exist
    const existingSections = Array.from(
      this.sectionsContainer.querySelectorAll<HTMLElement>(':scope > .rule-table__section'),
    );
    for (const existingEl of existingSections) {
      const key = existingEl.dataset.section;
      if (key && !expectedSectionKeys.has(key)) {
        this.sectionsContainer.removeChild(existingEl);
      }
    }

    // Remove any empty-state element if present
    const emptyEl = this.sectionsContainer.querySelector('.rule-table__empty');
    if (emptyEl) emptyEl.remove();

    let nextSibling: Element | null = this.sectionsContainer.firstElementChild;

    for (const section of sections) {
      const isCollapsed = this.collapsedSections.has(section.title);

      // Find or create section element
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

      // Update or create section header
      let header = sectionEl.querySelector<HTMLElement>('.rule-table__section-header');
      if (header) {
        updateSectionHeader(header, section.title, section.rules.length, isCollapsed);
      } else {
        header = createSectionHeader(section.title, section.rules.length, isCollapsed);
        sectionEl.insertBefore(header, sectionEl.firstChild);
      }

      // Rule rows (hidden if collapsed)
      let rowsContainer = sectionEl.querySelector<HTMLElement>('.rule-table__rows');
      if (isCollapsed) {
        if (rowsContainer) rowsContainer.remove();
      } else {
        if (!rowsContainer) {
          rowsContainer = h('div', { className: 'rule-table__rows', role: 'list' });
          sectionEl.appendChild(rowsContainer);
        }

        if (section.rules.length === 0) {
          // Show empty state for sections with no rules
          rowsContainer.innerHTML = '';
          if (section.title === 'NAT Rules') {
            // Show NAT action links
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
          // Remove any previous empty state text
          const emptyP = rowsContainer.querySelector('.rule-table__section-empty');
          if (emptyP) emptyP.remove();

          // Collect all rules for this section into a flat list for reconciliation
          const allSectionRules: EffectiveRule[] = [];
          const originGroups = this.groupRulesByOrigin(section.rules);
          for (const group of originGroups) {
            if (this.collapsedSections.has(`${section.title}:${group.title}`)) {
              continue;
            }
            allSectionRules.push(...group.rules);
          }

          // Build set of rule IDs with pending changes
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

          // Get hit counters for the active host
          const hitCounters = activeHostId
            ? state.hostStates.get(activeHostId)?.hitCounters
            : undefined;

          // Build ipList name lookup
          const ipListNames = new Map<string, string>();
          for (const [id, list] of state.ipLists) {
            ipListNames.set(id, list.name);
          }

          // Use reconcileList for rule rows within the section
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
              // Set hit count
              this.updateRowHitCount(rowEl, rule.id, hitCounters);
              return rowEl;
            },
            (el, rule) => {
              updateRuleRow(el, rule, pendingRuleIds.has(rule.id), ipListNames);
              el.classList.toggle('rule-table__row--default-policy', rule.section === 'default-policy');
              el.classList.toggle('rule-table__row--default-policy-accept', rule.section === 'default-policy' && rule.action === 'allow');
              // Update hit count
              this.updateRowHitCount(el, rule.id, hitCounters);
            },
          );

          // Initialize drag-and-drop reordering via SortableJS
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
      // Briefly flash the updating class for animated counter
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

  private buildRouteMap(): HTMLElement {
    const map = h('div', { className: 'rule-table__route-map' });

    // Determine the active chain based on current filter/tab
    const state = this.store.getState();
    const filterTab = state.ruleFilter.tab;

    // Row 1: Internet -> PREROUTING -> INPUT -> Local Machine
    //                               -> FORWARD -> POSTROUTING -> Out
    const chains: Array<{ name: string; activeFor: string[] }> = [
      { name: 'PREROUTING', activeFor: ['all'] },
      { name: 'INPUT', activeFor: ['all', 'allow', 'block'] },
      { name: 'FORWARD', activeFor: [] },
      { name: 'OUTPUT', activeFor: ['all'] },
      { name: 'POSTROUTING', activeFor: [] },
    ];

    // Build line 1: Internet -> [PREROUTING] -> [INPUT] -> Local
    map.appendChild(h('span', { className: 'rule-table__route-map-label' }, 'Internet'));
    map.appendChild(h('span', { className: 'rule-table__route-map-arrow' }, '\u2192'));

    for (const chain of chains) {
      const isActive = chain.activeFor.includes(filterTab);
      const node = h('span', {
        className: 'rule-table__route-map-node' + (isActive ? ' rule-table__route-map-node--active' : ''),
        dataset: { chain: chain.name },
      }, chain.name);
      map.appendChild(node);
      map.appendChild(h('span', { className: 'rule-table__route-map-arrow' }, '\u2192'));
    }

    map.appendChild(h('span', { className: 'rule-table__route-map-label' }, 'Out'));

    return map;
  }

  private switchTabContent(tab: AppState['activeTab']): void {
    // Show/hide panels
    this.sectionsContainer.style.display = tab === 'rules' ? '' : 'none';
    // Show/hide content areas based on active tab
    this.filterBarContainer.style.display = tab === 'rules' ? '' : 'none';
    this.sectionsContainer.style.display = tab === 'rules' ? '' : 'none';
    if (tab !== 'rules') {
      this.addRuleBtnContainer.style.display = 'none';
    }
    if (this.activityPanel) this.activityPanel.style.display = tab === 'activity' ? '' : 'none';
    if (this.terminalPanel) this.terminalPanel.style.display = tab === 'terminal' ? '' : 'none';

    // Activity tab — mount activity component lazily
    if (tab === 'activity' && this.activityPanel) {
      if (!this.activityComponent) {
        this.activityComponent = new Activity(this.activityPanel, this.store);
        this.addChild(this.activityComponent);
      }
    }

    // Terminal tab — render with sub-tab buttons
    if (tab === 'terminal' && this.terminalPanel) {
      this.renderTerminalTab();
    }
  }

  private updateSplitPanel(open: boolean, content: 'activity' | 'terminal'): void {
    if (!open) {
      // Remove split view
      if (this.splitContainer) {
        // Move sectionsContainer back out of split container
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

    // Create split view if not already present
    if (!this.splitContainer) {
      this.splitContainer = h('div', { className: 'rule-table__split-container' });
      this.splitContainer.style.display = 'flex';
      this.splitContainer.style.flexDirection = 'column';
      this.splitContainer.style.flex = '1';
      this.splitContainer.style.overflow = 'hidden';

      // Insert the split container where sectionsContainer was
      this.sectionsContainer.parentElement?.insertBefore(this.splitContainer, this.sectionsContainer);

      // Move sectionsContainer into split container (top panel)
      this.sectionsContainer.style.height = `${this.splitRatio * 100}%`;
      this.sectionsContainer.style.overflow = 'auto';
      this.splitContainer.appendChild(this.sectionsContainer);

      // Resizable divider
      this.splitDivider = h('div', { className: 'rule-table__split-divider' });
      this.splitDivider.style.height = '4px';
      this.splitDivider.style.cursor = 'row-resize';
      this.splitDivider.style.background = 'var(--border-color, #ccc)';
      this.splitDivider.style.flexShrink = '0';
      this.splitContainer.appendChild(this.splitDivider);

      // Bottom panel
      this.splitBottomPanel = h('div', { className: 'rule-table__split-bottom' });
      this.splitBottomPanel.style.height = `${(1 - this.splitRatio) * 100}%`;
      this.splitBottomPanel.style.overflow = 'auto';
      this.splitContainer.appendChild(this.splitBottomPanel);

      // Divider drag
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

    // Render content in bottom panel
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

  private rebuildHeader(host: Host): void {
    this.headerEl.innerHTML = '';
    const nameEl = h('span', { className: 'rule-table__host-name' }, host.name);
    this.headerEl.appendChild(nameEl);

    const statusLabel = host.status.charAt(0).toUpperCase() + host.status.slice(1);
    const statusEl = h('span', {
      className: `rule-table__host-status rule-table__host-status--${host.status}`,
    }, statusLabel);
    this.headerEl.appendChild(statusEl);

    const headerBtns = h('div', {
      className: 'rule-table__header-actions',
    });

    if (host.status === 'connected') {
      // Disconnect button
      const disconnectBtn = h('button', {
        className: 'rule-table__header-btn rule-table__header-btn--disconnect',
        type: 'button',
        title: 'Disconnect from host',
      }, 'Disconnect');
      this.listen(disconnectBtn, 'click', () => this.handleDisconnect(host.id));
      headerBtns.appendChild(disconnectBtn);
    } else if (host.status === 'disconnected' || host.status === 'unreachable') {
      // Reconnect button
      const reconnectBtn = h('button', {
        className: 'rule-table__header-btn rule-table__header-btn--reconnect',
        type: 'button',
        title: 'Reconnect to host',
      }, 'Reconnect');
      this.listen(reconnectBtn, 'click', () => this.handleReconnect(host));
      headerBtns.appendChild(reconnectBtn);
    }

    // Export button
    const exportBtn = h('button', {
      className: 'rule-table__header-btn',
      type: 'button',
      title: 'Export rules',
    }, 'Export');
    this.listen(exportBtn, 'click', () => {
      this.showExportDropdown(exportBtn, host.id);
    });
    headerBtns.appendChild(exportBtn);

    // History button (always shown)
    const historyBtn = h('button', {
      className: 'rule-table__header-btn',
      type: 'button',
      title: 'Snapshot History',
    }, 'History');
    this.listen(historyBtn, 'click', () => {
      this.store.dispatch({ type: 'SET_SIDE_PANEL_CONTENT', content: { type: 'snapshot-history' } });
      this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: true });
    });
    headerBtns.appendChild(historyBtn);
    this.headerEl.appendChild(headerBtns);
  }

  private handleReconnect(host: Host): void {
    this.store.dispatch({ type: 'SET_HOST_STATUS', hostId: host.id, status: 'connecting' });
    const operationId = `fetchRules-${host.id}-${Date.now()}`;
    connectHost(host.id, host.connection.hostname, host.connection.port, host.connection.username, host.connection.authMethod, host.connection.keyPath)
      .then(() => {
        this.store.dispatch({ type: 'SET_HOST_STATUS', hostId: host.id, status: 'connected' });
        this.store.dispatch({
          type: 'START_OPERATION',
          operationId,
          operationType: 'fetchRules',
          hostId: host.id,
        });

        // Provision if not already provisioned (non-blocking)
        if (!host.provisioned) {
          provisionHost(host.id)
            .then((result) => {
              if (result.success) {
                this.store.dispatch({
                  type: 'UPDATE_HOST',
                  hostId: host.id,
                  changes: { provisioned: true },
                });
              }
            })
            .catch((err) => {
              console.warn(`Host provisioning failed for ${host.id}:`, err);
            });
        }

        return fetchRules(host.id);
      })
      .then((ruleData) => {
        const rules = convertRuleSet(ruleData);
        this.store.dispatch({ type: 'SET_HOST_RULES', hostId: host.id, rules });
        this.store.dispatch({ type: 'COMPLETE_OPERATION', operationId });
      })
      .catch((err) => {
        this.store.dispatch({ type: 'SET_HOST_STATUS', hostId: host.id, status: 'unreachable' });
        const errorMsg = err instanceof Error ? err.message : 'Connection failed';
        this.store.dispatch({ type: 'FAIL_OPERATION', operationId, error: errorMsg });
      });
  }

  private handleDisconnect(hostId: string): void {
    disconnectHost(hostId)
      .then(() => {
        this.store.dispatch({ type: 'SET_HOST_STATUS', hostId, status: 'disconnected' });
        this.store.dispatch({ type: 'CLEAR_HOST_STATE', hostId });
      })
      .catch(() => {
        // Update status anyway since the UI should reflect the intent
        this.store.dispatch({ type: 'SET_HOST_STATUS', hostId, status: 'disconnected' });
        this.store.dispatch({ type: 'CLEAR_HOST_STATE', hostId });
      });
  }

  // ── Terminal Tab ──────────────────────────────────────────────

  private renderTerminalTab(): void {
    if (!this.terminalPanel) return;
    this.terminalPanel.innerHTML = '';

    const placeholder = h('div', { className: 'rule-table__terminal-placeholder' });

    // Sub-tab buttons
    const subTabs = h('div', { className: 'rule-table__terminal-sub-tabs' });
    const state = this.store.getState();
    const activeSubTab = state.activeTerminalSubTab;

    const subTabDefs: Array<{ id: AppState['activeTerminalSubTab']; label: string }> = [
      { id: 'raw', label: 'Raw Rules' },
      { id: 'tracer', label: 'Packet Tracer' },
      { id: 'sshlog', label: 'SSH Log' },
    ];

    for (const st of subTabDefs) {
      const btn = h('button', {
        className: `rule-table__terminal-sub-tab${activeSubTab === st.id ? ' rule-table__terminal-sub-tab--active' : ''}`,
        type: 'button',
        dataset: { subTab: st.id },
      }, st.label);
      this.listen(btn, 'click', () => {
        this.store.dispatch({ type: 'SET_TERMINAL_SUB_TAB', subTab: st.id });
        this.renderTerminalTab();
      });
      subTabs.appendChild(btn);
    }
    placeholder.appendChild(subTabs);

    // Content area
    const content = h('div', { className: 'terminal__content' });

    switch (activeSubTab) {
      case 'raw':
        this.renderRawRulesSubTab(content);
        break;
      case 'tracer':
        this.renderPacketTracerSubTab(content);
        break;
      case 'sshlog':
        this.renderSshLogSubTab(content);
        break;
    }

    placeholder.appendChild(content);
    this.terminalPanel.appendChild(placeholder);
  }

  private renderRawRulesSubTab(container: HTMLElement): void {
    const state = this.store.getState();
    const hostId = state.activeHostId;

    const textarea = document.createElement('textarea');
    textarea.className = 'terminal__editor';
    textarea.spellcheck = false;
    textarea.rows = 30;
    textarea.value = '# Connect to a host to see rules';

    if (hostId) {
      textarea.value = '# Loading...';
      fetchRules(hostId).then((ruleSet) => {
        textarea.value = ruleSet.rawIptablesSave || '# No rules loaded';
      }).catch(() => {
        textarea.value = '# Failed to load rules';
      });
    }

    container.appendChild(textarea);
  }

  private renderPacketTracerSubTab(container: HTMLElement): void {
    const form = h('div', { className: 'terminal__tracer-form' });

    const fields: Array<{ id: string; label: string; placeholder: string }> = [
      { id: 'sourceIp', label: 'Source IP', placeholder: '192.168.1.100' },
      { id: 'destIp', label: 'Destination IP', placeholder: '10.0.1.10' },
      { id: 'destPort', label: 'Destination Port', placeholder: '80' },
    ];

    const inputs: Record<string, HTMLInputElement> = {};
    for (const f of fields) {
      const field = h('div', { className: 'terminal__tracer-field' });
      field.appendChild(h('label', { className: 'dialog-label', for: `tracer-${f.id}` }, f.label));
      const input = document.createElement('input');
      input.type = 'text';
      input.id = `tracer-${f.id}`;
      input.className = 'dialog-input dialog-input--ip';
      input.placeholder = f.placeholder;
      inputs[f.id] = input;
      field.appendChild(input);
      form.appendChild(field);
    }

    // Protocol selector
    const protoField = h('div', { className: 'terminal__tracer-field' });
    protoField.appendChild(h('label', { className: 'dialog-label', for: 'tracer-protocol' }, 'Protocol'));
    const protoSelect = document.createElement('select');
    protoSelect.id = 'tracer-protocol';
    protoSelect.className = 'dialog-select';
    for (const proto of ['tcp', 'udp', 'icmp']) {
      const opt = document.createElement('option');
      opt.value = proto;
      opt.textContent = proto.toUpperCase();
      protoSelect.appendChild(opt);
    }
    protoField.appendChild(protoSelect);
    form.appendChild(protoField);

    // Trace button
    const traceBtn = h('button', {
      className: 'dialog-btn dialog-btn--primary',
      type: 'button',
      style: { marginTop: '12px' },
    }, 'Trace');

    // Result area
    const resultArea = h('div', { className: 'terminal__tracer-result' });

    this.listen(traceBtn, 'click', () => {
      const state = this.store.getState();
      const hostId = state.activeHostId;
      if (!hostId) {
        resultArea.textContent = 'No host selected.';
        return;
      }

      const packet: TestPacket = {
        sourceIp: inputs['sourceIp'].value.trim() || '0.0.0.0',
        destIp: inputs['destIp'].value.trim() || '0.0.0.0',
        destPort: parseInt(inputs['destPort'].value, 10) || 0,
        protocol: protoSelect.value as 'tcp' | 'udp' | 'icmp',
      };

      resultArea.textContent = 'Tracing...';
      tracePacket(hostId, packet).then((result) => {
        resultArea.innerHTML = '';
        resultArea.appendChild(h('div', { className: 'terminal__tracer-verdict' },
          `Verdict: ${result.verdict}`));
        if (result.chain.length > 0) {
          const chainPath = result.chain.map(t => `${t.table}/${t.chain}`).join(' -> ');
          resultArea.appendChild(h('div', { className: 'terminal__tracer-chain' },
            `Chain path: ${chainPath}`));
        }
        resultArea.appendChild(h('div', { className: 'terminal__tracer-explanation' },
          result.explanation));
      }).catch((err) => {
        resultArea.textContent = `Trace failed: ${err instanceof Error ? err.message : 'Unknown error'}`;
      });
    });

    form.appendChild(traceBtn);
    container.appendChild(form);
    container.appendChild(resultArea);
  }

  private renderSshLogSubTab(container: HTMLElement): void {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    const hostState = hostId ? state.hostStates.get(hostId) : undefined;
    const sshLog = hostState?.sshCommandLog ?? [];

    const logContainer = h('div', { className: 'terminal__ssh-log' });

    if (sshLog.length === 0) {
      // Show demo entries for demo hosts
      const demoEntries = [
        { timestamp: Date.now() - 300000, command: 'iptables-save', output: '', exitCode: 0 },
        { timestamp: Date.now() - 240000, command: 'iptables -L -n --line-numbers', output: '', exitCode: 0 },
        { timestamp: Date.now() - 180000, command: 'cat /proc/sys/net/netfilter/nf_conntrack_count', output: '', exitCode: 0 },
      ];

      for (const entry of demoEntries) {
        const ts = new Date(entry.timestamp).toLocaleTimeString();
        const line = h('div', { className: 'terminal__ssh-log-entry' },
          h('span', { className: 'terminal__ssh-log-time' }, ts),
          h('span', { className: 'terminal__ssh-log-cmd' }, `$ ${entry.command}`),
        );
        logContainer.appendChild(line);
      }
    } else {
      for (const entry of sshLog) {
        const ts = new Date(entry.timestamp).toLocaleTimeString();
        const line = h('div', { className: 'terminal__ssh-log-entry' },
          h('span', { className: 'terminal__ssh-log-time' }, ts),
          h('span', { className: 'terminal__ssh-log-cmd' }, `$ ${entry.command}`),
        );
        logContainer.appendChild(line);
      }
    }

    container.appendChild(logContainer);
  }

  // ── Export Dropdown ─────────────────────────────────────────

  private showExportDropdown(anchorBtn: HTMLElement, hostId: string): void {
    // Remove existing dropdown if any
    const existing = document.querySelector('.rule-table__export-dropdown');
    if (existing) { existing.remove(); return; }

    const dropdown = h('div', { className: 'rule-table__export-dropdown' });
    const options: Array<{ label: string; format: 'shell' | 'ansible' | 'iptables-save' }> = [
      { label: 'Shell Script', format: 'shell' },
      { label: 'Ansible Playbook', format: 'ansible' },
      { label: 'iptables-save', format: 'iptables-save' },
    ];

    for (const opt of options) {
      const btn = h('button', {
        className: 'rule-table__export-option',
        type: 'button',
      }, opt.label);

      this.listen(btn, 'click', () => {
        dropdown.remove();
        exportRules(hostId, opt.format).then((result) => {
          const ext = opt.format === 'ansible' ? '.yml' : opt.format === 'shell' ? '.sh' : '.rules';
          const blob = new Blob([result], { type: 'text/plain' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `${hostId}${ext}`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        }).catch(() => {
          // Export error — silently fail
        });
      });
      dropdown.appendChild(btn);
    }

    anchorBtn.style.position = 'relative';
    anchorBtn.appendChild(dropdown);

    // Close on outside click
    const closeHandler = (e: Event) => {
      if (!dropdown.contains(e.target as Node) && e.target !== anchorBtn) {
        dropdown.remove();
        document.removeEventListener('click', closeHandler);
      }
    };
    requestAnimationFrame(() => {
      document.addEventListener('click', closeHandler);
    });
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

    // Show NAT section if NAT rules exist or host has IP forwarding capabilities
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
    // Show NAT section if host has multiple interfaces (implies routing/forwarding)
    const ifaces = host.capabilities.interfaces;
    return ifaces != null && ifaces.length >= 2;
  }

  private renderEmptyState(): void {
    this.sectionsContainer.innerHTML = '';
    this.conflictsBanner = null;

    // Check if the active host is unreachable
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
    this.conflictsBanner = null;
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

    // Apply a web-server template as default suggested rules
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
