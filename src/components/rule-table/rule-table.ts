/**
 * Rule table component — the primary rules interface.
 *
 * Subscribes to: selectEffectiveRules, selectFilteredRules, ruleFilter, activeTab.
 * Shows rules organized by direction (Incoming / Outgoing / NAT) with
 * collapsible sections grouped by origin.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, EffectiveRule, HitCounter, Host } from '../../store/types';
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
import { disconnectHost, connectHost, fetchRules } from '../../ipc/bridge';
import { convertRuleSet } from '../../services/rule-converter';

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

  // Tab content panels
  private activityPanel: HTMLElement | null = null;
  private terminalPanel: HTMLElement | null = null;
  private activityComponent: Activity | null = null;

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
      style: { display: 'none' },
    });
    this.el.appendChild(this.activityPanel);

    // Terminal tab panel (hidden by default)
    this.terminalPanel = h('div', {
      className: 'rule-table__sections',
      id: 'tabpanel-terminal',
      role: 'tabpanel',
      'aria-labelledby': 'tab-terminal',
      style: { display: 'none' },
    });
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
          this.headerEl.innerHTML = '';
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
            const natActions = h('div', { className: 'rule-table__nat-actions', style: { padding: '8px 16px' } });
            const portFwdLink = h('button', {
              className: 'rule-table__nat-link',
              type: 'button',
              style: { background: 'none', border: 'none', color: 'var(--color-accent, #58a6ff)', cursor: 'pointer', fontSize: '13px', padding: '4px 0', display: 'block' },
            }, '+ Port Forwarding');
            const snatLink = h('button', {
              className: 'rule-table__nat-link',
              type: 'button',
              style: { background: 'none', border: 'none', color: 'var(--color-accent, #58a6ff)', cursor: 'pointer', fontSize: '13px', padding: '4px 0', display: 'block' },
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
              style: { margin: '8px 0 0', fontSize: '12px', color: 'var(--color-text-secondary, #888)' },
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
              }
              // Set hit count
              this.updateRowHitCount(rowEl, rule.id, hitCounters);
              return rowEl;
            },
            (el, rule) => {
              updateRuleRow(el, rule, pendingRuleIds.has(rule.id), ipListNames);
              el.classList.toggle('rule-table__row--default-policy', rule.section === 'default-policy');
              // Update hit count
              this.updateRowHitCount(el, rule.id, hitCounters);
            },
          );
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
    }
  }

  private formatHitCount(count: number): string {
    if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M`;
    if (count >= 1_000) return `${(count / 1_000).toFixed(1)}k`;
    return String(count);
  }

  private switchTabContent(tab: AppState['activeTab']): void {
    // Show/hide panels
    this.sectionsContainer.style.display = tab === 'rules' ? '' : 'none';
    this.filterBarContainer.style.display = tab === 'rules' ? '' : 'none';
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

    // Terminal tab — render placeholder with sub-tab buttons
    if (tab === 'terminal' && this.terminalPanel && this.terminalPanel.children.length === 0) {
      const placeholder = h('div', { className: 'rule-table__terminal-placeholder' });

      const subTabs = h('div', {
        className: 'rule-table__terminal-sub-tabs',
        style: { display: 'flex', gap: '8px', padding: '16px 24px 0' },
      });

      const rawBtn = h('button', {
        className: 'rule-table__terminal-sub-tab',
        type: 'button',
        disabled: true,
        style: { opacity: '0.5', cursor: 'not-allowed', padding: '6px 16px', borderRadius: '4px', border: '1px solid var(--color-border, #333)', background: 'var(--color-bg-secondary, #1a1a1a)', color: 'var(--color-text-secondary, #888)' },
      }, 'Raw Rules');

      const tracerBtn = h('button', {
        className: 'rule-table__terminal-sub-tab',
        type: 'button',
        disabled: true,
        style: { opacity: '0.5', cursor: 'not-allowed', padding: '6px 16px', borderRadius: '4px', border: '1px solid var(--color-border, #333)', background: 'var(--color-bg-secondary, #1a1a1a)', color: 'var(--color-text-secondary, #888)' },
      }, 'Packet Tracer');

      subTabs.appendChild(rawBtn);
      subTabs.appendChild(tracerBtn);
      placeholder.appendChild(subTabs);

      const message = h('div', {
        className: 'rule-table__terminal-message',
        style: { padding: '48px 24px', textAlign: 'center', color: 'var(--color-text-secondary, #888)' },
      });
      message.appendChild(h('p', {
        style: { fontSize: '14px', margin: '0' },
      }, 'Terminal is available when connected to a real server. In this demo, explore the Rules and Activity tabs to learn about firewall management.'));
      placeholder.appendChild(message);

      this.terminalPanel.appendChild(placeholder);
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
      style: { marginLeft: 'auto', display: 'flex', gap: '6px', alignItems: 'center' },
    });

    if (host.status === 'connected') {
      // Disconnect button
      const disconnectBtn = h('button', {
        className: 'rule-table__disconnect-btn',
        type: 'button',
        title: 'Disconnect from host',
        style: { padding: '4px 10px', fontSize: '12px', cursor: 'pointer', borderRadius: '4px', border: '1px solid var(--color-border, #333)', background: 'transparent', color: 'var(--color-block, #f85149)' },
      }, 'Disconnect');
      this.listen(disconnectBtn, 'click', () => this.handleDisconnect(host.id));
      headerBtns.appendChild(disconnectBtn);
    } else if (host.status === 'disconnected' || host.status === 'unreachable') {
      // Reconnect button
      const reconnectBtn = h('button', {
        className: 'rule-table__reconnect-btn',
        type: 'button',
        title: 'Reconnect to host',
        style: { padding: '4px 10px', fontSize: '12px', cursor: 'pointer', borderRadius: '4px', border: 'none', background: 'var(--color-primary, #007AFF)', color: '#fff' },
      }, 'Reconnect');
      this.listen(reconnectBtn, 'click', () => this.handleReconnect(host));
      headerBtns.appendChild(reconnectBtn);
    }

    // History button (always shown)
    const historyBtn = h('button', {
      className: 'rule-table__history-btn',
      type: 'button',
      title: 'Snapshot History',
      style: { padding: '4px 10px', fontSize: '12px', cursor: 'pointer', borderRadius: '4px', border: '1px solid var(--color-border, #333)', background: 'transparent', color: 'var(--color-text-secondary, #888)' },
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
    connectHost(host.id, host.connection.hostname, host.connection.port, host.connection.username, host.connection.authMethod, host.connection.keyPath)
      .then(() => {
        this.store.dispatch({ type: 'SET_HOST_STATUS', hostId: host.id, status: 'connected' });
        return fetchRules(host.id);
      })
      .then((ruleData) => {
        const rules = convertRuleSet(ruleData);
        this.store.dispatch({ type: 'SET_HOST_RULES', hostId: host.id, rules });
      })
      .catch(() => {
        this.store.dispatch({ type: 'SET_HOST_STATUS', hostId: host.id, status: 'unreachable' });
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
