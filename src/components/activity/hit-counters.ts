/**
 * Hit counter rows — displays rule hit counts sorted by count descending.
 *
 * Each row: status bar | rule name | hits (weight 600) | sparkline | rate | last hit.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, HitCounter, EffectiveRule } from '../../store/types';
import { selectEffectiveRules } from '../../store/selectors';
import { h } from '../../utils/dom';
import { formatCount, formatTimeAgo } from '../../utils/format';
import { Sparkline } from './sparkline';

interface HitRow {
  ruleId: string;
  label: string;
  action: string;
  packets: number;
  rate: number;
  lastHit: number;
}

export class HitCounters extends Component {
  private container!: HTMLElement;
  private sparklines: Map<string, Sparkline> = new Map();

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.container = container;
    this.container.className = 'hit-counters';

    // Delegated click handler for row clicks
    this.listen(this.container, 'click', (e) => {
      const row = (e.target as HTMLElement).closest('.hit-counters__row') as HTMLElement | null;
      if (!row) return;
      const ruleId = row.dataset.ruleId;
      if (ruleId) {
        this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: true });
        this.store.dispatch({ type: 'SET_SIDE_PANEL_CONTENT', content: { type: 'rule-detail', ruleId } });
      }
    });

    this.bindSubscriptions();
  }

  private bindSubscriptions(): void {
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hostStates.get(hostId)?.hitCounters ?? null;
      },
      () => this.renderRows(),
    );

    this.subscribe(
      selectEffectiveRules as (s: AppState) => EffectiveRule[] | null,
      () => this.renderRows(),
    );

    this.renderRows();
  }

  private getHitRows(): HitRow[] {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return [];

    const hostState = state.hostStates.get(hostId);
    if (!hostState) return [];

    const rules = this.store.select(selectEffectiveRules as (s: AppState) => EffectiveRule[] | null);
    if (!rules) return [];

    const counters = hostState.hitCounters;
    const prevCounters = hostState.prevHitCounters;
    const pollInterval = state.settings.pollIntervalMs / 1000;

    const rows: HitRow[] = [];

    for (const rule of rules) {
      const counter = counters.get(rule.id);
      const prevCounter = prevCounters.get(rule.id);
      const packets = counter?.packets ?? 0;
      const prevPackets = prevCounter?.packets ?? 0;
      const rate = pollInterval > 0 ? Math.max(0, (packets - prevPackets) / pollInterval) : 0;

      rows.push({
        ruleId: rule.id,
        label: rule.label,
        action: rule.action,
        packets,
        rate,
        lastHit: counter?.timestamp ?? 0,
      });
    }

    // Sort by hit count descending
    rows.sort((a, b) => b.packets - a.packets);

    return rows;
  }

  private renderRows(): void {
    const rows = this.getHitRows();
    this.container.innerHTML = '';

    // Cleanup old sparklines
    for (const sparkline of this.sparklines.values()) {
      sparkline.destroy();
    }
    this.sparklines.clear();

    if (rows.length === 0) {
      this.container.appendChild(
        h('div', { className: 'hit-counters__empty' }, 'No hit counter data available.'),
      );
      return;
    }

    // Header row
    this.container.appendChild(
      h('div', { className: 'hit-counters__header' },
        h('span', { className: 'hit-counters__col hit-counters__col--rule' }, 'Rule'),
        h('span', { className: 'hit-counters__col hit-counters__col--hits' }, 'Hits'),
        h('span', { className: 'hit-counters__col hit-counters__col--sparkline' }),
        h('span', { className: 'hit-counters__col hit-counters__col--rate' }, 'Rate'),
        h('span', { className: 'hit-counters__col hit-counters__col--last' }, 'Last Hit'),
      ),
    );

    for (const row of rows) {
      const statusColor = this.getActionColor(row.action);
      const rowEl = h('div', { className: 'hit-counters__row', dataset: { ruleId: row.ruleId } });

      // Status bar
      const statusBar = h('div', { className: 'hit-counters__status-bar' });
      statusBar.style.backgroundColor = statusColor;
      rowEl.appendChild(statusBar);

      // Rule name
      rowEl.appendChild(h('span', { className: 'hit-counters__col hit-counters__col--rule' }, row.label));

      // Hits (primary data)
      rowEl.appendChild(h('span', { className: 'hit-counters__col hit-counters__col--hits' },
        formatCount(row.packets),
      ));

      // Sparkline
      const sparkContainer = h('span', { className: 'hit-counters__col hit-counters__col--sparkline' });
      if (row.rate > 0) {
        const resolvedColor = this.resolveColor(statusColor);
        const sparkline = new Sparkline(sparkContainer, resolvedColor);
        sparkline.setData([row.packets]);
        this.sparklines.set(row.ruleId, sparkline);
      }
      rowEl.appendChild(sparkContainer);

      // Rate
      const rateText = row.rate > 0 ? `~${Math.round(row.rate)}/s` : '';
      rowEl.appendChild(h('span', { className: 'hit-counters__col hit-counters__col--rate' }, rateText));

      // Last hit
      const lastText = row.lastHit > 0 ? formatTimeAgo(row.lastHit) : '';
      rowEl.appendChild(h('span', { className: 'hit-counters__col hit-counters__col--last' }, lastText));

      this.container.appendChild(rowEl);
    }
  }

  private getActionColor(action: string): string {
    switch (action) {
      case 'allow': return 'var(--color-allow, #34C759)';
      case 'block': case 'block-reject': return 'var(--color-block, #FF3B30)';
      case 'log': case 'log-block': return 'var(--color-log, #5856D6)';
      default: return 'var(--color-info, #007AFF)';
    }
  }

  /**
   * Resolve a CSS variable string like "var(--color-allow, #34C759)" to a hex color
   * for use in canvas context which cannot resolve CSS variables.
   */
  private resolveColor(cssValue: string): string {
    const match = cssValue.match(/var\([^,]+,\s*(#[0-9A-Fa-f]{3,8})\)/);
    if (match) {
      return match[1];
    }
    return cssValue;
  }

  override destroy(): void {
    for (const sparkline of this.sparklines.values()) {
      sparkline.destroy();
    }
    this.sparklines.clear();
    super.destroy();
  }
}
