/**
 * Blocked traffic log — real-time entries with Block IP button per unique IP.
 *
 * Features:
 * - Individual entry view with per-IP block buttons
 * - Aggregated view when 20+ entries (grouped by dest port)
 * - Repeated offender alerts when a single IP appears 5+ times
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, BlockedEntry } from '../../store/types';
import { h } from '../../utils/dom';
import { formatTimeAgo } from '../../utils/format';

interface PortAggregation {
  destPort: number;
  serviceName: string;
  count: number;
  uniqueIps: Set<string>;
}

interface RepeatedOffender {
  sourceIp: string;
  count: number;
}

export class BlockedLog extends Component {
  private container: HTMLElement;
  private seenIps = new Set<string>();
  private showAggregated = true;
  private dismissedOffenders = new Set<string>();

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.container = container;
    this.container.className = 'blocked-log';
    this.bindSubscriptions();
  }

  private bindSubscriptions(): void {
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hostStates.get(hostId)?.blockedLog ?? null;
      },
      () => this.renderEntries(),
    );

    this.renderEntries();
  }

  private getEntries(): BlockedEntry[] {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return [];

    const hostState = state.hostStates.get(hostId);
    if (!hostState) return [];

    // Return latest entries sorted by timestamp desc
    return [...hostState.blockedLog]
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 50);
  }

  private getRepeatedOffenders(entries: BlockedEntry[]): RepeatedOffender[] {
    const ipCounts = new Map<string, number>();
    for (const entry of entries) {
      ipCounts.set(entry.sourceIp, (ipCounts.get(entry.sourceIp) ?? 0) + 1);
    }

    const offenders: RepeatedOffender[] = [];
    for (const [sourceIp, count] of ipCounts) {
      if (count >= 5 && !this.dismissedOffenders.has(sourceIp)) {
        offenders.push({ sourceIp, count });
      }
    }

    // Sort by count descending
    offenders.sort((a, b) => b.count - a.count);
    return offenders;
  }

  private getAggregatedByPort(entries: BlockedEntry[]): PortAggregation[] {
    const portMap = new Map<number, PortAggregation>();

    for (const entry of entries) {
      let agg = portMap.get(entry.destPort);
      if (!agg) {
        agg = {
          destPort: entry.destPort,
          serviceName: entry.serviceName ?? '',
          count: 0,
          uniqueIps: new Set(),
        };
        portMap.set(entry.destPort, agg);
      }
      agg.count++;
      agg.uniqueIps.add(entry.sourceIp);
      // Prefer a non-empty service name
      if (entry.serviceName && !agg.serviceName) {
        agg.serviceName = entry.serviceName;
      }
    }

    return Array.from(portMap.values()).sort((a, b) => b.count - a.count);
  }

  private renderEntries(): void {
    const entries = this.getEntries();
    this.container.innerHTML = '';
    this.seenIps.clear();

    if (entries.length === 0) {
      this.container.appendChild(
        h('div', { className: 'blocked-log__empty' },
          h('p', {}, 'No blocked traffic recorded.'),
          h('p', { className: 'blocked-log__hint' },
            'Detailed blocking log requires LOG rules on block rules.',
          ),
        ),
      );
      return;
    }

    // Render repeated offender alerts
    const offenders = this.getRepeatedOffenders(entries);
    for (const offender of offenders) {
      this.renderOffenderAlert(offender);
    }

    // Decide whether to show aggregated or individual view
    if (entries.length > 20) {
      this.renderAggregationToggle(entries);
    } else {
      // Less than 20 entries — always show individual view
      this.renderIndividualEntries(entries);
    }
  }

  private renderOffenderAlert(offender: RepeatedOffender): void {
    const alertEl = h('div', { className: 'blocked-log__offender-alert' });

    const textEl = h('span', { className: 'blocked-log__offender-text' },
      `\u26A0\uFE0F ${offender.sourceIp} has been blocked ${offender.count} times.`);
    alertEl.appendChild(textEl);

    const actions = h('div', { className: 'blocked-log__offender-actions' });

    const blockBtn = h('button', {
      className: 'blocked-log__offender-btn blocked-log__offender-btn--primary',
      type: 'button',
    }, 'Block this IP permanently');
    this.listen(blockBtn, 'click', () => {
      this.handleBlockIp(offender.sourceIp);
      this.dismissedOffenders.add(offender.sourceIp);
      alertEl.remove();
    });
    actions.appendChild(blockBtn);

    const dismissBtn = h('button', {
      className: 'blocked-log__offender-btn blocked-log__offender-btn--secondary',
      type: 'button',
    }, 'Dismiss');
    this.listen(dismissBtn, 'click', () => {
      this.dismissedOffenders.add(offender.sourceIp);
      alertEl.remove();
    });
    actions.appendChild(dismissBtn);

    alertEl.appendChild(actions);
    this.container.appendChild(alertEl);
  }

  private renderAggregationToggle(entries: BlockedEntry[]): void {
    if (this.showAggregated) {
      this.renderAggregatedView(entries);

      const toggleBtn = h('button', {
        className: 'blocked-log__toggle-btn',
        type: 'button',
      }, 'Show individual entries');
      this.listen(toggleBtn, 'click', () => {
        this.showAggregated = false;
        this.renderEntries();
      });
      this.container.appendChild(toggleBtn);
    } else {
      const toggleBtn = h('button', {
        className: 'blocked-log__toggle-btn',
        type: 'button',
      }, 'Show aggregated view');
      this.listen(toggleBtn, 'click', () => {
        this.showAggregated = true;
        this.renderEntries();
      });
      this.container.appendChild(toggleBtn);

      this.renderIndividualEntries(entries);
    }
  }

  private renderAggregatedView(entries: BlockedEntry[]): void {
    const aggregated = this.getAggregatedByPort(entries);

    const header = h('div', { className: 'blocked-log__agg-header' }, 'Top blocked ports:');
    this.container.appendChild(header);

    for (const agg of aggregated) {
      const serviceLabel = agg.serviceName ? ` (${agg.serviceName})` : '';
      const ipLabel = agg.uniqueIps.size === 1 ? '1 IP' : `${agg.uniqueIps.size} IPs`;
      const attemptLabel = agg.count === 1 ? '1 attempt' : `${agg.count} attempts`;

      const row = h('div', { className: 'blocked-log__agg-row' });
      row.appendChild(h('span', { className: 'blocked-log__agg-port' },
        `:${agg.destPort}${serviceLabel}`));
      row.appendChild(h('span', { className: 'blocked-log__agg-stats' },
        ` \u2014 ${attemptLabel}, ${ipLabel}`));
      this.container.appendChild(row);
    }
  }

  private renderIndividualEntries(entries: BlockedEntry[]): void {
    for (const entry of entries) {
      const rowEl = h('div', { className: 'blocked-log__row' });

      // Indicator
      rowEl.appendChild(h('span', { className: 'blocked-log__indicator' }));

      // Timestamp
      rowEl.appendChild(h('span', { className: 'blocked-log__time' }, formatTimeAgo(entry.timestamp)));

      // Source IP (monospace)
      rowEl.appendChild(h('span', { className: 'blocked-log__ip' }, entry.sourceIp));

      // Arrow + port
      rowEl.appendChild(h('span', { className: 'blocked-log__arrow' }, '\u2192'));
      rowEl.appendChild(h('span', { className: 'blocked-log__port' }, `:${entry.destPort}`));

      // Service name
      if (entry.serviceName) {
        rowEl.appendChild(h('span', { className: 'blocked-log__service' }, entry.serviceName));
      }

      // Block IP button — only on first occurrence of each unique IP
      if (!this.seenIps.has(entry.sourceIp)) {
        this.seenIps.add(entry.sourceIp);
        const blockBtn = h('button', {
          className: 'blocked-log__block-btn',
          dataset: { ip: entry.sourceIp },
        }, 'Block IP');

        this.listen(blockBtn, 'click', () => {
          this.handleBlockIp(entry.sourceIp);
        });
        rowEl.appendChild(blockBtn);
      }

      this.container.appendChild(rowEl);
    }
  }

  private handleBlockIp(ip: string): void {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return;

    const now = Date.now();
    this.store.dispatch({
      type: 'ADD_STAGED_CHANGE',
      hostId,
      change: {
        type: 'add',
        rule: {
          id: crypto.randomUUID(),
          label: `Block ${ip}`,
          action: 'block',
          source: { type: 'cidr', value: `${ip}/32` },
          destination: { type: 'anyone' },
          direction: 'incoming',
          addressFamily: ip.includes(':') ? 'v6' : 'v4',
          origin: { type: 'user' },
          position: 0,
          enabled: true,
          comment: 'Blocked from activity log',
          createdAt: now,
          updatedAt: now,
        },
        position: 0,
      },
    });
  }
}
