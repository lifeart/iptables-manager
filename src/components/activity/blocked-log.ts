/**
 * Blocked traffic log — real-time entries with Block IP button per unique IP.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, BlockedEntry } from '../../store/types';
import { h } from '../../utils/dom';
import { formatTimeAgo } from '../../utils/format';

export class BlockedLog extends Component {
  private container: HTMLElement;
  private seenIps = new Set<string>();

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
          addressFamily: 'v4',
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
