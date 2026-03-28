/**
 * Dual-stack comparison view — side-by-side display of IPv4 and IPv6 rules.
 *
 * Shows two columns comparing v4 and v6 iptables rules, highlighting
 * differences (rules present in one but not the other).
 *
 * Accessible from a "Compare v4/v6" button in the toolbar when
 * dual-stack mode is enabled on the active host.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import { selectActiveHost } from '../../store/selectors';
import { h } from '../../utils/dom';
import { checkDualStackDivergence, type DualStackDivergence } from '../../ipc/bridge';

export class DualStackCompare extends Component {
  private contentEl: HTMLElement;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);

    this.contentEl = h('div', { className: 'dual-stack-compare' });
    this.el.appendChild(this.contentEl);

    this.renderLoading();
    this.fetchAndRender();
  }

  private renderLoading(): void {
    this.contentEl.innerHTML = '';

    const header = h('div', { className: 'dual-stack-compare__header' },
      h('span', { className: 'dual-stack-compare__title' }, 'IPv4 / IPv6 Comparison'),
    );

    this.contentEl.appendChild(header);
    this.contentEl.appendChild(h('div', { className: 'dual-stack-compare__empty' }, 'Loading...'));
  }

  private async fetchAndRender(): Promise<void> {
    const host = this.store.select(selectActiveHost);
    if (!host) {
      this.renderError('No host selected.');
      return;
    }

    try {
      const divergence = await checkDualStackDivergence(host.id);
      this.renderComparison(divergence);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.renderError(`Failed to fetch divergence data: ${message}`);
    }
  }

  private renderError(message: string): void {
    this.contentEl.innerHTML = '';

    const header = h('div', { className: 'dual-stack-compare__header' },
      h('span', { className: 'dual-stack-compare__title' }, 'IPv4 / IPv6 Comparison'),
    );

    this.contentEl.appendChild(header);
    this.contentEl.appendChild(h('div', { className: 'dual-stack-compare__empty' }, message));
  }

  private renderComparison(data: DualStackDivergence): void {
    this.contentEl.innerHTML = '';

    // Header
    const header = h('div', { className: 'dual-stack-compare__header' },
      h('span', { className: 'dual-stack-compare__title' }, 'IPv4 / IPv6 Comparison'),
    );
    this.contentEl.appendChild(header);

    // Summary bar
    const summaryClass = data.diverged
      ? 'dual-stack-compare__summary dual-stack-compare__summary--diverged'
      : 'dual-stack-compare__summary';

    const summary = h('div', { className: summaryClass });

    summary.appendChild(h('span', { className: 'dual-stack-compare__summary-item' },
      'Status: ',
      h('span', { className: 'dual-stack-compare__summary-value' },
        data.diverged ? 'Diverged' : 'In sync'),
    ));

    summary.appendChild(h('span', { className: 'dual-stack-compare__summary-item' },
      'v4 rules: ',
      h('span', { className: 'dual-stack-compare__summary-value' }, String(data.ruleCountV4)),
    ));

    summary.appendChild(h('span', { className: 'dual-stack-compare__summary-item' },
      'v6 rules: ',
      h('span', { className: 'dual-stack-compare__summary-value' }, String(data.ruleCountV6)),
    ));

    this.contentEl.appendChild(summary);

    // Two-column grid
    const grid = h('div', { className: 'dual-stack-compare__grid' });

    // IPv4 column
    const v4Column = h('div', { className: 'dual-stack-compare__column' });
    v4Column.appendChild(h('div', { className: 'dual-stack-compare__column-header' },
      `IPv4 Rules (${data.ruleCountV4})`));

    if (data.v4OnlyChains.length > 0) {
      for (const chain of data.v4OnlyChains) {
        const ruleEl = h('div', {
          className: 'dual-stack-compare__rule dual-stack-compare__rule--only-here',
        }, `[v4-only] ${chain}`);
        v4Column.appendChild(ruleEl);
      }
    }

    if (data.ruleCountV4 === 0 && data.v4OnlyChains.length === 0) {
      v4Column.appendChild(h('div', { className: 'dual-stack-compare__empty' }, 'No IPv4 rules'));
    }

    // Mark v6-only chains as missing in v4
    if (data.v6OnlyChains.length > 0) {
      for (const chain of data.v6OnlyChains) {
        const ruleEl = h('div', {
          className: 'dual-stack-compare__rule dual-stack-compare__rule--missing',
        }, `[missing] ${chain} (v6-only)`);
        v4Column.appendChild(ruleEl);
      }
    }

    grid.appendChild(v4Column);

    // IPv6 column
    const v6Column = h('div', { className: 'dual-stack-compare__column' });
    v6Column.appendChild(h('div', { className: 'dual-stack-compare__column-header' },
      `IPv6 Rules (${data.ruleCountV6})`));

    if (data.v6OnlyChains.length > 0) {
      for (const chain of data.v6OnlyChains) {
        const ruleEl = h('div', {
          className: 'dual-stack-compare__rule dual-stack-compare__rule--only-here',
        }, `[v6-only] ${chain}`);
        v6Column.appendChild(ruleEl);
      }
    }

    if (data.ruleCountV6 === 0 && data.v6OnlyChains.length === 0) {
      v6Column.appendChild(h('div', { className: 'dual-stack-compare__empty' }, 'No IPv6 rules'));
    }

    // Mark v4-only chains as missing in v6
    if (data.v4OnlyChains.length > 0) {
      for (const chain of data.v4OnlyChains) {
        const ruleEl = h('div', {
          className: 'dual-stack-compare__rule dual-stack-compare__rule--missing',
        }, `[missing] ${chain} (v4-only)`);
        v6Column.appendChild(ruleEl);
      }
    }

    grid.appendChild(v6Column);

    this.contentEl.appendChild(grid);
  }
}
