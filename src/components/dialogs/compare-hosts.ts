/**
 * Compare Hosts dialog -- pick two connected hosts and view
 * a side-by-side diff of their iptables rules.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { Host } from '../../store/types';
import { compareHosts } from '../../ipc/bridge';
import type { CompareHostsResult } from '../../ipc/bridge';
import { h, trapFocus } from '../../utils/dom';

export class CompareHostsDialog extends Component {
  private overlay!: HTMLElement;
  private hostA: string | null = null;
  private hostB: string | null = null;
  private resultContainer!: HTMLElement;
  private compareBtn!: HTMLButtonElement;
  private isComparing = false;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
  }

  private getConnectedHosts(): Host[] {
    const state = this.store.getState();
    const hosts: Host[] = [];
    for (const host of state.hosts.values()) {
      if (host.status === 'connected') {
        hosts.push(host);
      }
    }
    return hosts;
  }

  private render(): void {
    this.overlay = h('div', { className: 'dialog-overlay' });
    const card = h('div', {
      className: 'dialog-card dialog-card--compare',
      role: 'dialog',
      'aria-modal': 'true',
      'aria-labelledby': 'compare-title',
    });

    // Header
    const header = h('div', { className: 'dialog-header' },
      h('span', { className: 'dialog-title', id: 'compare-title' }, 'Compare Hosts'),
      h('button', { className: 'dialog-close', 'aria-label': 'Close' }, '\u00D7'),
    );
    this.listen(header.querySelector('.dialog-close')!, 'click', () => this.close());
    card.appendChild(header);

    const body = h('div', { className: 'dialog-body' });

    const hosts = this.getConnectedHosts();

    if (hosts.length < 2) {
      body.appendChild(h('p', { className: 'dialog-help-text' },
        'At least two connected hosts are required to compare rules.'));
      const footer = h('div', { className: 'dialog-footer' });
      const closeBtn = h('button', {
        className: 'dialog-btn dialog-btn--secondary',
        type: 'button',
      }, 'Close') as HTMLButtonElement;
      this.listen(closeBtn, 'click', () => this.close());
      footer.appendChild(closeBtn);
      card.appendChild(body);
      card.appendChild(footer);
      this.overlay.appendChild(card);
      this.el.appendChild(this.overlay);
      trapFocus(card);
      return;
    }

    // Default selection
    this.hostA = hosts[0].id;
    this.hostB = hosts.length > 1 ? hosts[1].id : hosts[0].id;

    body.appendChild(h('p', { className: 'dialog-help-text' },
      'Select two connected hosts to compare their iptables rules.'));

    // Host selectors row
    const formRow = h('div', { className: 'compare-selector-row' });

    const groupA = h('div', { className: 'dialog-field' });
    groupA.appendChild(h('label', { className: 'dialog-label' }, 'Host A'));
    const selectA = document.createElement('select');
    selectA.className = 'dialog-input';
    for (const host of hosts) {
      const opt = document.createElement('option');
      opt.value = host.id;
      opt.textContent = host.name;
      if (host.id === this.hostA) opt.selected = true;
      selectA.appendChild(opt);
    }
    this.listen(selectA, 'change', () => { this.hostA = selectA.value; });
    groupA.appendChild(selectA);
    formRow.appendChild(groupA);

    formRow.appendChild(h('span', { className: 'compare-vs-label' }, 'vs'));

    const groupB = h('div', { className: 'dialog-field' });
    groupB.appendChild(h('label', { className: 'dialog-label' }, 'Host B'));
    const selectB = document.createElement('select');
    selectB.className = 'dialog-input';
    for (const host of hosts) {
      const opt = document.createElement('option');
      opt.value = host.id;
      opt.textContent = host.name;
      if (host.id === this.hostB) opt.selected = true;
      selectB.appendChild(opt);
    }
    this.listen(selectB, 'change', () => { this.hostB = selectB.value; });
    groupB.appendChild(selectB);
    formRow.appendChild(groupB);

    body.appendChild(formRow);

    // Result area
    this.resultContainer = h('div', { className: 'compare-results' });
    body.appendChild(this.resultContainer);

    card.appendChild(body);

    // Footer
    const footer = h('div', { className: 'dialog-footer' });
    const spacer = h('div', { className: 'dialog-footer-spacer' });
    footer.appendChild(spacer);

    this.compareBtn = h('button', {
      className: 'dialog-btn dialog-btn--primary',
      type: 'button',
    }, 'Compare') as HTMLButtonElement;
    this.listen(this.compareBtn, 'click', () => this.runCompare());
    footer.appendChild(this.compareBtn);

    const cancelBtn = h('button', {
      className: 'dialog-btn dialog-btn--secondary',
      type: 'button',
    }, 'Close') as HTMLButtonElement;
    this.listen(cancelBtn, 'click', () => this.close());
    footer.appendChild(cancelBtn);

    card.appendChild(footer);
    this.overlay.appendChild(card);
    this.el.appendChild(this.overlay);

    // Close on overlay click
    this.listen(this.overlay, 'click', (e) => {
      if (e.target === this.overlay) this.close();
    });

    trapFocus(card);
  }

  private async runCompare(): Promise<void> {
    if (!this.hostA || !this.hostB || this.isComparing) return;
    if (this.hostA === this.hostB) {
      this.resultContainer.innerHTML = '';
      this.resultContainer.appendChild(
        h('p', { className: 'compare-note' }, 'Please select two different hosts.'),
      );
      return;
    }

    this.isComparing = true;
    this.compareBtn.disabled = true;
    this.compareBtn.textContent = 'Comparing...';
    this.resultContainer.innerHTML = '';
    this.resultContainer.appendChild(
      h('p', { className: 'compare-loading' }, 'Fetching and comparing rules...'),
    );

    try {
      const result = await compareHosts(this.hostA, this.hostB);
      this.renderResult(result);
    } catch (err) {
      this.resultContainer.innerHTML = '';
      const msg = err instanceof Error ? err.message : String(err);
      this.resultContainer.appendChild(
        h('p', { className: 'compare-error' }, `Comparison failed: ${msg}`),
      );
    } finally {
      this.isComparing = false;
      this.compareBtn.disabled = false;
      this.compareBtn.textContent = 'Compare';
    }
  }

  private renderResult(result: CompareHostsResult): void {
    const state = this.store.getState();
    const nameA = state.hosts.get(this.hostA!)?.name ?? this.hostA!;
    const nameB = state.hosts.get(this.hostB!)?.name ?? this.hostB!;

    this.resultContainer.innerHTML = '';

    // Summary stats
    const summary = h('div', { className: 'compare-summary' });
    summary.appendChild(h('span', { className: 'compare-stat compare-stat--identical' },
      `${result.identical} identical`));
    summary.appendChild(h('span', { className: 'compare-stat compare-stat--only-a' },
      `${result.onlyInA.length} only in ${nameA}`));
    summary.appendChild(h('span', { className: 'compare-stat compare-stat--only-b' },
      `${result.onlyInB.length} only in ${nameB}`));
    summary.appendChild(h('span', { className: 'compare-stat compare-stat--different' },
      `${result.different.length} different`));
    this.resultContainer.appendChild(summary);

    // Detail sections
    if (result.onlyInA.length > 0) {
      this.resultContainer.appendChild(
        this.renderSection(`Only in ${nameA}`, result.onlyInA, 'compare-item--only-a'),
      );
    }
    if (result.onlyInB.length > 0) {
      this.resultContainer.appendChild(
        this.renderSection(`Only in ${nameB}`, result.onlyInB, 'compare-item--only-b'),
      );
    }
    if (result.different.length > 0) {
      this.resultContainer.appendChild(
        this.renderSection('Different', result.different, 'compare-item--different'),
      );
    }

    if (result.onlyInA.length === 0 && result.onlyInB.length === 0 && result.different.length === 0) {
      this.resultContainer.appendChild(
        h('p', { className: 'compare-note' }, 'Both hosts have identical rule sets.'),
      );
    }
  }

  private renderSection(title: string, items: string[], itemClass: string): HTMLElement {
    const section = h('div', { className: 'compare-section' });
    section.appendChild(h('h3', { className: 'compare-section-title' }, title));
    const list = h('ul', { className: 'compare-list' });
    for (const item of items) {
      list.appendChild(h('li', { className: `compare-item ${itemClass}` }, item));
    }
    section.appendChild(list);
    return section;
  }

  private close(): void {
    this.store.dispatch({ type: 'CLOSE_DIALOG' });
  }
}
