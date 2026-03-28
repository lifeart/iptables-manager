/**
 * Ipset suggestion card sub-component.
 *
 * Shows when ipset optimization opportunities are detected for the
 * current host's ruleset. Provides a one-click "Create ipset" action.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';
import type { IpsetSuggestion } from '../../bindings';

interface SuggestionCache {
  hostId: string;
  suggestions: IpsetSuggestion[];
  timestamp: number;
}

const CACHE_TTL_MS = 120_000; // 2 minutes

export class IpsetSuggestionCard extends Component {
  private cardEl: HTMLElement | null = null;
  private cache: SuggestionCache | null = null;
  private converting = false;

  constructor(
    container: HTMLElement,
    store: Store,
    private insertTarget: HTMLElement,
  ) {
    super(container, store);
    this.bindSubscriptions();
  }

  private bindSubscriptions(): void {
    // Re-check when rules change for the active host
    this.subscribe(
      (s: AppState) => {
        const hostId = s.activeHostId;
        if (!hostId) return null;
        return s.hostStates.get(hostId)?.rules ?? null;
      },
      (rules) => {
        const hostId = this.store.getState().activeHostId;
        if (hostId && rules && rules.length > 0) {
          this.fetchSuggestions(hostId);
        } else {
          this.clearCard();
        }
      },
    );
  }

  private async fetchSuggestions(hostId: string): Promise<void> {
    const now = Date.now();

    // Use cache if fresh
    if (
      this.cache &&
      this.cache.hostId === hostId &&
      now - this.cache.timestamp < CACHE_TTL_MS
    ) {
      this.renderSuggestions(this.cache.suggestions);
      return;
    }

    try {
      const { analyzeIpsetOpportunities } = await import('../../ipc/bridge');
      const suggestions = await analyzeIpsetOpportunities(hostId);

      this.cache = { hostId, suggestions, timestamp: Date.now() };
      this.renderSuggestions(suggestions);
    } catch (err) {
      console.warn('Ipset analysis failed:', err);
    }
  }

  private renderSuggestions(suggestions: IpsetSuggestion[]): void {
    if (suggestions.length === 0) {
      this.clearCard();
      return;
    }

    if (!this.cardEl) {
      this.cardEl = h('div', { className: 'ipset-suggestion-card' });
      this.insertTarget.insertBefore(
        this.cardEl,
        this.insertTarget.firstChild,
      );
    }

    clearChildren(this.cardEl);

    for (const suggestion of suggestions) {
      const item = this.createSuggestionItem(suggestion);
      this.cardEl.appendChild(item);
    }
  }

  private createSuggestionItem(suggestion: IpsetSuggestion): HTMLElement {
    const item = h('div', { className: 'ipset-suggestion-card__item' });

    // Icon
    const icon = h('span', { className: 'ipset-suggestion-card__icon' }, '\u26A1');

    // Text
    const text = h(
      'span',
      { className: 'ipset-suggestion-card__text' },
      `Performance opportunity: ${suggestion.ruleCount} rules in ${suggestion.chain} can be compiled into an ipset for O(1) lookups.`,
    );

    // Sample IPs preview
    const preview = h(
      'span',
      { className: 'ipset-suggestion-card__preview' },
      `Sample: ${suggestion.sampleIps.join(', ')}${suggestion.ruleCount > 5 ? '...' : ''}`,
    );

    // Action button
    const btn = document.createElement('button');
    btn.className = 'ipset-suggestion-card__btn';
    btn.type = 'button';
    btn.textContent = 'Create ipset';
    btn.setAttribute('aria-label', `Create ipset ${suggestion.suggestedName}`);
    this.listen(btn, 'click', () => this.handleConvert(suggestion, btn));

    const content = h('div', { className: 'ipset-suggestion-card__content' });
    content.appendChild(text);
    content.appendChild(preview);

    item.appendChild(icon);
    item.appendChild(content);
    item.appendChild(btn);

    return item;
  }

  private async handleConvert(
    suggestion: IpsetSuggestion,
    btn: HTMLButtonElement,
  ): Promise<void> {
    if (this.converting) return;

    const hostId = this.store.getState().activeHostId;
    if (!hostId) return;

    this.converting = true;
    btn.disabled = true;
    btn.textContent = 'Creating...';

    try {
      const { convertToIpset } = await import('../../ipc/bridge');
      const result = await convertToIpset(hostId, JSON.stringify(suggestion));

      btn.textContent = `Created ${result.ipsetName} (${result.entriesAdded} entries)`;
      btn.classList.add('ipset-suggestion-card__btn--success');

      // Invalidate cache so the suggestion disappears on next check
      this.cache = null;
    } catch (err) {
      btn.textContent = 'Failed';
      btn.classList.add('ipset-suggestion-card__btn--error');
      console.error('Ipset conversion failed:', err);

      // Reset after 3s
      setTimeout(() => {
        btn.textContent = 'Create ipset';
        btn.disabled = false;
        btn.classList.remove('ipset-suggestion-card__btn--error');
      }, 3000);
    } finally {
      this.converting = false;
    }
  }

  clearCard(): void {
    if (this.cardEl) {
      this.cardEl.remove();
      this.cardEl = null;
    }
  }
}
