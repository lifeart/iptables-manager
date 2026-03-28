/**
 * Import banner sub-component.
 *
 * Displays a banner offering to import existing iptables rules
 * that are not managed by Traffic Rules.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, Rule } from '../../store/types';
import { h } from '../../utils/dom';
import { importExistingRules } from '../../ipc/bridge';
import { convertRuleSet } from '../../services/rule-converter';

export class ImportBanner extends Component {
  private importBanner: HTMLElement | null = null;
  private importDismissed = new Set<string>();

  constructor(
    container: HTMLElement,
    store: Store,
    private insertTarget: HTMLElement,
  ) {
    super(container, store);
    this.bindSubscriptions();
  }

  private bindSubscriptions(): void {
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
      (r) =>
        r.origin?.type === 'imported' || r.origin?.type === 'system',
    ).length;

    if (importedCount > 0 && !this.importBanner) {
      this.importBanner = h('div', {
        className: 'rule-table__import-banner',
      });

      const text = h(
        'span',
        { className: 'rule-table__import-text' },
        `This host has ${importedCount} existing iptables rule${importedCount === 1 ? '' : 's'} not managed by Traffic Rules. Import them?`,
      );
      this.importBanner.appendChild(text);

      const importBtn = h(
        'button',
        { className: 'rule-table__import-btn', type: 'button' },
        'Import',
      );
      this.listen(importBtn, 'click', () =>
        this.handleImportRules(hostId),
      );
      this.importBanner.appendChild(importBtn);

      const dismissBtn = h(
        'button',
        {
          className: 'rule-table__import-dismiss',
          type: 'button',
          'aria-label': 'Dismiss',
        },
        '\u00D7',
      );
      this.listen(dismissBtn, 'click', () => {
        this.importDismissed.add(hostId);
        this.removeImportBanner();
      });
      this.importBanner.appendChild(dismissBtn);

      this.insertTarget.insertBefore(
        this.importBanner,
        this.insertTarget.firstChild,
      );
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
      const errorEl = h(
        'div',
        { className: 'rule-table__import-error' },
        msg,
      );
      this.importBanner?.appendChild(errorEl);
      setTimeout(() => errorEl.remove(), 5000);
    }
  }

  /** Clear the banner DOM reference (call when parent clears sectionsContainer). */
  clearBanner(): void {
    this.importBanner = null;
  }
}
