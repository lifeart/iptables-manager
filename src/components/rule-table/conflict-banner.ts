/**
 * Conflict banner sub-component.
 *
 * Displays a warning banner when rule conflicts are detected,
 * with an expandable list of individual conflicts.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState } from '../../store/types';
import { h } from '../../utils/dom';
import { detectConflicts } from '../../ipc/bridge';
import type { RuleConflict } from '../../ipc/bridge';

export class ConflictBanner extends Component {
  private conflictsBanner: HTMLElement | null = null;
  private conflictsExpanded = false;

  constructor(
    container: HTMLElement,
    store: Store,
    private insertTarget: HTMLElement,
  ) {
    super(container, store);
    this.bindSubscriptions();
  }

  private bindSubscriptions(): void {
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
          this.store.dispatch({
            type: 'SET_RULE_CONFLICTS',
            hostId,
            conflicts: [],
          });
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
  }

  private runConflictDetection(hostId: string): void {
    detectConflicts(hostId)
      .then((conflicts) => {
        if (this.store.getState().activeHostId === hostId) {
          this.store.dispatch({
            type: 'SET_RULE_CONFLICTS',
            hostId,
            conflicts,
          });
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
      this.conflictsBanner = h('div', {
        className: 'rule-table__conflicts-banner',
      });
      this.insertTarget.insertBefore(
        this.conflictsBanner,
        this.insertTarget.firstChild,
      );
    }

    const conflictTypeLabel = (type: RuleConflict['type']): string => {
      switch (type) {
        case 'shadow':
          return 'Shadow';
        case 'contradiction':
          return 'Contradiction';
        case 'redundant':
          return 'Redundancy';
        default:
          return type;
      }
    };

    this.conflictsBanner.innerHTML = '';

    const summary = h('button', {
      className: 'rule-table__conflicts-summary',
      type: 'button',
      'aria-expanded': String(this.conflictsExpanded),
    });
    const chevron = h(
      'span',
      {
        className:
          'rule-table__conflicts-chevron' +
          (this.conflictsExpanded
            ? ' rule-table__conflicts-chevron--open'
            : ''),
      },
      '\u25B6',
    );
    summary.appendChild(chevron);
    summary.appendChild(
      h(
        'span',
        {},
        `${conflicts.length} potential conflict${conflicts.length === 1 ? '' : 's'} detected`,
      ),
    );

    this.listen(summary, 'click', () => {
      this.conflictsExpanded = !this.conflictsExpanded;
      this.renderConflictsBanner(conflicts);
    });

    this.conflictsBanner.appendChild(summary);

    if (this.conflictsExpanded) {
      const list = h('div', { className: 'rule-table__conflicts-list' });
      for (const conflict of conflicts) {
        const item = h('div', { className: 'rule-table__conflicts-item' });
        const badge = h(
          'span',
          {
            className: `rule-table__conflicts-badge rule-table__conflicts-badge--${conflict.type}`,
          },
          conflictTypeLabel(conflict.type),
        );
        const rules = h(
          'span',
          { className: 'rule-table__conflicts-rules' },
          `Rules: ${conflict.ruleIdA.slice(0, 8)} \u2194 ${conflict.ruleIdB.slice(0, 8)}`,
        );
        const desc = h(
          'span',
          { className: 'rule-table__conflicts-desc' },
          conflict.description,
        );

        item.appendChild(badge);
        item.appendChild(rules);
        item.appendChild(desc);
        list.appendChild(item);
      }
      this.conflictsBanner.appendChild(list);
    }
  }

  /** Clear the banner DOM reference (call when parent clears sectionsContainer). */
  clearBanner(): void {
    this.conflictsBanner = null;
  }
}
