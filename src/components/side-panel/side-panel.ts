/**
 * Side panel component — 420px panel sliding from right.
 *
 * Subscribes to sidePanelOpen + sidePanelContent in store.
 * Renders different content based on sidePanelContent type:
 *   - 'rule-detail': RuleDetail
 *   - 'rule-edit' / 'rule-new': RuleEdit
 *   - 'snapshot-history': snapshot list
 * Cross-fades content when switching between rules (150ms).
 * On narrow screens (main < 600px remaining): becomes bottom sheet.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { SidePanelContent } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';
import { RuleDetail } from './rule-detail';
import { RuleEdit } from './rule-edit';
import { SnapshotHistory } from './snapshot-history';

export class SidePanel extends Component {
  private panelEl: HTMLElement;
  private contentEl: HTMLElement;
  private closeBtn: HTMLElement;
  private currentContent: Component | null = null;
  private isOpen = false;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);

    // Build panel structure
    this.panelEl = h('div', { className: 'side-panel', role: 'complementary', 'aria-label': 'Rule details' });

    // Header with close button
    const header = h('div', { className: 'side-panel__header' });
    this.closeBtn = h('button', {
      className: 'side-panel__close-btn',
      'aria-label': 'Close panel',
      type: 'button',
    }, '\u00D7');
    header.appendChild(this.closeBtn);
    this.panelEl.appendChild(header);

    // Content area
    this.contentEl = h('div', { className: 'side-panel__content' });
    this.panelEl.appendChild(this.contentEl);

    this.el.appendChild(this.panelEl);

    // Event listeners
    this.listen(this.closeBtn, 'click', () => this.close());
    this.listen(document, 'keydown', (e) => this.onKeyDown(e as KeyboardEvent));

    // Subscribe to store
    this.subscribe(
      (s) => s.sidePanelOpen,
      (open) => this.onOpenChanged(open),
    );

    this.subscribe(
      (s) => s.sidePanelContent,
      (content) => this.onContentChanged(content),
    );
  }

  private onKeyDown(e: KeyboardEvent): void {
    if (e.key === 'Escape' && this.isOpen) {
      e.preventDefault();
      this.close();
    }
  }

  private close(): void {
    this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: false });
    this.store.dispatch({ type: 'SET_SIDE_PANEL_CONTENT', content: null });
  }

  private onOpenChanged(open: boolean): void {
    this.isOpen = open;
    this.panelEl.classList.toggle('side-panel--open', open);
    this.el.classList.toggle('side-panel--open', open);

    // Check if we should use bottom sheet mode
    this.checkBottomSheet();

    if (!open) {
      this.destroyCurrentContent();
    }
  }

  private onContentChanged(content: SidePanelContent | null): void {
    if (!content) {
      this.destroyCurrentContent();
      return;
    }

    // Cross-fade: fade out old, render new, fade in
    this.contentEl.classList.add('side-panel__content--fading');

    // Use requestAnimationFrame to allow fade-out to start
    requestAnimationFrame(() => {
      this.destroyCurrentContent();
      this.renderContent(content);

      requestAnimationFrame(() => {
        this.contentEl.classList.remove('side-panel__content--fading');
      });
    });
  }

  private renderContent(content: SidePanelContent): void {
    clearChildren(this.contentEl);

    switch (content.type) {
      case 'rule-detail': {
        const detail = new RuleDetail(this.contentEl, this.store, content.ruleId);
        this.currentContent = detail;
        this.addChild(detail);
        break;
      }
      case 'rule-edit': {
        const edit = new RuleEdit(this.contentEl, this.store, content.ruleId);
        this.currentContent = edit;
        this.addChild(edit);
        break;
      }
      case 'rule-new': {
        const newEdit = new RuleEdit(this.contentEl, this.store, null);
        this.currentContent = newEdit;
        this.addChild(newEdit);
        break;
      }
      case 'snapshot-history': {
        const snapshotHistory = new SnapshotHistory(this.contentEl, this.store);
        this.currentContent = snapshotHistory;
        this.addChild(snapshotHistory);
        break;
      }
      case 'host-settings': {
        const settingsEl = h('div', { className: 'side-panel__host-settings' },
          h('h3', { className: 'side-panel__section-title' }, 'Host Settings'),
        );
        this.contentEl.appendChild(settingsEl);
        break;
      }
    }
  }

  private destroyCurrentContent(): void {
    if (this.currentContent) {
      this.removeChild(this.currentContent);
      this.currentContent = null;
    }
    clearChildren(this.contentEl);
  }

  private checkBottomSheet(): void {
    // Check if main content area would be less than 600px
    const mainContent = document.getElementById('main-content');
    if (mainContent && this.isOpen) {
      const mainWidth = mainContent.getBoundingClientRect().width;
      const remainingWidth = mainWidth - 420;
      this.panelEl.classList.toggle('side-panel--bottom-sheet', remainingWidth < 600);
    } else {
      this.panelEl.classList.remove('side-panel--bottom-sheet');
    }
  }
}
