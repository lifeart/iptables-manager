/**
 * Rule edit form — wraps the RuleBuilder in the side panel.
 *
 * Title: "Edit Rule" or "New Rule" depending on whether ruleId is provided.
 * Contains the rule builder form.
 * Cancel/Save buttons pinned to bottom.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { Rule } from '../../store/types';
import { h } from '../../utils/dom';
import { RuleBuilder } from '../rule-builder/rule-builder';

export class RuleEdit extends Component {
  private ruleId: string | null;
  private containerEl: HTMLElement;
  private builderContainer: HTMLElement;
  private ruleBuilder: RuleBuilder | null = null;

  constructor(container: HTMLElement, store: Store, ruleId: string | null) {
    super(container, store);
    this.ruleId = ruleId;

    this.containerEl = h('div', { className: 'rule-edit' });

    // Title
    const title = h('h2', { className: 'rule-edit__title' },
      ruleId ? 'Edit Rule' : 'New Rule');
    this.containerEl.appendChild(title);

    // Divider
    this.containerEl.appendChild(h('hr', { className: 'rule-edit__divider' }));

    // Builder form container
    this.builderContainer = h('div', { className: 'rule-edit__builder' });
    this.containerEl.appendChild(this.builderContainer);

    // Initialize rule builder
    const existingRule = this.findRule();
    this.ruleBuilder = new RuleBuilder(this.builderContainer, store, existingRule);
    this.addChild(this.ruleBuilder);

    // Footer with Cancel / Save buttons
    const footer = h('div', { className: 'rule-edit__footer' });

    const cancelBtn = h('button', {
      className: 'rule-edit__cancel-btn',
      type: 'button',
    }, 'Cancel');
    this.listen(cancelBtn, 'click', () => this.onCancel());

    const saveBtn = h('button', {
      className: 'rule-edit__save-btn',
      type: 'button',
    }, ruleId ? 'Save' : 'Add Rule');
    this.listen(saveBtn, 'click', () => this.onSave());

    footer.appendChild(cancelBtn);
    footer.appendChild(saveBtn);
    this.containerEl.appendChild(footer);

    this.el.appendChild(this.containerEl);
  }

  private findRule(): Rule | null {
    if (!this.ruleId) return null;
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (!hostId) return null;
    const hostState = state.hostStates.get(hostId);
    if (!hostState) return null;
    return hostState.rules.find((r) => r.id === this.ruleId) ?? null;
  }

  private onCancel(): void {
    if (this.ruleId) {
      // Go back to detail view
      this.store.dispatch({
        type: 'SET_SIDE_PANEL_CONTENT',
        content: { type: 'rule-detail', ruleId: this.ruleId },
      });
    } else {
      // Close the panel
      this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: false });
      this.store.dispatch({ type: 'SET_SIDE_PANEL_CONTENT', content: null });
    }
  }

  private onSave(): void {
    if (!this.ruleBuilder) return;

    const formData = this.ruleBuilder.getFormData();
    const activeHostId = this.store.getState().activeHostId;
    if (!activeHostId) return;

    if (this.ruleId) {
      // Edit existing rule
      const existingRule = this.findRule();
      if (!existingRule) return;

      this.store.dispatch({
        type: 'ADD_STAGED_CHANGE',
        hostId: activeHostId,
        change: {
          type: 'modify',
          ruleId: this.ruleId,
          before: {
            action: existingRule.action,
            protocol: existingRule.protocol,
            ports: existingRule.ports,
            source: existingRule.source,
            comment: existingRule.comment,
            interfaceIn: existingRule.interfaceIn,
          },
          after: {
            action: formData.action,
            protocol: formData.protocol,
            ports: formData.ports,
            source: formData.source,
            comment: formData.comment,
            interfaceIn: formData.interfaceIn,
          },
        },
      });

      // Switch back to detail view
      this.store.dispatch({
        type: 'SET_SIDE_PANEL_CONTENT',
        content: { type: 'rule-detail', ruleId: this.ruleId },
      });
    } else {
      // Add new rule
      const newRule: Rule = {
        id: `rule-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        label: formData.label,
        action: formData.action,
        protocol: formData.protocol,
        ports: formData.ports,
        source: formData.source,
        destination: { type: 'anyone' },
        direction: 'incoming',
        addressFamily: 'both',
        interfaceIn: formData.interfaceIn,
        comment: formData.comment,
        origin: { type: 'user' },
        position: 0,
        enabled: true,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };

      this.store.dispatch({
        type: 'ADD_STAGED_CHANGE',
        hostId: activeHostId,
        change: { type: 'add', rule: newRule, position: 0 },
      });

      // Close the panel
      this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: false });
      this.store.dispatch({ type: 'SET_SIDE_PANEL_CONTENT', content: null });
    }
  }
}
