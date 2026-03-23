/**
 * Group edit side panel — edit group name and manage member hosts.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, Rule } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';
import { RuleBuilder } from '../rule-builder/rule-builder';

export class GroupEdit extends Component {
  private groupId: string;
  private nameInput!: HTMLInputElement;
  private memberListEl!: HTMLElement;
  private rulesListEl!: HTMLElement;
  private ruleBuilderContainer: HTMLElement | null = null;
  private ruleBuilder: RuleBuilder | null = null;
  private pendingGroupRules: Rule[] = [];
  private saveBtn!: HTMLButtonElement;

  constructor(container: HTMLElement, store: Store, groupId: string) {
    super(container, store);
    this.groupId = groupId;
    this.render();
    this.bindSubscriptions();
  }

  private render(): void {
    this.el.innerHTML = '';

    const state = this.store.getState();
    const group = state.groups.get(this.groupId);
    if (!group) {
      this.el.appendChild(h('p', {}, 'Group not found.'));
      return;
    }

    // Title
    this.el.appendChild(h('h2', { className: 'side-panel__title' }, 'Edit Group'));

    // Group name
    const nameLabel = h('label', { className: 'side-panel__label' }, 'Group Name');
    this.nameInput = document.createElement('input');
    this.nameInput.type = 'text';
    this.nameInput.className = 'side-panel__input';
    this.nameInput.value = group.name;
    nameLabel.appendChild(this.nameInput);
    this.el.appendChild(nameLabel);

    // Member hosts section
    this.el.appendChild(h('h3', { className: 'side-panel__subtitle' }, 'Member Hosts'));
    this.memberListEl = h('div', { className: 'side-panel__member-list' });
    this.el.appendChild(this.memberListEl);

    this.renderMemberList();

    // Rules section
    this.el.appendChild(h('h3', { className: 'side-panel__subtitle' }, 'Group Rules'));
    this.rulesListEl = h('div', { className: 'side-panel__group-rules-list' });
    this.el.appendChild(this.rulesListEl);

    // Initialize pending rules from the group's existing rules
    this.pendingGroupRules = [...group.rules];
    this.renderGroupRules();

    const addRuleBtn = h('button', {
      className: 'dialog-btn dialog-btn--secondary',
      type: 'button',
    }, '+ Add Group Rule');
    this.listen(addRuleBtn, 'click', () => this.showRuleBuilder());
    this.el.appendChild(addRuleBtn);

    // Rule builder container (hidden until "+ Add Group Rule" is clicked)
    this.ruleBuilderContainer = h('div', { className: 'side-panel__group-rule-builder' });
    this.ruleBuilderContainer.style.display = 'none';
    this.el.appendChild(this.ruleBuilderContainer);

    // Save button
    this.saveBtn = document.createElement('button');
    this.saveBtn.className = 'dialog-btn dialog-btn--primary';
    this.saveBtn.type = 'button';
    this.saveBtn.textContent = 'Save';
    this.listen(this.saveBtn, 'click', () => this.save());
    this.el.appendChild(this.saveBtn);
  }

  private renderMemberList(): void {
    clearChildren(this.memberListEl);
    const state = this.store.getState();
    const group = state.groups.get(this.groupId);
    if (!group) return;

    const currentMembers = new Set(group.memberHostIds);

    for (const [hostId, host] of state.hosts) {
      const row = h('label', { className: 'side-panel__member-row' });
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.checked = currentMembers.has(hostId);
      checkbox.dataset.hostId = hostId;
      row.appendChild(checkbox);
      row.appendChild(h('span', {}, host.name));
      this.memberListEl.appendChild(row);
    }

    if (state.hosts.size === 0) {
      this.memberListEl.appendChild(h('p', { className: 'side-panel__empty' }, 'No hosts available.'));
    }
  }

  private renderGroupRules(): void {
    clearChildren(this.rulesListEl);

    if (this.pendingGroupRules.length === 0) {
      this.rulesListEl.appendChild(
        h('p', { className: 'side-panel__empty' }, 'No group rules yet.'),
      );
      return;
    }

    for (let i = 0; i < this.pendingGroupRules.length; i++) {
      const rule = this.pendingGroupRules[i];
      const row = h('div', { className: 'side-panel__group-rule-row' });
      row.appendChild(h('span', {}, `${rule.label} (${rule.action})`));
      const removeBtn = h('button', {
        className: 'dialog-btn dialog-btn--text',
        type: 'button',
      }, 'Remove');
      const ruleIndex = i;
      this.listen(removeBtn, 'click', () => {
        this.pendingGroupRules.splice(ruleIndex, 1);
        this.renderGroupRules();
      });
      row.appendChild(removeBtn);
      this.rulesListEl.appendChild(row);
    }
  }

  private showRuleBuilder(): void {
    if (!this.ruleBuilderContainer) return;
    this.ruleBuilderContainer.style.display = '';

    // Clean up previous builder
    if (this.ruleBuilder) {
      this.removeChild(this.ruleBuilder);
      this.ruleBuilder = null;
    }

    this.ruleBuilderContainer.innerHTML = '';
    this.ruleBuilder = new RuleBuilder(this.ruleBuilderContainer, this.store, null);
    this.addChild(this.ruleBuilder);

    const btnRow = h('div', { className: 'side-panel__group-rule-builder-actions' });
    const addBtn = h('button', {
      className: 'dialog-btn dialog-btn--primary',
      type: 'button',
    }, 'Add Rule');
    const cancelBtn = h('button', {
      className: 'dialog-btn dialog-btn--secondary',
      type: 'button',
    }, 'Cancel');

    this.listen(addBtn, 'click', () => {
      if (!this.ruleBuilder) return;
      const formData = this.ruleBuilder.getFormData();

      let resolvedAction: Rule['action'] = formData.action;
      if ((formData.action === 'block' || formData.action === 'log-block') && formData.blockType === 'reject') {
        resolvedAction = 'block-reject';
      }

      const newRule: Rule = {
        id: `rule-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        label: formData.label,
        action: resolvedAction,
        protocol: formData.protocol,
        ports: formData.ports,
        source: formData.source,
        destination: { type: 'anyone' },
        direction: 'incoming',
        addressFamily: 'both',
        interfaceIn: formData.interfaceIn,
        comment: formData.comment,
        origin: { type: 'group', groupId: this.groupId },
        position: this.pendingGroupRules.length,
        enabled: true,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };

      this.pendingGroupRules.push(newRule);
      this.renderGroupRules();
      this.hideRuleBuilder();
    });

    this.listen(cancelBtn, 'click', () => this.hideRuleBuilder());

    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(addBtn);
    this.ruleBuilderContainer.appendChild(btnRow);
  }

  private hideRuleBuilder(): void {
    if (!this.ruleBuilderContainer) return;
    this.ruleBuilderContainer.style.display = 'none';
    if (this.ruleBuilder) {
      this.removeChild(this.ruleBuilder);
      this.ruleBuilder = null;
    }
    this.ruleBuilderContainer.innerHTML = '';
  }

  private save(): void {
    const state = this.store.getState();
    const group = state.groups.get(this.groupId);
    if (!group) return;

    const newName = this.nameInput.value.trim() || group.name;
    const checkboxes = this.memberListEl.querySelectorAll<HTMLInputElement>('input[type="checkbox"]');
    const memberHostIds: string[] = [];
    for (const cb of checkboxes) {
      if (cb.checked && cb.dataset.hostId) {
        memberHostIds.push(cb.dataset.hostId);
      }
    }

    this.store.dispatch({
      type: 'UPDATE_GROUP',
      groupId: this.groupId,
      changes: { name: newName, memberHostIds, rules: this.pendingGroupRules },
    });

    // Close the panel
    this.store.dispatch({ type: 'SET_SIDE_PANEL_CONTENT', content: null });
  }

  private bindSubscriptions(): void {
    this.subscribe(
      (s: AppState) => s.groups.get(this.groupId),
      () => this.renderMemberList(),
    );

    this.subscribe(
      (s: AppState) => s.hosts,
      () => this.renderMemberList(),
    );
  }
}
