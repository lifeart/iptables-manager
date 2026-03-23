/**
 * Group edit side panel — edit group name and manage member hosts.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';

export class GroupEdit extends Component {
  private groupId: string;
  private nameInput!: HTMLInputElement;
  private memberListEl!: HTMLElement;
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
      changes: { name: newName, memberHostIds },
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
