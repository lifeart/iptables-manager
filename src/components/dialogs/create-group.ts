/**
 * Create Group dialog — name input and member host checkboxes.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { HostGroup } from '../../store/types';
import { h } from '../../utils/dom';

export class CreateGroupDialog extends Component {
  private overlay!: HTMLElement;
  private nameInput!: HTMLInputElement;
  private createBtn!: HTMLButtonElement;
  private memberCheckboxes: Map<string, HTMLInputElement> = new Map();

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindEvents();
  }

  private render(): void {
    this.overlay = h('div', { className: 'dialog-overlay' });
    const dialog = h('div', { className: 'dialog-card dialog-card--create-group' });

    // Header
    dialog.appendChild(h('div', { className: 'dialog-header' },
      h('span', { className: 'dialog-title' }, 'New Group'),
      h('button', { className: 'dialog-close', 'aria-label': 'Close' }, '\u00D7'),
    ));

    const body = h('div', { className: 'dialog-body' });

    // Name field
    const nameField = h('div', { className: 'dialog-field' },
      h('label', { className: 'dialog-label', for: 'group-name' }, 'Name'),
    );
    this.nameInput = document.createElement('input');
    this.nameInput.type = 'text';
    this.nameInput.id = 'group-name';
    this.nameInput.className = 'dialog-input';
    this.nameInput.placeholder = 'Web Servers';
    nameField.appendChild(this.nameInput);
    body.appendChild(nameField);

    // Members
    body.appendChild(h('label', { className: 'dialog-label' }, 'Members'));
    const membersList = h('div', { className: 'dialog-members-list' });

    const state = this.store.getState();
    for (const [id, host] of state.hosts) {
      const row = h('div', { className: 'dialog-member-row' });
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.id = `member-${id}`;
      checkbox.className = 'dialog-member-checkbox';
      this.memberCheckboxes.set(id, checkbox);

      row.appendChild(checkbox);
      row.appendChild(h('label', { for: `member-${id}`, className: 'dialog-member-label' }, host.name));
      membersList.appendChild(row);
    }

    if (state.hosts.size === 0) {
      membersList.appendChild(h('p', { className: 'dialog-empty-text' }, 'No hosts available.'));
    }

    body.appendChild(membersList);
    dialog.appendChild(body);

    // Footer
    const footer = h('div', { className: 'dialog-footer' });
    const spacer = h('div', { className: 'dialog-footer-spacer' });
    const cancelBtn = h('button', { className: 'dialog-btn dialog-btn--secondary' }, 'Cancel');
    this.createBtn = document.createElement('button');
    this.createBtn.className = 'dialog-btn dialog-btn--primary';
    this.createBtn.textContent = 'Create Group';
    this.createBtn.disabled = true;

    this.listen(cancelBtn, 'click', () => this.close());
    this.listen(this.createBtn, 'click', () => this.handleCreate());
    this.listen(dialog.querySelector('.dialog-close')!, 'click', () => this.close());
    this.listen(this.overlay, 'click', (e) => {
      if (e.target === this.overlay) this.close();
    });

    footer.appendChild(spacer);
    footer.appendChild(cancelBtn);
    footer.appendChild(this.createBtn);
    dialog.appendChild(footer);

    this.overlay.appendChild(dialog);
    this.el.appendChild(this.overlay);

    requestAnimationFrame(() => this.nameInput.focus());
  }

  private bindEvents(): void {
    this.listen(this.nameInput, 'input', () => {
      this.createBtn.disabled = !this.nameInput.value.trim();
    });
    this.listen(this.nameInput, 'keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Enter' && !this.createBtn.disabled) {
        this.handleCreate();
      }
    });
  }

  private handleCreate(): void {
    const name = this.nameInput.value.trim();
    if (!name) return;

    const memberHostIds: string[] = [];
    for (const [hostId, checkbox] of this.memberCheckboxes) {
      if (checkbox.checked) {
        memberHostIds.push(hostId);
      }
    }

    const now = Date.now();
    const group: HostGroup = {
      id: crypto.randomUUID(),
      name,
      memberHostIds,
      rules: [],
      position: this.store.getState().groups.size,
      createdAt: now,
      updatedAt: now,
    };

    this.store.dispatch({ type: 'ADD_GROUP', group });

    // Update member hosts to include this group
    for (const hostId of memberHostIds) {
      const host = this.store.getState().hosts.get(hostId);
      if (host) {
        this.store.dispatch({
          type: 'UPDATE_HOST',
          hostId,
          changes: {
            groupIds: [...host.groupIds, group.id],
            groupOrder: [...host.groupOrder, group.id],
          },
        });
      }
    }

    this.close();
  }

  private close(): void {
    this.overlay.remove();
    this.destroy();
  }
}
