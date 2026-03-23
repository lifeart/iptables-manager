/**
 * IP List edit side panel — edit list name and manage entries.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, IpListEntry } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';

export class IpListEdit extends Component {
  private ipListId: string;
  private nameInput!: HTMLInputElement;
  private entriesListEl!: HTMLElement;
  private addEntryInput!: HTMLInputElement;
  private addEntryBtn!: HTMLButtonElement;
  private saveBtn!: HTMLButtonElement;
  private localEntries: IpListEntry[] = [];

  constructor(container: HTMLElement, store: Store, ipListId: string) {
    super(container, store);
    this.ipListId = ipListId;

    // Initialize local entries from current state
    const ipList = store.getState().ipLists.get(ipListId);
    if (ipList) {
      this.localEntries = [...ipList.entries];
    }

    this.render();
  }

  private render(): void {
    this.el.innerHTML = '';

    const state = this.store.getState();
    const ipList = state.ipLists.get(this.ipListId);
    if (!ipList) {
      this.el.appendChild(h('p', {}, 'IP List not found.'));
      return;
    }

    // Title
    this.el.appendChild(h('h2', { className: 'side-panel__title' }, 'Edit IP List'));

    // List name
    const nameLabel = h('label', { className: 'side-panel__label' }, 'List Name');
    this.nameInput = document.createElement('input');
    this.nameInput.type = 'text';
    this.nameInput.className = 'side-panel__input';
    this.nameInput.value = ipList.name;
    nameLabel.appendChild(this.nameInput);
    this.el.appendChild(nameLabel);

    // Entries section
    this.el.appendChild(h('h3', { className: 'side-panel__subtitle' }, 'Addresses'));

    // Add entry row
    const addRow = h('div', { className: 'side-panel__add-entry-row' });
    this.addEntryInput = document.createElement('input');
    this.addEntryInput.type = 'text';
    this.addEntryInput.className = 'side-panel__input';
    this.addEntryInput.placeholder = '192.168.1.0/24 or 2001:db8::/32';
    addRow.appendChild(this.addEntryInput);

    this.addEntryBtn = document.createElement('button');
    this.addEntryBtn.className = 'dialog-btn dialog-btn--secondary dialog-btn--small';
    this.addEntryBtn.type = 'button';
    this.addEntryBtn.textContent = 'Add';
    this.listen(this.addEntryBtn, 'click', () => this.addEntry());
    addRow.appendChild(this.addEntryBtn);

    // Allow pressing Enter to add
    this.listen(this.addEntryInput, 'keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Enter') {
        e.preventDefault();
        this.addEntry();
      }
    });

    this.el.appendChild(addRow);

    // Entries list
    this.entriesListEl = h('div', { className: 'side-panel__entries-list' });
    this.el.appendChild(this.entriesListEl);
    this.renderEntries();

    // Save button
    this.saveBtn = document.createElement('button');
    this.saveBtn.className = 'dialog-btn dialog-btn--primary';
    this.saveBtn.type = 'button';
    this.saveBtn.textContent = 'Save';
    this.listen(this.saveBtn, 'click', () => this.save());
    this.el.appendChild(this.saveBtn);
  }

  private renderEntries(): void {
    clearChildren(this.entriesListEl);

    if (this.localEntries.length === 0) {
      this.entriesListEl.appendChild(h('p', { className: 'side-panel__empty' }, 'No addresses in this list.'));
      return;
    }

    for (let i = 0; i < this.localEntries.length; i++) {
      const entry = this.localEntries[i];
      const row = h('div', { className: 'side-panel__entry-row' });
      row.appendChild(h('span', { className: 'side-panel__entry-addr' }, entry.address));
      if (entry.comment) {
        row.appendChild(h('span', { className: 'side-panel__entry-comment' }, entry.comment));
      }

      const removeBtn = h('button', {
        className: 'side-panel__entry-remove-btn',
        type: 'button',
        'aria-label': `Remove ${entry.address}`,
      }, '\u00D7');
      const entryIndex = i;
      this.listen(removeBtn, 'click', () => {
        this.localEntries.splice(entryIndex, 1);
        this.renderEntries();
      });
      row.appendChild(removeBtn);
      this.entriesListEl.appendChild(row);
    }
  }

  private addEntry(): void {
    const value = this.addEntryInput.value.trim();
    if (!value) return;

    this.localEntries.push({ address: value });
    this.addEntryInput.value = '';
    this.renderEntries();
    this.addEntryInput.focus();
  }

  private save(): void {
    const state = this.store.getState();
    const ipList = state.ipLists.get(this.ipListId);
    if (!ipList) return;

    const newName = this.nameInput.value.trim() || ipList.name;

    // Update the IP list name and entries
    this.store.dispatch({
      type: 'UPDATE_IP_LIST',
      ipListId: this.ipListId,
      changes: { name: newName },
    });

    this.store.dispatch({
      type: 'SET_IP_LIST_ENTRIES',
      ipListId: this.ipListId,
      entries: [...this.localEntries],
    });

    // Close the panel
    this.store.dispatch({ type: 'SET_SIDE_PANEL_CONTENT', content: null });
  }
}
