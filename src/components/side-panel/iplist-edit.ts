/**
 * IP List edit side panel — edit list name and manage entries.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, IpListEntry } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';
import { syncIpList, deleteIpList } from '../../ipc/bridge';

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

    // Button row
    const btnRow = h('div', { className: 'side-panel__btn-row' });

    // Save button
    this.saveBtn = document.createElement('button');
    this.saveBtn.className = 'dialog-btn dialog-btn--primary';
    this.saveBtn.type = 'button';
    this.saveBtn.textContent = 'Save';
    this.listen(this.saveBtn, 'click', () => this.save());
    btnRow.appendChild(this.saveBtn);

    // Sync to Remote button
    const syncBtn = document.createElement('button');
    syncBtn.className = 'dialog-btn dialog-btn--secondary';
    syncBtn.type = 'button';
    syncBtn.textContent = 'Sync to Remote';
    this.listen(syncBtn, 'click', () => this.syncToRemote());
    btnRow.appendChild(syncBtn);

    // Delete button
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'dialog-btn dialog-btn--secondary side-panel__btn--danger';
    deleteBtn.type = 'button';
    deleteBtn.textContent = 'Delete';
    this.listen(deleteBtn, 'click', () => this.confirmDelete());
    btnRow.appendChild(deleteBtn);

    this.el.appendChild(btnRow);
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

  private async syncToRemote(): Promise<void> {
    const hostId = this.store.getState().activeHostId;
    if (!hostId) {
      this.showFeedback('No host selected.', true);
      return;
    }

    try {
      await syncIpList(hostId, this.ipListId);
      this.showFeedback('Synced to remote successfully.');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.showFeedback(`Sync failed: ${msg}`, true);
    }
  }

  private confirmDelete(): void {
    if (!confirm('Are you sure you want to delete this IP list? This cannot be undone.')) {
      return;
    }
    this.deleteIpListAction();
  }

  private async deleteIpListAction(): Promise<void> {
    const hostId = this.store.getState().activeHostId;

    // Delete from remote if a host is connected
    if (hostId) {
      try {
        await deleteIpList(hostId, this.ipListId);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.showFeedback(`Remote delete failed: ${msg}`, true);
        return;
      }
    }

    // Remove from local state
    this.store.dispatch({ type: 'REMOVE_IP_LIST', ipListId: this.ipListId });

    // Close the editor panel
    this.store.dispatch({ type: 'SET_SIDE_PANEL_CONTENT', content: null });
  }

  private showFeedback(message: string, isError = false): void {
    // Remove any existing feedback
    const existing = this.el.querySelector('.side-panel__feedback');
    if (existing) existing.remove();

    const feedback = h('div', {
      className: `side-panel__feedback${isError ? ' side-panel__feedback--error' : ''}`,
    }, message);
    this.el.appendChild(feedback);

    setTimeout(() => feedback.remove(), 4000);
  }
}
