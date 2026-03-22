/**
 * Create IP List dialog — name input, address list with add/remove,
 * per-entry validation (IPv4, IPv6, CIDR).
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { IpList, IpListEntry } from '../../store/types';
import { h } from '../../utils/dom';
import { isValidIPv4, isValidIPv6, isValidCIDR } from '../../utils/ip-validate';

function validateAddress(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return 'Address is required';
  if (isValidIPv4(trimmed) || isValidIPv6(trimmed) || isValidCIDR(trimmed)) return null;
  return 'Enter a valid IPv4, IPv6, or CIDR address';
}

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

export class CreateIpListDialog extends Component {
  private overlay!: HTMLElement;
  private nameInput!: HTMLInputElement;
  private entriesContainer!: HTMLElement;
  private addEntryInput!: HTMLInputElement;
  private addEntryBtn!: HTMLButtonElement;
  private addEntryError!: HTMLElement;
  private createBtn!: HTMLButtonElement;
  private entries: IpListEntry[] = [];

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindEvents();
  }

  private render(): void {
    this.overlay = h('div', { className: 'dialog-overlay' });
    const dialog = h('div', { className: 'dialog-card dialog-card--create-iplist' });

    // Header
    dialog.appendChild(h('div', { className: 'dialog-header' },
      h('span', { className: 'dialog-title' }, 'Create IP List'),
      h('button', { className: 'dialog-close', 'aria-label': 'Close' }, '\u00D7'),
    ));

    const body = h('div', { className: 'dialog-body' });

    // Name field
    const nameField = h('div', { className: 'dialog-field' },
      h('label', { className: 'dialog-label', for: 'iplist-name' }, 'Name'),
    );
    this.nameInput = document.createElement('input');
    this.nameInput.type = 'text';
    this.nameInput.id = 'iplist-name';
    this.nameInput.className = 'dialog-input';
    this.nameInput.placeholder = 'Office IPs';
    nameField.appendChild(this.nameInput);
    body.appendChild(nameField);

    // Entries section
    body.appendChild(h('label', { className: 'dialog-label' }, 'Addresses'));
    this.entriesContainer = h('div', { className: 'dialog-entries-list' });
    body.appendChild(this.entriesContainer);

    // Add entry row
    const addRow = h('div', { className: 'dialog-add-entry-row' });
    this.addEntryInput = document.createElement('input');
    this.addEntryInput.type = 'text';
    this.addEntryInput.className = 'dialog-input dialog-input--entry';
    this.addEntryInput.placeholder = '192.168.1.0/24';

    this.addEntryBtn = document.createElement('button');
    this.addEntryBtn.className = 'dialog-btn dialog-btn--secondary dialog-btn--small';
    this.addEntryBtn.textContent = 'Add';

    addRow.appendChild(this.addEntryInput);
    addRow.appendChild(this.addEntryBtn);
    body.appendChild(addRow);

    this.addEntryError = h('div', { className: 'dialog-error', style: { display: 'none' } });
    body.appendChild(this.addEntryError);

    dialog.appendChild(body);

    // Footer
    const footer = h('div', { className: 'dialog-footer' });
    const spacer = h('div', { className: 'dialog-footer-spacer' });
    const cancelBtn = h('button', { className: 'dialog-btn dialog-btn--secondary' }, 'Cancel');
    this.createBtn = document.createElement('button');
    this.createBtn.className = 'dialog-btn dialog-btn--primary';
    this.createBtn.textContent = 'Create IP List';
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
    this.listen(this.nameInput, 'input', () => this.updateCreateButton());
    this.listen(this.addEntryBtn, 'click', () => this.addEntry());
    this.listen(this.addEntryInput, 'keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Enter') this.addEntry();
    });
  }

  private addEntry(): void {
    const value = this.addEntryInput.value.trim();
    if (!value) return;

    const error = validateAddress(value);
    if (error) {
      this.addEntryError.textContent = error;
      this.addEntryError.style.display = '';
      this.addEntryInput.classList.add('dialog-input--error');
      return;
    }

    this.addEntryError.style.display = 'none';
    this.addEntryInput.classList.remove('dialog-input--error');

    this.entries.push({ address: value });
    this.addEntryInput.value = '';
    this.renderEntries();
    this.updateCreateButton();
    this.addEntryInput.focus();
  }

  private removeEntry(idx: number): void {
    this.entries.splice(idx, 1);
    this.renderEntries();
    this.updateCreateButton();
  }

  private renderEntries(): void {
    this.entriesContainer.innerHTML = '';
    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];
      const row = h('div', { className: 'dialog-entry-row' },
        h('span', { className: 'dialog-entry-address' }, entry.address),
      );
      const removeBtn = h('button', {
        className: 'dialog-btn dialog-btn--text dialog-btn--remove',
        'aria-label': `Remove ${entry.address}`,
      }, '\u00D7');
      this.listen(removeBtn, 'click', () => this.removeEntry(i));
      row.appendChild(removeBtn);
      this.entriesContainer.appendChild(row);
    }
  }

  private updateCreateButton(): void {
    this.createBtn.disabled = !this.nameInput.value.trim() || this.entries.length === 0;
  }

  private handleCreate(): void {
    const name = this.nameInput.value.trim();
    if (!name || this.entries.length === 0) return;

    const now = Date.now();
    const ipList: IpList = {
      id: crypto.randomUUID(),
      name,
      slug: slugify(name),
      entries: [...this.entries],
      usedInRuleIds: [],
      createdAt: now,
      updatedAt: now,
    };

    this.store.dispatch({ type: 'ADD_IP_LIST', ipList });
    this.close();
  }

  private close(): void {
    this.overlay.remove();
    this.destroy();
  }
}
