/**
 * Address picker combobox — source/destination selection.
 *
 * Options:
 *   - Anyone
 *   - My Current IP
 *   - Local Network
 *   - IP Lists section
 *   - Managed Hosts section
 *   - Manual entry: IP Address, CIDR range
 *
 * Uses ip-validate.ts for validation.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AddressSpec, IpList, Host } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';
import { isValidIPv4, isValidIPv6, isValidCIDR } from '../../utils/ip-validate';

interface AddressOption {
  label: string;
  value: AddressSpec;
  category?: string;
  detail?: string;
}

export class AddressPicker extends Component {
  private containerEl: HTMLElement;
  private inputEl: HTMLInputElement;
  private dropdownEl: HTMLElement;
  private isDropdownOpen = false;
  private selectedAddress: AddressSpec;
  private onSelect: (addr: AddressSpec) => void;
  private manualMode = false;
  private manualInput: HTMLInputElement | null = null;
  private validationMsg: HTMLElement | null = null;

  constructor(
    container: HTMLElement,
    store: Store,
    initialAddress: AddressSpec,
    onSelect: (addr: AddressSpec) => void,
  ) {
    super(container, store);
    this.selectedAddress = initialAddress;
    this.onSelect = onSelect;

    this.containerEl = h('div', { className: 'address-picker' });

    // Combobox input
    this.inputEl = document.createElement('input');
    this.inputEl.type = 'text';
    this.inputEl.className = 'address-picker__input';
    this.inputEl.placeholder = 'Anyone';
    this.inputEl.value = this.formatAddress(initialAddress);
    this.inputEl.setAttribute('role', 'combobox');
    this.inputEl.setAttribute('aria-expanded', 'false');
    this.inputEl.setAttribute('aria-autocomplete', 'list');

    const trigger = h('span', { className: 'address-picker__trigger' }, '\u25BE');

    const inputWrapper = h('div', { className: 'address-picker__input-wrapper' });
    inputWrapper.appendChild(this.inputEl);
    inputWrapper.appendChild(trigger);
    this.containerEl.appendChild(inputWrapper);

    // Dropdown
    this.dropdownEl = h('div', {
      className: 'address-picker__dropdown',
      role: 'listbox',
    });
    this.dropdownEl.style.display = 'none';
    this.containerEl.appendChild(this.dropdownEl);

    // Manual entry fields (hidden initially)
    this.buildManualEntry();

    this.el.appendChild(this.containerEl);

    // Events
    this.listen(this.inputEl, 'focus', () => this.openDropdown());
    this.listen(this.inputEl, 'input', () => this.onInputChange());
    this.listen(trigger, 'click', () => this.toggleDropdown());
    this.listen(document, 'click', (e) => {
      if (!this.containerEl.contains(e.target as Node)) {
        this.closeDropdown();
      }
    });
  }

  private formatAddress(addr: AddressSpec): string {
    switch (addr.type) {
      case 'anyone': return 'Anyone';
      case 'cidr': return addr.value;
      case 'iplist': {
        const ipList = this.store.getState().ipLists.get(addr.ipListId);
        return ipList ? ipList.name : addr.ipListId;
      }
      default: return '';
    }
  }

  private buildManualEntry(): void {
    const manualContainer = h('div', { className: 'address-picker__manual' });
    manualContainer.style.display = 'none';
    manualContainer.dataset.manualContainer = 'true';

    const label = h('label', { className: 'address-picker__manual-label' },
      'Enter IP address or CIDR range');

    this.manualInput = document.createElement('input');
    this.manualInput.type = 'text';
    this.manualInput.className = 'address-picker__manual-input';
    this.manualInput.placeholder = '192.168.1.0/24';
    this.listen(this.manualInput, 'input', () => this.onManualInput());
    this.listen(this.manualInput, 'blur', () => this.validateManualInput());

    this.validationMsg = h('p', { className: 'address-picker__validation' });
    this.validationMsg.style.display = 'none';

    manualContainer.appendChild(label);
    manualContainer.appendChild(this.manualInput);
    manualContainer.appendChild(this.validationMsg);

    this.containerEl.appendChild(manualContainer);
  }

  private openDropdown(): void {
    if (this.manualMode) return;
    this.isDropdownOpen = true;
    this.dropdownEl.style.display = '';
    this.inputEl.setAttribute('aria-expanded', 'true');
    this.renderDropdown(this.inputEl.value);
  }

  private closeDropdown(): void {
    this.isDropdownOpen = false;
    this.dropdownEl.style.display = 'none';
    this.inputEl.setAttribute('aria-expanded', 'false');
  }

  private toggleDropdown(): void {
    if (this.isDropdownOpen) {
      this.closeDropdown();
    } else {
      this.openDropdown();
    }
  }

  private onInputChange(): void {
    if (this.isDropdownOpen) {
      this.renderDropdown(this.inputEl.value);
    } else {
      this.openDropdown();
    }
  }

  private getOptions(): AddressOption[] {
    const options: AddressOption[] = [
      { label: 'Anyone', value: { type: 'anyone' } },
    ];

    // Resolve "My Current IP" from the active host's management interface
    const state = this.store.getState();
    const activeHostId = state.activeHostId;
    let myIp: string | null = null;
    if (activeHostId) {
      const host = state.hosts.get(activeHostId);
      if (host?.capabilities) {
        const mgmtIf = host.capabilities.managementInterface;
        if (mgmtIf) {
          const iface = host.capabilities.interfaces.find(i => i.name === mgmtIf);
          if (iface && iface.addresses.length > 0) {
            myIp = iface.addresses[0];
          }
        }
      }
    }

    options.push({
      label: 'My Current IP',
      value: { type: 'cidr', value: myIp ?? '0.0.0.0' },
      detail: myIp ?? 'Detecting...',
    });
    options.push(
      { label: 'Local Network', value: { type: 'cidr', value: '10.0.0.0/8' }, detail: 'Auto-detected' },
    );

    // IP Lists
    for (const [, ipList] of state.ipLists) {
      options.push({
        label: ipList.name,
        value: { type: 'iplist', ipListId: ipList.id },
        category: 'IP Lists',
      });
    }

    // Managed Hosts
    for (const [, host] of state.hosts) {
      if (host.capabilities?.interfaces) {
        const addrs = host.capabilities.interfaces
          .filter(iface => iface.type !== 'loopback' && iface.addresses.length > 0)
          .flatMap(iface => iface.addresses);
        if (addrs.length > 0) {
          options.push({
            label: `${host.name} (${addrs[0]})`,
            value: { type: 'cidr', value: addrs[0] },
            category: 'Managed Hosts',
          });
        }
      }
    }

    return options;
  }

  private renderDropdown(filter: string): void {
    clearChildren(this.dropdownEl);

    const filterLower = filter.toLowerCase();
    const options = this.getOptions();
    let currentCategory: string | undefined;

    for (const opt of options) {
      if (filterLower && !opt.label.toLowerCase().includes(filterLower)) continue;

      // Category header
      if (opt.category && opt.category !== currentCategory) {
        currentCategory = opt.category;
        this.dropdownEl.appendChild(
          h('div', { className: 'address-picker__category' }, opt.category),
        );
      }

      const item = h('div', {
        className: 'address-picker__item',
        role: 'option',
      });
      item.appendChild(h('span', { className: 'address-picker__item-label' }, opt.label));
      if (opt.detail) {
        item.appendChild(h('span', { className: 'address-picker__item-detail' }, opt.detail));
      }

      this.listen(item, 'click', () => {
        this.selectedAddress = opt.value;
        this.inputEl.value = opt.label;
        this.onSelect(this.selectedAddress);
        this.closeDropdown();
        this.exitManualMode();
      });
      this.dropdownEl.appendChild(item);
    }

    // Manual entry section
    const manualCategory = h('div', { className: 'address-picker__category' }, 'Enter manually');
    this.dropdownEl.appendChild(manualCategory);

    const ipItem = h('div', { className: 'address-picker__item', role: 'option' }, 'IP Address...');
    this.listen(ipItem, 'click', () => this.enterManualMode());
    this.dropdownEl.appendChild(ipItem);

    const cidrItem = h('div', { className: 'address-picker__item', role: 'option' }, 'IP Range (CIDR)...');
    this.listen(cidrItem, 'click', () => this.enterManualMode());
    this.dropdownEl.appendChild(cidrItem);
  }

  private enterManualMode(): void {
    this.manualMode = true;
    this.closeDropdown();
    this.inputEl.style.display = 'none';

    const manualContainer = this.containerEl.querySelector('[data-manual-container]') as HTMLElement;
    if (manualContainer) {
      manualContainer.style.display = '';
    }
    if (this.manualInput) {
      this.manualInput.focus();
    }
  }

  private exitManualMode(): void {
    this.manualMode = false;
    this.inputEl.style.display = '';

    const manualContainer = this.containerEl.querySelector('[data-manual-container]') as HTMLElement;
    if (manualContainer) {
      manualContainer.style.display = 'none';
    }
  }

  private onManualInput(): void {
    if (!this.manualInput || !this.validationMsg) return;
    const value = this.manualInput.value.trim();
    if (!value) {
      this.validationMsg.style.display = 'none';
      return;
    }

    // Validate as we type
    const isValid = isValidIPv4(value) || isValidIPv6(value) || isValidCIDR(value);
    if (isValid) {
      this.selectedAddress = { type: 'cidr', value };
      this.onSelect(this.selectedAddress);
      this.validationMsg.style.display = 'none';
      this.manualInput.classList.remove('address-picker__manual-input--error');
    }
  }

  private validateManualInput(): void {
    if (!this.manualInput || !this.validationMsg) return;
    const value = this.manualInput.value.trim();
    if (!value) {
      this.validationMsg.style.display = 'none';
      this.manualInput.classList.remove('address-picker__manual-input--error');
      return;
    }

    const isValid = isValidIPv4(value) || isValidIPv6(value) || isValidCIDR(value);
    if (!isValid) {
      this.validationMsg.textContent = 'Enter a valid IPv4, IPv6 address, or CIDR range.';
      this.validationMsg.style.display = '';
      this.manualInput.classList.add('address-picker__manual-input--error');
    } else {
      this.validationMsg.style.display = 'none';
      this.manualInput.classList.remove('address-picker__manual-input--error');
    }
  }
}
