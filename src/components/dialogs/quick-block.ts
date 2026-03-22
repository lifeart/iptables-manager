/**
 * Quick Block dialog — rapid IP blocking via Cmd+Shift+B.
 *
 * 380px wide, centered. Blue primary button.
 * Validates against dangerous IPs (0.0.0.0/0, 127.0.0.1, management IP).
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, Host } from '../../store/types';
import { h, trapFocus } from '../../utils/dom';
import { isValidIPv4, isValidIPv6, isValidCIDR } from '../../utils/ip-validate';

export class QuickBlockDialog extends Component {
  private overlay!: HTMLElement;
  private ipInput!: HTMLInputElement;
  private hostSelect!: HTMLSelectElement;
  private blockBtn!: HTMLButtonElement;
  private errorEl!: HTMLElement;

  private triggerElement: Element | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.triggerElement = document.activeElement;
    this.render();
    this.bindEvents();
  }

  private render(): void {
    this.overlay = h('div', { className: 'dialog-overlay' });
    const titleId = 'quick-block-dialog-title';
    const dialog = h('div', {
      className: 'dialog-card dialog-card--quick-block',
      role: 'dialog',
      'aria-modal': 'true',
      'aria-labelledby': titleId,
    });

    // Title
    dialog.appendChild(h('div', { className: 'dialog-header dialog-header--compact' },
      h('span', { className: 'dialog-title', id: titleId }, 'Block IP Address'),
    ));

    const body = h('div', { className: 'dialog-body' });

    // IP input
    this.ipInput = document.createElement('input');
    this.ipInput.type = 'text';
    this.ipInput.className = 'dialog-input dialog-input--ip';
    this.ipInput.placeholder = 'IP address or CIDR range';
    this.ipInput.setAttribute('aria-label', 'IP address to block');
    body.appendChild(this.ipInput);

    // Error message
    this.errorEl = h('div', { className: 'dialog-error', style: { display: 'none' } });
    body.appendChild(this.errorEl);

    // Host selector
    const hostField = h('div', { className: 'dialog-field dialog-field--inline' },
      h('label', { className: 'dialog-label' }, 'On'),
    );
    this.hostSelect = document.createElement('select');
    this.hostSelect.className = 'dialog-select';

    // Add "All Connected Hosts" option first
    const allOption = document.createElement('option');
    allOption.value = '__all__';
    allOption.textContent = 'All Connected Hosts';
    this.hostSelect.appendChild(allOption);

    // Add individual hosts
    const state = this.store.getState();
    const hosts = Array.from(state.hosts.values());
    for (const host of hosts) {
      if (host.status === 'connected') {
        const option = document.createElement('option');
        option.value = host.id;
        option.textContent = host.name;
        this.hostSelect.appendChild(option);
      }
    }

    hostField.appendChild(this.hostSelect);
    body.appendChild(hostField);

    dialog.appendChild(body);

    // Footer
    const footer = h('div', { className: 'dialog-footer' });
    const spacer = h('div', { className: 'dialog-footer-spacer' });
    const cancelBtn = h('button', { className: 'dialog-btn dialog-btn--secondary' }, 'Cancel');
    this.blockBtn = document.createElement('button');
    this.blockBtn.className = 'dialog-btn dialog-btn--primary';
    this.blockBtn.textContent = 'Block Now';
    this.blockBtn.disabled = true;

    this.listen(cancelBtn, 'click', () => this.close());
    this.listen(this.blockBtn, 'click', () => this.handleBlock());

    footer.appendChild(spacer);
    footer.appendChild(cancelBtn);
    footer.appendChild(this.blockBtn);
    dialog.appendChild(footer);

    this.overlay.appendChild(dialog);
    this.el.appendChild(this.overlay);

    // Focus trapping
    trapFocus(dialog, this.ac.signal);

    // Auto-focus
    requestAnimationFrame(() => this.ipInput.focus());

    // Close on overlay click
    this.listen(this.overlay, 'click', (e) => {
      if (e.target === this.overlay) this.close();
    });

    // Close on Escape
    this.listen(document, 'keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Escape') this.close();
    });
  }

  private bindEvents(): void {
    this.listen(this.ipInput, 'input', () => this.validate());
    this.listen(this.ipInput, 'paste', () => {
      requestAnimationFrame(() => this.validate());
    });
    this.listen(this.ipInput, 'keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Enter' && !this.blockBtn.disabled) {
        this.handleBlock();
      }
    });
  }

  private validate(): boolean {
    const value = this.ipInput.value.trim();
    this.errorEl.style.display = 'none';
    this.blockBtn.disabled = true;

    if (!value) return false;

    // Check if valid IP or CIDR
    const isIp = isValidIPv4(value) || isValidIPv6(value);
    const isCidr = isValidCIDR(value);

    if (!isIp && !isCidr) {
      this.showError('Enter a valid IP address or CIDR range');
      return false;
    }

    // Reject dangerous addresses
    const bareIp = value.includes('/') ? value.split('/')[0] : value;
    const cidrSuffix = value.includes('/') ? value.split('/')[1] : null;

    if (value === '0.0.0.0/0' || (bareIp === '0.0.0.0' && cidrSuffix === '0')) {
      this.showError('Cannot block 0.0.0.0/0 — this would block all traffic');
      return false;
    }

    if (bareIp === '127.0.0.1' || bareIp === '::1') {
      this.showError('Cannot block loopback address');
      return false;
    }

    // Check against management IP
    const state = this.store.getState();
    const activeHostId = state.activeHostId;
    if (activeHostId) {
      const activeHost = state.hosts.get(activeHostId);
      if (activeHost) {
        const mgmtIf = activeHost.capabilities?.managementInterface;
        if (mgmtIf) {
          const mgmtIp = activeHost.capabilities?.interfaces
            .find(iface => iface.name === mgmtIf)?.addresses[0];
          if (mgmtIp && bareIp === mgmtIp) {
            this.showError('Cannot block your management IP — you would lose SSH access');
            return false;
          }
        }
      }
    }

    this.blockBtn.disabled = false;
    return true;
  }

  private showError(msg: string): void {
    this.errorEl.textContent = msg;
    this.errorEl.style.display = '';
    this.ipInput.classList.add('dialog-input--error');
  }

  private handleBlock(): void {
    const ip = this.ipInput.value.trim();
    if (!this.validate()) return;

    const hostId = this.hostSelect.value;
    const state = this.store.getState();

    const targetHostIds: string[] = [];
    if (hostId === '__all__') {
      for (const [id, host] of state.hosts) {
        if (host.status === 'connected') {
          targetHostIds.push(id);
        }
      }
    } else {
      targetHostIds.push(hostId);
    }

    const now = Date.now();
    for (const targetId of targetHostIds) {
      this.store.dispatch({
        type: 'ADD_STAGED_CHANGE',
        hostId: targetId,
        change: {
          type: 'add',
          rule: {
            id: crypto.randomUUID(),
            label: `Block ${ip}`,
            action: 'block',
            source: { type: 'cidr', value: ip.includes('/') ? ip : `${ip}/32` },
            destination: { type: 'anyone' },
            direction: 'incoming',
            addressFamily: isValidIPv6(ip.split('/')[0]) ? 'v6' : 'v4',
            origin: { type: 'user' },
            position: 0,
            enabled: true,
            comment: 'Quick block',
            createdAt: now,
            updatedAt: now,
          },
          position: 0,
        },
      });
    }

    this.close();
  }

  private close(): void {
    this.store.dispatch({ type: 'TOGGLE_QUICK_BLOCK', open: false });
    this.overlay.remove();
    if (this.triggerElement instanceof HTMLElement) {
      this.triggerElement.focus();
    }
    this.destroy();
  }
}
