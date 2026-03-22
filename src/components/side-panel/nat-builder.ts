/**
 * NAT rule builders — Port Forwarding (DNAT) and Source NAT (MASQUERADE/SNAT).
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { Rule, AddressSpec } from '../../store/types';
import { h } from '../../utils/dom';
import { AddressPicker } from '../rule-builder/address-picker';
import { isValidPort } from '../../utils/ip-validate';

// ──────────────────────────────────────────────
// Port Forwarding (DNAT) Builder
// ──────────────────────────────────────────────

export class PortForwardBuilder extends Component {
  private externalPortInput!: HTMLInputElement;
  private targetIpInput!: HTMLInputElement;
  private targetPortInput!: HTMLInputElement;
  private protocolSelect!: HTMLSelectElement;
  private nameInput!: HTMLInputElement;
  private hairpinCheckbox!: HTMLInputElement;
  private addressPicker: AddressPicker | null = null;
  private selectedSource: AddressSpec = { type: 'anyone' };
  private errorEl!: HTMLElement;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
  }

  private render(): void {
    this.el.innerHTML = '';
    const form = h('div', { className: 'nat-builder' });

    // Title
    form.appendChild(h('h2', { className: 'side-panel__title' }, 'New Port Forward'));

    // Description
    form.appendChild(h('p', {
      style: { fontSize: '13px', color: 'var(--color-text-secondary)', marginBottom: '16px' },
    }, 'Forward incoming traffic on a port to an internal server.'));

    // External port
    const extGroup = this.fieldGroup('When traffic arrives on port');
    this.externalPortInput = document.createElement('input');
    this.externalPortInput.type = 'text';
    this.externalPortInput.className = 'rule-builder__input';
    this.externalPortInput.placeholder = 'e.g. 8080';
    this.externalPortInput.inputMode = 'numeric';
    extGroup.appendChild(this.externalPortInput);
    form.appendChild(extGroup);

    // Target IP + port
    const fwdLabel = h('label', { className: 'rule-builder__field-label' }, 'Forward it to');
    form.appendChild(fwdLabel);

    const targetRow = h('div', { style: { display: 'flex', gap: '8px', marginBottom: '12px' } });
    this.targetIpInput = document.createElement('input');
    this.targetIpInput.type = 'text';
    this.targetIpInput.className = 'rule-builder__input';
    this.targetIpInput.placeholder = 'IP address (e.g. 10.0.1.5)';
    this.targetIpInput.style.flex = '2';
    targetRow.appendChild(this.targetIpInput);

    const portLabel = h('span', {
      style: { alignSelf: 'center', color: 'var(--color-text-secondary)', fontSize: '13px' },
    }, 'port');
    targetRow.appendChild(portLabel);

    this.targetPortInput = document.createElement('input');
    this.targetPortInput.type = 'text';
    this.targetPortInput.className = 'rule-builder__input';
    this.targetPortInput.placeholder = '80';
    this.targetPortInput.inputMode = 'numeric';
    this.targetPortInput.style.flex = '1';
    targetRow.appendChild(this.targetPortInput);
    form.appendChild(targetRow);

    // Source restriction
    const sourceGroup = this.fieldGroup('From');
    const sourceContainer = h('div');
    this.addressPicker = new AddressPicker(sourceContainer, this.store, this.selectedSource, (addr) => {
      this.selectedSource = addr;
    });
    this.addChild(this.addressPicker);
    sourceGroup.appendChild(sourceContainer);
    form.appendChild(sourceGroup);

    // Protocol
    const protoGroup = this.fieldGroup('Protocol');
    this.protocolSelect = document.createElement('select');
    this.protocolSelect.className = 'rule-builder__select';
    this.protocolSelect.appendChild(this.opt('tcp', 'TCP'));
    this.protocolSelect.appendChild(this.opt('udp', 'UDP'));
    protoGroup.appendChild(this.protocolSelect);
    form.appendChild(protoGroup);

    // Name
    const nameGroup = this.fieldGroup('Name');
    this.nameInput = document.createElement('input');
    this.nameInput.type = 'text';
    this.nameInput.className = 'rule-builder__input';
    this.nameInput.placeholder = 'e.g. Web backend forward';
    nameGroup.appendChild(this.nameInput);
    form.appendChild(nameGroup);

    // Hairpin NAT
    const hairpinRow = h('label', {
      style: { display: 'flex', alignItems: 'center', gap: '8px', margin: '12px 0', fontSize: '13px', cursor: 'pointer' },
    });
    this.hairpinCheckbox = document.createElement('input');
    this.hairpinCheckbox.type = 'checkbox';
    hairpinRow.appendChild(this.hairpinCheckbox);
    hairpinRow.appendChild(document.createTextNode('Allow internal clients to reach this via the external IP'));
    form.appendChild(hairpinRow);

    // Error message
    this.errorEl = h('div', {
      style: { color: 'var(--color-block)', fontSize: '12px', minHeight: '20px', marginTop: '4px' },
    });
    form.appendChild(this.errorEl);

    // Buttons
    const btnRow = h('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '16px' } });
    const cancelBtn = h('button', {
      className: 'rule-builder__btn-secondary',
      type: 'button',
      style: { padding: '6px 16px', borderRadius: '6px', border: '1px solid var(--color-border)', background: 'transparent', color: 'var(--color-text-primary)', cursor: 'pointer', fontSize: '13px' },
    }, 'Cancel');
    this.listen(cancelBtn, 'click', () => {
      this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: false });
    });
    btnRow.appendChild(cancelBtn);

    const addBtn = h('button', {
      type: 'button',
      style: { padding: '6px 16px', borderRadius: '6px', border: 'none', background: 'var(--color-primary)', color: '#fff', cursor: 'pointer', fontSize: '13px', fontWeight: '500' },
    }, 'Add Forward');
    this.listen(addBtn, 'click', () => this.onSave());
    btnRow.appendChild(addBtn);
    form.appendChild(btnRow);

    this.el.appendChild(form);
  }

  private onSave(): void {
    this.errorEl.textContent = '';

    const extPort = this.externalPortInput.value.trim();
    const targetIp = this.targetIpInput.value.trim();
    const targetPort = this.targetPortInput.value.trim();

    if (!extPort || !isValidPort(parseInt(extPort, 10))) {
      this.errorEl.textContent = 'Enter a valid external port (1-65535)';
      return;
    }
    if (!targetIp) {
      this.errorEl.textContent = 'Enter the target IP address';
      return;
    }
    if (!targetPort || !isValidPort(parseInt(targetPort, 10))) {
      this.errorEl.textContent = 'Enter a valid target port (1-65535)';
      return;
    }

    const hostId = this.store.getState().activeHostId;
    if (!hostId) return;

    const now = Date.now();
    const rule: Rule = {
      id: `rule-${now}-${Math.random().toString(36).slice(2, 7)}`,
      label: this.nameInput.value.trim() || `Port ${extPort} → ${targetIp}:${targetPort}`,
      action: 'dnat',
      protocol: this.protocolSelect.value as Rule['protocol'],
      ports: { type: 'single', port: parseInt(extPort, 10) },
      source: this.selectedSource,
      destination: { type: 'anyone' },
      direction: 'incoming',
      addressFamily: 'both',
      dnat: {
        targetIp,
        targetPort: parseInt(targetPort, 10),
        hairpinNat: this.hairpinCheckbox.checked,
      },
      comment: this.nameInput.value.trim(),
      origin: { type: 'user' },
      position: 0,
      enabled: true,
      createdAt: now,
      updatedAt: now,
    };

    this.store.dispatch({
      type: 'ADD_STAGED_CHANGE',
      hostId,
      change: { type: 'add', rule, position: 0 },
    });

    this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: false });
  }

  private fieldGroup(label: string): HTMLElement {
    const group = h('div', { style: { marginBottom: '12px' } });
    group.appendChild(h('label', { className: 'rule-builder__field-label' }, label));
    return group;
  }

  private opt(value: string, text: string): HTMLOptionElement {
    const o = document.createElement('option');
    o.value = value;
    o.textContent = text;
    return o;
  }
}

// ──────────────────────────────────────────────
// Source NAT (MASQUERADE / SNAT) Builder
// ──────────────────────────────────────────────

export class SourceNatBuilder extends Component {
  private sourceInput!: HTMLInputElement;
  private interfaceSelect!: HTMLSelectElement;
  private methodRadios: HTMLInputElement[] = [];
  private snatIpInput!: HTMLInputElement;
  private nameInput!: HTMLInputElement;
  private errorEl!: HTMLElement;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
  }

  private render(): void {
    this.el.innerHTML = '';
    const form = h('div', { className: 'nat-builder' });

    form.appendChild(h('h2', { className: 'side-panel__title' }, 'New Source NAT Rule'));
    form.appendChild(h('p', {
      style: { fontSize: '13px', color: 'var(--color-text-secondary)', marginBottom: '16px' },
    }, 'Translate source addresses for outgoing traffic (e.g. VPN clients accessing the internet).'));

    // Traffic from (source subnet)
    const srcGroup = this.fieldGroup('Traffic from');
    this.sourceInput = document.createElement('input');
    this.sourceInput.type = 'text';
    this.sourceInput.className = 'rule-builder__input';
    this.sourceInput.placeholder = 'e.g. 10.200.0.0/24';
    srcGroup.appendChild(this.sourceInput);
    form.appendChild(srcGroup);

    // NAT via interface
    const ifaceGroup = this.fieldGroup('NAT via interface');
    this.interfaceSelect = document.createElement('select');
    this.interfaceSelect.className = 'rule-builder__select';
    this.interfaceSelect.appendChild(this.opt('eth0', 'eth0'));

    // Populate from host interfaces
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (hostId) {
      const host = state.hosts.get(hostId);
      const ifaces = host?.capabilities?.interfaces ?? [];
      if (ifaces.length > 0) {
        this.interfaceSelect.innerHTML = '';
        for (const iface of ifaces) {
          if (iface.type !== 'loopback') {
            const addr = iface.addresses[0] ? ` (${iface.addresses[0]})` : '';
            this.interfaceSelect.appendChild(this.opt(iface.name, `${iface.name}${addr}`));
          }
        }
      }
    }
    ifaceGroup.appendChild(this.interfaceSelect);
    form.appendChild(ifaceGroup);

    // Method
    const methodGroup = this.fieldGroup('Method');

    const masqLabel = h('label', {
      style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px', fontSize: '13px', cursor: 'pointer' },
    });
    const masqRadio = document.createElement('input');
    masqRadio.type = 'radio';
    masqRadio.name = 'nat-method';
    masqRadio.value = 'masquerade';
    masqRadio.checked = true;
    this.methodRadios.push(masqRadio);
    masqLabel.appendChild(masqRadio);
    masqLabel.appendChild(document.createTextNode('MASQUERADE (dynamic IP — recommended for most setups)'));
    methodGroup.appendChild(masqLabel);

    const snatLabel = h('label', {
      style: { display: 'flex', alignItems: 'start', gap: '8px', fontSize: '13px', cursor: 'pointer' },
    });
    const snatRadio = document.createElement('input');
    snatRadio.type = 'radio';
    snatRadio.name = 'nat-method';
    snatRadio.value = 'snat';
    this.methodRadios.push(snatRadio);
    snatLabel.appendChild(snatRadio);
    const snatText = h('div');
    snatText.appendChild(document.createTextNode('SNAT (static IP — better performance for datacenters)'));
    this.snatIpInput = document.createElement('input');
    this.snatIpInput.type = 'text';
    this.snatIpInput.className = 'rule-builder__input';
    this.snatIpInput.placeholder = 'Static IP (e.g. 198.51.100.1)';
    this.snatIpInput.style.marginTop = '6px';
    this.snatIpInput.disabled = true;
    snatText.appendChild(this.snatIpInput);
    snatLabel.appendChild(snatText);
    methodGroup.appendChild(snatLabel);

    // Toggle SNAT IP field on radio change
    this.listen(masqRadio, 'change', () => { this.snatIpInput.disabled = true; });
    this.listen(snatRadio, 'change', () => { this.snatIpInput.disabled = false; this.snatIpInput.focus(); });

    form.appendChild(methodGroup);

    // Name
    const nameGroup = this.fieldGroup('Name');
    this.nameInput = document.createElement('input');
    this.nameInput.type = 'text';
    this.nameInput.className = 'rule-builder__input';
    this.nameInput.placeholder = 'e.g. VPN Masquerade';
    nameGroup.appendChild(this.nameInput);
    form.appendChild(nameGroup);

    // Error
    this.errorEl = h('div', {
      style: { color: 'var(--color-block)', fontSize: '12px', minHeight: '20px', marginTop: '4px' },
    });
    form.appendChild(this.errorEl);

    // Buttons
    const btnRow = h('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '16px' } });
    const cancelBtn = h('button', {
      type: 'button',
      style: { padding: '6px 16px', borderRadius: '6px', border: '1px solid var(--color-border)', background: 'transparent', color: 'var(--color-text-primary)', cursor: 'pointer', fontSize: '13px' },
    }, 'Cancel');
    this.listen(cancelBtn, 'click', () => {
      this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: false });
    });
    btnRow.appendChild(cancelBtn);

    const addBtn = h('button', {
      type: 'button',
      style: { padding: '6px 16px', borderRadius: '6px', border: 'none', background: 'var(--color-primary)', color: '#fff', cursor: 'pointer', fontSize: '13px', fontWeight: '500' },
    }, 'Add NAT Rule');
    this.listen(addBtn, 'click', () => this.onSave());
    btnRow.appendChild(addBtn);
    form.appendChild(btnRow);

    this.el.appendChild(form);
  }

  private onSave(): void {
    this.errorEl.textContent = '';
    const source = this.sourceInput.value.trim();
    if (!source) {
      this.errorEl.textContent = 'Enter the source subnet (e.g. 10.200.0.0/24)';
      return;
    }

    const isMasquerade = this.methodRadios[0]?.checked;
    if (!isMasquerade) {
      const snatIp = this.snatIpInput.value.trim();
      if (!snatIp) {
        this.errorEl.textContent = 'Enter the static source IP for SNAT';
        return;
      }
    }

    const hostId = this.store.getState().activeHostId;
    if (!hostId) return;

    const action = isMasquerade ? 'masquerade' : 'snat';
    const snatNow = Date.now();
    const rule: Rule = {
      id: `rule-${snatNow}-${Math.random().toString(36).slice(2, 7)}`,
      label: this.nameInput.value.trim() || `${action === 'masquerade' ? 'Masquerade' : 'SNAT'} ${source}`,
      action: action as Rule['action'],
      source: { type: 'cidr', value: source },
      destination: { type: 'anyone' },
      direction: 'outgoing',
      addressFamily: 'both',
      interfaceOut: this.interfaceSelect.value,
      snat: action === 'snat' ? { sourceIp: this.snatIpInput.value.trim() } : undefined,
      comment: this.nameInput.value.trim(),
      origin: { type: 'user' },
      position: 0,
      enabled: true,
      createdAt: snatNow,
      updatedAt: snatNow,
    };

    this.store.dispatch({
      type: 'ADD_STAGED_CHANGE',
      hostId,
      change: { type: 'add', rule, position: 0 },
    });

    this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: false });
  }

  private fieldGroup(label: string): HTMLElement {
    const group = h('div', { style: { marginBottom: '12px' } });
    group.appendChild(h('label', { className: 'rule-builder__field-label' }, label));
    return group;
  }

  private opt(value: string, text: string): HTMLOptionElement {
    const o = document.createElement('option');
    o.value = value;
    o.textContent = text;
    return o;
  }
}
