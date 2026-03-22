/**
 * Rule builder — the main form for creating/editing rules.
 *
 * Fields:
 *   - Action: segmented control (Allow | Block | Log | Log+Block)
 *   - Service: combobox with categorized dropdown
 *   - Source: combobox (Anyone, My IP, Local Net, etc.)
 *   - Comment: text input
 *   - "More options..." reveals advanced fields with height animation
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { Rule, AddressSpec, PortSpec, NetworkInterface } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';
import { ServicePicker, type ServiceSelection } from './service-picker';
import { AddressPicker } from './address-picker';
import { selectActiveHost } from '../../store/selectors';

export interface RuleFormData {
  label: string;
  action: Rule['action'];
  protocol: Rule['protocol'];
  ports: PortSpec | undefined;
  source: AddressSpec;
  comment: string;
  interfaceIn: string | undefined;
  duration?: 'permanent' | '1h' | '4h' | '24h' | '1w';
}

type ActionChoice = 'allow' | 'block' | 'log' | 'log-block';

const ACTION_OPTIONS: { value: ActionChoice; label: string }[] = [
  { value: 'allow', label: 'Allow' },
  { value: 'block', label: 'Block' },
  { value: 'log', label: 'Log' },
  { value: 'log-block', label: 'Log+Block' },
];

export class RuleBuilder extends Component {
  private formEl: HTMLElement;
  private selectedAction: ActionChoice = 'allow';
  private serviceSelection: ServiceSelection = { label: '', protocol: undefined, ports: undefined };
  private selectedSource: AddressSpec = { type: 'anyone' };
  private commentValue = '';
  private moreOptionsOpen = false;

  private segmentEls: Map<ActionChoice, HTMLElement> = new Map();
  private segmentIndicator: HTMLElement;
  private commentInput: HTMLInputElement;
  private moreOptionsContainer: HTMLElement;
  private servicePicker: ServicePicker | null = null;
  private addressPicker: AddressPicker | null = null;

  // Interface selector (shown in main form when host has 2+ interfaces)
  private interfaceGroup: HTMLElement | null = null;
  private interfaceSelect: HTMLSelectElement | null = null;
  private selectedInterface = 'any';
  private selectedDuration: 'permanent' | '1h' | '4h' | '24h' | '1w' = 'permanent';

  // Rate limit UI state
  private rateLimitEnabled = false;
  private rateLimitMax = '';
  private rateLimitScope: 'source' | 'global' = 'source';
  private rateLimitPer: 'second' | 'minute' = 'second';
  private rateLimitBurst = '';

  // Cached "More options" display elements
  private protocolDisplay: HTMLElement | null = null;
  private portDisplay: HTMLElement | null = null;
  private directionDisplay: HTMLElement | null = null;
  private previewCodeEl: HTMLElement | null = null;

  constructor(container: HTMLElement, store: Store, existingRule: Rule | null) {
    super(container, store);

    // Initialize from existing rule if editing
    if (existingRule) {
      this.selectedAction = this.ruleActionToChoice(existingRule.action);
      this.serviceSelection = {
        label: existingRule.label,
        protocol: existingRule.protocol,
        ports: existingRule.ports,
      };
      this.selectedSource = existingRule.source;
      this.commentValue = existingRule.comment ?? '';
    }

    this.formEl = h('div', { className: 'rule-builder' });

    // --- Action ---
    const actionGroup = this.createFieldGroup('Action');
    const segmentControl = h('div', { className: 'rule-builder__segment-control' });
    this.segmentIndicator = h('div', { className: 'rule-builder__segment-indicator' });
    segmentControl.appendChild(this.segmentIndicator);

    for (const opt of ACTION_OPTIONS) {
      const btn = h('button', {
        className: 'rule-builder__segment-btn',
        type: 'button',
        dataset: { value: opt.value },
      }, opt.label);
      if (opt.value === this.selectedAction) {
        btn.classList.add('rule-builder__segment-btn--active');
      }
      this.listen(btn, 'click', () => this.selectAction(opt.value));
      this.segmentEls.set(opt.value, btn);
      segmentControl.appendChild(btn);
    }
    actionGroup.appendChild(segmentControl);
    this.formEl.appendChild(actionGroup);

    // --- Service ---
    const serviceGroup = this.createFieldGroup('Service');
    const serviceContainer = h('div', { className: 'rule-builder__service-container' });
    this.servicePicker = new ServicePicker(serviceContainer, store, this.serviceSelection, (sel) => {
      this.serviceSelection = sel;
      this.updateMoreOptionsDetails();
      this.updatePreview();
    });
    this.addChild(this.servicePicker);
    serviceGroup.appendChild(serviceContainer);
    this.formEl.appendChild(serviceGroup);

    // --- Source ---
    const sourceGroup = this.createFieldGroup('Source');
    const sourceContainer = h('div', { className: 'rule-builder__source-container' });
    this.addressPicker = new AddressPicker(sourceContainer, store, this.selectedSource, (addr) => {
      this.selectedSource = addr;
      this.updatePreview();
    });
    this.addChild(this.addressPicker);
    sourceGroup.appendChild(sourceContainer);
    this.formEl.appendChild(sourceGroup);

    // --- Interface (shown when host has 2+ interfaces) ---
    this.interfaceGroup = this.createFieldGroup('Interface');
    this.interfaceGroup.style.display = 'none';
    this.interfaceSelect = document.createElement('select');
    this.interfaceSelect.className = 'rule-builder__select';
    this.interfaceSelect.appendChild(this.createOption('any', 'Any interface'));
    this.listen(this.interfaceSelect, 'change', () => {
      if (this.interfaceSelect) {
        this.selectedInterface = this.interfaceSelect.value;
        this.updatePreview();
      }
    });
    this.interfaceGroup.appendChild(this.interfaceSelect);
    this.formEl.appendChild(this.interfaceGroup);
    this.populateInterfaces();

    // --- Comment ---
    const commentGroup = this.createFieldGroup('Comment');
    this.commentInput = document.createElement('input');
    this.commentInput.type = 'text';
    this.commentInput.className = 'rule-builder__input';
    this.commentInput.placeholder = 'Optional comment...';
    this.commentInput.value = this.commentValue;
    this.listen(this.commentInput, 'input', () => {
      this.commentValue = this.commentInput.value;
      this.updatePreview();
    });
    commentGroup.appendChild(this.commentInput);
    this.formEl.appendChild(commentGroup);

    // --- More Options ---
    const moreOptionsLink = h('button', {
      className: 'rule-builder__more-options-link',
      type: 'button',
    }, 'Show advanced options...');
    this.listen(moreOptionsLink, 'click', () => this.toggleMoreOptions());
    this.formEl.appendChild(moreOptionsLink);

    this.moreOptionsContainer = h('div', { className: 'rule-builder__more-options' });
    this.moreOptionsContainer.style.display = 'none';
    this.buildMoreOptions();
    this.formEl.appendChild(this.moreOptionsContainer);

    this.el.appendChild(this.formEl);

    // Position the segment indicator after layout
    requestAnimationFrame(() => this.updateSegmentIndicator());
  }

  getFormData(): RuleFormData {
    return {
      label: this.serviceSelection.label || 'Custom Rule',
      action: this.selectedAction,
      protocol: this.serviceSelection.protocol,
      ports: this.serviceSelection.ports,
      source: this.selectedSource,
      comment: this.commentValue,
      interfaceIn: this.selectedInterface === 'any' ? undefined : this.selectedInterface,
      duration: this.selectedDuration,
    };
  }

  /**
   * Populate the interface selector from the active host's capabilities.
   * Only shows the selector when the host has 2 or more interfaces.
   */
  private populateInterfaces(): void {
    const host = this.store.select(selectActiveHost);
    const interfaces = host?.capabilities?.interfaces;

    if (!interfaces || interfaces.length < 2) {
      if (this.interfaceGroup) {
        this.interfaceGroup.style.display = 'none';
      }
      return;
    }

    if (this.interfaceGroup) {
      this.interfaceGroup.style.display = '';
    }

    if (this.interfaceSelect) {
      // Clear existing options except the first "Any"
      while (this.interfaceSelect.options.length > 1) {
        this.interfaceSelect.remove(1);
      }

      for (const iface of interfaces) {
        const addrStr = iface.addresses.length > 0 ? ` (${iface.addresses[0]})` : '';
        const label = `${iface.name}${addrStr}`;
        this.interfaceSelect.appendChild(this.createOption(iface.name, label));
      }
    }
  }

  private ruleActionToChoice(action: Rule['action']): ActionChoice {
    switch (action) {
      case 'allow': return 'allow';
      case 'block':
      case 'block-reject': return 'block';
      case 'log': return 'log';
      case 'log-block': return 'log-block';
      default: return 'allow';
    }
  }

  private selectAction(value: ActionChoice): void {
    this.selectedAction = value;
    for (const [key, el] of this.segmentEls) {
      el.classList.toggle('rule-builder__segment-btn--active', key === value);
    }
    this.updateSegmentIndicator();
    this.updatePreview();
  }

  private updateSegmentIndicator(): void {
    const activeBtn = this.segmentEls.get(this.selectedAction);
    if (!activeBtn) return;

    const container = activeBtn.parentElement;
    if (!container) return;

    const containerRect = container.getBoundingClientRect();
    const btnRect = activeBtn.getBoundingClientRect();

    this.segmentIndicator.style.left = `${btnRect.left - containerRect.left}px`;
    this.segmentIndicator.style.width = `${btnRect.width}px`;
  }

  private createFieldGroup(label: string): HTMLElement {
    const group = h('div', { className: 'rule-builder__field-group' });
    group.appendChild(h('label', { className: 'rule-builder__field-label' }, label));
    return group;
  }

  private toggleMoreOptions(): void {
    this.moreOptionsOpen = !this.moreOptionsOpen;
    this.moreOptionsContainer.style.display = this.moreOptionsOpen ? '' : 'none';
    this.moreOptionsContainer.classList.toggle('rule-builder__more-options--open', this.moreOptionsOpen);
  }

  private buildMoreOptions(): void {
    // Duration selector
    const durationGroup = this.createFieldGroup('Duration');
    const durationSelect = document.createElement('select');
    durationSelect.className = 'rule-builder__select';
    durationSelect.appendChild(this.createOption('permanent', 'Permanent'));
    durationSelect.appendChild(this.createOption('1h', '1 hour'));
    durationSelect.appendChild(this.createOption('4h', '4 hours'));
    durationSelect.appendChild(this.createOption('24h', '24 hours'));
    durationSelect.appendChild(this.createOption('1w', '1 week'));
    this.listen(durationSelect, 'change', () => {
      this.selectedDuration = durationSelect.value as typeof this.selectedDuration;
    });
    durationGroup.appendChild(durationSelect);
    this.moreOptionsContainer.appendChild(durationGroup);

    // Details section
    const detailsHeader = h('div', { className: 'rule-builder__section-header' }, 'Details');
    this.moreOptionsContainer.appendChild(detailsHeader);

    const protocolField = this.createFieldGroup('Protocol');
    this.protocolDisplay = h('span', { className: 'rule-builder__static-value' },
      this.serviceSelection.protocol ? String(this.serviceSelection.protocol).toUpperCase() : 'Any');
    protocolField.appendChild(this.protocolDisplay);
    this.moreOptionsContainer.appendChild(protocolField);

    const portField = this.createFieldGroup('Port');
    this.portDisplay = h('span', { className: 'rule-builder__static-value' },
      this.serviceSelection.ports ? this.formatPorts(this.serviceSelection.ports) : 'Any');
    portField.appendChild(this.portDisplay);
    this.moreOptionsContainer.appendChild(portField);

    const directionField = this.createFieldGroup('Direction');
    this.directionDisplay = h('span', { className: 'rule-builder__static-value' }, 'Incoming');
    directionField.appendChild(this.directionDisplay);
    this.moreOptionsContainer.appendChild(directionField);

    // Advanced section
    const advancedHeader = h('div', { className: 'rule-builder__section-header' }, 'Advanced');
    this.moreOptionsContainer.appendChild(advancedHeader);

    // Connection states (conntrack)
    const conntrackGroup = this.createFieldGroup('Connection States');
    const states = ['New', 'Established', 'Related'];
    const stateContainer = h('div', { className: 'rule-builder__checkbox-group' });
    for (const state of states) {
      const checkLabel = h('label', { className: 'rule-builder__checkbox-label' });
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.className = 'rule-builder__checkbox';
      checkbox.checked = state !== 'Related';
      checkLabel.appendChild(checkbox);
      checkLabel.appendChild(document.createTextNode(` ${state}`));
      stateContainer.appendChild(checkLabel);
    }
    conntrackGroup.appendChild(stateContainer);
    this.moreOptionsContainer.appendChild(conntrackGroup);

    // Rate Limit
    const rateLimitGroup = this.createFieldGroup('Rate Limit');
    const rateLimitCheckLabel = h('label', { className: 'rule-builder__checkbox-label' });
    const rateLimitCheckbox = document.createElement('input');
    rateLimitCheckbox.type = 'checkbox';
    rateLimitCheckbox.className = 'rule-builder__checkbox';
    rateLimitCheckLabel.appendChild(rateLimitCheckbox);
    rateLimitCheckLabel.appendChild(document.createTextNode(' Enable rate limiting'));
    rateLimitGroup.appendChild(rateLimitCheckLabel);

    const rateLimitFields = h('div', {
      className: 'rule-builder__rate-limit-fields',
      style: { display: 'none', marginTop: '8px', gap: '6px' },
    });

    const maxLabel = document.createTextNode('Max ');
    rateLimitFields.appendChild(maxLabel);
    const maxInput = document.createElement('input');
    maxInput.type = 'number';
    maxInput.className = 'rule-builder__input';
    maxInput.placeholder = '10';
    maxInput.style.width = '60px';
    maxInput.style.display = 'inline-block';
    this.listen(maxInput, 'input', () => { this.rateLimitMax = maxInput.value; });
    rateLimitFields.appendChild(maxInput);

    rateLimitFields.appendChild(document.createTextNode(' per '));
    const scopeSelect = document.createElement('select');
    scopeSelect.className = 'rule-builder__select';
    scopeSelect.style.width = 'auto';
    scopeSelect.style.display = 'inline-block';
    scopeSelect.appendChild(this.createOption('source', 'Source IP'));
    scopeSelect.appendChild(this.createOption('global', 'Global'));
    this.listen(scopeSelect, 'change', () => {
      this.rateLimitScope = scopeSelect.value as 'source' | 'global';
    });
    rateLimitFields.appendChild(scopeSelect);

    rateLimitFields.appendChild(document.createTextNode(' per '));
    const perSelect = document.createElement('select');
    perSelect.className = 'rule-builder__select';
    perSelect.style.width = 'auto';
    perSelect.style.display = 'inline-block';
    perSelect.appendChild(this.createOption('second', 'Second'));
    perSelect.appendChild(this.createOption('minute', 'Minute'));
    this.listen(perSelect, 'change', () => {
      this.rateLimitPer = perSelect.value as 'second' | 'minute';
    });
    rateLimitFields.appendChild(perSelect);

    rateLimitFields.appendChild(document.createTextNode(' Burst '));
    const burstInput = document.createElement('input');
    burstInput.type = 'number';
    burstInput.className = 'rule-builder__input';
    burstInput.placeholder = '5';
    burstInput.style.width = '60px';
    burstInput.style.display = 'inline-block';
    this.listen(burstInput, 'input', () => { this.rateLimitBurst = burstInput.value; });
    rateLimitFields.appendChild(burstInput);

    this.listen(rateLimitCheckbox, 'change', () => {
      this.rateLimitEnabled = rateLimitCheckbox.checked;
      rateLimitFields.style.display = rateLimitCheckbox.checked ? '' : 'none';
    });

    rateLimitGroup.appendChild(rateLimitFields);
    this.moreOptionsContainer.appendChild(rateLimitGroup);

    // iptables preview disclosure
    const disclosure = h('details', { className: 'rule-builder__disclosure' });
    const summary = h('summary', { className: 'rule-builder__disclosure-summary' },
      'Show iptables command');
    disclosure.appendChild(summary);
    this.previewCodeEl = h('code', {}, this.generateIptablesPreview());
    const codeBlock = h('pre', { className: 'rule-builder__code' }, this.previewCodeEl);
    disclosure.appendChild(codeBlock);
    this.moreOptionsContainer.appendChild(disclosure);
  }

  /**
   * Update the "More options" detail fields when service selection changes.
   */
  private updateMoreOptionsDetails(): void {
    if (this.protocolDisplay) {
      this.protocolDisplay.textContent =
        this.serviceSelection.protocol ? String(this.serviceSelection.protocol).toUpperCase() : 'Any';
    }
    if (this.portDisplay) {
      this.portDisplay.textContent =
        this.serviceSelection.ports ? this.formatPorts(this.serviceSelection.ports) : 'Any';
    }
  }

  /**
   * Regenerate the iptables preview text when form state changes.
   */
  private updatePreview(): void {
    if (this.previewCodeEl) {
      this.previewCodeEl.textContent = this.generateIptablesPreview();
    }
  }

  private createOption(value: string, text: string): HTMLOptionElement {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = text;
    return option;
  }

  private formatPorts(ports: PortSpec): string {
    switch (ports.type) {
      case 'single': return String(ports.port);
      case 'range': return `${ports.from}-${ports.to}`;
      case 'multi': return ports.ports.join(', ');
      default: return '';
    }
  }

  private generateIptablesPreview(): string {
    const parts = ['iptables', '-A', 'INPUT'];

    if (this.selectedInterface !== 'any') {
      parts.push('-i', this.selectedInterface);
    }

    if (this.serviceSelection.protocol) {
      parts.push('-p', String(this.serviceSelection.protocol));
    }

    if (this.serviceSelection.ports) {
      parts.push('--dport', this.formatPorts(this.serviceSelection.ports));
    }

    if (this.selectedSource.type === 'cidr') {
      parts.push('-s', this.selectedSource.value);
    }

    switch (this.selectedAction) {
      case 'allow': parts.push('-j', 'ACCEPT'); break;
      case 'block': parts.push('-j', 'DROP'); break;
      case 'log': parts.push('-j', 'LOG'); break;
      case 'log-block': parts.push('-j', 'LOG'); break;
    }

    if (this.commentValue) {
      parts.push('-m', 'comment', '--comment', `"${this.commentValue}"`);
    }

    return parts.join(' ');
  }
}
