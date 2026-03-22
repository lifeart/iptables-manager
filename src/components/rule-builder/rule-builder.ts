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
import type { Rule, AddressSpec, PortSpec } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';
import { ServicePicker, type ServiceSelection } from './service-picker';
import { AddressPicker } from './address-picker';

export interface RuleFormData {
  label: string;
  action: Rule['action'];
  protocol: Rule['protocol'];
  ports: PortSpec | undefined;
  source: AddressSpec;
  comment: string;
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

    // ─── Action ────────────────────────────────────────────────
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

    // ─── Service ───────────────────────────────────────────────
    const serviceGroup = this.createFieldGroup('Service');
    const serviceContainer = h('div', { className: 'rule-builder__service-container' });
    this.servicePicker = new ServicePicker(serviceContainer, store, this.serviceSelection, (sel) => {
      this.serviceSelection = sel;
    });
    this.addChild(this.servicePicker);
    serviceGroup.appendChild(serviceContainer);
    this.formEl.appendChild(serviceGroup);

    // ─── Source ────────────────────────────────────────────────
    const sourceGroup = this.createFieldGroup('Source');
    const sourceContainer = h('div', { className: 'rule-builder__source-container' });
    this.addressPicker = new AddressPicker(sourceContainer, store, this.selectedSource, (addr) => {
      this.selectedSource = addr;
    });
    this.addChild(this.addressPicker);
    sourceGroup.appendChild(sourceContainer);
    this.formEl.appendChild(sourceGroup);

    // ─── Comment ──────────────────────────────────────────────
    const commentGroup = this.createFieldGroup('Comment');
    this.commentInput = document.createElement('input');
    this.commentInput.type = 'text';
    this.commentInput.className = 'rule-builder__input';
    this.commentInput.placeholder = 'Optional comment...';
    this.commentInput.value = this.commentValue;
    this.listen(this.commentInput, 'input', () => {
      this.commentValue = this.commentInput.value;
    });
    commentGroup.appendChild(this.commentInput);
    this.formEl.appendChild(commentGroup);

    // ─── More Options ─────────────────────────────────────────
    const moreOptionsLink = h('button', {
      className: 'rule-builder__more-options-link',
      type: 'button',
    }, 'More options...');
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
    };
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
    // Interface selector
    const interfaceGroup = this.createFieldGroup('Interface');
    const interfaceSelect = document.createElement('select');
    interfaceSelect.className = 'rule-builder__select';
    interfaceSelect.appendChild(this.createOption('any', 'Any interface'));
    interfaceGroup.appendChild(interfaceSelect);
    this.moreOptionsContainer.appendChild(interfaceGroup);

    // Duration selector
    const durationGroup = this.createFieldGroup('Duration');
    const durationSelect = document.createElement('select');
    durationSelect.className = 'rule-builder__select';
    durationSelect.appendChild(this.createOption('permanent', 'Permanent'));
    durationSelect.appendChild(this.createOption('1h', '1 hour'));
    durationSelect.appendChild(this.createOption('4h', '4 hours'));
    durationSelect.appendChild(this.createOption('24h', '24 hours'));
    durationSelect.appendChild(this.createOption('1w', '1 week'));
    durationGroup.appendChild(durationSelect);
    this.moreOptionsContainer.appendChild(durationGroup);

    // Details section
    const detailsHeader = h('div', { className: 'rule-builder__section-header' }, 'Details');
    this.moreOptionsContainer.appendChild(detailsHeader);

    const protocolField = this.createFieldGroup('Protocol');
    const protocolDisplay = h('span', { className: 'rule-builder__static-value' },
      this.serviceSelection.protocol ? String(this.serviceSelection.protocol).toUpperCase() : 'Any');
    protocolField.appendChild(protocolDisplay);
    this.moreOptionsContainer.appendChild(protocolField);

    const portField = this.createFieldGroup('Port');
    const portDisplay = h('span', { className: 'rule-builder__static-value' },
      this.serviceSelection.ports ? this.formatPorts(this.serviceSelection.ports) : 'Any');
    portField.appendChild(portDisplay);
    this.moreOptionsContainer.appendChild(portField);

    const directionField = this.createFieldGroup('Direction');
    const directionDisplay = h('span', { className: 'rule-builder__static-value' }, 'Incoming');
    directionField.appendChild(directionDisplay);
    this.moreOptionsContainer.appendChild(directionField);

    // Advanced section
    const advancedHeader = h('div', { className: 'rule-builder__section-header' }, 'Advanced');
    this.moreOptionsContainer.appendChild(advancedHeader);

    // Conntrack states
    const conntrackGroup = this.createFieldGroup('Conntrack');
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

    // iptables preview disclosure
    const disclosure = h('details', { className: 'rule-builder__disclosure' });
    const summary = h('summary', { className: 'rule-builder__disclosure-summary' },
      'Show iptables command');
    disclosure.appendChild(summary);
    const codeBlock = h('pre', { className: 'rule-builder__code' },
      h('code', {}, this.generateIptablesPreview()));
    disclosure.appendChild(codeBlock);
    this.moreOptionsContainer.appendChild(disclosure);
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
