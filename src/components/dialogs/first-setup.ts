/**
 * First Setup dialog — shown on first connection to a host.
 *
 * Shows detected services, suggests rules, and offers quick setup options.
 * Handles three scenarios: clean server, existing rules, Docker/fail2ban detected.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { DetectedService, DetectedTool, Rule } from '../../store/types';
import { h } from '../../utils/dom';

export interface FirstSetupConfig {
  hostId: string;
  hostName: string;
  scenario: 'clean' | 'existing' | 'system-tools';
  services: DetectedService[];
  existingRuleCount: number;
  ruleHealthGood: number;
  ruleHealthWarnings: string[];
  ruleHealthSuggestions: string[];
  detectedTools: DetectedTool[];
  suggestedRules: SuggestedRule[];
  managementIp?: string;
}

export interface SuggestedRule {
  label: string;
  description: string;
  checked: boolean;
  rule: Rule;
  isBlockAll?: boolean;
}

export class FirstSetupDialog extends Component {
  private overlay!: HTMLElement;
  private config: FirstSetupConfig;
  private checkboxes: Map<string, HTMLInputElement> = new Map();
  private onCompleteCallback: ((selectedRules: Rule[]) => void) | null = null;
  private onSkipCallback: (() => void) | null = null;

  constructor(container: HTMLElement, store: Store, config: FirstSetupConfig) {
    super(container, store);
    this.config = config;
    this.render();
  }

  onComplete(cb: (selectedRules: Rule[]) => void): void {
    this.onCompleteCallback = cb;
  }

  onSkip(cb: () => void): void {
    this.onSkipCallback = cb;
  }

  private render(): void {
    this.overlay = h('div', { className: 'dialog-overlay' });
    const dialog = h('div', { className: 'dialog-card dialog-card--first-setup' });

    switch (this.config.scenario) {
      case 'clean':
        this.renderCleanSetup(dialog);
        break;
      case 'existing':
        this.renderExistingRules(dialog);
        break;
      case 'system-tools':
        this.renderSystemTools(dialog);
        break;
    }

    this.overlay.appendChild(dialog);
    this.el.appendChild(this.overlay);

    // Stagger animations for suggested rules
    const ruleItems = dialog.querySelectorAll('.setup-rule-item');
    ruleItems.forEach((item, idx) => {
      const el = item as HTMLElement;
      el.style.opacity = '0';
      el.style.transform = 'translateY(8px)';
      setTimeout(() => {
        el.style.transition = 'opacity 200ms ease-out, transform 200ms ease-out';
        el.style.opacity = '1';
        el.style.transform = 'translateY(0)';
      }, 100 * idx);
    });
  }

  private renderCleanSetup(dialog: HTMLElement): void {
    // Header
    dialog.appendChild(h('div', { className: 'dialog-header' },
      h('span', { className: 'dialog-title' }, `${this.config.hostName} \u2014 Quick Setup`),
    ));

    const body = h('div', { className: 'dialog-body' });

    body.appendChild(h('p', { className: 'setup-notice' },
      'This server has no firewall rules. All traffic is currently allowed.',
    ));

    // Detected services
    if (this.config.services.length > 0) {
      body.appendChild(h('h3', { className: 'setup-section-title' }, 'Detected services:'));
      const servicesTable = h('div', { className: 'setup-services' });
      const maxVisible = 5;
      const visibleServices = this.config.services.slice(0, maxVisible);
      const hiddenCount = this.config.services.length - maxVisible;

      for (const svc of visibleServices) {
        servicesTable.appendChild(
          h('div', { className: 'setup-service-row' },
            h('span', { className: 'setup-service-name' }, svc.name),
            h('span', { className: 'setup-service-ports' }, `port${svc.ports.length > 1 ? 's' : ''} ${svc.ports.join(', ')}`),
          ),
        );
      }

      if (hiddenCount > 0) {
        const showMoreBtn = h('button', { className: 'dialog-btn dialog-btn--text setup-show-more' },
          `Show ${hiddenCount} more services...`,
        );
        this.listen(showMoreBtn, 'click', () => {
          servicesTable.innerHTML = '';
          for (const svc of this.config.services) {
            servicesTable.appendChild(
              h('div', { className: 'setup-service-row' },
                h('span', { className: 'setup-service-name' }, svc.name),
                h('span', { className: 'setup-service-ports' }, `port${svc.ports.length > 1 ? 's' : ''} ${svc.ports.join(', ')}`),
              ),
            );
          }
          showMoreBtn.remove();
        });
        servicesTable.appendChild(showMoreBtn);
      }

      body.appendChild(servicesTable);
    }

    // Suggested rules
    if (this.config.suggestedRules.length > 0) {
      body.appendChild(h('h3', { className: 'setup-section-title' }, 'Suggested rules:'));
      body.appendChild(this.renderSuggestedRules());
    }

    if (this.config.managementIp) {
      body.appendChild(h('p', { className: 'setup-footnote' }, `* Your current IP address: ${this.config.managementIp}`));
    }

    dialog.appendChild(body);

    // Footer
    const footer = h('div', { className: 'dialog-footer dialog-footer--setup' });
    const skipBtn = h('button', { className: 'dialog-btn dialog-btn--text' }, 'Skip \u2014 I\'ll configure manually');
    const customizeBtn = h('button', { className: 'dialog-btn dialog-btn--secondary' }, 'Customize First');
    const applyBtn = h('button', { className: 'dialog-btn dialog-btn--primary' }, 'Apply & Secure');

    this.listen(skipBtn, 'click', () => this.handleSkip());
    this.listen(customizeBtn, 'click', () => this.handleCustomize());
    this.listen(applyBtn, 'click', () => this.handleApply());

    footer.appendChild(skipBtn);
    footer.appendChild(customizeBtn);
    footer.appendChild(applyBtn);
    dialog.appendChild(footer);
  }

  private renderExistingRules(dialog: HTMLElement): void {
    dialog.appendChild(h('div', { className: 'dialog-header' },
      h('span', { className: 'dialog-title' }, `${this.config.hostName} \u2014 Existing Rules Detected`),
    ));

    const body = h('div', { className: 'dialog-body' });

    body.appendChild(h('p', { className: 'setup-notice' },
      `This server has ${this.config.existingRuleCount} existing firewall rules. We imported them \u2014 no changes were made.`,
    ));

    // Rule health check
    body.appendChild(h('h3', { className: 'setup-section-title' }, 'Rule Health Check:'));
    const healthEl = h('div', { className: 'setup-health' });

    if (this.config.ruleHealthGood > 0) {
      healthEl.appendChild(h('div', { className: 'setup-health-item setup-health-item--good' },
        `\u2705 ${this.config.ruleHealthGood} rules look good`,
      ));
    }

    for (const warning of this.config.ruleHealthWarnings) {
      healthEl.appendChild(h('div', { className: 'setup-health-item setup-health-item--warning' },
        `\u26A0\uFE0F ${warning}`,
      ));
    }

    for (const suggestion of this.config.ruleHealthSuggestions) {
      healthEl.appendChild(h('div', { className: 'setup-health-item setup-health-item--suggestion' },
        `\uD83D\uDCA1 ${suggestion}`,
      ));
    }

    body.appendChild(healthEl);

    // Suggested rules preview
    if (this.config.suggestedRules.length > 0) {
      body.appendChild(h('h3', { className: 'setup-section-title' }, 'Preview:'));
      body.appendChild(this.renderSuggestedRules());
    }

    dialog.appendChild(body);

    // Footer
    const footer = h('div', { className: 'dialog-footer' });
    const spacer = h('div', { className: 'dialog-footer-spacer' });
    const importBtn = h('button', { className: 'dialog-btn dialog-btn--primary' }, 'Import & Manage');

    this.listen(importBtn, 'click', () => this.handleApply());

    footer.appendChild(spacer);
    footer.appendChild(importBtn);
    dialog.appendChild(footer);
  }

  private renderSystemTools(dialog: HTMLElement): void {
    dialog.appendChild(h('div', { className: 'dialog-header' },
      h('span', { className: 'dialog-title' }, 'System Rules Detected'),
    ));

    const body = h('div', { className: 'dialog-body' });

    for (const tool of this.config.detectedTools) {
      const toolEl = h('div', { className: 'setup-tool' });
      const icon = tool.type === 'docker' ? '\uD83D\uDC33' : '\uD83D\uDEE1\uFE0F';
      const name = tool.type === 'docker' ? 'Docker' : tool.type === 'fail2ban' ? 'fail2ban' : tool.type;
      toolEl.appendChild(h('div', { className: 'setup-tool-header' },
        h('span', { className: 'setup-tool-icon' }, icon),
        h('span', { className: 'setup-tool-name' }, name),
      ));
      toolEl.appendChild(h('p', { className: 'setup-tool-detail' },
        `${tool.ruleCount} rules in ${tool.chains.join(', ')} chain${tool.chains.length > 1 ? 's' : ''}`,
      ));
      body.appendChild(toolEl);
    }

    body.appendChild(h('p', { className: 'setup-notice setup-notice--info' },
      'System rules are shown read-only and will never be modified by this app. Your rules coexist safely alongside them.',
    ));

    dialog.appendChild(body);

    // Footer
    const footer = h('div', { className: 'dialog-footer' });
    const spacer = h('div', { className: 'dialog-footer-spacer' });
    const gotItBtn = h('button', { className: 'dialog-btn dialog-btn--primary' }, 'Got it');

    this.listen(gotItBtn, 'click', () => this.close());

    footer.appendChild(spacer);
    footer.appendChild(gotItBtn);
    dialog.appendChild(footer);
  }

  private renderSuggestedRules(): HTMLElement {
    const list = h('div', { className: 'setup-rules-list' });

    for (const suggested of this.config.suggestedRules) {
      const item = h('div', { className: 'setup-rule-item' });

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.checked = suggested.checked;
      checkbox.className = 'setup-rule-checkbox';
      checkbox.id = `setup-rule-${suggested.rule.id}`;
      this.checkboxes.set(suggested.rule.id, checkbox);

      const indicator = h('span', {
        className: `setup-rule-indicator setup-rule-indicator--${suggested.isBlockAll ? 'block' : 'allow'}`,
      }, suggested.isBlockAll ? '\uD83D\uDD34' : '\u2705');

      const label = h('label', {
        className: 'setup-rule-label',
        for: `setup-rule-${suggested.rule.id}`,
      }, suggested.label);

      item.appendChild(checkbox);
      item.appendChild(indicator);
      item.appendChild(label);

      if (suggested.description) {
        item.appendChild(h('span', { className: 'setup-rule-desc' }, suggested.description));
      }

      list.appendChild(item);
    }

    return list;
  }

  private getSelectedRules(): Rule[] {
    const selected: Rule[] = [];
    for (const suggested of this.config.suggestedRules) {
      const checkbox = this.checkboxes.get(suggested.rule.id);
      if (checkbox?.checked) {
        selected.push(suggested.rule);
      }
    }
    return selected;
  }

  private handleApply(): void {
    const selectedRules = this.getSelectedRules();
    this.onCompleteCallback?.(selectedRules);
    this.close();
  }

  private handleCustomize(): void {
    // Apply selected rules but also switch to rules view for customization
    const selectedRules = this.getSelectedRules();
    this.onCompleteCallback?.(selectedRules);
    this.close();
  }

  private handleSkip(): void {
    this.onSkipCallback?.();
    this.close();
  }

  private close(): void {
    this.overlay.remove();
    this.destroy();
  }
}
