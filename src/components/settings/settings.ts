/**
 * Settings panel — theme, safety timeout, auto-refresh,
 * IP version mode, default action, system rules visibility,
 * SSH timeouts, export/import, about section.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, AppSettings } from '../../store/types';
import { themeManager } from '../../services/theme';
import { h } from '../../utils/dom';

export class Settings extends Component {
  // Cached element references for in-place updates
  private themeSelect: HTMLSelectElement | null = null;
  private safetyTimeoutSelect: HTMLSelectElement | null = null;
  private pollIntervalSelect: HTMLSelectElement | null = null;
  private showSystemRulesCheckbox: HTMLInputElement | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.render();
    this.bindSubscriptions();
  }

  private render(): void {
    this.el.innerHTML = '';
    this.el.className = 'settings-panel';

    const settings = this.store.getState().settings;

    // Header
    this.el.appendChild(h('div', { className: 'settings-panel__header' },
      h('h1', { className: 'settings-panel__title' }, 'Settings'),
    ));

    const body = h('div', { className: 'settings-panel__body' });

    // --- General Section ---
    body.appendChild(this.renderSectionHeader('General'));

    // Theme selector
    const themeField = this.renderSelect('Theme', 'theme', settings.theme, [
      { value: 'light', label: 'Light' },
      { value: 'dark', label: 'Dark' },
      { value: 'system', label: 'System (follow OS)' },
    ]);
    this.themeSelect = themeField.querySelector('select');
    body.appendChild(themeField);

    // Safety timeout
    const safetyField = this.renderSelect('Safety timeout', 'safetyTimeout', String(settings.defaultSafetyTimeout), [
      { value: '30', label: '30 seconds' },
      { value: '60', label: '60 seconds (recommended)' },
      { value: '120', label: '120 seconds' },
      { value: '0', label: 'Disabled (dangerous)' },
    ]);
    this.safetyTimeoutSelect = safetyField.querySelector('select');
    body.appendChild(safetyField);

    // Auto-refresh interval
    const pollField = this.renderSelect('Auto-refresh', 'pollInterval', String(settings.pollIntervalMs), [
      { value: '10000', label: 'Every 10 seconds' },
      { value: '30000', label: 'Every 30 seconds' },
      { value: '60000', label: 'Every 60 seconds' },
      { value: '0', label: 'Manual only' },
    ]);
    this.pollIntervalSelect = pollField.querySelector('select');
    body.appendChild(pollField);

    // --- Advanced Section ---
    body.appendChild(this.renderSectionHeader('Advanced'));

    // IP version mode
    body.appendChild(this.renderRadioGroup('IP Version', 'ipVersion', [
      { value: 'combined', label: 'IPv4 and IPv6 together', checked: true },
      { value: 'separate', label: 'Manage separately', checked: false },
    ]));

    // Default action
    body.appendChild(this.renderSelect('Default action', 'defaultAction', 'block', [
      { value: 'block', label: 'Block (recommended)' },
      { value: 'allow', label: 'Allow' },
    ]));

    // System rules visibility — "Show system rules" with direct value
    const sysRulesField = this.renderCheckbox(
      'Show system rules',
      'showSystemRules',
      settings.showSystemRules,
      'Docker, K8s, fail2ban rules',
    );
    this.showSystemRulesCheckbox = sysRulesField.querySelector('input[type="checkbox"]');
    body.appendChild(sysRulesField);

    // SSH connection timeout
    body.appendChild(this.renderNumberField('SSH connection timeout', 'sshConnTimeout', 10, 'seconds'));

    // Command timeout
    body.appendChild(this.renderNumberField('Command timeout', 'cmdTimeout', 30, 'seconds'));

    // --- Data Section ---
    body.appendChild(this.renderSectionHeader('Data'));

    // Export / Import
    const dataRow = h('div', { className: 'settings-panel__data-row' });
    const exportBtn = h('button', { className: 'dialog-btn dialog-btn--secondary' }, 'Export...');
    const importBtn = h('button', { className: 'dialog-btn dialog-btn--secondary' }, 'Import...');
    dataRow.appendChild(h('div', { className: 'settings-panel__data-item' },
      h('span', {}, 'Export all settings and hosts'),
      exportBtn,
    ));
    dataRow.appendChild(h('div', { className: 'settings-panel__data-item' },
      h('span', {}, 'Import from backup'),
      importBtn,
    ));
    body.appendChild(dataRow);

    this.listen(exportBtn, 'click', () => this.handleExport());
    this.listen(importBtn, 'click', () => this.handleImport());

    body.appendChild(h('p', { className: 'settings-panel__hint' },
      'Staged changes are stored locally and persist across app restarts.',
    ));

    // --- About Section ---
    body.appendChild(h('div', { className: 'settings-panel__separator' }));
    body.appendChild(h('div', { className: 'settings-panel__about' },
      h('p', { className: 'settings-panel__about-title' }, 'About'),
      h('p', { className: 'settings-panel__about-version' }, 'Traffic Rules v0.1.0'),
      h('p', { className: 'settings-panel__about-link' }, 'github.com/lifeart/iptables-manager'),
    ));

    this.el.appendChild(body);
  }

  private bindSubscriptions(): void {
    this.subscribe(
      (s: AppState) => s.settings,
      (settings) => {
        // Update individual DOM elements instead of full re-render
        this.updateElements(settings);
      },
    );
  }

  /**
   * Update cached element values in-place to avoid focus loss.
   */
  private updateElements(settings: AppSettings): void {
    if (this.themeSelect && this.themeSelect.value !== settings.theme) {
      this.themeSelect.value = settings.theme;
    }
    if (this.safetyTimeoutSelect && this.safetyTimeoutSelect.value !== String(settings.defaultSafetyTimeout)) {
      this.safetyTimeoutSelect.value = String(settings.defaultSafetyTimeout);
    }
    if (this.pollIntervalSelect && this.pollIntervalSelect.value !== String(settings.pollIntervalMs)) {
      this.pollIntervalSelect.value = String(settings.pollIntervalMs);
    }
    if (this.showSystemRulesCheckbox && this.showSystemRulesCheckbox.checked !== settings.showSystemRules) {
      this.showSystemRulesCheckbox.checked = settings.showSystemRules;
    }
  }

  private renderSectionHeader(title: string): HTMLElement {
    return h('div', { className: 'settings-panel__section-header' }, title);
  }

  private renderSelect(
    label: string,
    id: string,
    currentValue: string,
    options: Array<{ value: string; label: string }>,
  ): HTMLElement {
    const field = h('div', { className: 'settings-panel__field' },
      h('label', { className: 'settings-panel__label', for: `settings-${id}` }, label),
    );

    const select = document.createElement('select');
    select.id = `settings-${id}`;
    select.className = 'dialog-select settings-panel__select';

    for (const opt of options) {
      const option = document.createElement('option');
      option.value = opt.value;
      option.textContent = opt.label;
      option.selected = opt.value === currentValue;
      select.appendChild(option);
    }

    this.listen(select, 'change', () => {
      this.handleSettingChange(id, select.value);
    });

    field.appendChild(select);
    return field;
  }

  private renderRadioGroup(
    label: string,
    name: string,
    options: Array<{ value: string; label: string; checked: boolean }>,
  ): HTMLElement {
    const field = h('div', { className: 'settings-panel__field' },
      h('label', { className: 'settings-panel__label' }, label),
    );

    const group = h('div', { className: 'settings-panel__radio-group' });
    for (const opt of options) {
      const radio = document.createElement('input');
      radio.type = 'radio';
      radio.name = name;
      radio.value = opt.value;
      radio.id = `settings-${name}-${opt.value}`;
      radio.checked = opt.checked;

      this.listen(radio, 'change', () => {
        if (radio.checked) {
          this.handleSettingChange(name, opt.value);
        }
      });

      group.appendChild(radio);
      group.appendChild(h('label', { for: `settings-${name}-${opt.value}` }, opt.label));
    }

    field.appendChild(group);
    return field;
  }

  private renderCheckbox(
    label: string,
    id: string,
    checked: boolean,
    description: string,
  ): HTMLElement {
    const field = h('div', { className: 'settings-panel__field settings-panel__field--checkbox' });
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.id = `settings-${id}`;
    checkbox.checked = checked;

    this.listen(checkbox, 'change', () => {
      this.handleSettingChange(id, checkbox.checked);
    });

    field.appendChild(checkbox);
    field.appendChild(h('label', { for: `settings-${id}` },
      h('span', {}, label),
      h('span', { className: 'settings-panel__checkbox-desc' }, description),
    ));
    return field;
  }

  private renderNumberField(label: string, id: string, defaultValue: number, suffix: string): HTMLElement {
    const field = h('div', { className: 'settings-panel__field' },
      h('label', { className: 'settings-panel__label', for: `settings-${id}` }, label),
    );

    const inputWrap = h('div', { className: 'settings-panel__number-wrap' });
    const input = document.createElement('input');
    input.type = 'number';
    input.id = `settings-${id}`;
    input.className = 'dialog-input settings-panel__number-input';
    input.value = String(defaultValue);
    input.min = '1';
    input.max = '300';

    this.listen(input, 'change', () => {
      const val = parseInt(input.value, 10);
      if (!isNaN(val) && val > 0) {
        this.handleSettingChange(id, val);
      }
    });

    inputWrap.appendChild(input);
    inputWrap.appendChild(h('span', { className: 'settings-panel__number-suffix' }, suffix));
    field.appendChild(inputWrap);
    return field;
  }

  private handleSettingChange(id: string, value: unknown): void {
    const changes: Partial<AppSettings> = {};

    switch (id) {
      case 'theme':
        changes.theme = value as AppSettings['theme'];
        themeManager.setTheme(value as AppSettings['theme']);
        break;
      case 'safetyTimeout':
        changes.defaultSafetyTimeout = parseInt(value as string, 10);
        break;
      case 'pollInterval':
        changes.pollIntervalMs = parseInt(value as string, 10);
        break;
      case 'showSystemRules':
        changes.showSystemRules = value as boolean;
        break;
      default:
        // Other settings are handled but not yet mapped to AppSettings
        return;
    }

    this.store.dispatch({ type: 'UPDATE_SETTINGS', changes });
  }

  private handleExport(): void {
    const state = this.store.getState();
    const data = {
      hosts: Array.from(state.hosts.values()).map(h => ({
        ...h,
        // Strip credentials
        connection: { ...h.connection, keyPath: undefined },
      })),
      groups: Array.from(state.groups.values()),
      ipLists: Array.from(state.ipLists.values()),
      settings: state.settings,
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'traffic-rules-export.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  private handleImport(): void {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';

    input.addEventListener('change', () => {
      const file = input.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = () => {
        try {
          const data = JSON.parse(reader.result as string);

          // Hydrate store with imported data
          this.store.dispatch({
            type: 'HYDRATE',
            payload: {
              hosts: data.hosts,
              groups: data.groups,
              ipLists: data.ipLists,
              settings: data.settings,
            },
          });
        } catch (err) {
          const errorMsg = err instanceof Error ? err.message : 'Invalid file format';
          const errorBanner = h('div', {
            className: 'settings-panel__import-error',
            style: { color: 'var(--color-block, #FF3B30)', fontSize: '13px', padding: '8px 0' },
          }, `Import failed: ${errorMsg}`);
          const existingError = this.el.querySelector('.settings-panel__import-error');
          if (existingError) existingError.remove();
          this.el.querySelector('.settings-panel__body')?.appendChild(errorBanner);
        }
      };
      reader.readAsText(file);
    });

    input.click();
  }
}
