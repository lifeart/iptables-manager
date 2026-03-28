/**
 * Terminal tab sub-component.
 *
 * Renders the terminal tab content with sub-tabs:
 * Raw Rules, Packet Tracer, and SSH Log.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState } from '../../store/types';
import { h } from '../../utils/dom';
import { fetchRules, tracePacket } from '../../ipc/bridge';
import type { TestPacket } from '../../ipc/bridge';

export class TerminalTab extends Component {
  constructor(container: HTMLElement, store: Store) {
    super(container, store);
  }

  /** Re-render the terminal tab content. */
  renderContent(): void {
    this.el.innerHTML = '';

    const placeholder = h('div', { className: 'rule-table__terminal-placeholder' });

    const subTabs = h('div', { className: 'rule-table__terminal-sub-tabs' });
    const state = this.store.getState();
    const activeSubTab = state.activeTerminalSubTab;

    const subTabDefs: Array<{ id: AppState['activeTerminalSubTab']; label: string }> = [
      { id: 'raw', label: 'Raw Rules' },
      { id: 'tracer', label: 'Packet Tracer' },
      { id: 'sshlog', label: 'SSH Log' },
    ];

    for (const st of subTabDefs) {
      const btn = h('button', {
        className: `rule-table__terminal-sub-tab${activeSubTab === st.id ? ' rule-table__terminal-sub-tab--active' : ''}`,
        type: 'button',
        dataset: { subTab: st.id },
      }, st.label);
      this.listen(btn, 'click', () => {
        this.store.dispatch({ type: 'SET_TERMINAL_SUB_TAB', subTab: st.id });
        this.renderContent();
      });
      subTabs.appendChild(btn);
    }
    placeholder.appendChild(subTabs);

    const contentEl = h('div', { className: 'terminal__content' });

    switch (activeSubTab) {
      case 'raw':
        this.renderRawRulesSubTab(contentEl);
        break;
      case 'tracer':
        this.renderPacketTracerSubTab(contentEl);
        break;
      case 'sshlog':
        this.renderSshLogSubTab(contentEl);
        break;
    }

    placeholder.appendChild(contentEl);
    this.el.appendChild(placeholder);
  }

  private renderRawRulesSubTab(container: HTMLElement): void {
    const state = this.store.getState();
    const hostId = state.activeHostId;

    const textarea = document.createElement('textarea');
    textarea.className = 'terminal__editor';
    textarea.spellcheck = false;
    textarea.rows = 30;
    textarea.value = '# Connect to a host to see rules';

    if (hostId) {
      textarea.value = '# Loading...';
      fetchRules(hostId).then((ruleSet) => {
        textarea.value = ruleSet.rawIptablesSave || '# No rules loaded';
      }).catch(() => {
        textarea.value = '# Failed to load rules';
      });
    }

    container.appendChild(textarea);
  }

  private renderPacketTracerSubTab(container: HTMLElement): void {
    const form = h('div', { className: 'terminal__tracer-form' });

    const fields: Array<{ id: string; label: string; placeholder: string }> = [
      { id: 'sourceIp', label: 'Source IP', placeholder: '192.168.1.100' },
      { id: 'destIp', label: 'Destination IP', placeholder: '10.0.1.10' },
      { id: 'destPort', label: 'Destination Port', placeholder: '80' },
    ];

    const inputs: Record<string, HTMLInputElement> = {};
    for (const f of fields) {
      const field = h('div', { className: 'terminal__tracer-field' });
      field.appendChild(h('label', { className: 'dialog-label', for: `tracer-${f.id}` }, f.label));
      const input = document.createElement('input');
      input.type = 'text';
      input.id = `tracer-${f.id}`;
      input.className = 'dialog-input dialog-input--ip';
      input.placeholder = f.placeholder;
      inputs[f.id] = input;
      field.appendChild(input);
      form.appendChild(field);
    }

    const protoField = h('div', { className: 'terminal__tracer-field' });
    protoField.appendChild(h('label', { className: 'dialog-label', for: 'tracer-protocol' }, 'Protocol'));
    const protoSelect = document.createElement('select');
    protoSelect.id = 'tracer-protocol';
    protoSelect.className = 'dialog-select';
    for (const proto of ['tcp', 'udp', 'icmp']) {
      const opt = document.createElement('option');
      opt.value = proto;
      opt.textContent = proto.toUpperCase();
      protoSelect.appendChild(opt);
    }
    protoField.appendChild(protoSelect);
    form.appendChild(protoField);

    const traceBtn = h('button', {
      className: 'dialog-btn dialog-btn--primary',
      type: 'button',
      style: { marginTop: '12px' },
    }, 'Trace');

    const resultArea = h('div', { className: 'terminal__tracer-result' });

    this.listen(traceBtn, 'click', () => {
      const traceState = this.store.getState();
      const hostId = traceState.activeHostId;
      if (!hostId) {
        resultArea.textContent = 'No host selected.';
        return;
      }

      const packet: TestPacket = {
        sourceIp: inputs['sourceIp'].value.trim() || '0.0.0.0',
        destIp: inputs['destIp'].value.trim() || '0.0.0.0',
        destPort: parseInt(inputs['destPort'].value, 10) || 0,
        protocol: protoSelect.value as 'tcp' | 'udp' | 'icmp',
        interfaceIn: '',
        direction: 'Incoming',
        conntrackState: 'New',
      };

      resultArea.textContent = 'Tracing...';
      tracePacket(hostId, packet).then((result) => {
        resultArea.innerHTML = '';
        resultArea.appendChild(h('div', { className: 'terminal__tracer-verdict' },
          `Verdict: ${result.verdict}`));
        if (result.chain.length > 0) {
          const chainPath = result.chain.map(t => `${t.table}/${t.chain}`).join(' -> ');
          resultArea.appendChild(h('div', { className: 'terminal__tracer-chain' },
            `Chain path: ${chainPath}`));
        }
        resultArea.appendChild(h('div', { className: 'terminal__tracer-explanation' },
          result.explanation));
      }).catch((err) => {
        resultArea.textContent = `Trace failed: ${err instanceof Error ? err.message : 'Unknown error'}`;
      });
    });

    form.appendChild(traceBtn);
    container.appendChild(form);
    container.appendChild(resultArea);
  }

  private renderSshLogSubTab(container: HTMLElement): void {
    const state = this.store.getState();
    const hostId = state.activeHostId;
    const hostState = hostId ? state.hostStates.get(hostId) : undefined;
    const sshLog = hostState?.sshCommandLog ?? [];

    const logContainer = h('div', { className: 'terminal__ssh-log' });

    if (sshLog.length === 0) {
      const demoEntries = [
        { timestamp: Date.now() - 300000, command: 'iptables-save', output: '', exitCode: 0 },
        { timestamp: Date.now() - 240000, command: 'iptables -L -n --line-numbers', output: '', exitCode: 0 },
        { timestamp: Date.now() - 180000, command: 'cat /proc/sys/net/netfilter/nf_conntrack_count', output: '', exitCode: 0 },
      ];

      for (const entry of demoEntries) {
        const ts = new Date(entry.timestamp).toLocaleTimeString();
        const line = h('div', { className: 'terminal__ssh-log-entry' },
          h('span', { className: 'terminal__ssh-log-time' }, ts),
          h('span', { className: 'terminal__ssh-log-cmd' }, `$ ${entry.command}`),
        );
        logContainer.appendChild(line);
      }
    } else {
      for (const entry of sshLog) {
        const ts = new Date(entry.timestamp).toLocaleTimeString();
        const line = h('div', { className: 'terminal__ssh-log-entry' },
          h('span', { className: 'terminal__ssh-log-time' }, ts),
          h('span', { className: 'terminal__ssh-log-cmd' }, `$ ${entry.command}`),
        );
        logContainer.appendChild(line);
      }
    }

    container.appendChild(logContainer);
  }
}
