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
import { fetchRules, tracePacket, liveTrace } from '../../ipc/bridge';
import type { TestPacket, LiveTraceRequest, LiveTraceResult } from '../../ipc/bridge';

export class TerminalTab extends Component {
  constructor(container: HTMLElement, store: Store) {
    super(container, store);
  }

  /** Re-render the terminal tab content. */
  renderContent(): void {
    this.el.innerHTML = '';

    const placeholder = h('div', { className: 'rule-table__terminal-placeholder' });

    const subTabs = h('div', {
      className: 'rule-table__terminal-sub-tabs',
      role: 'tablist',
      'aria-label': 'Terminal views',
    });
    const state = this.store.getState();
    const activeSubTab = state.activeTerminalSubTab;

    const subTabDefs: Array<{ id: AppState['activeTerminalSubTab']; label: string }> = [
      { id: 'raw', label: 'Raw Rules' },
      { id: 'tracer', label: 'Packet Tracer' },
      { id: 'livetrace', label: 'Live Trace' },
      { id: 'sshlog', label: 'SSH Log' },
    ];

    for (const st of subTabDefs) {
      const isActive = activeSubTab === st.id;
      const btn = h('button', {
        className: `rule-table__terminal-sub-tab${isActive ? ' rule-table__terminal-sub-tab--active' : ''}`,
        type: 'button',
        role: 'tab',
        'aria-selected': isActive ? 'true' : 'false',
        dataset: { subTab: st.id },
      }, st.label);
      this.listen(btn, 'click', () => {
        this.store.dispatch({ type: 'SET_TERMINAL_SUB_TAB', subTab: st.id });
        this.renderContent();
      });
      subTabs.appendChild(btn);
    }
    placeholder.appendChild(subTabs);

    const contentEl = h('div', { className: 'terminal__content', role: 'tabpanel' });

    switch (activeSubTab) {
      case 'raw':
        this.renderRawRulesSubTab(contentEl);
        break;
      case 'tracer':
        this.renderPacketTracerSubTab(contentEl);
        break;
      case 'livetrace':
        this.renderLiveTraceSubTab(contentEl);
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

  private renderLiveTraceSubTab(container: HTMLElement): void {
    const form = h('div', { className: 'terminal__tracer-form' });

    const fields: Array<{ id: string; label: string; placeholder: string }> = [
      { id: 'sourceIp', label: 'Source IP', placeholder: '10.0.0.1' },
      { id: 'destIp', label: 'Destination IP', placeholder: '192.168.1.1' },
      { id: 'destPort', label: 'Destination Port', placeholder: '22' },
      { id: 'interfaceIn', label: 'Interface', placeholder: 'eth0' },
    ];

    const inputs: Record<string, HTMLInputElement> = {};
    for (const f of fields) {
      const field = h('div', { className: 'terminal__tracer-field' });
      field.appendChild(h('label', { className: 'dialog-label', for: `lt-${f.id}` }, f.label));
      const input = document.createElement('input');
      input.type = 'text';
      input.id = `lt-${f.id}`;
      input.className = 'dialog-input dialog-input--ip';
      input.placeholder = f.placeholder;
      inputs[f.id] = input;
      field.appendChild(input);
      form.appendChild(field);
    }

    // Protocol dropdown
    const protoField = h('div', { className: 'terminal__tracer-field' });
    protoField.appendChild(h('label', { className: 'dialog-label', for: 'lt-protocol' }, 'Protocol'));
    const protoSelect = document.createElement('select');
    protoSelect.id = 'lt-protocol';
    protoSelect.className = 'dialog-select';
    for (const proto of ['', 'tcp', 'udp', 'icmp']) {
      const opt = document.createElement('option');
      opt.value = proto;
      opt.textContent = proto ? proto.toUpperCase() : 'Any';
      protoSelect.appendChild(opt);
    }
    protoField.appendChild(protoSelect);
    form.appendChild(protoField);

    // Timeout field
    const timeoutField = h('div', { className: 'terminal__tracer-field' });
    timeoutField.appendChild(h('label', { className: 'dialog-label', for: 'lt-timeout' }, 'Timeout (s)'));
    const timeoutInput = document.createElement('input');
    timeoutInput.type = 'number';
    timeoutInput.id = 'lt-timeout';
    timeoutInput.className = 'dialog-input';
    timeoutInput.value = '10';
    timeoutInput.min = '1';
    timeoutInput.max = '60';
    timeoutField.appendChild(timeoutInput);
    form.appendChild(timeoutField);

    // Start Trace button
    const traceBtn = h('button', {
      className: 'dialog-btn dialog-btn--primary',
      type: 'button',
      style: { marginTop: '12px' },
    }, 'Start Trace');

    const resultArea = h('div', { className: 'terminal__tracer-result' });

    this.listen(traceBtn, 'click', () => {
      const traceState = this.store.getState();
      const hostId = traceState.activeHostId;
      if (!hostId) {
        resultArea.textContent = 'No host selected.';
        return;
      }

      const request: LiveTraceRequest = {
        sourceIp: inputs['sourceIp'].value.trim() || null,
        destIp: inputs['destIp'].value.trim() || null,
        protocol: protoSelect.value || null,
        destPort: inputs['destPort'].value.trim() ? parseInt(inputs['destPort'].value, 10) : null,
        interfaceIn: inputs['interfaceIn'].value.trim() || null,
        timeoutSecs: parseInt(timeoutInput.value, 10) || 10,
      };

      // Disable button and show countdown
      traceBtn.setAttribute('disabled', 'true');
      traceBtn.textContent = `Tracing (${request.timeoutSecs}s)...`;
      resultArea.innerHTML = '';
      resultArea.appendChild(h('div', { className: 'terminal__live-trace-status' },
        'Inserting TRACE rules and collecting output...'));

      let countdown = request.timeoutSecs;
      const countdownInterval = setInterval(() => {
        countdown--;
        if (countdown > 0) {
          traceBtn.textContent = `Tracing (${countdown}s)...`;
        }
      }, 1000);

      liveTrace(hostId, request).then((result: LiveTraceResult) => {
        clearInterval(countdownInterval);
        traceBtn.removeAttribute('disabled');
        traceBtn.textContent = 'Start Trace';
        resultArea.innerHTML = '';

        // Show collection method
        resultArea.appendChild(h('div', { className: 'terminal__live-trace-method' },
          `Collection method: ${result.collectionMethod}`));

        // Show cleanup status
        const statusParts: string[] = [];
        if (result.traceRuleInserted) statusParts.push('TRACE rules inserted');
        if (result.traceRuleRemoved) statusParts.push('TRACE rules removed');
        if (!result.traceRuleRemoved) statusParts.push('WARNING: TRACE rules may not have been removed');
        resultArea.appendChild(h('div', { className: 'terminal__live-trace-status' },
          statusParts.join(' | ')));

        if (result.events.length === 0) {
          resultArea.appendChild(h('div', { className: 'terminal__live-trace-empty' },
            'No events captured. Try broadening your filter or increasing the timeout.'));
          return;
        }

        // Build results table
        const table = document.createElement('table');
        table.className = 'terminal__live-trace-table';

        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        for (const col of ['Timestamp', 'Table', 'Chain', 'Rule #', 'Verdict', 'Packet Info']) {
          const th = document.createElement('th');
          th.textContent = col;
          headerRow.appendChild(th);
        }
        thead.appendChild(headerRow);
        table.appendChild(thead);

        const tbody = document.createElement('tbody');
        for (const event of result.events) {
          const row = document.createElement('tr');
          for (const val of [event.timestamp, event.table, event.chain, String(event.ruleNum), event.verdict, event.packetInfo]) {
            const td = document.createElement('td');
            td.textContent = val;
            row.appendChild(td);
          }
          tbody.appendChild(row);
        }
        table.appendChild(tbody);
        resultArea.appendChild(table);
      }).catch((err) => {
        clearInterval(countdownInterval);
        traceBtn.removeAttribute('disabled');
        traceBtn.textContent = 'Start Trace';
        resultArea.textContent = `Live trace failed: ${err instanceof Error ? err.message : 'Unknown error'}`;
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
