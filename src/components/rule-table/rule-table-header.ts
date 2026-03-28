/**
 * Rule table header sub-component.
 *
 * Displays the host name, connection status indicator,
 * and action buttons (disconnect/reconnect, export, history).
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, Host } from '../../store/types';
import { selectActiveHost } from '../../store/selectors';
import { h } from '../../utils/dom';
import {
  disconnectHost,
  connectHost,
  fetchRules,
  exportRules,
  provisionHost,
} from '../../ipc/bridge';
import { convertRuleSet } from '../../services/rule-converter';

export class RuleTableHeader extends Component {
  private currentHeaderHostId: string | null = null;
  private currentHeaderStatus: string | null = null;

  /** Fired when there is no active host (triggers welcome screen in parent). */
  public onNoActiveHost: (() => void) | null = null;
  /** Fired when a host becomes active (parent may need to show tabs). */
  public onActiveHost: (() => void) | null = null;
  /** Fired when the "Compare v4/v6" button is clicked. */
  public onCompareV4V6: (() => void) | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.bindSubscriptions();
  }

  private bindSubscriptions(): void {
    this.subscribe(selectActiveHost, (host) => {
      if (host) {
        this.onActiveHost?.();
        const needsRebuild =
          this.currentHeaderHostId !== host.id ||
          this.currentHeaderStatus !== host.status;

        if (needsRebuild) {
          this.currentHeaderHostId = host.id;
          this.currentHeaderStatus = host.status;
          this.rebuildHeader(host);
        } else {
          const nameEl = this.el.querySelector('.rule-table__host-name');
          if (nameEl && nameEl.textContent !== host.name) {
            nameEl.textContent = host.name;
          }
        }
      } else {
        this.currentHeaderHostId = null;
        this.currentHeaderStatus = null;
        this.el.innerHTML = '';
        this.onNoActiveHost?.();
      }
    });
  }

  private rebuildHeader(host: Host): void {
    this.el.innerHTML = '';
    const nameEl = h('span', { className: 'rule-table__host-name' }, host.name);
    this.el.appendChild(nameEl);

    const statusLabel =
      host.status.charAt(0).toUpperCase() + host.status.slice(1);
    const statusEl = h(
      'span',
      {
        className: `rule-table__host-status rule-table__host-status--${host.status}`,
      },
      statusLabel,
    );
    this.el.appendChild(statusEl);

    const headerBtns = h('div', { className: 'rule-table__header-actions' });

    if (host.status === 'connected') {
      const disconnectBtn = h(
        'button',
        {
          className:
            'rule-table__header-btn rule-table__header-btn--disconnect',
          type: 'button',
          title: 'Disconnect from host',
        },
        'Disconnect',
      );
      this.listen(disconnectBtn, 'click', () =>
        this.handleDisconnect(host.id),
      );
      headerBtns.appendChild(disconnectBtn);
    } else if (
      host.status === 'disconnected' ||
      host.status === 'unreachable'
    ) {
      const reconnectBtn = h(
        'button',
        {
          className:
            'rule-table__header-btn rule-table__header-btn--reconnect',
          type: 'button',
          title: 'Reconnect to host',
        },
        'Reconnect',
      );
      this.listen(reconnectBtn, 'click', () => this.handleReconnect(host));
      headerBtns.appendChild(reconnectBtn);
    }

    const exportBtn = h(
      'button',
      { className: 'rule-table__header-btn', type: 'button', title: 'Export rules' },
      'Export',
    );
    this.listen(exportBtn, 'click', () => {
      this.showExportDropdown(exportBtn, host.id);
    });
    headerBtns.appendChild(exportBtn);

    const historyBtn = h(
      'button',
      { className: 'rule-table__header-btn', type: 'button', title: 'Snapshot History' },
      'History',
    );
    this.listen(historyBtn, 'click', () => {
      this.store.dispatch({
        type: 'SET_SIDE_PANEL_CONTENT',
        content: { type: 'snapshot-history' },
      });
      this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: true });
    });
    headerBtns.appendChild(historyBtn);

    // "Compare v4/v6" button — only visible when dual-stack is enabled
    if (host.dualStackEnabled) {
      const compareBtn = h(
        'button',
        {
          className: 'dual-stack-compare-btn',
          type: 'button',
          title: 'Compare IPv4 and IPv6 rules side by side',
        },
        'Compare v4/v6',
      );
      this.listen(compareBtn, 'click', () => {
        this.onCompareV4V6?.();
      });
      headerBtns.appendChild(compareBtn);
    }

    this.el.appendChild(headerBtns);
  }

  private handleReconnect(host: Host): void {
    this.store.dispatch({
      type: 'SET_HOST_STATUS',
      hostId: host.id,
      status: 'connecting',
    });
    const operationId = `fetchRules-${host.id}-${Date.now()}`;
    connectHost(
      host.id,
      host.connection.hostname,
      host.connection.port,
      host.connection.username,
      host.connection.authMethod,
      host.connection.keyPath,
    )
      .then(() => {
        this.store.dispatch({
          type: 'SET_HOST_STATUS',
          hostId: host.id,
          status: 'connected',
        });
        this.store.dispatch({
          type: 'START_OPERATION',
          operationId,
          operationType: 'fetchRules',
          hostId: host.id,
        });

        if (!host.provisioned) {
          provisionHost(host.id)
            .then((result) => {
              if (result.success) {
                this.store.dispatch({
                  type: 'UPDATE_HOST',
                  hostId: host.id,
                  changes: { provisioned: true },
                });
              }
            })
            .catch((err) => {
              console.warn(`Host provisioning failed for ${host.id}:`, err);
            });
        }

        return fetchRules(host.id);
      })
      .then((ruleData) => {
        const rules = convertRuleSet(ruleData);
        this.store.dispatch({ type: 'SET_HOST_RULES', hostId: host.id, rules });
        this.store.dispatch({ type: 'COMPLETE_OPERATION', operationId });
      })
      .catch((err) => {
        this.store.dispatch({
          type: 'SET_HOST_STATUS',
          hostId: host.id,
          status: 'unreachable',
        });
        const errorMsg =
          err instanceof Error ? err.message : 'Connection failed';
        this.store.dispatch({
          type: 'FAIL_OPERATION',
          operationId,
          error: errorMsg,
        });
      });
  }

  private handleDisconnect(hostId: string): void {
    disconnectHost(hostId)
      .then(() => {
        this.store.dispatch({
          type: 'SET_HOST_STATUS',
          hostId,
          status: 'disconnected',
        });
        this.store.dispatch({ type: 'CLEAR_HOST_STATE', hostId });
      })
      .catch(() => {
        this.store.dispatch({
          type: 'SET_HOST_STATUS',
          hostId,
          status: 'disconnected',
        });
        this.store.dispatch({ type: 'CLEAR_HOST_STATE', hostId });
      });
  }

  private showExportDropdown(anchorBtn: HTMLElement, hostId: string): void {
    const existing = document.querySelector('.rule-table__export-dropdown');
    if (existing) {
      existing.remove();
      return;
    }

    const dropdown = h('div', { className: 'rule-table__export-dropdown' });
    const options: Array<{
      label: string;
      format: 'shell' | 'ansible' | 'iptables-save';
    }> = [
      { label: 'Shell Script', format: 'shell' },
      { label: 'Ansible Playbook', format: 'ansible' },
      { label: 'iptables-save', format: 'iptables-save' },
    ];

    for (const opt of options) {
      const btn = h(
        'button',
        { className: 'rule-table__export-option', type: 'button' },
        opt.label,
      );

      this.listen(btn, 'click', () => {
        dropdown.remove();
        exportRules(hostId, opt.format)
          .then((result) => {
            const ext =
              opt.format === 'ansible'
                ? '.yml'
                : opt.format === 'shell'
                  ? '.sh'
                  : '.rules';
            const blob = new Blob([result], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${hostId}${ext}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
          })
          .catch(() => {
            // Export error — silently fail
          });
      });
      dropdown.appendChild(btn);
    }

    anchorBtn.style.position = 'relative';
    anchorBtn.appendChild(dropdown);

    const closeHandler = (e: Event) => {
      if (
        !dropdown.contains(e.target as Node) &&
        e.target !== anchorBtn
      ) {
        dropdown.remove();
        document.removeEventListener('click', closeHandler);
      }
    };
    requestAnimationFrame(() => {
      document.addEventListener('click', closeHandler);
    });
  }
}
