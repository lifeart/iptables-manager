/**
 * Add Host dialog — quick add with single-field parsing,
 * expandable full form, test connection, and connect.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { Host } from '../../store/types';
import { testConnection, connectHost, detectHost, fetchRules, provisionHost } from '../../ipc/bridge';
import type { TestResult } from '../../ipc/bridge';
import { convertRuleSet } from '../../services/rule-converter';
import { h, trapFocus } from '../../utils/dom';
import { isValidIPv4, isValidIPv6, isValidPort } from '../../utils/ip-validate';

interface ParsedInput {
  username: string;
  host: string;
  port: number;
}

function parseQuickInput(input: string): ParsedInput | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  let username = 'root';
  let host = '';
  let port = 22;

  let remaining = trimmed;

  // Extract user@
  const atIdx = remaining.indexOf('@');
  if (atIdx !== -1) {
    username = remaining.slice(0, atIdx);
    remaining = remaining.slice(atIdx + 1);
  }

  // Handle IPv6 in brackets [::1]:port
  if (remaining.startsWith('[')) {
    const closeBracket = remaining.indexOf(']');
    if (closeBracket === -1) return null;
    host = remaining.slice(1, closeBracket);
    const afterBracket = remaining.slice(closeBracket + 1);
    if (afterBracket.startsWith(':')) {
      const p = parseInt(afterBracket.slice(1), 10);
      if (!isNaN(p)) port = p;
    }
  } else {
    // Extract :port from the end
    const colonIdx = remaining.lastIndexOf(':');
    if (colonIdx !== -1) {
      const possiblePort = remaining.slice(colonIdx + 1);
      const p = parseInt(possiblePort, 10);
      if (!isNaN(p) && String(p) === possiblePort && p > 0 && p <= 65535) {
        port = p;
        remaining = remaining.slice(0, colonIdx);
      }
    }
    host = remaining;
  }

  if (!host) return null;
  return { username, host, port };
}

function isValidHostname(value: string): boolean {
  if (isValidIPv4(value)) return true;
  if (isValidIPv6(value)) return true;
  // DNS hostname
  return /^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$/.test(value);
}

export class AddHostDialog extends Component {
  private overlay!: HTMLElement;
  private quickInput!: HTMLInputElement;
  private parsedInfo!: HTMLElement;
  private expandedForm!: HTMLElement;
  private testStatusEl!: HTMLElement;
  private connectBtn!: HTMLButtonElement;
  private testBtn!: HTMLButtonElement;
  private expanded = false;

  // Full form fields
  private nameInput!: HTMLInputElement;
  private hostInput!: HTMLInputElement;
  private portInput!: HTMLInputElement;
  private usernameInput!: HTMLInputElement;
  private authMethodKey!: HTMLInputElement;
  private authMethodPassword!: HTMLInputElement;
  private keyPathInput!: HTMLInputElement;
  private groupsInput!: HTMLInputElement;
  private jumpHostInput!: HTMLInputElement;

  private onCloseCallback: (() => void) | null = null;
  private triggerElement: Element | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.triggerElement = document.activeElement;
    this.render();
    this.bindEvents();
  }

  onClose(cb: () => void): void {
    this.onCloseCallback = cb;
  }

  private render(): void {
    this.overlay = h('div', { className: 'dialog-overlay' });
    const titleId = 'addhost-dialog-title';
    const dialog = h('div', {
      className: 'dialog-card dialog-card--add-host',
      role: 'dialog',
      'aria-modal': 'true',
      'aria-labelledby': titleId,
    });

    // Header
    const header = h('div', { className: 'dialog-header' },
      h('span', { className: 'dialog-title', id: titleId }, 'Add Host'),
      h('button', { className: 'dialog-close', 'aria-label': 'Close' }, '\u00D7'),
    );
    dialog.appendChild(header);

    // Quick add field
    const quickSection = h('div', { className: 'dialog-body' });
    this.quickInput = document.createElement('input');
    this.quickInput.type = 'text';
    this.quickInput.placeholder = 'root@192.168.1.50:22';
    this.quickInput.className = 'dialog-input dialog-input--quick';
    this.quickInput.setAttribute('aria-label', 'Quick add host');
    quickSection.appendChild(this.quickInput);

    this.parsedInfo = h('div', { className: 'dialog-parsed-info' });
    quickSection.appendChild(this.parsedInfo);

    dialog.appendChild(quickSection);

    // Expanded full form (hidden by default)
    this.expandedForm = h('div', { className: 'dialog-expanded-form', style: { display: 'none' } });

    const fields: Array<{ label: string; id: string; type?: string; placeholder?: string }> = [
      { label: 'Name', id: 'name', placeholder: 'web-03' },
      { label: 'Host', id: 'host', placeholder: '192.168.1.50' },
      { label: 'Port', id: 'port', type: 'number', placeholder: '22' },
      { label: 'Username', id: 'username', placeholder: 'root' },
    ];

    for (const field of fields) {
      const row = h('div', { className: 'dialog-field' },
        h('label', { className: 'dialog-label', for: `addhost-${field.id}` }, field.label),
      );
      const input = document.createElement('input');
      input.type = field.type ?? 'text';
      input.id = `addhost-${field.id}`;
      input.className = 'dialog-input';
      input.placeholder = field.placeholder ?? '';
      row.appendChild(input);
      this.expandedForm.appendChild(row);

      // Store references
      switch (field.id) {
        case 'name': this.nameInput = input; break;
        case 'host': this.hostInput = input; break;
        case 'port': this.portInput = input; break;
        case 'username': this.usernameInput = input; break;
      }
    }

    // Auth method
    const authRow = h('div', { className: 'dialog-field' },
      h('label', { className: 'dialog-label' }, 'Authentication'),
    );
    const authOptions = h('div', { className: 'dialog-radio-group' });

    this.authMethodKey = document.createElement('input');
    this.authMethodKey.type = 'radio';
    this.authMethodKey.name = 'auth-method';
    this.authMethodKey.value = 'key';
    this.authMethodKey.id = 'auth-key';
    this.authMethodKey.checked = true;

    this.authMethodPassword = document.createElement('input');
    this.authMethodPassword.type = 'radio';
    this.authMethodPassword.name = 'auth-method';
    this.authMethodPassword.value = 'password';
    this.authMethodPassword.id = 'auth-password';

    authOptions.appendChild(this.authMethodKey);
    authOptions.appendChild(h('label', { for: 'auth-key' }, 'SSH Key'));
    authOptions.appendChild(this.authMethodPassword);
    authOptions.appendChild(h('label', { for: 'auth-password' }, 'Password'));
    authRow.appendChild(authOptions);
    this.expandedForm.appendChild(authRow);

    // Key path
    const keyRow = h('div', { className: 'dialog-field' },
      h('label', { className: 'dialog-label', for: 'addhost-keypath' }, 'Key Path'),
    );
    this.keyPathInput = document.createElement('input');
    this.keyPathInput.type = 'text';
    this.keyPathInput.id = 'addhost-keypath';
    this.keyPathInput.className = 'dialog-input';
    this.keyPathInput.placeholder = '~/.ssh/id_rsa';
    this.keyPathInput.value = '~/.ssh/id_rsa';
    keyRow.appendChild(this.keyPathInput);
    this.expandedForm.appendChild(keyRow);

    // Groups
    const groupsRow = h('div', { className: 'dialog-field' },
      h('label', { className: 'dialog-label', for: 'addhost-groups' }, 'Groups'),
    );
    this.groupsInput = document.createElement('input');
    this.groupsInput.type = 'text';
    this.groupsInput.id = 'addhost-groups';
    this.groupsInput.className = 'dialog-input';
    this.groupsInput.placeholder = 'Web Servers, Production';
    groupsRow.appendChild(this.groupsInput);
    this.expandedForm.appendChild(groupsRow);

    // Jump host
    const jumpRow = h('div', { className: 'dialog-field' },
      h('label', { className: 'dialog-label', for: 'addhost-jumphost' }, 'Jump Host'),
    );
    this.jumpHostInput = document.createElement('input');
    this.jumpHostInput.type = 'text';
    this.jumpHostInput.id = 'addhost-jumphost';
    this.jumpHostInput.className = 'dialog-input';
    this.jumpHostInput.placeholder = 'user@bastion:22';
    jumpRow.appendChild(this.jumpHostInput);
    this.expandedForm.appendChild(jumpRow);

    dialog.appendChild(this.expandedForm);

    // Test connection status
    this.testStatusEl = h('div', { className: 'dialog-test-status' });
    dialog.appendChild(this.testStatusEl);

    // Footer buttons
    const footer = h('div', { className: 'dialog-footer' });

    const editDetailsBtn = h('button', { className: 'dialog-btn dialog-btn--text' }, 'Edit details \u25B8');
    this.testBtn = document.createElement('button');
    this.testBtn.className = 'dialog-btn dialog-btn--secondary';
    this.testBtn.textContent = 'Test Connection';
    this.testBtn.style.display = 'none';

    const spacer = h('div', { className: 'dialog-footer-spacer' });

    const cancelBtn = h('button', { className: 'dialog-btn dialog-btn--secondary' }, 'Cancel');
    this.connectBtn = document.createElement('button');
    this.connectBtn.className = 'dialog-btn dialog-btn--primary';
    this.connectBtn.textContent = 'Connect';
    this.connectBtn.disabled = true;

    footer.appendChild(editDetailsBtn);
    footer.appendChild(this.testBtn);
    footer.appendChild(spacer);
    footer.appendChild(cancelBtn);
    footer.appendChild(this.connectBtn);
    dialog.appendChild(footer);

    this.overlay.appendChild(dialog);
    this.el.appendChild(this.overlay);

    // Focus trapping
    trapFocus(dialog, this.ac.signal);

    // Escape to close
    this.listen(document, 'keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Escape') this.close();
    });

    // Focus the quick input
    requestAnimationFrame(() => this.quickInput.focus());

    // Store references for events
    this.listen(editDetailsBtn, 'click', () => this.toggleExpanded());
    this.listen(cancelBtn, 'click', () => this.close());
    this.listen(this.connectBtn, 'click', () => this.handleConnect());
    this.listen(this.testBtn, 'click', () => this.handleTestConnection());
    this.listen(header.querySelector('.dialog-close')!, 'click', () => this.close());
    this.listen(this.overlay, 'click', (e) => {
      if (e.target === this.overlay) this.close();
    });
  }

  private bindEvents(): void {
    this.listen(this.quickInput, 'input', () => this.onQuickInputChange());
    this.listen(this.quickInput, 'paste', () => {
      // Wait for paste to complete
      requestAnimationFrame(() => this.onQuickInputChange());
    });
    this.listen(this.quickInput, 'keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Enter') {
        this.handleConnect();
      }
    });

    // Validate expanded form fields on blur
    this.listen(this.hostInput, 'blur', () => this.validateExpandedForm());
    this.listen(this.portInput, 'blur', () => this.validateExpandedForm());
  }

  private onQuickInputChange(): void {
    const parsed = parseQuickInput(this.quickInput.value);
    if (parsed) {
      this.parsedInfo.textContent = `Parsed: user=${parsed.username}, host=${parsed.host}, port=${parsed.port}`;
      this.parsedInfo.className = 'dialog-parsed-info';

      // Validate
      const valid = isValidHostname(parsed.host) && isValidPort(parsed.port);
      this.connectBtn.disabled = !valid;
      if (!valid) {
        this.parsedInfo.className = 'dialog-parsed-info dialog-parsed-info--error';
        if (!isValidHostname(parsed.host)) {
          this.parsedInfo.textContent += ' (invalid hostname)';
        } else {
          this.parsedInfo.textContent += ' (invalid port)';
        }
      }

      // Sync to expanded form
      this.nameInput.value = parsed.host;
      this.hostInput.value = parsed.host;
      this.portInput.value = String(parsed.port);
      this.usernameInput.value = parsed.username;
    } else {
      this.parsedInfo.textContent = '';
      this.connectBtn.disabled = true;
    }
  }

  private toggleExpanded(): void {
    this.expanded = !this.expanded;
    this.expandedForm.style.display = this.expanded ? '' : 'none';
    this.testBtn.style.display = this.expanded ? '' : 'none';

    if (this.expanded) {
      this.connectBtn.textContent = 'Add Host';
    } else {
      this.connectBtn.textContent = 'Connect';
    }
  }

  private validateExpandedForm(): boolean {
    const host = this.hostInput.value.trim();
    const port = parseInt(this.portInput.value, 10);

    let valid = true;
    if (host && !isValidHostname(host)) {
      this.hostInput.classList.add('dialog-input--error');
      valid = false;
    } else {
      this.hostInput.classList.remove('dialog-input--error');
    }

    if (this.portInput.value && (!isValidPort(port))) {
      this.portInput.classList.add('dialog-input--error');
      valid = false;
    } else {
      this.portInput.classList.remove('dialog-input--error');
    }

    this.connectBtn.disabled = !valid || !host;
    return valid;
  }

  private async handleTestConnection(): Promise<void> {
    const params = this.getConnectionParams();
    if (!params) return;

    this.testBtn.disabled = true;
    this.testBtn.textContent = 'Testing...';
    this.testStatusEl.innerHTML = '';

    try {
      const result: TestResult = await testConnection(params);
      this.renderTestResult(result);
    } catch (err) {
      this.testStatusEl.innerHTML = '';
      this.testStatusEl.appendChild(
        h('div', { className: 'dialog-test-item dialog-test-item--error' },
          `Connection failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
        ),
      );
    } finally {
      this.testBtn.disabled = false;
      this.testBtn.textContent = 'Test Connection';
    }
  }

  private renderTestResult(result: TestResult): void {
    this.testStatusEl.innerHTML = '';

    const items: Array<{ ok: boolean; text: string }> = [];
    if (result.success) {
      items.push({ ok: true, text: `Connected (latency: ${result.latencyMs}ms)` });
    } else {
      items.push({ ok: false, text: `Connection failed${result.error ? ': ' + result.error : ''}` });
    }
    items.push({
      ok: result.iptablesAvailable,
      text: result.iptablesAvailable
        ? `iptables available${result.nftablesBackend ? ' (iptables-nft backend)' : ''}`
        : 'iptables not found',
    });
    items.push({
      ok: result.rootAccess,
      text: result.rootAccess ? 'Root/sudo access confirmed' : 'No root/sudo access',
    });
    if (result.dockerDetected) {
      items.push({ ok: true, text: 'Docker detected — system rules will be preserved' });
    }
    if (result.fail2banDetected) {
      items.push({ ok: true, text: 'fail2ban detected' });
    }

    for (const item of items) {
      this.testStatusEl.appendChild(
        h('div', {
          className: `dialog-test-item dialog-test-item--${item.ok ? 'ok' : 'error'}`,
        }, `${item.ok ? '\u2705' : '\u26A0\uFE0F'} ${item.text}`),
      );
    }
  }

  private getConnectionParams(): { hostname: string; port: number; username: string; authMethod: string; keyPath?: string } | null {
    let hostname: string;
    let port: number;
    let username: string;

    if (this.expanded) {
      hostname = this.hostInput.value.trim();
      port = parseInt(this.portInput.value, 10) || 22;
      username = this.usernameInput.value.trim() || 'root';
    } else {
      const parsed = parseQuickInput(this.quickInput.value);
      if (!parsed) return null;
      hostname = parsed.host;
      port = parsed.port;
      username = parsed.username;
    }

    if (!hostname) return null;

    const authMethod = this.authMethodKey.checked ? 'key' : 'password';
    const keyPath = authMethod === 'key' ? (this.keyPathInput.value.trim() || '~/.ssh/id_rsa') : undefined;

    return { hostname, port, username, authMethod, keyPath };
  }

  private async handleConnect(): Promise<void> {
    const params = this.getConnectionParams();
    if (!params) return;
    if (this.connectBtn.disabled) return;

    const now = Date.now();
    const host: Host = {
      id: crypto.randomUUID(),
      name: this.expanded ? (this.nameInput.value.trim() || params.hostname) : params.hostname,
      connection: {
        hostname: params.hostname,
        port: params.port,
        username: params.username,
        authMethod: params.authMethod as 'key' | 'password',
        keyPath: params.keyPath,
      },
      capabilities: null,
      status: 'connecting',
      groupIds: [],
      groupOrder: [],
      provisioned: false,
      createdAt: now,
      updatedAt: now,
    };

    // Add host to store immediately (shows as "connecting")
    this.store.dispatch({ type: 'ADD_HOST', host });
    this.store.dispatch({ type: 'SET_ACTIVE_HOST', hostId: host.id });

    // Disable button while connecting
    this.connectBtn.disabled = true;
    this.connectBtn.textContent = 'Connecting...';

    try {
      // Initiate SSH connection via IPC
      await connectHost(
        host.id,
        params.hostname,
        params.port,
        params.username,
        params.authMethod,
        params.keyPath,
      );

      // Update host status to connected
      this.store.dispatch({
        type: 'UPDATE_HOST',
        hostId: host.id,
        changes: { status: 'connected' as const, lastConnected: Date.now() },
      });

      // Fetch rules from the connected host
      fetchRules(host.id)
        .then((ruleSet) => {
          const rules = convertRuleSet(ruleSet);
          this.store.dispatch({ type: 'SET_HOST_RULES', hostId: host.id, rules });

          // If the host has no existing rules, open the first-setup wizard
          if (rules.length === 0) {
            this.store.dispatch({ type: 'OPEN_DIALOG', dialog: 'first-setup' });
          }
        })
        .catch(() => {
          // Rule fetch failure after connect is handled by the empty state UI
        });

      // Run detection in the background (non-blocking)
      detectHost(host.id)
        .then((result) => {
          if (result.completed && result.capabilities) {
            this.store.dispatch({
              type: 'UPDATE_HOST',
              hostId: host.id,
              changes: { capabilities: result.capabilities as Host['capabilities'] },
            });
          }
        })
        .catch(() => {
          // Detection failure is non-fatal; host works without capabilities
        });

      // Provision host in the background (non-blocking)
      // Sets up directories, revert script, and HMAC secret on the remote host
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
          // Provisioning failure is non-fatal; connection still works without safety timer
          console.warn(`Host provisioning failed for ${host.id}:`, err);
        });

      this.close();
    } catch (err) {
      // Connection failed — update status and show error
      this.store.dispatch({
        type: 'UPDATE_HOST',
        hostId: host.id,
        changes: { status: 'unreachable' as const },
      });

      this.connectBtn.disabled = false;
      this.connectBtn.textContent = this.expanded ? 'Add Host' : 'Connect';

      this.testStatusEl.innerHTML = '';
      const errorMsg = err instanceof Error ? err.message : 'Connection failed';
      this.testStatusEl.appendChild(
        h('div', { className: 'dialog-test-item dialog-test-item--error' },
          `Connection failed: ${errorMsg}`,
        ),
      );
    }
  }

  private close(): void {
    this.overlay.remove();
    this.onCloseCallback?.();
    if (this.triggerElement instanceof HTMLElement) {
      this.triggerElement.focus();
    }
    this.destroy();
  }
}
