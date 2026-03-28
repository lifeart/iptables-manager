/**
 * Persistence Setup dialog — shows current persistence status and offers
 * one-click setup to install the persistence package and enable the service.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { PersistenceStatus } from '../../store/types';
import { enablePersistence } from '../../ipc/bridge';
import { h, trapFocus } from '../../utils/dom';
import { selectActiveHost } from '../../store/selectors';

export class PersistenceSetupDialog extends Component {
  private overlay!: HTMLElement;
  private enableBtn!: HTMLButtonElement;
  private statusBody!: HTMLElement;
  private resultEl!: HTMLElement;
  private triggerElement: Element | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);
    this.triggerElement = document.activeElement;
    this.render();
  }

  private render(): void {
    const host = this.store.select(selectActiveHost);
    if (!host) {
      this.close();
      return;
    }

    const ps: PersistenceStatus | undefined = host.capabilities?.persistenceStatus;

    this.overlay = h('div', { className: 'dialog-overlay' });
    const titleId = 'persistence-setup-dialog-title';
    const dialog = h('div', {
      className: 'dialog-card dialog-card--persistence-setup',
      role: 'dialog',
      'aria-modal': 'true',
      'aria-labelledby': titleId,
    });

    // Header
    const header = h('div', { className: 'dialog-header' },
      h('span', { className: 'dialog-title', id: titleId }, 'Persistence Setup'),
      h('button', { className: 'dialog-close', 'aria-label': 'Close' }, '\u00D7'),
    );
    dialog.appendChild(header);

    // Body — status rows
    this.statusBody = h('div', { className: 'dialog-body' });

    if (ps) {
      const methodLabel = ps.method === 'iptables-persistent'
        ? 'iptables-persistent (Debian/Ubuntu)'
        : ps.method === 'iptables-services'
          ? 'iptables-services (RHEL/CentOS)'
          : 'Manual';

      this.statusBody.appendChild(
        h('div', { className: 'dialog-help-text' },
          `Method: ${methodLabel}`,
        ),
      );

      this.statusBody.appendChild(this.createStatusRow(
        'Package',
        ps.packageInstalled ? 'Installed' : 'Not Installed',
        ps.packageInstalled,
      ));
      this.statusBody.appendChild(this.createStatusRow(
        'Service',
        ps.serviceEnabled ? 'Enabled' : 'Not Enabled',
        ps.serviceEnabled,
      ));
      this.statusBody.appendChild(this.createStatusRow(
        'Service Status',
        ps.serviceActive ? 'Active' : 'Not Active',
        ps.serviceActive,
      ));

      const lastSavedText = ps.lastSaved
        ? new Date(parseInt(ps.lastSaved, 10) * 1000).toLocaleString()
        : 'Never';
      this.statusBody.appendChild(this.createStatusRow(
        'Last Saved',
        lastSavedText,
        !!ps.lastSaved,
      ));

      // Warning text when action is available
      const needsSetup = !ps.packageInstalled || !ps.serviceEnabled;
      if (needsSetup && ps.method !== 'manual') {
        const pkgName = ps.method === 'iptables-persistent'
          ? 'iptables-persistent'
          : 'iptables-services';
        this.statusBody.appendChild(
          h('div', { className: 'persistence-warning' },
            `This will install ${pkgName} and enable the persistence service.`,
          ),
        );
      }
    } else {
      this.statusBody.appendChild(
        h('div', { className: 'dialog-help-text' },
          'Persistence status not yet detected. Connect and detect host capabilities first.',
        ),
      );
    }

    dialog.appendChild(this.statusBody);

    // Result area
    this.resultEl = h('div', { className: 'dialog-test-status' });
    dialog.appendChild(this.resultEl);

    // Footer
    const footer = h('div', { className: 'dialog-footer' });
    const spacer = h('div', { className: 'dialog-footer-spacer' });

    const cancelBtn = h('button', { className: 'dialog-btn dialog-btn--secondary' }, 'Close');

    this.enableBtn = document.createElement('button');
    this.enableBtn.className = 'dialog-btn dialog-btn--primary';
    this.enableBtn.textContent = 'Enable Persistence';

    // Disable button if persistence is already fully configured, or method is manual
    const canEnable = ps
      && ps.method !== 'manual'
      && (!ps.packageInstalled || !ps.serviceEnabled);
    this.enableBtn.disabled = !canEnable;

    footer.appendChild(spacer);
    footer.appendChild(cancelBtn);
    footer.appendChild(this.enableBtn);
    dialog.appendChild(footer);

    this.overlay.appendChild(dialog);
    this.el.appendChild(this.overlay);

    // Focus trapping
    trapFocus(dialog, this.ac.signal);

    // Events
    this.listen(document, 'keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Escape') this.close();
    });
    this.listen(header.querySelector('.dialog-close')!, 'click', () => this.close());
    this.listen(cancelBtn, 'click', () => this.close());
    this.listen(this.overlay, 'click', (e) => {
      if (e.target === this.overlay) this.close();
    });
    this.listen(this.enableBtn, 'click', () => this.handleEnable());
  }

  private createStatusRow(label: string, value: string, ok: boolean): HTMLElement {
    return h('div', {
      className: `persistence-status-row`,
    },
      h('span', { className: 'persistence-status-label' }, `${label}:`),
      h('span', {
        className: ok
          ? 'persistence-status-value persistence-status-value--ok'
          : 'persistence-status-value persistence-status-value--warn',
      }, value),
    );
  }

  private async handleEnable(): Promise<void> {
    const host = this.store.select(selectActiveHost);
    if (!host) return;

    this.enableBtn.disabled = true;
    this.enableBtn.textContent = 'Installing...';
    this.resultEl.innerHTML = '';

    try {
      const result = await enablePersistence(host.id);

      this.resultEl.innerHTML = '';
      if (result.success) {
        this.resultEl.appendChild(
          h('div', { className: 'dialog-test-item dialog-test-item--ok' },
            result.message,
          ),
        );
        this.enableBtn.textContent = 'Done';
        // The button stays disabled since setup is complete
      } else {
        this.resultEl.appendChild(
          h('div', { className: 'dialog-test-item dialog-test-item--error' },
            result.message,
          ),
        );
        this.enableBtn.disabled = false;
        this.enableBtn.textContent = 'Enable Persistence';
      }
    } catch (err) {
      this.resultEl.innerHTML = '';
      this.resultEl.appendChild(
        h('div', { className: 'dialog-test-item dialog-test-item--error' },
          `Failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
        ),
      );
      this.enableBtn.disabled = false;
      this.enableBtn.textContent = 'Enable Persistence';
    }
  }

  private close(): void {
    this.overlay.remove();
    this.store.dispatch({ type: 'CLOSE_DIALOG' });
    if (this.triggerElement instanceof HTMLElement) {
      this.triggerElement.focus();
    }
    this.destroy();
  }
}
