/**
 * Service selection combobox.
 *
 * Features:
 *   - Search/filter as you type
 *   - Categorized results (Common, VPN, Databases, Custom, Detected)
 *   - Selecting a preset auto-fills protocol and port
 *   - "Custom Service..." opens protocol + port fields
 *   - Typing a number jumps to Custom with that port pre-filled
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { PortSpec } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';

export interface ServiceSelection {
  label: string;
  protocol: 'tcp' | 'udp' | 'icmp' | 'icmpv6' | 'gre' | 'esp' | 'ah' | 'sctp' | number | undefined;
  ports: PortSpec | undefined;
}

interface ServicePreset {
  label: string;
  ports: number[];
  protocol: 'tcp' | 'udp' | 'icmp' | 'esp' | 'gre';
  category: string;
}

const SERVICE_PRESETS: ServicePreset[] = [
  // Common
  { label: 'Web Traffic (80, 443)', ports: [80, 443], protocol: 'tcp', category: 'Common' },
  { label: 'SSH (22)', ports: [22], protocol: 'tcp', category: 'Common' },
  { label: 'DNS (53)', ports: [53], protocol: 'tcp', category: 'Common' },
  { label: 'Ping', ports: [], protocol: 'icmp', category: 'Common' },
  { label: 'NTP (123)', ports: [123], protocol: 'udp', category: 'Common' },
  { label: 'DHCP (67, 68)', ports: [67, 68], protocol: 'udp', category: 'Common' },
  { label: 'Syslog (514)', ports: [514], protocol: 'udp', category: 'Common' },
  // Email
  { label: 'SMTP (25, 587)', ports: [25, 587], protocol: 'tcp', category: 'Email' },
  { label: 'IMAP (143, 993)', ports: [143, 993], protocol: 'tcp', category: 'Email' },
  { label: 'POP3 (110, 995)', ports: [110, 995], protocol: 'tcp', category: 'Email' },
  { label: 'Email All (25, 587, 143, 993)', ports: [25, 587, 143, 993], protocol: 'tcp', category: 'Email' },
  // Remote access
  { label: 'RDP (3389)', ports: [3389], protocol: 'tcp', category: 'Remote Access' },
  { label: 'VNC (5900)', ports: [5900], protocol: 'tcp', category: 'Remote Access' },
  { label: 'Telnet (23)', ports: [23], protocol: 'tcp', category: 'Remote Access' },
  // VPN
  { label: 'WireGuard (51820)', ports: [51820], protocol: 'udp', category: 'VPN' },
  { label: 'OpenVPN (1194)', ports: [1194], protocol: 'udp', category: 'VPN' },
  { label: 'IPSec/IKE (500, 4500)', ports: [500, 4500], protocol: 'udp', category: 'VPN' },
  { label: 'IPSec Data', ports: [], protocol: 'esp', category: 'VPN' },
  { label: 'L2TP (1701)', ports: [1701], protocol: 'udp', category: 'VPN' },
  // Databases
  { label: 'PostgreSQL (5432)', ports: [5432], protocol: 'tcp', category: 'Databases' },
  { label: 'MySQL (3306)', ports: [3306], protocol: 'tcp', category: 'Databases' },
  { label: 'MongoDB (27017)', ports: [27017], protocol: 'tcp', category: 'Databases' },
  { label: 'Redis (6379)', ports: [6379], protocol: 'tcp', category: 'Databases' },
  { label: 'MSSQL (1433)', ports: [1433], protocol: 'tcp', category: 'Databases' },
  { label: 'Elasticsearch (9200)', ports: [9200], protocol: 'tcp', category: 'Databases' },
  { label: 'Cassandra (9042)', ports: [9042], protocol: 'tcp', category: 'Databases' },
  { label: 'Memcached (11211)', ports: [11211], protocol: 'tcp', category: 'Databases' },
  { label: 'InfluxDB (8086)', ports: [8086], protocol: 'tcp', category: 'Databases' },
  { label: 'CockroachDB (26257)', ports: [26257], protocol: 'tcp', category: 'Databases' },
  // Message Brokers
  { label: 'RabbitMQ (5672)', ports: [5672], protocol: 'tcp', category: 'Message Brokers' },
  { label: 'Kafka (9092)', ports: [9092], protocol: 'tcp', category: 'Message Brokers' },
  { label: 'NATS (4222)', ports: [4222], protocol: 'tcp', category: 'Message Brokers' },
  { label: 'MQTT (1883)', ports: [1883], protocol: 'tcp', category: 'Message Brokers' },
  { label: 'MQTT over TLS (8883)', ports: [8883], protocol: 'tcp', category: 'Message Brokers' },
  // Containers & Orchestration
  { label: 'Kubernetes API (6443)', ports: [6443], protocol: 'tcp', category: 'Containers' },
  { label: 'Docker API (2375)', ports: [2375], protocol: 'tcp', category: 'Containers' },
  { label: 'Docker API TLS (2376)', ports: [2376], protocol: 'tcp', category: 'Containers' },
  { label: 'etcd (2379, 2380)', ports: [2379, 2380], protocol: 'tcp', category: 'Containers' },
  { label: 'Kubelet (10250)', ports: [10250], protocol: 'tcp', category: 'Containers' },
  { label: 'Consul (8500)', ports: [8500], protocol: 'tcp', category: 'Containers' },
  { label: 'Vault (8200)', ports: [8200], protocol: 'tcp', category: 'Containers' },
  { label: 'Nomad (4646)', ports: [4646], protocol: 'tcp', category: 'Containers' },
  { label: 'Docker Registry (5000)', ports: [5000], protocol: 'tcp', category: 'Containers' },
  // Monitoring & Observability
  { label: 'Prometheus (9090)', ports: [9090], protocol: 'tcp', category: 'Monitoring' },
  { label: 'Node Exporter (9100)', ports: [9100], protocol: 'tcp', category: 'Monitoring' },
  { label: 'Grafana (3000)', ports: [3000], protocol: 'tcp', category: 'Monitoring' },
  { label: 'Alertmanager (9093)', ports: [9093], protocol: 'tcp', category: 'Monitoring' },
  { label: 'Jaeger (16686)', ports: [16686], protocol: 'tcp', category: 'Monitoring' },
  { label: 'Zipkin (9411)', ports: [9411], protocol: 'tcp', category: 'Monitoring' },
  { label: 'OpenTelemetry (4317, 4318)', ports: [4317, 4318], protocol: 'tcp', category: 'Monitoring' },
  { label: 'Kibana (5601)', ports: [5601], protocol: 'tcp', category: 'Monitoring' },
  // Proxy & Load Balancing
  { label: 'HTTP Proxy Alt (8080)', ports: [8080], protocol: 'tcp', category: 'Proxy' },
  { label: 'Squid Proxy (3128)', ports: [3128], protocol: 'tcp', category: 'Proxy' },
  { label: 'SOCKS Proxy (1080)', ports: [1080], protocol: 'tcp', category: 'Proxy' },
  // Directory & Auth
  { label: 'LDAP (389, 636)', ports: [389, 636], protocol: 'tcp', category: 'Directory' },
  { label: 'Kerberos (88)', ports: [88], protocol: 'tcp', category: 'Directory' },
  // File Transfer
  { label: 'FTP (21)', ports: [21], protocol: 'tcp', category: 'File Transfer' },
  { label: 'TFTP (69)', ports: [69], protocol: 'udp', category: 'File Transfer' },
  { label: 'rsync (873)', ports: [873], protocol: 'tcp', category: 'File Transfer' },
  // Infrastructure
  { label: 'BGP (179)', ports: [179], protocol: 'tcp', category: 'Infrastructure' },
  { label: 'SNMP (161)', ports: [161], protocol: 'udp', category: 'Infrastructure' },
  { label: 'SIP (5060, 5061)', ports: [5060, 5061], protocol: 'tcp', category: 'Infrastructure' },
  { label: 'STUN/TURN (3478)', ports: [3478], protocol: 'udp', category: 'Infrastructure' },
  { label: 'GRE Tunnel', ports: [], protocol: 'gre', category: 'Infrastructure' },
];

export class ServicePicker extends Component {
  private containerEl: HTMLElement;
  private inputEl: HTMLInputElement;
  private dropdownEl: HTMLElement;
  private isDropdownOpen = false;
  private selection: ServiceSelection;
  private onSelect: (sel: ServiceSelection) => void;
  private customMode = false;
  private customProtocolSelect: HTMLSelectElement | null = null;
  private customPortInput: HTMLInputElement | null = null;
  private customNameInput: HTMLInputElement | null = null;

  constructor(
    container: HTMLElement,
    store: Store,
    initialSelection: ServiceSelection,
    onSelect: (sel: ServiceSelection) => void,
  ) {
    super(container, store);
    this.selection = initialSelection;
    this.onSelect = onSelect;

    this.containerEl = h('div', { className: 'service-picker' });

    // Combobox input
    this.inputEl = document.createElement('input');
    this.inputEl.type = 'text';
    this.inputEl.className = 'service-picker__input';
    this.inputEl.placeholder = 'Search services (e.g. SSH, Web)...';
    this.inputEl.value = initialSelection.label;
    this.inputEl.setAttribute('role', 'combobox');
    this.inputEl.setAttribute('aria-expanded', 'false');
    this.inputEl.setAttribute('aria-autocomplete', 'list');

    // Dropdown trigger icon
    const trigger = h('span', { className: 'service-picker__trigger' }, '\u25BE');

    const inputWrapper = h('div', { className: 'service-picker__input-wrapper' });
    inputWrapper.appendChild(this.inputEl);
    inputWrapper.appendChild(trigger);
    this.containerEl.appendChild(inputWrapper);

    // Dropdown
    this.dropdownEl = h('div', {
      className: 'service-picker__dropdown',
      role: 'listbox',
    });
    this.dropdownEl.style.display = 'none';
    this.containerEl.appendChild(this.dropdownEl);

    // Custom service fields (hidden by default)
    this.buildCustomFields();

    this.el.appendChild(this.containerEl);

    // Event listeners
    this.listen(this.inputEl, 'focus', () => this.openDropdown());
    this.listen(this.inputEl, 'input', () => this.onInputChange());
    this.listen(trigger, 'click', () => this.toggleDropdown());
    this.listen(document, 'click', (e) => {
      if (!this.containerEl.contains(e.target as Node)) {
        this.closeDropdown();
      }
    });
  }

  private buildCustomFields(): void {
    const customContainer = h('div', { className: 'service-picker__custom-fields' });
    customContainer.style.display = 'none';
    customContainer.dataset.customContainer = 'true';

    // Name field
    const nameGroup = h('div', { className: 'service-picker__custom-group' });
    nameGroup.appendChild(h('label', { className: 'service-picker__custom-label' }, 'Name'));
    this.customNameInput = document.createElement('input');
    this.customNameInput.type = 'text';
    this.customNameInput.className = 'service-picker__custom-input';
    this.customNameInput.placeholder = 'My Service';
    this.listen(this.customNameInput, 'input', () => this.updateCustomSelection());
    nameGroup.appendChild(this.customNameInput);
    customContainer.appendChild(nameGroup);

    // Protocol selector
    const protocolGroup = h('div', { className: 'service-picker__custom-group' });
    protocolGroup.appendChild(h('label', { className: 'service-picker__custom-label' }, 'Protocol'));
    this.customProtocolSelect = document.createElement('select');
    this.customProtocolSelect.className = 'service-picker__custom-select';
    const protocols = ['TCP', 'UDP', 'ICMP', 'ICMPv6', 'GRE (47)', 'ESP (50)', 'AH (51)', 'SCTP (132)'];
    const protocolValues = ['tcp', 'udp', 'icmp', 'icmpv6', 'gre', 'esp', 'ah', 'sctp'];
    for (let i = 0; i < protocols.length; i++) {
      const option = document.createElement('option');
      option.value = protocolValues[i];
      option.textContent = protocols[i];
      this.customProtocolSelect.appendChild(option);
    }
    this.listen(this.customProtocolSelect, 'change', () => this.onProtocolChange());
    protocolGroup.appendChild(this.customProtocolSelect);
    customContainer.appendChild(protocolGroup);

    // Port field
    const portGroup = h('div', { className: 'service-picker__custom-group' });
    portGroup.appendChild(h('label', { className: 'service-picker__custom-label' }, 'Port(s)'));
    this.customPortInput = document.createElement('input');
    this.customPortInput.type = 'text';
    this.customPortInput.className = 'service-picker__custom-input';
    this.customPortInput.placeholder = '8080, 8443';
    this.listen(this.customPortInput, 'input', () => this.updateCustomSelection());
    this.listen(this.customPortInput, 'blur', () => this.validatePorts());
    portGroup.appendChild(this.customPortInput);

    const portHint = h('p', { className: 'service-picker__hint' },
      'Commas for multiple (80,443). Dash for ranges (8000-8100).');
    portGroup.appendChild(portHint);
    customContainer.appendChild(portGroup);

    this.containerEl.appendChild(customContainer);
  }

  private openDropdown(): void {
    if (this.customMode) return;
    this.isDropdownOpen = true;
    this.dropdownEl.style.display = '';
    this.inputEl.setAttribute('aria-expanded', 'true');
    this.renderDropdown(this.inputEl.value);
  }

  private closeDropdown(): void {
    this.isDropdownOpen = false;
    this.dropdownEl.style.display = 'none';
    this.inputEl.setAttribute('aria-expanded', 'false');
  }

  private toggleDropdown(): void {
    if (this.isDropdownOpen) {
      this.closeDropdown();
    } else {
      this.openDropdown();
    }
  }

  private onInputChange(): void {
    const value = this.inputEl.value.trim();

    // If typing a number, jump to custom mode with that port
    if (/^\d+$/.test(value) && parseInt(value, 10) > 0) {
      this.enterCustomMode(value);
      return;
    }

    if (this.isDropdownOpen) {
      this.renderDropdown(value);
    } else {
      this.openDropdown();
    }
  }

  private renderDropdown(filter: string): void {
    clearChildren(this.dropdownEl);

    const filterLower = filter.toLowerCase();
    const categories = new Map<string, ServicePreset[]>();

    for (const preset of SERVICE_PRESETS) {
      if (filterLower && !preset.label.toLowerCase().includes(filterLower)) continue;
      if (!categories.has(preset.category)) {
        categories.set(preset.category, []);
      }
      categories.get(preset.category)!.push(preset);
    }

    for (const [category, presets] of categories) {
      const categoryHeader = h('div', { className: 'service-picker__category' }, category);
      this.dropdownEl.appendChild(categoryHeader);

      for (const preset of presets) {
        const item = h('div', {
          className: 'service-picker__item',
          role: 'option',
        });
        const labelSpan = h('span', { className: 'service-picker__item-label' }, preset.label);
        const protocolSpan = h('span', { className: 'service-picker__item-protocol' },
          preset.protocol.toUpperCase());
        item.appendChild(labelSpan);
        item.appendChild(protocolSpan);

        this.listen(item, 'click', () => this.selectPreset(preset));
        this.dropdownEl.appendChild(item);
      }
    }

    // Custom Service option
    const customCategory = h('div', { className: 'service-picker__category' }, 'Custom');
    this.dropdownEl.appendChild(customCategory);

    const customItem = h('div', {
      className: 'service-picker__item',
      role: 'option',
    }, 'Custom Service...');
    this.listen(customItem, 'click', () => this.enterCustomMode(''));
    this.dropdownEl.appendChild(customItem);

    // Detected services from host
    const state = this.store.getState();
    const hostId = state.activeHostId;
    if (hostId) {
      const host = state.hosts.get(hostId);
      if (host?.capabilities?.runningServices && host.capabilities.runningServices.length > 0) {
        const detectedCategory = h('div', { className: 'service-picker__category' },
          'Detected on this host');
        this.dropdownEl.appendChild(detectedCategory);

        for (const svc of host.capabilities.runningServices) {
          const portStr = svc.ports.length > 0 ? ` (${svc.ports.join(', ')})` : '';
          const item = h('div', {
            className: 'service-picker__item',
            role: 'option',
          });
          item.appendChild(h('span', { className: 'service-picker__item-label' },
            `${svc.name}${portStr} \u2014 running`));
          item.appendChild(h('span', { className: 'service-picker__item-protocol' },
            svc.protocol.toUpperCase()));

          this.listen(item, 'click', () => {
            const ports: PortSpec | undefined = svc.ports.length === 1
              ? { type: 'single', port: svc.ports[0] }
              : svc.ports.length > 1
                ? { type: 'multi', ports: svc.ports }
                : undefined;
            this.selection = {
              label: svc.name,
              protocol: svc.protocol,
              ports,
            };
            this.inputEl.value = svc.name;
            this.onSelect(this.selection);
            this.closeDropdown();
          });
          this.dropdownEl.appendChild(item);
        }
      }
    }
  }

  private selectPreset(preset: ServicePreset): void {
    const ports: PortSpec | undefined = preset.ports.length === 1
      ? { type: 'single', port: preset.ports[0] }
      : preset.ports.length > 1
        ? { type: 'multi', ports: preset.ports }
        : undefined;

    this.selection = {
      label: preset.label,
      protocol: preset.protocol,
      ports,
    };
    this.inputEl.value = preset.label;
    this.onSelect(this.selection);
    this.closeDropdown();
    this.exitCustomMode();
  }

  private enterCustomMode(prefillPort: string): void {
    this.customMode = true;
    this.closeDropdown();
    this.inputEl.style.display = 'none';

    const customContainer = this.containerEl.querySelector('[data-custom-container]') as HTMLElement;
    if (customContainer) {
      customContainer.style.display = '';
    }

    if (prefillPort && this.customPortInput) {
      this.customPortInput.value = prefillPort;
    }

    this.updateCustomSelection();
  }

  private exitCustomMode(): void {
    this.customMode = false;
    this.inputEl.style.display = '';

    const customContainer = this.containerEl.querySelector('[data-custom-container]') as HTMLElement;
    if (customContainer) {
      customContainer.style.display = 'none';
    }
  }

  private onProtocolChange(): void {
    if (!this.customProtocolSelect || !this.customPortInput) return;
    const protocol = this.customProtocolSelect.value;
    // Disable port field for non-port protocols
    const noPortProtocols = ['gre', 'esp', 'ah', 'icmp', 'icmpv6'];
    this.customPortInput.disabled = noPortProtocols.includes(protocol);
    if (this.customPortInput.disabled) {
      this.customPortInput.value = '';
      this.customPortInput.placeholder = 'This protocol does not use ports.';
    } else {
      this.customPortInput.placeholder = '8080, 8443';
    }
    this.updateCustomSelection();
  }

  private updateCustomSelection(): void {
    if (!this.customProtocolSelect || !this.customPortInput || !this.customNameInput) return;

    const protocol = this.customProtocolSelect.value as ServiceSelection['protocol'];
    const portStr = this.customPortInput.value.trim();
    const name = this.customNameInput.value.trim() || 'Custom Service';

    let ports: PortSpec | undefined;
    if (portStr) {
      ports = this.parsePortString(portStr);
    }

    this.selection = { label: name, protocol, ports };
    this.onSelect(this.selection);
  }

  private parsePortString(portStr: string): PortSpec | undefined {
    // Range: 8000-8100
    if (portStr.includes('-')) {
      const parts = portStr.split('-').map(s => parseInt(s.trim(), 10));
      if (parts.length === 2 && !isNaN(parts[0]) && !isNaN(parts[1])) {
        return { type: 'range', from: parts[0], to: parts[1] };
      }
    }

    // Multi: 80, 443
    if (portStr.includes(',')) {
      const parts = portStr.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
      if (parts.length > 0) {
        return { type: 'multi', ports: parts };
      }
    }

    // Single
    const port = parseInt(portStr, 10);
    if (!isNaN(port) && port >= 0 && port <= 65535) {
      return { type: 'single', port };
    }

    return undefined;
  }

  private validatePorts(): void {
    if (!this.customPortInput) return;
    const value = this.customPortInput.value.trim();
    if (!value) return;

    const ports = this.parsePortString(value);
    if (!ports) {
      this.customPortInput.classList.add('service-picker__custom-input--error');
    } else {
      this.customPortInput.classList.remove('service-picker__custom-input--error');

      // Validate individual port values
      let valid = true;
      switch (ports.type) {
        case 'single':
          valid = ports.port >= 0 && ports.port <= 65535;
          break;
        case 'range':
          valid = ports.from >= 0 && ports.from <= 65535 &&
                  ports.to >= 0 && ports.to <= 65535 &&
                  ports.from < ports.to;
          break;
        case 'multi':
          valid = ports.ports.every(p => p >= 0 && p <= 65535);
          break;
      }

      this.customPortInput.classList.toggle('service-picker__custom-input--error', !valid);
    }
  }
}
