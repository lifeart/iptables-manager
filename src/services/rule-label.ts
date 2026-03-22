/**
 * Auto-generate human-readable labels from rule properties.
 */

import type { Rule, PortSpec } from '../store/types';

/** Well-known port-to-label mappings. */
const PORT_LABELS: Record<number, string> = {
  20: 'FTP Data',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  143: 'IMAP',
  161: 'SNMP',
  162: 'SNMP Trap',
  443: 'HTTPS',
  465: 'SMTPS',
  514: 'Syslog',
  587: 'SMTP Submission',
  993: 'IMAPS',
  995: 'POP3S',
  1194: 'OpenVPN',
  1433: 'MSSQL',
  1521: 'Oracle DB',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5672: 'RabbitMQ',
  5900: 'VNC',
  6379: 'Redis',
  6443: 'Kubernetes API',
  8080: 'HTTP Alt',
  8443: 'HTTPS Alt',
  9090: 'Prometheus',
  9100: 'Node Exporter',
  11211: 'Memcached',
  27017: 'MongoDB',
  51820: 'WireGuard',
};

/** Well-known multi-port combinations. */
const MULTI_PORT_LABELS: Array<{ ports: number[]; label: string }> = [
  { ports: [80, 443], label: 'Web Traffic' },
  { ports: [25, 587], label: 'SMTP' },
  { ports: [143, 993], label: 'IMAP' },
  { ports: [110, 995], label: 'POP3' },
  { ports: [500, 4500], label: 'IKE/NAT-T' },
  { ports: [67, 68], label: 'DHCP' },
];

function portsMatch(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;
  const sorted1 = [...a].sort((x, y) => x - y);
  const sorted2 = [...b].sort((x, y) => x - y);
  return sorted1.every((v, i) => v === sorted2[i]);
}

function labelFromPorts(ports: PortSpec): string | null {
  switch (ports.type) {
    case 'single': {
      const known = PORT_LABELS[ports.port];
      return known ?? `Custom Port ${ports.port}`;
    }
    case 'multi': {
      // Check multi-port combos first
      for (const combo of MULTI_PORT_LABELS) {
        if (portsMatch(ports.ports, combo.ports)) {
          return combo.label;
        }
      }
      // Try to find a label for the first port
      const labels = ports.ports.map(p => PORT_LABELS[p]).filter(Boolean);
      if (labels.length > 0) return labels.join(' / ');
      return `Custom Ports ${ports.ports.join(',')}`;
    }
    case 'range':
      return `Ports ${ports.from}-${ports.to}`;
    default:
      return null;
  }
}

/**
 * Generate a human-readable label from rule properties.
 *
 * Examples:
 *   - port 80,443 + tcp -> "Web Traffic"
 *   - port 22 + tcp -> "SSH"
 *   - port 5432 + tcp -> "PostgreSQL"
 *   - port 53 -> "DNS"
 *   - ICMP protocol -> "Ping"
 *   - unknown port -> "Custom Port 8080"
 */
export function generateRuleLabel(rule: Partial<Rule>): string {
  // ICMP -> Ping
  if (rule.protocol === 'icmp' || rule.protocol === 'icmpv6') {
    return 'Ping';
  }

  // If ports are specified, use port-based labeling
  if (rule.ports) {
    const portLabel = labelFromPorts(rule.ports);
    if (portLabel) return portLabel;
  }

  // Protocol-only rules
  if (rule.protocol === 'gre') return 'GRE Tunnel';
  if (rule.protocol === 'esp') return 'IPSec ESP';
  if (rule.protocol === 'ah') return 'IPSec AH';
  if (rule.protocol === 'sctp') return 'SCTP';

  // Action-based fallbacks
  if (rule.action === 'masquerade') return 'NAT Masquerade';
  if (rule.action === 'dnat') return 'DNAT';
  if (rule.action === 'snat') return 'SNAT';
  if (rule.action === 'block' || rule.action === 'block-reject') return 'Block All';
  if (rule.action === 'log') return 'Log Traffic';
  if (rule.action === 'log-block') return 'Log & Block';

  return 'Custom Rule';
}
