/**
 * Auto-generate human-readable labels from rule properties.
 */

import type { Rule, PortSpec } from '../store/types';

/** Well-known port-to-label mappings. */
const PORT_LABELS: Record<number, string> = {
  // File transfer
  20: 'FTP Data',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  69: 'TFTP',
  115: 'SFTP',
  873: 'rsync',
  // Email
  25: 'SMTP',
  110: 'POP3',
  143: 'IMAP',
  465: 'SMTPS',
  587: 'SMTP Submission',
  993: 'IMAPS',
  995: 'POP3S',
  4190: 'Sieve',
  // Web
  80: 'HTTP',
  443: 'HTTPS',
  8080: 'HTTP Alt',
  8443: 'HTTPS Alt',
  8888: 'HTTP Proxy Alt',
  // DNS & network
  53: 'DNS',
  67: 'DHCP Server',
  68: 'DHCP Client',
  123: 'NTP',
  161: 'SNMP',
  162: 'SNMP Trap',
  514: 'Syslog',
  853: 'DNS over TLS',
  // Remote access
  3389: 'RDP',
  5900: 'VNC',
  5938: 'TeamViewer',
  // Databases
  1433: 'MSSQL',
  1521: 'Oracle DB',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  6379: 'Redis',
  9042: 'Cassandra',
  11211: 'Memcached',
  27017: 'MongoDB',
  5984: 'CouchDB',
  8529: 'ArangoDB',
  26257: 'CockroachDB',
  28015: 'RethinkDB',
  7474: 'Neo4j HTTP',
  7687: 'Neo4j Bolt',
  9200: 'Elasticsearch',
  9300: 'Elasticsearch Transport',
  5601: 'Kibana',
  8086: 'InfluxDB',
  4317: 'OpenTelemetry gRPC',
  4318: 'OpenTelemetry HTTP',
  // Message brokers
  5672: 'RabbitMQ',
  15672: 'RabbitMQ Management',
  9092: 'Kafka',
  4222: 'NATS',
  6222: 'NATS Cluster',
  1883: 'MQTT',
  8883: 'MQTT over TLS',
  61613: 'STOMP',
  61616: 'ActiveMQ',
  // Container & orchestration
  2375: 'Docker API',
  2376: 'Docker API TLS',
  2377: 'Docker Swarm',
  6443: 'Kubernetes API',
  10250: 'Kubelet',
  10255: 'Kubelet Read-Only',
  2379: 'etcd Client',
  2380: 'etcd Peer',
  8500: 'Consul',
  8600: 'Consul DNS',
  4646: 'Nomad',
  8200: 'Vault',
  // Monitoring & observability
  9090: 'Prometheus',
  9100: 'Node Exporter',
  9093: 'Alertmanager',
  3000: 'Grafana',
  9411: 'Zipkin',
  14268: 'Jaeger',
  16686: 'Jaeger UI',
  8125: 'StatsD',
  // CI/CD & development
  8081: 'Nexus',
  9000: 'SonarQube',
  50000: 'Jenkins Agent',
  8082: 'Artifactory',
  5000: 'Docker Registry',
  // VPN
  1194: 'OpenVPN',
  51820: 'WireGuard',
  500: 'IKE',
  4500: 'IPSec NAT-T',
  1701: 'L2TP',
  1723: 'PPTP',
  // Proxy & load balancing
  3128: 'Squid Proxy',
  1080: 'SOCKS Proxy',
  8090: 'HAProxy Stats',
  // Git & collaboration
  9418: 'Git',
  3478: 'STUN/TURN',
  5349: 'STUN/TURN TLS',
  // Game / media servers
  25565: 'Minecraft',
  27015: 'Steam/Source',
  8554: 'RTSP',
  1935: 'RTMP',
  // LDAP & directory
  389: 'LDAP',
  636: 'LDAPS',
  88: 'Kerberos',
  464: 'Kerberos Password',
  // Misc infrastructure
  179: 'BGP',
  5060: 'SIP',
  5061: 'SIP TLS',
  11371: 'OpenPGP Keyserver',
};

/** Well-known multi-port combinations. */
const MULTI_PORT_LABELS: Array<{ ports: number[]; label: string }> = [
  { ports: [80, 443], label: 'Web Traffic' },
  { ports: [25, 587], label: 'SMTP' },
  { ports: [25, 465, 587], label: 'SMTP (all)' },
  { ports: [143, 993], label: 'IMAP' },
  { ports: [110, 995], label: 'POP3' },
  { ports: [25, 587, 993], label: 'Email (SMTP + IMAP)' },
  { ports: [25, 587, 143, 993, 110, 995], label: 'Email (all)' },
  { ports: [500, 4500], label: 'IKE/NAT-T' },
  { ports: [67, 68], label: 'DHCP' },
  { ports: [9200, 9300], label: 'Elasticsearch' },
  { ports: [5672, 15672], label: 'RabbitMQ' },
  { ports: [2379, 2380], label: 'etcd' },
  { ports: [7474, 7687], label: 'Neo4j' },
  { ports: [9090, 9093], label: 'Prometheus + Alertmanager' },
  { ports: [9090, 9100], label: 'Monitoring' },
  { ports: [4317, 4318], label: 'OpenTelemetry' },
  { ports: [2375, 2376], label: 'Docker API' },
  { ports: [3478, 5349], label: 'STUN/TURN' },
  { ports: [5060, 5061], label: 'SIP' },
  { ports: [389, 636], label: 'LDAP' },
  { ports: [88, 464], label: 'Kerberos' },
  { ports: [1883, 8883], label: 'MQTT' },
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
