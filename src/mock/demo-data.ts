/**
 * Demo data for standalone browser mode.
 *
 * Populates the store with sample hosts, groups, IP lists, rules,
 * hit counters, and blocked log entries so the UI is fully interactive
 * without a Tauri backend.
 */

import type { Store } from '../store/index';
import type {
  Host,
  HostGroup,
  IpList,
  Rule,
  HitCounter,
  BlockedEntry,
} from '../store/types';

// ─── Stable IDs ─────────────────────────────────────────────

const HOST_WEB01 = 'demo-host-web-01';
const HOST_DB01 = 'demo-host-db-01';
const HOST_CACHE01 = 'demo-host-cache-01';

const GROUP_WEB = 'demo-group-web-servers';

const IPLIST_OFFICE = 'demo-iplist-office';

const RULE_WEB_HTTP = 'demo-rule-web-http';
const RULE_WEB_SSH = 'demo-rule-web-ssh';
const RULE_WEB_MON = 'demo-rule-web-monitoring';
const RULE_WEB_BLOCK = 'demo-rule-web-block-all';

const RULE_DB_PG = 'demo-rule-db-postgres';
const RULE_DB_SSH = 'demo-rule-db-ssh';
const RULE_DB_BLOCK = 'demo-rule-db-block-all';

// ─── Helpers ────────────────────────────────────────────────

const now = Date.now();

function ts(minutesAgo: number): number {
  return now - minutesAgo * 60_000;
}

// ─── Hosts ──────────────────────────────────────────────────

const hosts: Host[] = [
  {
    id: HOST_WEB01,
    name: 'web-01',
    connection: { hostname: '10.0.1.10', port: 22, username: 'root', authMethod: 'key' },
    capabilities: {
      iptablesVariant: 'iptables-nft',
      iptablesVersion: '1.8.9',
      safetyMechanism: 'iptables-apply',
      atdRunning: true,
      ipsetAvailable: true,
      ip6tablesAvailable: true,
      detectedTools: [],
      distro: { name: 'Ubuntu 22.04', family: 'debian' },
      interfaces: [
        { name: 'eth0', type: 'physical', addresses: ['10.0.1.10'], isUp: true },
        { name: 'lo', type: 'loopback', addresses: ['127.0.0.1'], isUp: true },
      ],
      runningServices: [
        { name: 'nginx', ports: [80, 443], protocol: 'tcp' },
        { name: 'node-exporter', ports: [9100], protocol: 'tcp' },
        { name: 'sshd', ports: [22], protocol: 'tcp' },
      ],
      persistenceMethod: 'iptables-persistent',
      managementInterface: 'eth0',
      managementIsVpn: false,
    },
    status: 'connected',
    groupIds: [GROUP_WEB],
    groupOrder: [GROUP_WEB],
    lastConnected: ts(5),
    lastSyncedRuleHash: 'abc123',
    provisioned: true,
    createdAt: ts(10080), // 7 days ago
    updatedAt: ts(5),
  },
  {
    id: HOST_DB01,
    name: 'db-01',
    connection: { hostname: '10.0.2.20', port: 22, username: 'root', authMethod: 'key' },
    capabilities: {
      iptablesVariant: 'iptables-legacy',
      iptablesVersion: '1.8.7',
      safetyMechanism: 'at',
      atdRunning: true,
      ipsetAvailable: false,
      ip6tablesAvailable: true,
      detectedTools: [],
      distro: { name: 'Debian 12', family: 'debian' },
      interfaces: [
        { name: 'eth0', type: 'physical', addresses: ['10.0.2.20'], isUp: true },
        { name: 'lo', type: 'loopback', addresses: ['127.0.0.1'], isUp: true },
      ],
      runningServices: [
        { name: 'postgresql', ports: [5432], protocol: 'tcp' },
        { name: 'sshd', ports: [22], protocol: 'tcp' },
      ],
      persistenceMethod: 'iptables-persistent',
      managementInterface: 'eth0',
      managementIsVpn: false,
    },
    status: 'connected',
    groupIds: [],
    groupOrder: [],
    lastConnected: ts(3),
    lastSyncedRuleHash: 'def456',
    provisioned: true,
    createdAt: ts(10080),
    updatedAt: ts(3),
  },
  {
    id: HOST_CACHE01,
    name: 'cache-01',
    connection: { hostname: '10.0.3.30', port: 22, username: 'admin', authMethod: 'key' },
    capabilities: null,
    status: 'unreachable',
    groupIds: [],
    groupOrder: [],
    lastConnected: ts(4320), // 3 days ago
    provisioned: false,
    createdAt: ts(20160), // 14 days ago
    updatedAt: ts(4320),
  },
];

// ─── Groups ─────────────────────────────────────────────────

const groups: HostGroup[] = [
  {
    id: GROUP_WEB,
    name: 'Web Servers',
    memberHostIds: [HOST_WEB01],
    rules: [],
    position: 0,
    createdAt: ts(10080),
    updatedAt: ts(10080),
  },
];

// ─── IP Lists ───────────────────────────────────────────────

const ipLists: IpList[] = [
  {
    id: IPLIST_OFFICE,
    name: 'Office IPs',
    slug: 'office-ips',
    entries: [
      { address: '203.0.113.10/32', comment: 'HQ Office' },
      { address: '198.51.100.0/24', comment: 'Remote Office' },
    ],
    usedInRuleIds: [RULE_WEB_SSH],
    createdAt: ts(10080),
    updatedAt: ts(1440),
  },
];

// ─── Rules for web-01 ───────────────────────────────────────

const web01Rules: Rule[] = [
  {
    id: RULE_WEB_HTTP,
    label: 'Allow Web Traffic',
    action: 'allow',
    protocol: 'tcp',
    ports: { type: 'multi', ports: [80, 443] },
    source: { type: 'anyone' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'v4',
    origin: { type: 'user' },
    position: 0,
    enabled: true,
    comment: 'HTTP and HTTPS',
    createdAt: ts(10080),
    updatedAt: ts(10080),
  },
  {
    id: RULE_WEB_SSH,
    label: 'Allow SSH',
    action: 'allow',
    protocol: 'tcp',
    ports: { type: 'single', port: 22 },
    source: { type: 'iplist', ipListId: IPLIST_OFFICE },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'v4',
    origin: { type: 'user' },
    position: 1,
    enabled: true,
    comment: 'SSH restricted to Office IPs',
    createdAt: ts(10080),
    updatedAt: ts(10080),
  },
  {
    id: RULE_WEB_MON,
    label: 'Allow Monitoring',
    action: 'allow',
    protocol: 'tcp',
    ports: { type: 'single', port: 9100 },
    source: { type: 'cidr', value: '10.0.0.0/8' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'v4',
    origin: { type: 'user' },
    position: 2,
    enabled: true,
    comment: 'Prometheus node-exporter',
    createdAt: ts(10080),
    updatedAt: ts(10080),
  },
  {
    id: RULE_WEB_BLOCK,
    label: 'Drop Everything Else',
    action: 'block',
    source: { type: 'anyone' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'both',
    origin: { type: 'user' },
    position: 3,
    enabled: true,
    comment: 'Default deny policy',
    createdAt: ts(10080),
    updatedAt: ts(10080),
  },
];

// ─── Rules for db-01 ────────────────────────────────────────

const db01Rules: Rule[] = [
  {
    id: RULE_DB_PG,
    label: 'Allow PostgreSQL',
    action: 'allow',
    protocol: 'tcp',
    ports: { type: 'single', port: 5432 },
    source: { type: 'cidr', value: '10.0.1.10/32' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'v4',
    origin: { type: 'user' },
    position: 0,
    enabled: true,
    comment: 'PostgreSQL from web-01 only',
    createdAt: ts(10080),
    updatedAt: ts(10080),
  },
  {
    id: RULE_DB_SSH,
    label: 'Allow SSH',
    action: 'allow',
    protocol: 'tcp',
    ports: { type: 'single', port: 22 },
    source: { type: 'anyone' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'v4',
    origin: { type: 'user' },
    position: 1,
    enabled: true,
    comment: 'SSH from anywhere',
    createdAt: ts(10080),
    updatedAt: ts(10080),
  },
  {
    id: RULE_DB_BLOCK,
    label: 'Drop Everything Else',
    action: 'block',
    source: { type: 'anyone' },
    destination: { type: 'anyone' },
    direction: 'incoming',
    addressFamily: 'both',
    origin: { type: 'user' },
    position: 2,
    enabled: true,
    comment: 'Default deny policy',
    createdAt: ts(10080),
    updatedAt: ts(10080),
  },
];

// ─── Hit Counters for web-01 ────────────────────────────────

const web01HitCounters: HitCounter[] = [
  { ruleId: RULE_WEB_HTTP, packets: 1247, bytes: 892_400, timestamp: ts(1) },
  { ruleId: RULE_WEB_SSH, packets: 3, bytes: 1_200, timestamp: ts(30) },
  { ruleId: RULE_WEB_MON, packets: 89, bytes: 12_460, timestamp: ts(2) },
  { ruleId: RULE_WEB_BLOCK, packets: 412, bytes: 24_720, timestamp: ts(1) },
];

// ─── Blocked Log for web-01 ─────────────────────────────────

const web01BlockedLog: BlockedEntry[] = [
  {
    id: 'blocked-1',
    timestamp: ts(1),
    sourceIp: '45.33.32.156',
    destPort: 3306,
    protocol: 'tcp',
    serviceName: 'MySQL',
    interfaceIn: 'eth0',
    count: 47,
  },
  {
    id: 'blocked-2',
    timestamp: ts(3),
    sourceIp: '185.220.101.42',
    destPort: 23,
    protocol: 'tcp',
    serviceName: 'Telnet',
    interfaceIn: 'eth0',
    count: 12,
  },
  {
    id: 'blocked-3',
    timestamp: ts(8),
    sourceIp: '91.240.118.172',
    destPort: 8080,
    protocol: 'tcp',
    interfaceIn: 'eth0',
    count: 5,
  },
  {
    id: 'blocked-4',
    timestamp: ts(15),
    sourceIp: '122.228.19.80',
    destPort: 445,
    protocol: 'tcp',
    serviceName: 'SMB',
    interfaceIn: 'eth0',
    count: 3,
  },
];

// ─── Load into store ────────────────────────────────────────

export function loadDemoData(store: Store): void {
  // Add hosts
  for (const host of hosts) {
    store.dispatch({ type: 'ADD_HOST', host });
  }

  // Add groups
  for (const group of groups) {
    store.dispatch({ type: 'ADD_GROUP', group });
  }

  // Add IP lists
  for (const ipList of ipLists) {
    store.dispatch({ type: 'ADD_IP_LIST', ipList });
  }

  // Set rules for web-01
  store.dispatch({
    type: 'SET_HOST_RULES',
    hostId: HOST_WEB01,
    rules: web01Rules,
  });

  // Set rules for db-01
  store.dispatch({
    type: 'SET_HOST_RULES',
    hostId: HOST_DB01,
    rules: db01Rules,
  });

  // Set hit counters for web-01
  store.dispatch({
    type: 'UPDATE_HIT_COUNTERS',
    hostId: HOST_WEB01,
    counters: web01HitCounters,
  });

  // Add blocked log entries for web-01
  for (const entry of web01BlockedLog) {
    store.dispatch({
      type: 'ADD_BLOCKED_ENTRY',
      hostId: HOST_WEB01,
      entry,
    });
  }

  // Set conntrack for web-01
  store.dispatch({
    type: 'SET_CONNTRACK_USAGE',
    hostId: HOST_WEB01,
    current: 1_247,
    max: 65_536,
  });

  // Select web-01 as the active host
  store.dispatch({ type: 'SET_ACTIVE_HOST', hostId: HOST_WEB01 });
}
