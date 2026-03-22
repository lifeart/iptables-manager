/**
 * Rule templates — predefined rulesets for common server configurations.
 *
 * Each template returns an array of Rule objects that can be applied as a batch.
 * Templates cover the 11 standard configurations from the spec.
 */

import type { Rule } from '../store/types';

export interface RuleTemplate {
  id: string;
  name: string;
  description: string;
  /** Generate rules for this template. managementIp is the user's current IP. */
  generate(opts: TemplateOptions): Rule[];
}

export interface TemplateOptions {
  managementIp?: string;
  vpnInterface?: string;
  vpnSubnet?: string;
  physicalInterface?: string;
  vpnPort?: number;
}

function uid(): string {
  return crypto.randomUUID();
}

function now(): number {
  return Date.now();
}

function makeRule(partial: Partial<Rule> & Pick<Rule, 'label' | 'action' | 'direction'>): Rule {
  const t = now();
  return {
    id: uid(),
    label: partial.label,
    action: partial.action,
    protocol: partial.protocol,
    ports: partial.ports,
    source: partial.source ?? { type: 'anyone' },
    destination: partial.destination ?? { type: 'anyone' },
    direction: partial.direction,
    addressFamily: partial.addressFamily ?? 'both',
    interfaceIn: partial.interfaceIn,
    interfaceOut: partial.interfaceOut,
    conntrackStates: partial.conntrackStates,
    rateLimit: partial.rateLimit,
    logPrefix: partial.logPrefix,
    logRateLimit: partial.logRateLimit,
    tcpFlags: partial.tcpFlags,
    ipsecPolicy: partial.ipsecPolicy,
    conntrackHelper: partial.conntrackHelper,
    customMatches: partial.customMatches,
    dnat: partial.dnat,
    snat: partial.snat,
    comment: partial.comment,
    origin: partial.origin ?? { type: 'user' },
    position: partial.position ?? 0,
    enabled: partial.enabled ?? true,
    temporary: partial.temporary,
    raw: partial.raw,
    createdAt: t,
    updatedAt: t,
  };
}

function sshRule(managementIp?: string): Rule {
  return makeRule({
    label: 'Allow SSH',
    action: 'allow',
    protocol: 'tcp',
    ports: { type: 'single', port: 22 },
    source: managementIp ? { type: 'cidr', value: managementIp.includes('/') ? managementIp : `${managementIp}/32` } : { type: 'anyone' },
    direction: 'incoming',
    comment: managementIp ? 'SSH restricted to management IP' : 'SSH from anywhere',
  });
}

function pingRule(): Rule {
  return makeRule({
    label: 'Allow Ping',
    action: 'allow',
    protocol: 'icmp',
    direction: 'incoming',
    comment: 'Allow ICMP echo requests',
  });
}

function blockAllRule(): Rule {
  return makeRule({
    label: 'Drop Everything Else',
    action: 'block',
    direction: 'incoming',
    comment: 'Default deny policy',
  });
}

// ─── Template Definitions ────────────────────────────────────

const webServer: RuleTemplate = {
  id: 'web-server',
  name: 'Web Server',
  description: 'HTTP/HTTPS + SSH + Ping',
  generate(opts) {
    return [
      makeRule({
        label: 'Allow Web Traffic',
        action: 'allow',
        protocol: 'tcp',
        ports: { type: 'multi', ports: [80, 443] },
        direction: 'incoming',
        comment: 'HTTP and HTTPS',
      }),
      sshRule(opts.managementIp),
      pingRule(),
      blockAllRule(),
    ];
  },
};

const databaseServer: RuleTemplate = {
  id: 'database-server',
  name: 'Database Server',
  description: 'DB port + SSH, internal network only',
  generate(opts) {
    return [
      makeRule({
        label: 'Allow PostgreSQL',
        action: 'allow',
        protocol: 'tcp',
        ports: { type: 'single', port: 5432 },
        source: { type: 'cidr', value: '10.0.0.0/8' },
        direction: 'incoming',
        comment: 'PostgreSQL from internal network',
      }),
      makeRule({
        label: 'Allow MySQL',
        action: 'allow',
        protocol: 'tcp',
        ports: { type: 'single', port: 3306 },
        source: { type: 'cidr', value: '10.0.0.0/8' },
        direction: 'incoming',
        comment: 'MySQL from internal network',
      }),
      sshRule(opts.managementIp),
      pingRule(),
      blockAllRule(),
    ];
  },
};

const mailServer: RuleTemplate = {
  id: 'mail-server',
  name: 'Mail Server',
  description: 'SMTP/IMAP/POP + SSH',
  generate(opts) {
    return [
      makeRule({
        label: 'Allow SMTP',
        action: 'allow',
        protocol: 'tcp',
        ports: { type: 'multi', ports: [25, 587] },
        direction: 'incoming',
        comment: 'SMTP and submission',
      }),
      makeRule({
        label: 'Allow IMAP',
        action: 'allow',
        protocol: 'tcp',
        ports: { type: 'multi', ports: [143, 993] },
        direction: 'incoming',
        comment: 'IMAP and IMAPS',
      }),
      makeRule({
        label: 'Allow POP3',
        action: 'allow',
        protocol: 'tcp',
        ports: { type: 'multi', ports: [110, 995] },
        direction: 'incoming',
        comment: 'POP3 and POP3S',
      }),
      sshRule(opts.managementIp),
      pingRule(),
      blockAllRule(),
    ];
  },
};

const bastionHost: RuleTemplate = {
  id: 'bastion-host',
  name: 'Bastion Host',
  description: 'SSH only, strict egress',
  generate(opts) {
    return [
      sshRule(opts.managementIp),
      makeRule({
        label: 'Allow Outbound SSH',
        action: 'allow',
        protocol: 'tcp',
        ports: { type: 'single', port: 22 },
        direction: 'outgoing',
        comment: 'SSH to internal servers',
      }),
      makeRule({
        label: 'Allow Outbound DNS',
        action: 'allow',
        protocol: 'udp',
        ports: { type: 'single', port: 53 },
        direction: 'outgoing',
        comment: 'DNS resolution',
      }),
      pingRule(),
      blockAllRule(),
      makeRule({
        label: 'Block Outgoing',
        action: 'block',
        direction: 'outgoing',
        comment: 'Strict egress policy',
      }),
    ];
  },
};

const dockerHost: RuleTemplate = {
  id: 'docker-host',
  name: 'Docker Host',
  description: 'Docker-aware with DOCKER-USER chain rules',
  generate(opts) {
    return [
      makeRule({
        label: 'Allow Web Traffic',
        action: 'allow',
        protocol: 'tcp',
        ports: { type: 'multi', ports: [80, 443] },
        direction: 'incoming',
        comment: 'HTTP/HTTPS for containers',
      }),
      sshRule(opts.managementIp),
      makeRule({
        label: 'Allow Docker Internal',
        action: 'allow',
        protocol: 'tcp',
        source: { type: 'cidr', value: '172.16.0.0/12' },
        direction: 'forwarded',
        comment: 'Docker bridge network traffic',
      }),
      pingRule(),
      blockAllRule(),
    ];
  },
};

const natGateway: RuleTemplate = {
  id: 'nat-gateway',
  name: 'NAT Gateway',
  description: 'Forwarding + SNAT/MASQUERADE',
  generate(opts) {
    const physIf = opts.physicalInterface ?? 'eth0';
    return [
      sshRule(opts.managementIp),
      makeRule({
        label: 'Forward Internal to External',
        action: 'allow',
        direction: 'forwarded',
        interfaceIn: physIf,
        comment: 'Allow forwarded traffic',
      }),
      makeRule({
        label: 'NAT Masquerade',
        action: 'masquerade',
        direction: 'outgoing',
        interfaceOut: physIf,
        comment: 'MASQUERADE outbound traffic',
      }),
      pingRule(),
      blockAllRule(),
    ];
  },
};

const vpnWireGuard: RuleTemplate = {
  id: 'vpn-wireguard',
  name: 'VPN Server (WireGuard)',
  description: 'INPUT + FORWARD + NAT + sysctl for WireGuard',
  generate(opts) {
    const vpnIf = opts.vpnInterface ?? 'wg0';
    const vpnSubnet = opts.vpnSubnet ?? '10.200.0.0/24';
    const physIf = opts.physicalInterface ?? 'eth0';
    const vpnPort = opts.vpnPort ?? 51820;

    return [
      makeRule({
        label: 'Allow WireGuard',
        action: 'allow',
        protocol: 'udp',
        ports: { type: 'single', port: vpnPort },
        direction: 'incoming',
        comment: 'WireGuard VPN port',
      }),
      sshRule(opts.managementIp),
      makeRule({
        label: 'Forward VPN to Network',
        action: 'allow',
        direction: 'forwarded',
        interfaceIn: vpnIf,
        interfaceOut: physIf,
        comment: 'VPN clients to network',
      }),
      makeRule({
        label: 'Forward Network to VPN',
        action: 'allow',
        direction: 'forwarded',
        interfaceIn: physIf,
        interfaceOut: vpnIf,
        conntrackStates: ['established', 'related'],
        comment: 'Return traffic to VPN clients',
      }),
      makeRule({
        label: 'NAT VPN Clients',
        action: 'masquerade',
        direction: 'outgoing',
        interfaceOut: physIf,
        source: { type: 'cidr', value: vpnSubnet },
        comment: 'MASQUERADE VPN client traffic',
      }),
      makeRule({
        label: 'Enable IP Forwarding',
        action: 'allow',
        direction: 'forwarded',
        comment: 'sysctl: net.ipv4.ip_forward=1',
        raw: 'sysctl -w net.ipv4.ip_forward=1',
      }),
      pingRule(),
      blockAllRule(),
    ];
  },
};

const vpnOpenVPN: RuleTemplate = {
  id: 'vpn-openvpn',
  name: 'VPN Server (OpenVPN)',
  description: 'INPUT + FORWARD + NAT + sysctl for OpenVPN',
  generate(opts) {
    const vpnIf = opts.vpnInterface ?? 'tun0';
    const vpnSubnet = opts.vpnSubnet ?? '10.8.0.0/24';
    const physIf = opts.physicalInterface ?? 'eth0';
    const vpnPort = opts.vpnPort ?? 1194;

    return [
      makeRule({
        label: 'Allow OpenVPN',
        action: 'allow',
        protocol: 'udp',
        ports: { type: 'single', port: vpnPort },
        direction: 'incoming',
        comment: 'OpenVPN port',
      }),
      sshRule(opts.managementIp),
      makeRule({
        label: 'Forward VPN to Network',
        action: 'allow',
        direction: 'forwarded',
        interfaceIn: vpnIf,
        interfaceOut: physIf,
        comment: 'VPN clients to network',
      }),
      makeRule({
        label: 'Forward Network to VPN',
        action: 'allow',
        direction: 'forwarded',
        interfaceIn: physIf,
        interfaceOut: vpnIf,
        conntrackStates: ['established', 'related'],
        comment: 'Return traffic to VPN clients',
      }),
      makeRule({
        label: 'NAT VPN Clients',
        action: 'masquerade',
        direction: 'outgoing',
        interfaceOut: physIf,
        source: { type: 'cidr', value: vpnSubnet },
        comment: 'MASQUERADE VPN client traffic',
      }),
      makeRule({
        label: 'Enable IP Forwarding',
        action: 'allow',
        direction: 'forwarded',
        comment: 'sysctl: net.ipv4.ip_forward=1',
        raw: 'sysctl -w net.ipv4.ip_forward=1',
      }),
      pingRule(),
      blockAllRule(),
    ];
  },
};

const ipsecGateway: RuleTemplate = {
  id: 'ipsec-gateway',
  name: 'IPSec Gateway',
  description: 'IKE + ESP + FORWARD + NAT',
  generate(opts) {
    const physIf = opts.physicalInterface ?? 'eth0';
    const vpnSubnet = opts.vpnSubnet ?? '10.100.0.0/24';

    return [
      makeRule({
        label: 'Allow IKE',
        action: 'allow',
        protocol: 'udp',
        ports: { type: 'multi', ports: [500, 4500] },
        direction: 'incoming',
        comment: 'IKE and NAT-T',
      }),
      makeRule({
        label: 'Allow ESP',
        action: 'allow',
        protocol: 'esp',
        direction: 'incoming',
        comment: 'IPSec ESP protocol',
      }),
      sshRule(opts.managementIp),
      makeRule({
        label: 'Forward IPSec Traffic',
        action: 'allow',
        direction: 'forwarded',
        ipsecPolicy: { direction: 'in', policy: 'ipsec' },
        comment: 'Forward decrypted IPSec traffic',
      }),
      makeRule({
        label: 'NAT IPSec Clients',
        action: 'masquerade',
        direction: 'outgoing',
        interfaceOut: physIf,
        source: { type: 'cidr', value: vpnSubnet },
        comment: 'MASQUERADE IPSec client traffic',
      }),
      makeRule({
        label: 'Enable IP Forwarding',
        action: 'allow',
        direction: 'forwarded',
        comment: 'sysctl: net.ipv4.ip_forward=1',
        raw: 'sysctl -w net.ipv4.ip_forward=1',
      }),
      pingRule(),
      blockAllRule(),
    ];
  },
};

const lockdown: RuleTemplate = {
  id: 'lockdown',
  name: 'Lockdown',
  description: 'Block all except SSH',
  generate(opts) {
    return [
      sshRule(opts.managementIp),
      blockAllRule(),
    ];
  },
};

const minimal: RuleTemplate = {
  id: 'minimal',
  name: 'Minimal',
  description: 'INVALID drop + Established + SSH',
  generate(opts) {
    return [
      sshRule(opts.managementIp),
      pingRule(),
      blockAllRule(),
    ];
  },
};

// ─── Exports ─────────────────────────────────────────────────

export const allTemplates: RuleTemplate[] = [
  webServer,
  databaseServer,
  mailServer,
  bastionHost,
  dockerHost,
  natGateway,
  vpnWireGuard,
  vpnOpenVPN,
  ipsecGateway,
  lockdown,
  minimal,
];

/**
 * Get a template by ID.
 */
export function getTemplate(id: string): RuleTemplate | undefined {
  return allTemplates.find(t => t.id === id);
}

/**
 * Generate rules from a template.
 */
export function generateFromTemplate(templateId: string, opts: TemplateOptions = {}): Rule[] {
  const template = getTemplate(templateId);
  if (!template) return [];
  return template.generate(opts);
}
