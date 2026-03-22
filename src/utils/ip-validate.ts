/**
 * IP address, CIDR, and port validation utilities.
 */

/**
 * Validate an IPv4 address (e.g., "192.168.1.1").
 */
export function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = parseInt(part, 10);
    if (num < 0 || num > 255) return false;
    // Reject leading zeros (e.g., "01" is invalid)
    if (part.length > 1 && part.startsWith('0')) return false;
  }
  return true;
}

/**
 * Validate an IPv6 address.
 * Supports full form, compressed (::), and mixed IPv4-mapped form.
 */
export function isValidIPv6(ip: string): boolean {
  // Quick sanity checks
  if (ip.length < 2 || ip.length > 45) return false;

  // Handle IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1)
  const lastColon = ip.lastIndexOf(':');
  if (lastColon !== -1) {
    const possibleIpv4 = ip.slice(lastColon + 1);
    if (possibleIpv4.includes('.')) {
      if (!isValidIPv4(possibleIpv4)) return false;
      const ipv6Part = ip.slice(0, lastColon + 1);
      // Validate the IPv6 prefix without the IPv4 part
      // It should end with : and have valid IPv6 groups before it
      return isValidIPv6Prefix(ipv6Part);
    }
  }

  // Handle :: (double colon)
  const doubleColonCount = (ip.match(/::/g) || []).length;
  if (doubleColonCount > 1) return false;

  if (doubleColonCount === 1) {
    const parts = ip.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    if (left.length + right.length > 7) return false;
    for (const group of [...left, ...right]) {
      if (!isValidIPv6Group(group)) return false;
    }
    return true;
  }

  // No :: — must have exactly 8 groups
  const groups = ip.split(':');
  if (groups.length !== 8) return false;
  return groups.every(isValidIPv6Group);
}

function isValidIPv6Group(group: string): boolean {
  if (group.length < 1 || group.length > 4) return false;
  return /^[0-9a-fA-F]{1,4}$/.test(group);
}

function isValidIPv6Prefix(prefix: string): boolean {
  // Remove trailing colon for validation
  if (prefix.endsWith('::')) {
    const withoutDoubleColon = prefix.slice(0, -2);
    if (withoutDoubleColon === '') return true;
    const groups = withoutDoubleColon.split(':');
    return groups.length <= 5 && groups.every(isValidIPv6Group);
  }
  if (prefix.endsWith(':')) {
    const withoutColon = prefix.slice(0, -1);
    if (withoutColon.includes('::')) {
      const parts = withoutColon.split('::');
      const left = parts[0] ? parts[0].split(':') : [];
      const right = parts[1] ? parts[1].split(':') : [];
      return left.length + right.length <= 5 &&
        [...left, ...right].every(isValidIPv6Group);
    }
  }
  return false;
}

/**
 * Validate an IPv4 CIDR notation (e.g., "192.168.1.0/24").
 */
export function isValidIPv4CIDR(cidr: string): boolean {
  const parts = cidr.split('/');
  if (parts.length !== 2) return false;
  if (!isValidIPv4(parts[0])) return false;
  const prefix = parseInt(parts[1], 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;
  if (parts[1] !== String(prefix)) return false; // no leading zeros
  return true;
}

/**
 * Validate an IPv6 CIDR notation (e.g., "2001:db8::/32").
 */
export function isValidIPv6CIDR(cidr: string): boolean {
  const slashIdx = cidr.lastIndexOf('/');
  if (slashIdx === -1) return false;
  const ip = cidr.slice(0, slashIdx);
  const prefixStr = cidr.slice(slashIdx + 1);
  if (!isValidIPv6(ip)) return false;
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 128) return false;
  if (prefixStr !== String(prefix)) return false;
  return true;
}

/**
 * Validate a CIDR notation (either IPv4 or IPv6).
 */
export function isValidCIDR(cidr: string): boolean {
  return isValidIPv4CIDR(cidr) || isValidIPv6CIDR(cidr);
}

/**
 * Validate a port number (1-65535).
 */
export function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * Validate a port string (e.g., "80", "443").
 */
export function isValidPortString(portStr: string): boolean {
  if (!/^\d{1,5}$/.test(portStr)) return false;
  const port = parseInt(portStr, 10);
  return isValidPort(port);
}

/**
 * Validate a port range string (e.g., "1024:65535").
 */
export function isValidPortRange(range: string): boolean {
  const parts = range.split(':');
  if (parts.length !== 2) return false;
  if (!isValidPortString(parts[0]) || !isValidPortString(parts[1])) return false;
  const from = parseInt(parts[0], 10);
  const to = parseInt(parts[1], 10);
  return from < to;
}

/**
 * Detect whether a string is an IPv4 or IPv6 address.
 */
export function detectAddressFamily(address: string): 'v4' | 'v6' | null {
  // Strip CIDR notation for detection
  const bare = address.includes('/') ? address.split('/')[0] : address;
  if (isValidIPv4(bare)) return 'v4';
  if (isValidIPv6(bare)) return 'v6';
  return null;
}
