/**
 * Port string validation and parsing utilities.
 *
 * Supported formats:
 *   - Single port: "80"
 *   - Comma-separated: "80,443"
 *   - Range: "8000-8100"
 */

import type { PortSpec } from '../store/types';

function isPortInRange(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * Validate a port string.
 * Accepts single ports ("80"), comma-separated ("80,443"), and ranges ("8000-8100").
 */
export function isValidPortString(input: string): boolean {
  const trimmed = input.trim();
  if (trimmed === '') return false;

  // Range: "8000-8100"
  if (trimmed.includes('-')) {
    const parts = trimmed.split('-');
    if (parts.length !== 2) return false;
    const from = parseInt(parts[0].trim(), 10);
    const to = parseInt(parts[1].trim(), 10);
    if (isNaN(from) || isNaN(to)) return false;
    if (!isPortInRange(from) || !isPortInRange(to)) return false;
    return from < to;
  }

  // Comma-separated: "80,443"
  if (trimmed.includes(',')) {
    const parts = trimmed.split(',');
    for (const part of parts) {
      const p = parseInt(part.trim(), 10);
      if (isNaN(p) || !isPortInRange(p)) return false;
      // Reject non-numeric characters
      if (!/^\s*\d+\s*$/.test(part)) return false;
    }
    return parts.length >= 2;
  }

  // Single port: "80"
  if (!/^\d+$/.test(trimmed)) return false;
  const port = parseInt(trimmed, 10);
  return isPortInRange(port);
}

/**
 * Parse a port string into a PortSpec.
 * Returns null if the input is invalid.
 */
export function parsePortString(input: string): PortSpec | null {
  const trimmed = input.trim();
  if (!isValidPortString(trimmed)) return null;

  // Range
  if (trimmed.includes('-')) {
    const parts = trimmed.split('-');
    return {
      type: 'range',
      from: parseInt(parts[0].trim(), 10),
      to: parseInt(parts[1].trim(), 10),
    };
  }

  // Multi
  if (trimmed.includes(',')) {
    const ports = trimmed.split(',').map(p => parseInt(p.trim(), 10));
    return { type: 'multi', ports };
  }

  // Single
  return { type: 'single', port: parseInt(trimmed, 10) };
}
