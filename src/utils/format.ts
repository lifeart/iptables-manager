/**
 * Formatting utilities for display.
 */

/**
 * Format a count with optional singular/plural labels.
 *
 * @example
 *   formatCount(5, 'rule', 'rules')  // "5 rules"
 *   formatCount(1, 'rule', 'rules')  // "1 rule"
 *   formatCount(0, 'rule', 'rules')  // "0 rules"
 *   formatCount(1234)                // "1,234"
 */
export function formatCount(count: number, singular?: string, plural?: string): string {
  const formatted = count.toLocaleString('en-US');
  if (!singular) return formatted;
  const label = count === 1 ? singular : (plural ?? singular + 's');
  return `${formatted} ${label}`;
}

/**
 * Format a timestamp as a relative time string ("3m ago", "2h ago", etc.).
 *
 * @param timestamp - Unix timestamp in milliseconds
 * @param now - Current time in ms (default: Date.now())
 */
export function formatTimeAgo(timestamp: number, now?: number): string {
  const currentTime = now ?? Date.now();
  const diffMs = currentTime - timestamp;

  if (diffMs < 0) return 'just now';

  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;

  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;

  const years = Math.floor(days / 365);
  return `${years}y ago`;
}

/**
 * Format a duration in milliseconds to a human-readable string.
 *
 * @example
 *   formatDuration(65000)     // "1m 5s"
 *   formatDuration(3661000)   // "1h 1m 1s"
 *   formatDuration(500)       // "0s"
 *   formatDuration(45000)     // "45s"
 */
export function formatDuration(ms: number): string {
  ms = Math.max(0, ms);
  if (ms < 1000) return '0s';

  const seconds = Math.floor(ms / 1000) % 60;
  const minutes = Math.floor(ms / 60000) % 60;
  const hours = Math.floor(ms / 3600000);

  const parts: string[] = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (seconds > 0 || parts.length === 0) parts.push(`${seconds}s`);

  return parts.join(' ');
}

/**
 * Format a byte count to a human-readable string.
 *
 * @example
 *   formatBytes(0)           // "0 B"
 *   formatBytes(1024)        // "1.0 KB"
 *   formatBytes(1536)        // "1.5 KB"
 *   formatBytes(1048576)     // "1.0 MB"
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const k = 1024;
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  const unitIndex = Math.min(i, units.length - 1);

  if (unitIndex === 0) return `${bytes} B`;

  const value = bytes / Math.pow(k, unitIndex);
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

/**
 * Format a packets-per-second rate.
 *
 * @example
 *   formatRate(0)       // "0 pps"
 *   formatRate(1234.5)  // "1,235 pps"
 */
export function formatRate(pps: number): string {
  return `${Math.round(pps).toLocaleString('en-US')} pps`;
}
