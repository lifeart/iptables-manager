/**
 * Version update checker.
 *
 * In Tauri mode, uses the native updater plugin to check for updates
 * (signed artifacts from GitHub Releases). Falls back to the GitHub
 * API when the plugin is unavailable (browser mode, missing pubkey, etc.).
 *
 * Failures are silently swallowed — this is a best-effort check
 * that must never block or break the app.
 */

import type { Update } from '@tauri-apps/plugin-updater';

const GITHUB_API = 'https://api.github.com/repos/lifeart/iptables-manager/releases/latest';
const CURRENT_VERSION: string = __APP_VERSION__;

const IS_TAURI = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

export interface UpdateInfo {
  latestVersion: string;
  currentVersion: string;
  downloadUrl: string;
  releaseNotes: string;
  /** Native update handle — present only in Tauri mode. */
  update?: Update;
}

export async function checkForUpdates(): Promise<UpdateInfo | null> {
  // Try native updater first in Tauri mode
  if (IS_TAURI) {
    try {
      const result = await checkViaTauriPlugin();
      if (result) return result;
      // Plugin returned null (no update) — that's fine, don't fall through
      // to GitHub API since the plugin check succeeded
      return null;
    } catch {
      // Plugin not configured (empty pubkey), not available, etc.
      // Fall through to GitHub API fallback
    }
  }

  return checkViaGitHubApi();
}

async function checkViaTauriPlugin(): Promise<UpdateInfo | null> {
  const { check } = await import('@tauri-apps/plugin-updater');
  const update = await check();
  if (update) {
    return {
      latestVersion: update.version,
      currentVersion: CURRENT_VERSION,
      downloadUrl: '', // not needed — native updater handles download
      releaseNotes: update.body || '',
      update,
    };
  }
  return null;
}

async function checkViaGitHubApi(): Promise<UpdateInfo | null> {
  try {
    const res = await fetch(GITHUB_API);
    if (!res.ok) return null;
    const data = await res.json();
    const latest = (data.tag_name as string).replace(/^v/, '');
    if (isNewerVersion(latest, CURRENT_VERSION)) {
      return {
        latestVersion: latest,
        currentVersion: CURRENT_VERSION,
        downloadUrl: data.html_url as string,
        releaseNotes: (data.body as string) || '',
      };
    }
    return null;
  } catch {
    // Network error, offline, rate-limited, etc. — not critical
    return null;
  }
}

function isNewerVersion(latest: string, current: string): boolean {
  const l = latest.split('.').map(Number);
  const c = current.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((l[i] || 0) > (c[i] || 0)) return true;
    if ((l[i] || 0) < (c[i] || 0)) return false;
  }
  return false;
}
