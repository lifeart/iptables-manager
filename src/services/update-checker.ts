/**
 * Version update checker.
 *
 * Fetches the latest GitHub release and compares it against the
 * build-time version to determine if an update is available.
 * Failures are silently swallowed — this is a best-effort check
 * that must never block or break the app.
 */

const GITHUB_API = 'https://api.github.com/repos/lifeart/iptables-manager/releases/latest';
const CURRENT_VERSION: string = __APP_VERSION__;

export interface UpdateInfo {
  latestVersion: string;
  currentVersion: string;
  downloadUrl: string;
  releaseNotes: string;
}

export async function checkForUpdates(): Promise<UpdateInfo | null> {
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
