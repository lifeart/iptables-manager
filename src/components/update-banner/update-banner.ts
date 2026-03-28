/**
 * Update notification banner.
 *
 * Shows a non-intrusive banner at the bottom of the window when a
 * newer version of Traffic Rules is available. In Tauri mode with
 * the updater plugin configured, offers one-click "Update Now" that
 * downloads and installs the update in-place. Otherwise falls back
 * to opening the GitHub release page.
 */

import { h } from '../../utils/dom';
import type { UpdateInfo } from '../../services/update-checker';

const DISMISSED_KEY = 'update-banner-dismissed-version';

export class UpdateBanner {
  private el: HTMLElement;
  private textEl!: HTMLSpanElement;
  private actionBtn!: HTMLButtonElement;
  private progressEl!: HTMLElement;
  private info: UpdateInfo;

  constructor(info: UpdateInfo) {
    this.info = info;
    this.el = this.render();
  }

  /** Mount the banner into the DOM. */
  mount(parent: HTMLElement): void {
    parent.appendChild(this.el);
    // Trigger slide-in on next frame so the transition fires
    requestAnimationFrame(() => {
      this.el.classList.add('update-banner--visible');
    });
  }

  /** Check if the user already dismissed this version. */
  static isDismissed(version: string): boolean {
    try {
      return localStorage.getItem(DISMISSED_KEY) === version;
    } catch {
      return false;
    }
  }

  private render(): HTMLElement {
    const banner = h('div', { className: 'update-banner' });
    const content = h('div', { className: 'update-banner__content' });

    const icon = h('span', { className: 'update-banner__icon' }, '\u2B06');

    this.textEl = h(
      'span',
      { className: 'update-banner__text' },
      `Traffic Rules v${this.info.latestVersion} is available. You\u2019re on v${this.info.currentVersion}.`,
    ) as HTMLSpanElement;

    this.progressEl = h('div', { className: 'update-banner__progress' });
    const progressBar = h('div', { className: 'update-banner__progress-bar' });
    this.progressEl.appendChild(progressBar);
    this.progressEl.style.display = 'none';

    // Main action button: "Update Now" for native updater, "Download" for browser fallback
    this.actionBtn = document.createElement('button');
    this.actionBtn.className = 'update-banner__download-btn';
    this.actionBtn.type = 'button';

    if (this.info.update) {
      this.actionBtn.textContent = 'Update Now';
      this.actionBtn.setAttribute('aria-label', 'Download and install update');
      this.actionBtn.addEventListener('click', () => this.handleAutoUpdate());
    } else {
      this.actionBtn.textContent = 'Download';
      this.actionBtn.setAttribute('aria-label', 'Download latest version');
      this.actionBtn.addEventListener('click', () => this.handleDownload());
    }

    const dismissBtn = document.createElement('button');
    dismissBtn.className = 'update-banner__dismiss-btn';
    dismissBtn.type = 'button';
    dismissBtn.textContent = '\u00D7';
    dismissBtn.title = 'Dismiss';
    dismissBtn.setAttribute('aria-label', 'Dismiss update notification');
    dismissBtn.addEventListener('click', () => this.handleDismiss());

    content.appendChild(icon);
    content.appendChild(this.textEl);
    content.appendChild(this.progressEl);
    content.appendChild(this.actionBtn);
    content.appendChild(dismissBtn);
    banner.appendChild(content);

    return banner;
  }

  private async handleAutoUpdate(): Promise<void> {
    const update = this.info.update;
    if (!update) return;

    this.actionBtn.disabled = true;
    this.actionBtn.textContent = 'Downloading\u2026';
    this.progressEl.style.display = '';

    const progressBar = this.progressEl.querySelector(
      '.update-banner__progress-bar',
    ) as HTMLElement;

    try {
      let downloaded = 0;
      let contentLength: number | undefined;

      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case 'Started':
            contentLength = event.data.contentLength ?? undefined;
            break;
          case 'Progress':
            downloaded += event.data.chunkLength;
            if (contentLength) {
              const pct = Math.min(100, (downloaded / contentLength) * 100);
              progressBar.style.width = `${pct}%`;
              this.actionBtn.textContent = `Downloading ${Math.round(pct)}%`;
            }
            break;
          case 'Finished':
            progressBar.style.width = '100%';
            break;
        }
      });

      // Install succeeded — prompt restart
      this.textEl.textContent = 'Update installed. Restart to apply.';
      this.actionBtn.textContent = 'Restart';
      this.actionBtn.disabled = false;
      this.progressEl.style.display = 'none';

      // Replace click handler for restart
      this.actionBtn.replaceWith(this.actionBtn.cloneNode(true));
      this.actionBtn = this.el.querySelector('.update-banner__download-btn') as HTMLButtonElement;
      this.actionBtn.addEventListener('click', async () => {
        try {
          const mod = '@tauri-apps/plugin-process';
          const { relaunch } = await import(/* @vite-ignore */ mod);
          await (relaunch as () => Promise<void>)();
        } catch {
          this.textEl.textContent = 'Please restart the app manually to apply the update.';
        }
      });
    } catch (err) {
      // Download/install failed — offer manual download fallback
      this.textEl.textContent = `Update failed: ${err instanceof Error ? err.message : 'unknown error'}`;
      this.actionBtn.textContent = 'Download Manually';
      this.actionBtn.disabled = false;
      this.progressEl.style.display = 'none';

      this.actionBtn.replaceWith(this.actionBtn.cloneNode(true));
      this.actionBtn = this.el.querySelector('.update-banner__download-btn') as HTMLButtonElement;
      this.actionBtn.addEventListener('click', () => this.handleDownload());
    }
  }

  private async handleDownload(): Promise<void> {
    const url =
      this.info.downloadUrl ||
      `https://github.com/lifeart/iptables-manager/releases/latest`;
    try {
      const mod = '@tauri-apps/plugin-shell';
      const { open } = await import(/* @vite-ignore */ mod);
      await (open as (url: string) => Promise<void>)(url);
    } catch {
      window.open(url, '_blank');
    }
  }

  private handleDismiss(): void {
    try {
      localStorage.setItem(DISMISSED_KEY, this.info.latestVersion);
    } catch {
      // localStorage may be unavailable — dismiss still works for this session
    }

    this.el.classList.remove('update-banner--visible');
    this.el.classList.add('update-banner--hiding');

    setTimeout(() => {
      this.el.remove();
    }, 300);
  }
}
