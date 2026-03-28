/**
 * Update notification banner.
 *
 * Shows a non-intrusive banner at the bottom of the window when a
 * newer version of Traffic Rules is available on GitHub. The user
 * can dismiss the banner (persisted per-version in localStorage)
 * or click "Download" to open the release page.
 */

import { h } from '../../utils/dom';
import type { UpdateInfo } from '../../services/update-checker';

const DISMISSED_KEY = 'update-banner-dismissed-version';

export class UpdateBanner {
  private el: HTMLElement;

  constructor(private info: UpdateInfo) {
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

    const text = h(
      'span',
      { className: 'update-banner__text' },
      `Traffic Rules v${this.info.latestVersion} is available. You\u2019re on v${this.info.currentVersion}.`,
    );

    const downloadBtn = document.createElement('button');
    downloadBtn.className = 'update-banner__download-btn';
    downloadBtn.type = 'button';
    downloadBtn.textContent = 'Download';
    downloadBtn.setAttribute('aria-label', 'Download latest version');
    downloadBtn.addEventListener('click', () => this.handleDownload());

    const dismissBtn = document.createElement('button');
    dismissBtn.className = 'update-banner__dismiss-btn';
    dismissBtn.type = 'button';
    dismissBtn.textContent = '\u00D7';
    dismissBtn.title = 'Dismiss';
    dismissBtn.setAttribute('aria-label', 'Dismiss update notification');
    dismissBtn.addEventListener('click', () => this.handleDismiss());

    content.appendChild(icon);
    content.appendChild(text);
    content.appendChild(downloadBtn);
    content.appendChild(dismissBtn);
    banner.appendChild(content);

    return banner;
  }

  private async handleDownload(): Promise<void> {
    const url = this.info.downloadUrl;
    try {
      // Try Tauri shell plugin (opens URL in default browser).
      // The plugin may not be installed, so we use a dynamic string import
      // to avoid compile-time module resolution failures.
      const mod = '@tauri-apps/plugin-shell';
      const { open } = await import(/* @vite-ignore */ mod);
      await (open as (url: string) => Promise<void>)(url);
    } catch {
      // Fallback: plain browser open
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
