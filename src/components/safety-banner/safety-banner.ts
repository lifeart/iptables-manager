/**
 * Safety timer banner component.
 *
 * - Top-center, 400px wide, dark background
 * - Green progress bar fills left-to-right
 * - "Changes applied to {host}. Confirming in {N} seconds"
 * - "Revert Changes" button
 * - Subscribes to safetyTimers in store
 * - Compact mode after 5+ uses (single line)
 * - Slide-down animation on appear, slide-up on dismiss
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { SafetyTimerState } from '../../store/types';
import { h, clearChildren } from '../../utils/dom';

export class SafetyBanner extends Component {
  private bannerEl: HTMLElement;
  private contentEl: HTMLElement;
  private progressBarEl: HTMLElement;
  private timerInterval: ReturnType<typeof setInterval> | null = null;
  private useCount = 0;
  private currentTimers: Map<string, SafetyTimerState> = new Map();

  // Cached DOM elements for updateDisplay — created once in show()
  private textEl: HTMLElement | null = null;
  private revertBtn: HTMLButtonElement | null = null;
  private compactLine: HTMLElement | null = null;
  private compactTextSpan: HTMLElement | null = null;
  private compactRevertBtn: HTMLButtonElement | null = null;
  private currentHostId: string | null = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);

    this.bannerEl = h('div', { className: 'safety-banner' });
    this.bannerEl.style.display = 'none';

    this.progressBarEl = h('div', { className: 'safety-banner__progress' });
    const progressTrack = h('div', { className: 'safety-banner__progress-track' });
    progressTrack.appendChild(this.progressBarEl);
    this.bannerEl.appendChild(progressTrack);

    this.contentEl = h('div', { className: 'safety-banner__content' });
    this.bannerEl.appendChild(this.contentEl);

    this.el.appendChild(this.bannerEl);

    // Subscribe to safety timers
    this.subscribe(
      (s) => s.safetyTimers,
      (timers) => this.onTimersChanged(timers),
    );
  }

  private onTimersChanged(timers: Map<string, SafetyTimerState>): void {
    this.currentTimers = timers;

    if (timers.size === 0) {
      this.hide();
      return;
    }

    this.useCount++;
    this.show();
    this.startTimer();
  }

  private show(): void {
    this.bannerEl.style.display = '';
    this.bannerEl.classList.add('safety-banner--visible');
    const isCompact = this.useCount > 5;
    this.bannerEl.classList.toggle('safety-banner--compact', isCompact);

    // Build content elements once
    clearChildren(this.contentEl);
    this.textEl = null;
    this.revertBtn = null;
    this.compactLine = null;
    this.compactTextSpan = null;
    this.compactRevertBtn = null;
    this.currentHostId = null;

    if (isCompact) {
      this.compactLine = h('div', { className: 'safety-banner__compact-line' });
      this.compactTextSpan = h('span', {}, '');
      this.compactLine.appendChild(this.compactTextSpan);

      this.compactRevertBtn = document.createElement('button');
      this.compactRevertBtn.className = 'safety-banner__revert-btn safety-banner__revert-btn--compact';
      this.compactRevertBtn.type = 'button';
      this.compactRevertBtn.textContent = 'Revert';
      this.listen(this.compactRevertBtn, 'click', () => {
        if (this.currentHostId) this.revertChanges(this.currentHostId);
      });
      this.compactLine.appendChild(this.compactRevertBtn);
      this.contentEl.appendChild(this.compactLine);
    } else {
      this.textEl = h('p', { className: 'safety-banner__text' }, '');
      this.contentEl.appendChild(this.textEl);

      this.revertBtn = document.createElement('button');
      this.revertBtn.className = 'safety-banner__revert-btn';
      this.revertBtn.type = 'button';
      this.revertBtn.textContent = 'Revert Changes';
      this.listen(this.revertBtn, 'click', () => {
        if (this.currentHostId) this.revertChanges(this.currentHostId);
      });
      this.contentEl.appendChild(this.revertBtn);
    }

    this.updateDisplay();
  }

  private hide(): void {
    this.bannerEl.classList.remove('safety-banner--visible');
    this.bannerEl.classList.add('safety-banner--hiding');

    // Wait for slide-up animation
    setTimeout(() => {
      this.bannerEl.style.display = 'none';
      this.bannerEl.classList.remove('safety-banner--hiding');
    }, 300);

    this.stopTimer();
  }

  private startTimer(): void {
    this.stopTimer();
    this.timerInterval = setInterval(() => {
      this.updateDisplay();
    }, 1000);
  }

  private stopTimer(): void {
    if (this.timerInterval !== null) {
      clearInterval(this.timerInterval);
      this.timerInterval = null;
    }
  }

  private updateDisplay(): void {
    const isCompact = this.useCount > 5;
    const now = Date.now();

    for (const [hostId, timer] of this.currentTimers) {
      const remaining = Math.max(0, Math.ceil((timer.expiresAt - now) / 1000));
      const total = Math.max(1, (timer.expiresAt - timer.startedAt) / 1000);
      const elapsed = Math.max(0, total - remaining);
      const progress = Math.min(1, elapsed / total);

      // Update progress bar
      this.progressBarEl.style.width = `${progress * 100}%`;

      // Track current host for revert button
      this.currentHostId = hostId;

      // Get host name
      const host = this.store.getState().hosts.get(hostId);
      const hostName = host ? host.name : hostId;

      if (remaining <= 0) {
        // Timer expired, clear it
        this.store.dispatch({ type: 'CLEAR_SAFETY_TIMER', hostId });
        continue;
      }

      if (isCompact) {
        if (this.compactTextSpan) {
          this.compactTextSpan.textContent = `Confirming... ${remaining}s`;
        }
      } else {
        if (this.textEl) {
          this.textEl.textContent = `Changes applied to ${hostName}. Confirming in ${remaining} seconds`;
        }
      }
    }
  }

  private async revertChanges(hostId: string): Promise<void> {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('safety:revert', { hostId });
    } catch {
      console.warn('Failed to invoke safety:revert');
    }
    this.store.dispatch({ type: 'CLEAR_SAFETY_TIMER', hostId });
  }

  destroy(): void {
    this.stopTimer();
    super.destroy();
  }
}
