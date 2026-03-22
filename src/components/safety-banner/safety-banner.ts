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
    this.bannerEl.classList.toggle('safety-banner--compact', this.useCount > 5);
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
    clearChildren(this.contentEl);

    const isCompact = this.useCount > 5;
    const now = Date.now();

    for (const [hostId, timer] of this.currentTimers) {
      const remaining = Math.max(0, Math.ceil((timer.expiresAt - now) / 1000));
      const total = Math.max(1, (timer.expiresAt - timer.startedAt) / 1000);
      const elapsed = Math.max(0, total - remaining);
      const progress = Math.min(1, elapsed / total);

      // Update progress bar
      this.progressBarEl.style.width = `${progress * 100}%`;

      // Get host name
      const host = this.store.getState().hosts.get(hostId);
      const hostName = host ? host.name : hostId;

      if (remaining <= 0) {
        // Timer expired, clear it
        this.store.dispatch({ type: 'CLEAR_SAFETY_TIMER', hostId });
        continue;
      }

      if (isCompact) {
        // Compact mode: single line
        const line = h('div', { className: 'safety-banner__compact-line' });
        line.appendChild(h('span', {}, `Confirming... ${remaining}s`));

        const revertBtn = h('button', {
          className: 'safety-banner__revert-btn safety-banner__revert-btn--compact',
          type: 'button',
        }, 'Revert');
        this.listen(revertBtn, 'click', () => this.revertChanges(hostId));
        line.appendChild(revertBtn);

        this.contentEl.appendChild(line);
      } else {
        // Full mode
        const text = h('p', { className: 'safety-banner__text' },
          `Changes applied to ${hostName}. Confirming in ${remaining} seconds`);
        this.contentEl.appendChild(text);

        const revertBtn = h('button', {
          className: 'safety-banner__revert-btn',
          type: 'button',
        }, 'Revert Changes');
        this.listen(revertBtn, 'click', () => this.revertChanges(hostId));
        this.contentEl.appendChild(revertBtn);
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
