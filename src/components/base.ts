import type { Store } from '../store/index';
import type { AppState } from '../store/types';

/**
 * Base component class with AbortController-based lifecycle.
 *
 * All subscriptions (store, DOM events, IPC listeners) are automatically
 * cleaned up when destroy() is called via the AbortController signal.
 */
export abstract class Component {
  protected el: HTMLElement;
  protected ac = new AbortController();
  private children: Component[] = [];

  constructor(container: HTMLElement, protected store: Store) {
    this.el = container;
  }

  /**
   * Subscribe to store changes — auto-cleaned on destroy.
   * Callback only fires when the selected value changes (=== check).
   * Errors in the callback are caught and logged.
   */
  protected subscribe<T>(
    selector: (s: AppState) => T,
    cb: (val: T, prev: T) => void,
  ): void {
    const safeCb = (val: T, prev: T) => {
      try {
        cb.call(this, val, prev);
      } catch (e) {
        console.error(`${this.constructor.name} error:`, e);
      }
    };
    const unsub = this.store.subscribeSelector(selector, safeCb);
    this.ac.signal.addEventListener('abort', unsub);
  }

  /**
   * Add a DOM event listener — auto-cleaned on destroy via AbortSignal.
   */
  protected listen(
    target: EventTarget,
    event: string,
    handler: EventListener,
  ): void {
    target.addEventListener(event, handler, { signal: this.ac.signal });
  }

  /**
   * Listen to a Tauri IPC event — auto-cleaned on destroy.
   * Uses dynamic import to avoid hard dependency on @tauri-apps/api at module level.
   */
  protected listenIpc<T>(event: string, handler: (payload: T) => void): void {
    const setupListener = async () => {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        const unlisten = await listen<T>(event, (e) => handler(e.payload));
        // If the component was destroyed while awaiting, clean up immediately
        if (this.ac.signal.aborted) {
          unlisten();
          return;
        }
        this.ac.signal.addEventListener('abort', () => {
          unlisten();
        });
      } catch {
        // @tauri-apps/api may not be available in non-Tauri environments
        console.warn(`Failed to set up IPC listener for "${event}"`);
      }
    };
    setupListener();
  }

  /**
   * Register a child component — destroyed when this component is destroyed.
   */
  protected addChild(child: Component): void {
    this.children.push(child);
  }

  /**
   * Remove a specific child component and destroy it.
   */
  protected removeChild(child: Component): void {
    const idx = this.children.indexOf(child);
    if (idx !== -1) {
      this.children.splice(idx, 1);
      child.destroy();
    }
  }

  /**
   * Destroy this component and all children.
   * Aborts the AbortController, which cleans up:
   * - All store subscriptions
   * - All DOM event listeners
   * - All IPC event listeners
   */
  destroy(): void {
    this.ac.abort();
    for (const child of this.children) {
      child.destroy();
    }
    this.children.length = 0;
  }
}
