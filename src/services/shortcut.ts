/**
 * Keyboard shortcut service.
 *
 * Registers global shortcuts:
 *   - Cmd+K (palette)
 *   - Cmd+Shift+B (quick block)
 *   - Cmd+S (apply)
 *   - Cmd+Z / Cmd+Shift+Z (undo/redo)
 *   - Cmd+N (add host)
 *   - Cmd+0 (toggle sidebar)
 *   - Cmd+1/2/3 (tabs)
 *   - Cmd+\ (split view)
 *
 * Handles platform detection (Cmd vs Ctrl).
 */

import type { Store } from '../store/index';

interface ShortcutBinding {
  key: string;
  meta: boolean;
  shift: boolean;
  handler: () => void;
}

/**
 * Detect whether the platform uses Meta (macOS) or Ctrl (Windows/Linux)
 * as the primary modifier key.
 */
function isMac(): boolean {
  return typeof navigator !== 'undefined' && /mac/i.test(navigator.platform);
}

/**
 * Check if the platform modifier key (Cmd on Mac, Ctrl otherwise) is pressed.
 */
function hasPlatformModifier(e: KeyboardEvent): boolean {
  return isMac() ? e.metaKey : e.ctrlKey;
}

export class ShortcutService {
  private bindings: ShortcutBinding[] = [];
  private ac = new AbortController();

  constructor(private store: Store) {
    this.registerBindings();
    this.listen();
  }

  private registerBindings(): void {
    // Cmd+K — command palette
    this.bindings.push({
      key: 'k',
      meta: true,
      shift: false,
      handler: () => {
        const state = this.store.getState();
        this.store.dispatch({
          type: 'TOGGLE_COMMAND_PALETTE',
          open: !state.commandPaletteOpen,
        });
      },
    });

    // Cmd+Shift+B — quick block
    this.bindings.push({
      key: 'b',
      meta: true,
      shift: true,
      handler: () => {
        this.store.dispatch({ type: 'TOGGLE_QUICK_BLOCK', open: true });
      },
    });

    // Cmd+S — apply changes
    this.bindings.push({
      key: 's',
      meta: true,
      shift: false,
      handler: () => {
        // Apply changes will be handled by the apply service
        // For now, just prevent default browser save
      },
    });

    // Cmd+Z — undo
    this.bindings.push({
      key: 'z',
      meta: true,
      shift: false,
      handler: () => {
        const hostId = this.store.getState().activeHostId;
        if (hostId) {
          this.store.dispatch({ type: 'UNDO_STAGED_CHANGE', hostId });
        }
      },
    });

    // Cmd+Shift+Z — redo
    this.bindings.push({
      key: 'z',
      meta: true,
      shift: true,
      handler: () => {
        const hostId = this.store.getState().activeHostId;
        if (hostId) {
          this.store.dispatch({ type: 'REDO_STAGED_CHANGE', hostId });
        }
      },
    });

    // Cmd+N — add host
    this.bindings.push({
      key: 'n',
      meta: true,
      shift: false,
      handler: () => {
        this.store.dispatch({ type: 'OPEN_DIALOG', dialog: 'add-host' });
      },
    });

    // Cmd+0 — toggle sidebar
    this.bindings.push({
      key: '0',
      meta: true,
      shift: false,
      handler: () => {
        const state = this.store.getState();
        this.store.dispatch({
          type: 'TOGGLE_SIDEBAR',
          collapsed: !state.sidebarCollapsed,
        });
      },
    });

    // Cmd+1 — Rules tab
    this.bindings.push({
      key: '1',
      meta: true,
      shift: false,
      handler: () => {
        this.store.dispatch({ type: 'SET_ACTIVE_TAB', tab: 'rules' });
      },
    });

    // Cmd+2 — Activity tab
    this.bindings.push({
      key: '2',
      meta: true,
      shift: false,
      handler: () => {
        this.store.dispatch({ type: 'SET_ACTIVE_TAB', tab: 'activity' });
      },
    });

    // Cmd+3 — Terminal tab
    this.bindings.push({
      key: '3',
      meta: true,
      shift: false,
      handler: () => {
        this.store.dispatch({ type: 'SET_ACTIVE_TAB', tab: 'terminal' });
      },
    });

    // Cmd+\ — toggle split view
    this.bindings.push({
      key: '\\',
      meta: true,
      shift: false,
      handler: () => {
        const state = this.store.getState();
        this.store.dispatch({
          type: 'TOGGLE_SPLIT_PANEL',
          open: !state.splitPanelOpen,
        });
      },
    });
  }

  private listen(): void {
    document.addEventListener('keydown', (e: KeyboardEvent) => {
      // Don't intercept shortcuts when typing in inputs (except Escape and Cmd+K)
      const target = e.target as HTMLElement;
      const isInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;

      if (!hasPlatformModifier(e)) return;

      for (const binding of this.bindings) {
        if (e.key.toLowerCase() !== binding.key) continue;
        if (binding.meta && !hasPlatformModifier(e)) continue;
        if (binding.shift !== e.shiftKey) continue;

        // Allow Cmd+K in inputs (to open palette)
        if (isInput && binding.key !== 'k') continue;

        e.preventDefault();
        e.stopPropagation();
        binding.handler();
        return;
      }
    }, { signal: this.ac.signal });
  }

  destroy(): void {
    this.ac.abort();
  }
}
