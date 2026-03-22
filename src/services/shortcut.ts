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
 *   - Cmd+, (settings)
 *   - Per-rule: E, D, N, /, Delete, Alt+Up/Down
 *
 * Handles platform detection (Cmd vs Ctrl).
 */

import type { Store } from '../store/index';

interface ShortcutBinding {
  key: string;
  meta: boolean;
  shift: boolean;
  alt: boolean;
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
      alt: false,
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
      alt: false,
      handler: () => {
        this.store.dispatch({ type: 'TOGGLE_QUICK_BLOCK', open: true });
      },
    });

    // Cmd+S — apply changes
    this.bindings.push({
      key: 's',
      meta: true,
      shift: false,
      alt: false,
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
      alt: false,
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
      alt: false,
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
      alt: false,
      handler: () => {
        this.store.dispatch({ type: 'OPEN_DIALOG', dialog: 'add-host' });
      },
    });

    // Cmd+0 — toggle sidebar
    this.bindings.push({
      key: '0',
      meta: true,
      shift: false,
      alt: false,
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
      alt: false,
      handler: () => {
        this.store.dispatch({ type: 'SET_ACTIVE_TAB', tab: 'rules' });
      },
    });

    // Cmd+2 — Activity tab
    this.bindings.push({
      key: '2',
      meta: true,
      shift: false,
      alt: false,
      handler: () => {
        this.store.dispatch({ type: 'SET_ACTIVE_TAB', tab: 'activity' });
      },
    });

    // Cmd+3 — Terminal tab
    this.bindings.push({
      key: '3',
      meta: true,
      shift: false,
      alt: false,
      handler: () => {
        this.store.dispatch({ type: 'SET_ACTIVE_TAB', tab: 'terminal' });
      },
    });

    // Cmd+\ — toggle split view
    this.bindings.push({
      key: '\\',
      meta: true,
      shift: false,
      alt: false,
      handler: () => {
        const state = this.store.getState();
        this.store.dispatch({
          type: 'TOGGLE_SPLIT_PANEL',
          open: !state.splitPanelOpen,
        });
      },
    });

    // Cmd+, — settings
    this.bindings.push({
      key: ',',
      meta: true,
      shift: false,
      alt: false,
      handler: () => {
        this.store.dispatch({
          type: 'SET_SIDE_PANEL_CONTENT',
          content: { type: 'host-settings' },
        });
        this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: true });
      },
    });

    // ── Per-rule shortcuts (no modifier, only on Rules tab, not in inputs) ──

    // E — edit selected rule
    this.bindings.push({
      key: 'e',
      meta: false,
      shift: false,
      alt: false,
      handler: () => {
        const state = this.store.getState();
        if (state.sidePanelContent?.type === 'rule-detail') {
          this.store.dispatch({
            type: 'SET_SIDE_PANEL_CONTENT',
            content: { type: 'rule-edit', ruleId: state.sidePanelContent.ruleId },
          });
        }
      },
    });

    // D — toggle disable/enable selected rule
    this.bindings.push({
      key: 'd',
      meta: false,
      shift: false,
      alt: false,
      handler: () => {
        const state = this.store.getState();
        const hostId = state.activeHostId;
        if (!hostId) return;
        if (state.sidePanelContent?.type === 'rule-detail') {
          const ruleId = state.sidePanelContent.ruleId;
          const hostState = state.hostStates.get(hostId);
          const rule = hostState?.rules.find(r => r.id === ruleId);
          if (rule) {
            this.store.dispatch({
              type: 'ADD_STAGED_CHANGE',
              hostId,
              change: {
                type: 'modify',
                ruleId,
                before: { enabled: rule.enabled },
                after: { enabled: !rule.enabled },
              },
            });
          }
        }
      },
    });

    // N — add new rule (same as "+ Add Rule")
    this.bindings.push({
      key: 'n',
      meta: false,
      shift: false,
      alt: false,
      handler: () => {
        this.store.dispatch({
          type: 'SET_SIDE_PANEL_CONTENT',
          content: { type: 'rule-new' },
        });
        this.store.dispatch({ type: 'TOGGLE_SIDE_PANEL', open: true });
      },
    });

    // / — focus filter search input
    this.bindings.push({
      key: '/',
      meta: false,
      shift: false,
      alt: false,
      handler: () => {
        const searchInput = document.querySelector<HTMLInputElement>('.filter-bar__search-input');
        if (searchInput) {
          searchInput.focus();
        }
      },
    });

    // Delete / Backspace — delete selected rule
    this.bindings.push({
      key: 'delete',
      meta: false,
      shift: false,
      alt: false,
      handler: () => {
        const state = this.store.getState();
        const hostId = state.activeHostId;
        if (!hostId) return;
        if (state.sidePanelContent?.type === 'rule-detail') {
          this.store.dispatch({
            type: 'ADD_STAGED_CHANGE',
            hostId,
            change: { type: 'delete', ruleId: state.sidePanelContent.ruleId },
          });
        }
      },
    });

    this.bindings.push({
      key: 'backspace',
      meta: false,
      shift: false,
      alt: false,
      handler: () => {
        const state = this.store.getState();
        const hostId = state.activeHostId;
        if (!hostId) return;
        if (state.sidePanelContent?.type === 'rule-detail') {
          this.store.dispatch({
            type: 'ADD_STAGED_CHANGE',
            hostId,
            change: { type: 'delete', ruleId: state.sidePanelContent.ruleId },
          });
        }
      },
    });

    // Alt+ArrowUp — reorder staged change up
    this.bindings.push({
      key: 'arrowup',
      meta: false,
      shift: false,
      alt: true,
      handler: () => {
        const state = this.store.getState();
        const hostId = state.activeHostId;
        if (!hostId) return;
        if (state.sidePanelContent?.type === 'rule-detail') {
          const ruleId = state.sidePanelContent.ruleId;
          const hostState = state.hostStates.get(hostId);
          const rule = hostState?.rules.find(r => r.id === ruleId);
          if (rule && rule.position > 0) {
            this.store.dispatch({
              type: 'ADD_STAGED_CHANGE',
              hostId,
              change: {
                type: 'reorder',
                ruleId,
                fromPosition: rule.position,
                toPosition: rule.position - 1,
              },
            });
          }
        }
      },
    });

    // Alt+ArrowDown — reorder staged change down
    this.bindings.push({
      key: 'arrowdown',
      meta: false,
      shift: false,
      alt: true,
      handler: () => {
        const state = this.store.getState();
        const hostId = state.activeHostId;
        if (!hostId) return;
        if (state.sidePanelContent?.type === 'rule-detail') {
          const ruleId = state.sidePanelContent.ruleId;
          const hostState = state.hostStates.get(hostId);
          const rule = hostState?.rules.find(r => r.id === ruleId);
          if (rule) {
            this.store.dispatch({
              type: 'ADD_STAGED_CHANGE',
              hostId,
              change: {
                type: 'reorder',
                ruleId,
                fromPosition: rule.position,
                toPosition: rule.position + 1,
              },
            });
          }
        }
      },
    });
  }

  private listen(): void {
    document.addEventListener('keydown', (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      const isInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;

      for (const binding of this.bindings) {
        if (e.key.toLowerCase() !== binding.key) continue;
        if (binding.meta && !hasPlatformModifier(e)) continue;
        if (!binding.meta && hasPlatformModifier(e)) continue;
        if (binding.shift !== e.shiftKey) continue;
        if (binding.alt !== e.altKey) continue;

        // For meta shortcuts: allow Cmd+K in inputs but skip others
        if (binding.meta) {
          if (isInput && binding.key !== 'k') continue;
        } else {
          // Non-meta shortcuts: skip when typing in inputs
          if (isInput) continue;
          // Per-rule shortcuts only on Rules tab
          const state = this.store.getState();
          if (state.activeTab !== 'rules') continue;
        }

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
