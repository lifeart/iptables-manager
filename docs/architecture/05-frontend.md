# Frontend Architecture

## State Management

Centralized store with **selector-based subscriptions** (no path wildcards).

```typescript
class Store<T> {
  private state: T;

  getState(): T;
  dispatch(action: Action): void;

  // Selector-based subscription — only fires when selected value changes
  subscribeSelector<R>(selector: (s: T) => R, cb: (val: R, prev: R) => void): Unsubscribe;

  // Memoized selector
  select<R>(selector: (s: T) => R): R;
}

function createSelector<T, A, R>(
  selectorA: (s: T) => A,
  combiner: (a: A) => R
): (s: T) => R;

function createSelector<T, A, B, R>(
  selectorA: (s: T) => A,
  selectorB: (s: T) => B,
  combiner: (a: A, b: B) => R
): (s: T) => R;
```

### App State Shape

```typescript
interface AppState {
  // Navigation
  activeHostId: string | null;
  activeTab: 'rules' | 'activity' | 'terminal';
  activeTerminalSubTab: 'raw' | 'tracer' | 'sshlog';
  sidePanelOpen: boolean;
  sidePanelContent: SidePanelContent | null;
  splitPanelOpen: boolean;
  splitPanelContent: 'activity' | 'terminal';
  sidebarCollapsed: boolean;
  commandPaletteOpen: boolean;
  quickBlockOpen: boolean;
  ruleFilter: { tab: 'all' | 'allow' | 'block' | 'log'; search: string };

  // @persisted — synced to IndexedDB
  hosts: Map<string, Host>;
  groups: Map<string, HostGroup>;
  ipLists: Map<string, IpList>;
  settings: AppSettings;

  // @persisted (immediate writes)
  stagedChanges: Map<string, StagedChangeset>;  // per hostId
  safetyTimers: Map<string, SafetyTimerState>;

  // @ephemeral — re-fetched on connect, never persisted
  hostStates: Map<string, {
    rules: Rule[];                     // current remote rules
    hitCounters: Map<string, HitCounter>;
    prevHitCounters: Map<string, HitCounter>;  // for delta/rate computation
    blockedLog: BlockedEntry[];        // capped at 500
    conntrackUsage: { current: number; max: number };
    sshCommandLog: SshLogEntry[];      // capped at 1000
  }>;

  // Async operation tracking
  operations: Map<string, {
    type: string;
    hostId?: string;
    status: 'pending' | 'success' | 'error';
    error?: string;
    startedAt: number;
  }>;
}
```

**Note**: `effectiveRules` is NOT in state. It's a memoized selector:

```typescript
const selectEffectiveRules = createSelector(
  (s: AppState) => s.activeHostId,
  (s: AppState) => s.hosts,
  (s: AppState) => s.groups,
  (s: AppState) => s.hostStates,
  (s: AppState) => s.stagedChanges,
  (activeId, hosts, groups, hostStates, staged) => {
    if (!activeId) return null;
    return computeEffectiveRuleset(activeId, hosts, groups, hostStates, staged);
  }
);
```

### Hit Counter Delta Computation

```typescript
function computeRates(current: HitCounter, previous: HitCounter | null, intervalMs: number): number {
  if (!previous) return 0;
  const delta = current.packets - previous.packets;
  if (delta < 0) return 0;  // counter reset detected (e.g., after apply)
  return delta / (intervalMs / 1000);  // packets per second
}
```

Previous values stored in `prevHitCounters` in ephemeral state. Updated every poll cycle.

## Component Pattern

### Base Class with AbortController

```typescript
abstract class Component {
  protected el: HTMLElement;
  protected ac = new AbortController();
  private children: Component[] = [];

  constructor(container: HTMLElement, protected store: Store<AppState>) {
    this.el = container;
  }

  // Store subscription — auto-cleaned on destroy
  protected subscribe<T>(selector: (s: AppState) => T, cb: (val: T, prev: T) => void): void {
    const safeCb = (val: T, prev: T) => {
      try { cb.call(this, val, prev); }
      catch (e) { console.error(`${this.constructor.name} error:`, e); }
    };
    const unsub = this.store.subscribeSelector(selector, safeCb);
    this.ac.signal.addEventListener('abort', unsub);
  }

  // DOM event listener — auto-cleaned on destroy
  protected listen(target: EventTarget, event: string, handler: EventListener): void {
    target.addEventListener(event, handler, { signal: this.ac.signal });
  }

  // IPC event listener — auto-cleaned on destroy
  protected listenIpc<T>(event: string, handler: (payload: T) => void): void {
    const unlisten = listen<T>(event, (e) => handler(e.payload));
    this.ac.signal.addEventListener('abort', () => { unlisten.then(fn => fn()); });
  }

  protected addChild(child: Component): void {
    this.children.push(child);
  }

  destroy(): void {
    this.ac.abort();  // kills ALL subscriptions, DOM listeners, IPC listeners
    this.children.forEach(c => c.destroy());
    this.children.length = 0;
  }
}
```

### Leaf Components (stateless)

For simple, data-driven elements (HostRow, RuleRow), use plain functions:

```typescript
export function createRuleRow(rule: EffectiveRule): HTMLElement { /* build DOM */ }
export function updateRuleRow(el: HTMLElement, rule: EffectiveRule): void { /* patch changes */ }
```

### Keyed List Reconciler

For rule tables, blocked log, host list — a lightweight reconciler:

```typescript
function reconcileList<T>(
  container: HTMLElement,
  items: T[],
  getKey: (item: T) => string,
  create: (item: T) => HTMLElement,
  update: (el: HTMLElement, item: T) => void,
  options?: { onRemove?: (el: HTMLElement) => Promise<void> }  // for exit animations
): void;
```

No virtual DOM. For expected rule counts (5-50 visible), native DOM is fast enough. Virtual scrolling reserved for blocked log (potentially thousands of entries).

### Animations

- CSS transitions for hover, panel slide, fade (via CSS classes)
- CSS `@starting-style` for enter animations
- `transitionend` listener for deferred removal (exit animations)
- `requestAnimationFrame` only for the packet tracer traveling dot

## IPC Bridge

Typed wrapper with error handling:

```typescript
async function ipcCall<T>(cmd: string, args: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    const err = typeof e === 'string' ? JSON.parse(e) : e;
    throw new IpcError(err.kind, err.detail);
  }
}

// Type-safe exports
export const connectHost = (hostId: string) => ipcCall<ConnectionResult>('host:connect', { hostId });
export const fetchRules = (hostId: string) => ipcCall<Rule[]>('rules:fetch', { hostId });
export const applyChanges = (hostId: string, changes: StagedChange[]) =>
  ipcCall<ApplyResult>('rules:apply', { hostId, changes });
```

### Type Sync (Rust → TypeScript)

`ts-rs` generates types on Vite dev server start:

```typescript
// vite.config.ts
plugins: [{
  name: 'ts-rs-sync',
  buildStart() {
    execSync('cargo test export_bindings', { cwd: 'src-tauri', stdio: 'inherit' });
  }
}]
```

Generated types: `src/ipc/types.generated.ts` (committed to git).

## IndexedDB Layer

### Migrations

```typescript
const migrations: Record<number, (db: IDBDatabase) => void> = {
  1: (db) => {
    db.createObjectStore('hosts', { keyPath: 'id' });
    db.createObjectStore('groups', { keyPath: 'id' });
    db.createObjectStore('ipLists', { keyPath: 'id' });
    db.createObjectStore('stagedChanges', { keyPath: 'hostId' });
    db.createObjectStore('snapshots', { keyPath: 'id' }).createIndex('hostId', 'hostId');
    db.createObjectStore('settings', { keyPath: 'key' });
    db.createObjectStore('sshLog', { keyPath: 'id', autoIncrement: true });
    db.createObjectStore('safetyTimers', { keyPath: 'hostId' });
  },
};
```

### Write Strategies

```typescript
class IndexedDBSync {
  private pending = new Map<string, unknown>();
  private flushScheduled = false;

  // Normal writes: batched per-tick
  write(store: string, value: unknown): void {
    this.pending.set(`${store}:${value.id}`, { store, value });
    if (!this.flushScheduled) {
      this.flushScheduled = true;
      queueMicrotask(() => this.flush());
    }
  }

  // Immediate writes: stagedChanges, safetyTimers
  async writeImmediate(store: string, value: unknown): Promise<void> {
    const db = await getDB();
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value);
    await tx.done;
  }

  private async flush(): Promise<void> {
    this.flushScheduled = false;
    const writes = [...this.pending.values()];
    this.pending.clear();
    try {
      const db = await getDB();
      const stores = [...new Set(writes.map(w => w.store))];
      const tx = db.transaction(stores, 'readwrite');
      for (const { store, value } of writes) {
        tx.objectStore(store).put(value);
      }
      await tx.done;
    } catch (e) {
      if (e.name === 'QuotaExceededError') {
        store.dispatch({ type: 'STORAGE_QUOTA_EXCEEDED' });
      }
    }
  }
}
```

## Startup Sequence

```typescript
async function bootstrap(): Promise<void> {
  showLoadingScreen();

  // 1. Initialize IndexedDB
  await initDB();

  // 2. Load persisted state
  const data = await loadPersistedState();

  // 3. Check for orphaned safety timers
  const orphanedTimers = data.safetyTimers;
  // Show recovery UI if any exist

  // 4. Hydrate store
  store.dispatch({ type: 'HYDRATE', payload: data });

  // 5. Mount app
  hideLoadingScreen();
  mountApp(document.getElementById('app')!);

  // 6. Auto-reconnect to last active host
  if (data.settings?.lastActiveHostId) {
    ipc.connectHost(data.settings.lastActiveHostId).catch(() => {});
  }
}
```

## CSS Architecture

### Naming: BEM Convention

```css
/* sidebar.css */
.sidebar { }
.sidebar__host-row { }
.sidebar__host-row--selected { }
.sidebar__group-row { }

/* rule-table.css */
.rule-table { }
.rule-table__row { }
.rule-table__row--pending { }
.rule-table__section-header { }
```

### Dark Mode

Media query as default, `data-theme` attribute for user override:

```css
:root { --color-bg: #FFFFFF; }

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) { --color-bg: #000000; }
}
:root[data-theme="dark"] { --color-bg: #000000; }
```

### Layer Organization

```css
@layer reset, tokens, base, components, utilities;
```

## Heavy Library Loading

CodeMirror 6 and @xyflow/vanilla are **dynamically imported** on Terminal tab activation:

```typescript
async function activateTerminalTab(): Promise<void> {
  const [rawRules, packetTracer] = await Promise.all([
    import('./terminal/raw-rules.js'),
    import('./terminal/packet-tracer.js'),
  ]);
  // Vite handles code splitting automatically
}
```

Bundle target: main < 100KB gzipped. Lazy chunks loaded on demand.

## Module List

| Module | Responsibility |
|--------|---------------|
| `store/` | Central store, actions, reducers, memoized selectors |
| `ipc/bridge` | Typed Tauri IPC wrapper with error handling |
| `ipc/types.generated` | Auto-generated from Rust via ts-rs |
| `db/` | IndexedDB setup, migrations, sync (batched + immediate) |
| `components/base` | Component base class with AbortController lifecycle |
| `components/sidebar/` | Host list, groups, IP lists, search |
| `components/rule-table/` | Rule rows, sections, filtering, reorder (SortableJS) |
| `components/side-panel/` | Rule detail/edit, snapshot history |
| `components/rule-builder/` | New/edit form with progressive disclosure |
| `components/activity/` | Hits (with sparklines), blocked log, conntrack, fail2ban |
| `components/terminal/` | Raw rules (CodeMirror), packet tracer (@xyflow), SSH log |
| `components/command-palette/` | Search + quick actions |
| `components/safety-banner/` | Apply countdown with green progress bar |
| `components/dialogs/` | Add host, create group, quick block, first setup |
| `services/rule-merge` | Effective ruleset computation (pure function) |
| `services/rule-label` | Auto-label from iptables specs + service-templates.json |
| `services/shortcut` | Keyboard shortcut registry |
| `services/theme` | Light/dark/system with `data-theme` attribute |
| `services/templates` | Rule templates (Web Server, VPN, etc.) |
| `utils/` | Validation, formatting, animation, DOM helpers, reconciler |
