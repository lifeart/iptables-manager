/**
 * Application bootstrap sequence.
 *
 * 1. Show loading screen
 * 2. Initialize IndexedDB
 * 3. Load persisted state and hydrate store
 * 4. Initialize theme
 * 5. Hide loading screen, mount app
 * 6. Auto-reconnect to last active host
 */

import { store } from './store/index';
import { initDB, loadPersistedState } from './db/index';
import { themeManager } from './services/theme';
import { dbSync } from './db/sync';
import { STORE_NAMES } from './db/schema';
import { h } from './utils/dom';
import { Sidebar } from './components/sidebar/sidebar';
import { RuleTable } from './components/rule-table/rule-table';
import { SidePanel } from './components/side-panel/side-panel';
import { SafetyBanner } from './components/safety-banner/safety-banner';
import { CommandPalette } from './components/command-palette/command-palette';
import { DialogManager } from './components/dialogs/dialog-manager';
import { ShortcutService } from './services/shortcut';
import { loadDemoData } from './mock/demo-data';

function showLoadingScreen(): void {
  const app = document.getElementById('app');
  if (app) {
    app.innerHTML = '<div class="loading-screen"><p>Loading Traffic Rules...</p></div>';
  }
}

function hideLoadingScreen(): void {
  const app = document.getElementById('app');
  if (app) {
    const loading = app.querySelector('.loading-screen');
    if (loading) {
      loading.remove();
    }
  }
}

function mountApp(container: HTMLElement): void {
  container.innerHTML = '';

  // Create layout skeleton
  const layout = h('div', { className: 'app-layout' },
    h('aside', { className: 'sidebar', id: 'sidebar' }),
    h('main', { className: 'main-content', id: 'main-content' }),
    h('aside', { className: 'side-panel', id: 'side-panel' }),
  );

  // App title bar (above main layout)
  const titleBar = h('header', { className: 'app-title-bar' },
    h('span', { className: 'app-title-bar__logo' }, 'Traffic Rules'),
    h('span', { className: 'app-title-bar__subtitle' }, 'Firewall Manager'),
  );
  container.appendChild(titleBar);
  container.appendChild(layout);

  // Safety banner (top-level, renders when active)
  const bannerEl = h('div', { id: 'safety-banner' });
  container.appendChild(bannerEl);

  // Command palette (top-level overlay)
  const paletteEl = h('div', { id: 'command-palette' });
  container.appendChild(paletteEl);

  // Dialog container (top-level overlay for modals)
  const dialogEl = h('div', { id: 'dialog-container' });
  container.appendChild(dialogEl);

  // Instantiate components
  const sidebarEl = document.getElementById('sidebar')!;
  const mainEl = document.getElementById('main-content')!;
  const sidePanelEl = document.getElementById('side-panel')!;

  new Sidebar(sidebarEl, store);
  new RuleTable(mainEl, store);
  new SidePanel(sidePanelEl, store);
  new SafetyBanner(bannerEl, store);
  new CommandPalette(paletteEl, store);
  new DialogManager(dialogEl, store);

  // Initialize keyboard shortcuts
  new ShortcutService(store);
}

async function autoReconnect(): Promise<void> {
  const state = store.getState();
  const lastHostId = state.settings.lastActiveHostId;
  if (!lastHostId) return;

  // Look up the host's connection details from the store
  const host = state.hosts.get(lastHostId);
  if (!host) return;

  try {
    const { connectHost } = await import('./ipc/bridge');
    await connectHost(
      lastHostId,
      host.connection.hostname,
      host.connection.port,
      host.connection.username,
      host.connection.authMethod,
      host.connection.keyPath,
    );
    store.dispatch({
      type: 'UPDATE_HOST',
      hostId: lastHostId,
      changes: { status: 'connected' as const, lastConnected: Date.now() },
    });
  } catch {
    // Auto-reconnect failure is non-fatal
    console.warn('Auto-reconnect failed for host:', lastHostId);
    store.dispatch({
      type: 'UPDATE_HOST',
      hostId: lastHostId,
      changes: { status: 'disconnected' as const },
    });
  }
}

async function bootstrap(): Promise<void> {
  showLoadingScreen();

  try {
    // 1. Initialize IndexedDB
    await initDB();

    // 2. Load persisted state
    const data = await loadPersistedState();

    // 3. Check for orphaned safety timers
    if (data.safetyTimers.length > 0) {
      console.warn('Orphaned safety timers detected:', data.safetyTimers.length);
      // TODO: Show recovery UI for orphaned timers
    }

    // 4. Hydrate store
    store.dispatch({
      type: 'HYDRATE',
      payload: {
        hosts: data.hosts,
        groups: data.groups,
        ipLists: data.ipLists,
        stagedChanges: data.stagedChanges,
        safetyTimers: data.safetyTimers,
        settings: data.settings,
      },
    });

    // 5. Initialize theme from settings
    themeManager.init(store.getState().settings.theme);

    // 6. Mount app
    hideLoadingScreen();
    const appContainer = document.getElementById('app');
    if (appContainer) {
      mountApp(appContainer);
    }

    // 7. Load demo data if no real hosts exist
    if (store.getState().hosts.size === 0) {
      loadDemoData(store);
    }

    // 8. Wire dbSync to store for persistence
    wireDbSync();

    // 9. Auto-reconnect to last active host
    if (store.getState().settings.autoReconnect) {
      autoReconnect().catch(() => {});
    }
  } catch (e) {
    console.error('Bootstrap failed:', e);
    hideLoadingScreen();
    const app = document.getElementById('app');
    if (app) {
      app.textContent = '';
      const retryBtn = h('button', {}, 'Retry');
      retryBtn.addEventListener('click', () => location.reload());
      app.appendChild(
        h('div', { className: 'error-screen' },
          h('h1', {}, 'Failed to start Traffic Rules'),
          h('p', {}, e instanceof Error ? e.message : 'Unknown error'),
          retryBtn,
        ),
      );
    }
  }
}

function wireDbSync(): void {
  // Batched writes for hosts, groups, ipLists, settings
  store.subscribeSelector(
    (s) => s.hosts,
    (newHosts, oldHosts) => {
      if (newHosts === oldHosts) return;
      for (const [id, host] of newHosts) {
        if (oldHosts.get(id) !== host) {
          dbSync.write(STORE_NAMES.HOSTS, host);
        }
      }
      for (const id of oldHosts.keys()) {
        if (!newHosts.has(id)) {
          dbSync.deleteRecord(STORE_NAMES.HOSTS, id);
        }
      }
    },
  );

  store.subscribeSelector(
    (s) => s.groups,
    (newGroups, oldGroups) => {
      if (newGroups === oldGroups) return;
      for (const [id, group] of newGroups) {
        if (oldGroups.get(id) !== group) {
          dbSync.write(STORE_NAMES.GROUPS, group);
        }
      }
      for (const id of oldGroups.keys()) {
        if (!newGroups.has(id)) {
          dbSync.deleteRecord(STORE_NAMES.GROUPS, id);
        }
      }
    },
  );

  store.subscribeSelector(
    (s) => s.ipLists,
    (newIpLists, oldIpLists) => {
      if (newIpLists === oldIpLists) return;
      for (const [id, ipList] of newIpLists) {
        if (oldIpLists.get(id) !== ipList) {
          dbSync.write(STORE_NAMES.IP_LISTS, ipList);
        }
      }
      for (const id of oldIpLists.keys()) {
        if (!newIpLists.has(id)) {
          dbSync.deleteRecord(STORE_NAMES.IP_LISTS, id);
        }
      }
    },
  );

  store.subscribeSelector(
    (s) => s.settings,
    (newSettings, oldSettings) => {
      if (newSettings === oldSettings) return;
      for (const [key, value] of Object.entries(newSettings)) {
        if ((oldSettings as unknown as Record<string, unknown>)[key] !== value) {
          dbSync.writeSetting(key, value);
        }
      }
    },
  );

  // Immediate writes for stagedChanges and safetyTimers
  store.subscribeSelector(
    (s) => s.stagedChanges,
    (newStaged, oldStaged) => {
      if (newStaged === oldStaged) return;
      for (const [hostId, changeset] of newStaged) {
        if (oldStaged.get(hostId) !== changeset) {
          dbSync.writeImmediate(STORE_NAMES.STAGED_CHANGES, changeset);
        }
      }
      for (const hostId of oldStaged.keys()) {
        if (!newStaged.has(hostId)) {
          dbSync.deleteImmediate(STORE_NAMES.STAGED_CHANGES, hostId);
        }
      }
    },
  );

  store.subscribeSelector(
    (s) => s.safetyTimers,
    (newTimers, oldTimers) => {
      if (newTimers === oldTimers) return;
      for (const [hostId, timer] of newTimers) {
        if (oldTimers.get(hostId) !== timer) {
          dbSync.writeImmediate(STORE_NAMES.SAFETY_TIMERS, timer);
        }
      }
      for (const hostId of oldTimers.keys()) {
        if (!newTimers.has(hostId)) {
          dbSync.deleteImmediate(STORE_NAMES.SAFETY_TIMERS, hostId);
        }
      }
    },
  );
}

bootstrap();
