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
  // Clear any remaining loading content
  container.innerHTML = '';

  // Create the main app layout structure
  const layout = document.createElement('div');
  layout.className = 'app-layout';
  layout.innerHTML = `
    <aside class="sidebar" id="sidebar"></aside>
    <main class="main-content" id="main-content">
      <div class="toolbar" id="toolbar"></div>
      <div class="content-area" id="content-area"></div>
    </main>
    <aside class="side-panel" id="side-panel"></aside>
  `;
  container.appendChild(layout);
}

async function autoReconnect(): Promise<void> {
  const state = store.getState();
  const lastHostId = state.settings.lastActiveHostId;
  if (!lastHostId) return;

  try {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('host:connect', { hostId: lastHostId });
  } catch {
    // Auto-reconnect failure is non-fatal
    console.warn('Auto-reconnect failed for host:', lastHostId);
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

    // 7. Auto-reconnect to last active host
    if (store.getState().settings.autoReconnect) {
      autoReconnect().catch(() => {});
    }
  } catch (e) {
    console.error('Bootstrap failed:', e);
    hideLoadingScreen();
    const app = document.getElementById('app');
    if (app) {
      app.innerHTML = `
        <div class="error-screen">
          <h1>Failed to start Traffic Rules</h1>
          <p>${e instanceof Error ? e.message : 'Unknown error'}</p>
          <button onclick="location.reload()">Retry</button>
        </div>
      `;
    }
  }
}

bootstrap();
