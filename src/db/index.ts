/**
 * IndexedDB initialization with version migrations.
 *
 * Uses the `idb` library for a promise-based wrapper around IndexedDB.
 */

import { openDB, type IDBPDatabase } from 'idb';
import { DB_NAME, DB_VERSION, migrations, STORE_NAMES } from './schema';
import type {
  Host,
  HostGroup,
  IpList,
  StagedChangeset,
  SafetyTimerState,
  AppSettings,
} from '../store/types';

let dbInstance: IDBPDatabase | null = null;

/**
 * Initialize and open the IndexedDB database.
 * Runs migrations on upgrade.
 */
export async function initDB(): Promise<IDBPDatabase> {
  if (dbInstance) return dbInstance;

  dbInstance = await openDB(DB_NAME, DB_VERSION, {
    upgrade(db, oldVersion, newVersion) {
      // Run all migrations from oldVersion+1 to newVersion
      // The idb library wraps IDBDatabase; migrations use the raw API
      // which is compatible since we only call createObjectStore/createIndex
      const target = newVersion ?? DB_VERSION;
      const rawDb = db as unknown as IDBDatabase;
      for (let v = oldVersion + 1; v <= target; v++) {
        const migration = migrations[v];
        if (migration) {
          migration(rawDb);
        }
      }
    },
    blocked() {
      console.warn('IndexedDB upgrade blocked — close other tabs');
    },
    blocking() {
      // Close the connection to unblock other tabs
      dbInstance?.close();
      dbInstance = null;
    },
    terminated() {
      dbInstance = null;
    },
  });

  return dbInstance;
}

/**
 * Get the database instance. Throws if not initialized.
 */
export function getDB(): IDBPDatabase {
  if (!dbInstance) {
    throw new Error('Database not initialized. Call initDB() first.');
  }
  return dbInstance;
}

/**
 * Load all persisted state from IndexedDB for hydration.
 */
export async function loadPersistedState(): Promise<{
  hosts: Host[];
  groups: HostGroup[];
  ipLists: IpList[];
  stagedChanges: StagedChangeset[];
  safetyTimers: SafetyTimerState[];
  settings: Partial<AppSettings>;
}> {
  const db = getDB();

  const [hosts, groups, ipLists, stagedChanges, safetyTimers, settingsEntries] =
    await Promise.all([
      db.getAll(STORE_NAMES.HOSTS) as Promise<Host[]>,
      db.getAll(STORE_NAMES.GROUPS) as Promise<HostGroup[]>,
      db.getAll(STORE_NAMES.IP_LISTS) as Promise<IpList[]>,
      db.getAll(STORE_NAMES.STAGED_CHANGES) as Promise<StagedChangeset[]>,
      db.getAll(STORE_NAMES.SAFETY_TIMERS) as Promise<SafetyTimerState[]>,
      db.getAll(STORE_NAMES.SETTINGS) as Promise<Array<{ key: string; value: unknown }>>,
    ]);

  // Reconstruct settings from key-value pairs
  const settings: Record<string, unknown> = {};
  for (const entry of settingsEntries) {
    settings[entry.key] = entry.value;
  }

  return {
    hosts,
    groups,
    ipLists,
    stagedChanges,
    safetyTimers,
    settings: settings as Partial<AppSettings>,
  };
}

/**
 * Close the database connection.
 */
export function closeDB(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}
