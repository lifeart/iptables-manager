/**
 * IndexedDB schema constants and migration definitions.
 *
 * Database: "traffic-rules"
 *
 * Object Stores:
 *   hosts           keyPath: "id"
 *   groups          keyPath: "id"
 *   ipLists         keyPath: "id"
 *   stagedChanges   keyPath: "hostId"
 *   snapshots       keyPath: "id"       indexes: [hostId]
 *   settings        keyPath: "key"
 *   sshLog          keyPath: "id"       autoIncrement, indexes: [hostId, timestamp]
 *   safetyTimers    keyPath: "hostId"
 */

export const DB_NAME = 'traffic-rules';
export const DB_VERSION = 1;

export const STORE_NAMES = {
  HOSTS: 'hosts',
  GROUPS: 'groups',
  IP_LISTS: 'ipLists',
  STAGED_CHANGES: 'stagedChanges',
  SNAPSHOTS: 'snapshots',
  SETTINGS: 'settings',
  SSH_LOG: 'sshLog',
  SAFETY_TIMERS: 'safetyTimers',
} as const;

export type StoreName = typeof STORE_NAMES[keyof typeof STORE_NAMES];

/**
 * Migrations keyed by version number.
 * Each migration receives the IDBDatabase and creates/modifies object stores.
 */
/**
 * Migrations receive the raw IDBDatabase from the upgrade transaction.
 * The `idb` library provides this through its upgrade callback.
 */
export const migrations: Record<number, (db: IDBDatabase) => void> = {
  1: (db) => {
    const hosts = db.createObjectStore(STORE_NAMES.HOSTS, { keyPath: 'id' });
    hosts.createIndex('name', 'name');
    hosts.createIndex('status', 'status');

    const groups = db.createObjectStore(STORE_NAMES.GROUPS, { keyPath: 'id' });
    groups.createIndex('name', 'name');

    const ipLists = db.createObjectStore(STORE_NAMES.IP_LISTS, { keyPath: 'id' });
    ipLists.createIndex('name', 'name');

    db.createObjectStore(STORE_NAMES.STAGED_CHANGES, { keyPath: 'hostId' });

    const snapshots = db.createObjectStore(STORE_NAMES.SNAPSHOTS, { keyPath: 'id' });
    snapshots.createIndex('hostId', 'hostId');
    snapshots.createIndex('timestamp', 'timestamp');

    db.createObjectStore(STORE_NAMES.SETTINGS, { keyPath: 'key' });

    const sshLog = db.createObjectStore(STORE_NAMES.SSH_LOG, { keyPath: 'id', autoIncrement: true });
    sshLog.createIndex('hostId', 'hostId');
    sshLog.createIndex('timestamp', 'timestamp');

    db.createObjectStore(STORE_NAMES.SAFETY_TIMERS, { keyPath: 'hostId' });
  },
};
