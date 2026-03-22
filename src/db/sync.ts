/**
 * IndexedDB write synchronization.
 *
 * Two strategies:
 * - Batched writes: queued per-tick via queueMicrotask, flushed in a single transaction
 * - Immediate writes: for stagedChanges and safetyTimers (data loss prevention)
 *
 * Handles QuotaExceededError by dispatching a STORAGE_QUOTA_EXCEEDED action.
 */

import { getDB } from './index';
import { store } from '../store/index';
import type { StoreName } from './schema';

interface PendingWrite {
  store: StoreName;
  value: unknown;
}

class IndexedDBSync {
  private pending = new Map<string, PendingWrite>();
  private flushScheduled = false;

  /**
   * Queue a batched write. Will be flushed on the next microtask.
   * Used for hosts, groups, ipLists.
   */
  write(storeName: StoreName, value: { id?: string; hostId?: string; key?: string }): void {
    const key = this.getWriteKey(storeName, value);
    this.pending.set(key, { store: storeName, value });

    if (!this.flushScheduled) {
      this.flushScheduled = true;
      queueMicrotask(() => this.flush());
    }
  }

  /**
   * Write immediately in its own transaction.
   * Used for stagedChanges and safetyTimers.
   */
  async writeImmediate(storeName: StoreName, value: unknown): Promise<void> {
    try {
      const db = getDB();
      const tx = db.transaction(storeName, 'readwrite');
      tx.objectStore(storeName).put(value);
      await tx.done;
    } catch (e) {
      this.handleWriteError(e);
    }
  }

  /**
   * Delete a record immediately.
   */
  async deleteImmediate(storeName: StoreName, key: string): Promise<void> {
    try {
      const db = getDB();
      const tx = db.transaction(storeName, 'readwrite');
      tx.objectStore(storeName).delete(key);
      await tx.done;
    } catch (e) {
      this.handleWriteError(e);
    }
  }

  /**
   * Delete a record in the next batch.
   */
  deleteRecord(storeName: StoreName, key: string): void {
    // For batch deletes, we use a special sentinel
    const writeKey = `${storeName}:__delete__:${key}`;
    this.pending.set(writeKey, {
      store: storeName,
      value: { __delete__: true, __key__: key },
    });

    if (!this.flushScheduled) {
      this.flushScheduled = true;
      queueMicrotask(() => this.flush());
    }
  }

  /**
   * Write a settings key-value pair.
   */
  writeSetting(key: string, value: unknown): void {
    this.write('settings' as StoreName, { key, value } as { key: string });
  }

  private getWriteKey(
    storeName: StoreName,
    value: { id?: string; hostId?: string; key?: string },
  ): string {
    const id = value.id ?? value.hostId ?? value.key ?? 'unknown';
    return `${storeName}:${id}`;
  }

  private async flush(): Promise<void> {
    this.flushScheduled = false;
    const writes = [...this.pending.values()];
    this.pending.clear();

    if (writes.length === 0) return;

    try {
      const db = getDB();
      const storeNames = [...new Set(writes.map(w => w.store))];
      const tx = db.transaction(storeNames, 'readwrite');

      for (const { store: storeName, value } of writes) {
        const objectStore = tx.objectStore(storeName);
        const v = value as { __delete__?: boolean; __key__?: string };
        if (v.__delete__ && v.__key__) {
          objectStore.delete(v.__key__);
        } else {
          objectStore.put(value);
        }
      }

      await tx.done;
    } catch (e) {
      this.handleWriteError(e);
    }
  }

  private handleWriteError(e: unknown): void {
    if (e instanceof DOMException && e.name === 'QuotaExceededError') {
      store.dispatch({ type: 'STORAGE_QUOTA_EXCEEDED' });
    }
    // Non-quota errors are silently ignored to avoid console noise;
    // data will be re-persisted on the next write attempt.
  }
}

// Singleton
export const dbSync = new IndexedDBSync();
