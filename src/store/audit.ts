/**
 * Audit log helper — creates and dispatches audit entries.
 */

import type { AuditEntry } from './types';
import { store } from './index';

let auditCounter = 0;

function generateAuditId(): string {
  auditCounter++;
  return `audit-${Date.now()}-${auditCounter}`;
}

export function addAuditEntry(
  hostId: string,
  hostName: string,
  action: AuditEntry['action'],
  changeCount: number,
  details: string,
): void {
  const entry: AuditEntry = {
    id: generateAuditId(),
    timestamp: Date.now(),
    hostId,
    hostName,
    action,
    changeCount,
    details,
  };
  store.dispatch({ type: 'ADD_AUDIT_ENTRY', entry });
}
