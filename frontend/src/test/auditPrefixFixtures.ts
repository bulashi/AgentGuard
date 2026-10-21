import { auditEventCore, type AuditPrefixReport } from '../auditPrefixBinding'
import type { AuditEventView } from '../types'
import { savedSnapshot } from './fixtures'

// Synthetic wire fixture only: the browser does not recompute this SM3 hash or verify this signature.
export function mockAuditPrefixReport(event: AuditEventView, taskId = savedSnapshot.task.task_id): AuditPrefixReport {
  return {
    schema_version: '1.0', task_id: taskId,
    verification: {
      valid: true, checked_events: event.event_sequence, latest_event_sequence: event.event_sequence,
      latest_event_hash: event.event_hash, rollback_detected: false, first_invalid_sequence: null,
    },
    checkpoint: {
      signed_object_hash: 'd'.repeat(64),
      signed_checkpoint: {
        payload: {
          schema_version: '1.0', checkpoint_sequence: 1, latest_event_sequence: event.event_sequence,
          latest_event_hash: event.event_hash, timestamp: event.timestamp + 1,
        },
        signature: {
          algorithm: 'SM2', key_id: 'checkpoint-display-mock', key_purpose: 'AUDIT_CHECKPOINT_SIGNING',
          encoding: 'SM2_RS_HEX_128_LOWERCASE', value: 'e'.repeat(128), signed_at: event.timestamp + 1,
        },
      },
    },
    event_bindings: [{
      event_sequence: event.event_sequence, event_id: event.event_id, event_hash: event.event_hash,
      matched: true, covered: true, verified_event: auditEventCore(event) as NonNullable<AuditPrefixReport['event_bindings'][number]['verified_event']>,
    }],
  }
}
