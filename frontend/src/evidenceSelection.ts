import type { EvidenceSelection } from './executionModel'
import type { AuditEventView, TaskSnapshot } from './types'

function sameReference(left: unknown, right: unknown): boolean {
  return typeof left === 'string' && left.length > 0 && left === right
}

function uniqueRecord<T>(records: readonly T[], matches: (record: T) => boolean): T | undefined {
  const found = records.filter(matches)
  return found.length === 1 ? found[0] : undefined
}

function currentAuditEvent(event: AuditEventView, snapshot: TaskSnapshot): AuditEventView | undefined {
  const current = uniqueRecord(snapshot.audit_events, (item) => sameReference(event.event_id, item.event_id))
  if (!current || snapshot.audit_events.filter((item) => item.event_sequence === current.event_sequence).length !== 1) return undefined
  return current.event_sequence === event.event_sequence && sameReference(event.event_hash, current.event_hash)
    && current.schema_version === event.schema_version && current.event_type === event.event_type
    && current.execution_id === event.execution_id && sameReference(event.evidence_reference, current.evidence_reference)
    && sameReference(event.payload_hash, current.payload_hash) && sameReference(event.previous_event_hash, current.previous_event_hash)
    && current.timestamp === event.timestamp ? current : undefined
}

export function scopeEvidenceSelection(selection: EvidenceSelection, taskId: string | null): EvidenceSelection {
  if (selection.kind === 'scenario' || !taskId) return selection
  return { ...selection, taskId: selection.taskId ?? taskId }
}

// Resolve display references only. Equality with a BFF projection is not signature verification.
export function resolveEvidenceSelection(selection: EvidenceSelection | null, snapshot: TaskSnapshot | null): EvidenceSelection | null {
  if (!selection || selection.kind === 'scenario' || (selection.kind === 'pipeline' && selection.taskId === undefined)) return selection
  if (!snapshot || (selection.taskId !== undefined && selection.taskId !== snapshot.task.task_id)) return null

  switch (selection.kind) {
    case 'credential': {
      const captured = selection.credential
      const credential = uniqueRecord(snapshot.credentials, (item) => sameReference(captured.credential_id, item.credential_id))
      return credential && sameReference(captured.signed_object_hash, credential.signed_object_hash)
        ? { ...selection, credential } : null
    }
    case 'execution': {
      const captured = selection.execution
      const execution = uniqueRecord(snapshot.executions, (item) => sameReference(captured.execution_id, item.execution_id))
      return execution && sameReference(captured.request_hash, execution.request_hash)
        && sameReference(captured.credential_chain_hash, execution.credential_chain_hash) && sameReference(captured.parameter_hash, execution.parameter_hash)
        && sameReference(captured.tool_service, execution.tool_service) && sameReference(captured.tool_name, execution.tool_name)
        && sameReference(captured.tool_version, execution.tool_version) && execution.business_action_id === captured.business_action_id
        && execution.created_at === captured.created_at ? { ...selection, execution } : null
    }
    case 'receipt': {
      const captured = selection.receipt
      const receipt = uniqueRecord(snapshot.receipts, (item) => sameReference(captured.receipt_id, item.receipt_id))
      return receipt && sameReference(captured.execution_id, receipt.execution_id) && sameReference(captured.receipt_hash, receipt.receipt_hash)
        && receipt.receipt_type === captured.receipt_type && receipt.decision === captured.decision
        && receipt.reason_code === captured.reason_code && receipt.created_at === captured.created_at
        ? { ...selection, receipt } : null
    }
    case 'audit': {
      const event = currentAuditEvent(selection.event, snapshot)
      return event ? { ...selection, event } : null
    }
    case 'workflow': {
      const run = uniqueRecord(snapshot.workflow_runs ?? [], (item) => sameReference(selection.runId, item.run_id))
      if (!run || (selection.sequence !== undefined && !uniqueRecord(run.events, (event) => event.sequence === selection.sequence))) return null
      return selection
    }
    case 'stage': {
      if (selection.auditEvents === undefined) return selection
      const references = selection.auditEvents
      if (new Set(references.map((event) => event.event_id)).size !== references.length) return null
      const auditEvents: AuditEventView[] = []
      for (const reference of references) {
        const event = currentAuditEvent(reference, snapshot)
        if (!event) return null
        auditEvents.push(event)
      }
      return { ...selection, auditEvents }
    }
    default:
      return selection
  }
}
