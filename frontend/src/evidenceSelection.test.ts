import { describe, expect, it } from 'vitest'
import { resolveEvidenceSelection, scopeEvidenceSelection } from './evidenceSelection'
import type { EvidenceSelection } from './executionModel'
import { savedSnapshot, workflowSnapshot } from './test/fixtures'
import type { TaskSnapshot } from './types'

// Projection and identity fixtures only; no signatures are created or verified by these tests.
const references: Array<{ name: string; selection: EvidenceSelection; snapshot: TaskSnapshot }> = [
  { name: 'credential', selection: { kind: 'credential', credential: savedSnapshot.credentials[0] }, snapshot: savedSnapshot },
  { name: 'execution', selection: { kind: 'execution', execution: savedSnapshot.executions[0] }, snapshot: savedSnapshot },
  { name: 'receipt', selection: { kind: 'receipt', receipt: savedSnapshot.receipts[0] }, snapshot: savedSnapshot },
  { name: 'audit', selection: { kind: 'audit', event: savedSnapshot.audit_events[0] }, snapshot: savedSnapshot },
  { name: 'workflow', selection: { kind: 'workflow', runId: 'RUN-fixture', sequence: 10 }, snapshot: workflowSnapshot },
  { name: 'task', selection: { kind: 'task' }, snapshot: savedSnapshot },
  { name: 'stage', selection: { kind: 'stage', stage: 'evidence' }, snapshot: savedSnapshot },
  { name: 'agent', selection: { kind: 'agent', agentId: 'agent-refund' }, snapshot: workflowSnapshot },
  { name: 'business', selection: { kind: 'business', resource: 'result' }, snapshot: savedSnapshot },
  { name: 'trace', selection: { kind: 'trace', step: workflowSnapshot.workflow_runs![0].events[0] }, snapshot: workflowSnapshot },
  { name: 'pipeline', selection: { kind: 'pipeline', title: 'display-mock', value: { state: 'INFERRED_PASS' } }, snapshot: savedSnapshot },
]

describe('current evidence selection from a task projection', () => {
  it.each(references)('pins the $name reference to its task and rejects a foreign snapshot', ({ selection, snapshot }) => {
    const scoped = scopeEvidenceSelection(selection, snapshot.task.task_id)
    expect(scoped.taskId).toBe(snapshot.task.task_id)
    expect(resolveEvidenceSelection(scoped, snapshot)).toEqual(scoped)
    expect(resolveEvidenceSelection(scoped, { ...snapshot, task: { ...snapshot.task, task_id: 'TASK-FOREIGN' } })).toBeNull()
    expect(resolveEvidenceSelection(scoped, null)).toBeNull()
  })

  it('does not rebind an already scoped record to the newly selected task', () => {
    const selection: EvidenceSelection = { kind: 'task', taskId: 'TASK-ORIGINAL' }
    expect(scopeEvidenceSelection(selection, 'TASK-NEW').taskId).toBe('TASK-ORIGINAL')
    expect(resolveEvidenceSelection(scopeEvidenceSelection(selection, savedSnapshot.task.task_id), savedSnapshot)).toBeNull()
    expect(resolveEvidenceSelection(null, savedSnapshot)).toBeNull()
  })

  it('refreshes mutable credential, execution, receipt and audit projection fields', () => {
    const credential = { ...savedSnapshot.credentials[0], revoked_at: 0 }
    const execution = { ...savedSnapshot.executions[0], receipt_status: 'PENDING', updated_at: 1790000010 }
    const receipt = { ...savedSnapshot.receipts[0], signature: { ...savedSnapshot.receipts[0].signature, valid: false } }
    const event = { ...savedSnapshot.audit_events[0], evidence_binding_valid: false }
    const snapshot = { ...savedSnapshot, credentials: [credential], executions: [execution], receipts: [receipt], audit_events: [event] }
    const selections: EvidenceSelection[] = [
      { kind: 'credential', credential: savedSnapshot.credentials[0] },
      { kind: 'execution', execution: savedSnapshot.executions[0] },
      { kind: 'receipt', receipt: savedSnapshot.receipts[0] },
      { kind: 'audit', event: savedSnapshot.audit_events[0] },
    ]
    expect(selections.map((selection) => resolveEvidenceSelection(selection, snapshot))).toEqual([
      { kind: 'credential', credential }, { kind: 'execution', execution }, { kind: 'receipt', receipt }, { kind: 'audit', event },
    ])
  })

  it.each(references.slice(0, 5))('does not resurrect the captured $name when no records remain', ({ selection, snapshot }) => {
    expect(resolveEvidenceSelection(selection, {
      ...snapshot, credentials: [], executions: [], receipts: [], audit_events: [], workflow_runs: [],
    })).toBeNull()
  })

  it.each(references.slice(0, 5))('rejects duplicate $name identities even if one object has a matching hash', ({ selection, snapshot }) => {
    const duplicated: TaskSnapshot = {
      ...snapshot,
      credentials: [...snapshot.credentials, ...snapshot.credentials.map((item) => ({ ...item, signed_object_hash: '0'.repeat(64) }))],
      executions: [...snapshot.executions, ...snapshot.executions.map((item) => ({ ...item, request_hash: '0'.repeat(64) }))],
      receipts: [...snapshot.receipts, ...snapshot.receipts.map((item) => ({ ...item, receipt_hash: '0'.repeat(64) }))],
      audit_events: [...snapshot.audit_events, ...snapshot.audit_events.map((item) => ({ ...item, event_hash: '0'.repeat(64) }))],
      workflow_runs: [...(snapshot.workflow_runs ?? []), ...(snapshot.workflow_runs ?? [])],
    }
    expect(resolveEvidenceSelection(selection, duplicated)).toBeNull()
  })

  it('rejects replacement signed objects and request identities rather than silently changing records', () => {
    expect(resolveEvidenceSelection({ kind: 'credential', credential: savedSnapshot.credentials[0] }, {
      ...savedSnapshot, credentials: [{ ...savedSnapshot.credentials[0], signed_object_hash: '0'.repeat(64) }],
    })).toBeNull()
    expect(resolveEvidenceSelection({ kind: 'execution', execution: savedSnapshot.executions[0] }, {
      ...savedSnapshot, executions: [{ ...savedSnapshot.executions[0], request_hash: '0'.repeat(64) }],
    })).toBeNull()
    expect(resolveEvidenceSelection({ kind: 'execution', execution: savedSnapshot.executions[0] }, {
      ...savedSnapshot, executions: [{ ...savedSnapshot.executions[0], parameter_hash: '0'.repeat(64) }],
    })).toBeNull()
    expect(resolveEvidenceSelection({ kind: 'execution', execution: savedSnapshot.executions[0] }, {
      ...savedSnapshot, executions: [{ ...savedSnapshot.executions[0], credential_chain_hash: '0'.repeat(64) }],
    })).toBeNull()
    expect(resolveEvidenceSelection({ kind: 'receipt', receipt: savedSnapshot.receipts[0] }, {
      ...savedSnapshot, receipts: [{ ...savedSnapshot.receipts[0], execution_id: 'EXEC-REPLACEMENT' }],
    })).toBeNull()
    expect(resolveEvidenceSelection({ kind: 'receipt', receipt: savedSnapshot.receipts[0] }, {
      ...savedSnapshot, receipts: [{ ...savedSnapshot.receipts[0], receipt_hash: '0'.repeat(64) }],
    })).toBeNull()
    expect(resolveEvidenceSelection({ kind: 'audit', event: savedSnapshot.audit_events[0] }, {
      ...savedSnapshot, audit_events: [{ ...savedSnapshot.audit_events[0], event_hash: '0'.repeat(64) }],
    })).toBeNull()
  })

  it('rejects a duplicated audit sequence with different event IDs', () => {
    const event = savedSnapshot.audit_events[0]
    expect(resolveEvidenceSelection({ kind: 'audit', event }, {
      ...savedSnapshot, audit_events: [event, { ...event, event_id: 'OTHER-EVENT' }],
    })).toBeNull()
  })

  it('does not use empty or omitted hashes as an identity anchor', () => {
    const credential = { ...savedSnapshot.credentials[0], signed_object_hash: '' }
    expect(resolveEvidenceSelection({ kind: 'credential', credential }, { ...savedSnapshot, credentials: [credential] })).toBeNull()
    const execution = { ...savedSnapshot.executions[0], request_hash: undefined as unknown as string }
    expect(resolveEvidenceSelection({ kind: 'execution', execution }, { ...savedSnapshot, executions: [execution] })).toBeNull()
    const receipt = { ...savedSnapshot.receipts[0], receipt_id: '' }
    expect(resolveEvidenceSelection({ kind: 'receipt', receipt }, { ...savedSnapshot, receipts: [receipt] })).toBeNull()
  })

  it('keeps an empty replay mask empty and refreshes only its selected audit references', () => {
    const event = savedSnapshot.audit_events[0]
    const current = { ...event, evidence_binding_valid: false }
    const future = { ...event, event_id: 'FUTURE-EVENT', event_sequence: event.event_sequence + 1, event_hash: '0'.repeat(64) }
    const snapshot = { ...savedSnapshot, audit_events: [current, future] }
    const empty: EvidenceSelection = { kind: 'stage', stage: 'evidence', auditEvents: [] }
    expect(resolveEvidenceSelection(empty, snapshot)).toEqual(empty)
    expect(resolveEvidenceSelection({ kind: 'stage', stage: 'evidence', auditEvents: [event] }, snapshot)).toEqual({
      kind: 'stage', stage: 'evidence', auditEvents: [current],
    })
    expect(resolveEvidenceSelection({ kind: 'stage', stage: 'evidence', auditEvents: [event] }, {
      ...snapshot, audit_events: [future],
    })).toBeNull()
    expect(resolveEvidenceSelection({ kind: 'stage', stage: 'evidence', auditEvents: [event, event] }, snapshot)).toBeNull()
  })

  it('requires a unique explicitly selected workflow event without falling back to run details', () => {
    const run = workflowSnapshot.workflow_runs![0]
    const event = run.events[0]
    expect(resolveEvidenceSelection({ kind: 'workflow', runId: run.run_id }, workflowSnapshot)).toEqual({ kind: 'workflow', runId: run.run_id })
    expect(resolveEvidenceSelection({ kind: 'workflow', runId: run.run_id, sequence: 999 }, workflowSnapshot)).toBeNull()
    expect(resolveEvidenceSelection({ kind: 'workflow', runId: run.run_id, sequence: event.sequence }, {
      ...workflowSnapshot, workflow_runs: [{ ...run, events: [event, event] }],
    })).toBeNull()
  })

  it('permits unscoped explanatory pipeline values without treating them as a current record', () => {
    const selection: EvidenceSelection = { kind: 'pipeline', title: 'static-display', value: { evidence_type: 'inferred_from_first_failure' } }
    expect(resolveEvidenceSelection(selection, null)).toBe(selection)
    expect(scopeEvidenceSelection(selection, null)).toBe(selection)
  })

  it('requires a current task for scoped pipeline observations but preserves their captured nature', () => {
    const selection = scopeEvidenceSelection({ kind: 'pipeline', title: 'gateway', value: { state: 'INFERRED_PASS' } }, savedSnapshot.task.task_id)
    expect(resolveEvidenceSelection(selection, savedSnapshot)).toEqual(selection)
    expect(resolveEvidenceSelection(selection, null)).toBeNull()
    expect(resolveEvidenceSelection(selection, { ...savedSnapshot, task: { ...savedSnapshot.task, task_id: 'TASK-OTHER' } })).toBeNull()
  })
})
