import { describe, expect, it } from 'vitest'
import { buildExecutionSteps, credentialLevel, executionForTrace, runOutcome, taskAuditNeedsRefresh } from './executionModel'
import { savedSnapshot, workflowSnapshot } from './test/fixtures'
import type { DemoResult, Overview } from './types'
import { businessOutcome } from './workflowModel'

describe('persisted event replay', () => {
  it('marks newly observed audit events pending even when the previous report was valid', () => {
    const old = { audit: { verification: { valid: true, rollback_detected: false, first_invalid_sequence: null, latest_event_sequence: 9 } } } as Overview
    expect(taskAuditNeedsRefresh(savedSnapshot, old)).toBe(true)
    expect(taskAuditNeedsRefresh(savedSnapshot, null)).toBe(true)
    expect(taskAuditNeedsRefresh(savedSnapshot, { ...old, audit: { ...old.audit, verification: { ...old.audit.verification, latest_event_sequence: 10 } } })).toBe(false)
    expect(taskAuditNeedsRefresh(null, old)).toBe(false)
  })
  it('keeps issuance as a recorded event without applying current revocation to its historical timestamp', () => {
    const snapshot = { ...savedSnapshot, credentials: [{ ...savedSnapshot.credentials[0], revoked_at: 0 }] }
    const step = buildExecutionSteps(snapshot, null).find((item) => item.selection.kind === 'credential')
    expect(step?.status).toBe('RECORDED')
    expect(step?.timestamp).toBe(savedSnapshot.credentials[0].issued_at)
    expect(runOutcome(snapshot).label).toBe('已拒绝')
  })

  it('does not undo a persisted committed result because its root is now revoked', () => {
    const snapshot = { ...workflowSnapshot, credentials: [{ ...workflowSnapshot.credentials[0], revoked_at: 0 }] }
    expect(runOutcome(snapshot).label).toBe('已提交')
    expect(snapshot.business_effects.refunds[0].amount_fen).toBe(7000)
  })

  it('reports a rejected business verification as no refund, even when no workflow run was persisted', () => {
    const snapshot = { ...savedSnapshot, business_context: { ...savedSnapshot.business_context!, ticket: {
      ticket_id: 'T10095', customer_id: 'C9595', title: '重复扣款申请', description: '', status: 'OPEN',
      verification_status: 'REJECTED' as const, payment_verification_status: 'REJECTED' as const,
      can_refund: false,
    } } }
    expect(businessOutcome(snapshot)).toMatchObject({ status: 'BUSINESS_STOPPED', label: '退款未执行', refundFen: 0 })
    expect(runOutcome(snapshot)).toMatchObject({ status: 'DENIED', label: '退款未执行' })
  })

  it('counts actual parent edges rather than remaining delegation depth', () => {
    const root = { ...savedSnapshot.credentials[0], delegation_depth: 2 }
    expect(credentialLevel(root, [root])).toBe(0)
    const child = { ...root, credential_id: 'child', parent_credential_id: root.credential_id, delegation_depth: 0 }
    expect(credentialLevel(child, [root, child])).toBe(1)
    expect(credentialLevel(child, [child])).toBeNull()
    const cycle = { ...root, parent_credential_id: child.credential_id }
    expect(credentialLevel(child, [cycle, child])).toBeNull()
  })
  it('reconstructs saved evidence without inventing Agent steps or losing denial', () => {
    const steps = buildExecutionSteps(savedSnapshot, null)
    expect(steps).toHaveLength(4)
    expect(steps.every((item) => item.selection.kind !== 'trace')).toBe(true)
    expect(steps.find((item) => item.id === 'audit-10')?.status).toBe('DENIED')
    expect(steps.find((item) => item.id === 'audit-10')?.stage).toBe('gateway')
    expect(runOutcome(savedSnapshot).label).toBe('已拒绝')
  })
  it('never displays a trace belonging to a different task', () => {
    const foreign: DemoResult = { demo_kind: 'NORMAL', task_id: 'foreign-task', planner: 'deterministic', status: 'COMPLETED', reason_code: null,
      trace: [{ sequence: 1, agent_id: 'agent-refund', action: 'call_tool', status: 'COMPLETED', details: {} }] }
    expect(buildExecutionSteps(savedSnapshot, foreign).every((item) => item.selection.kind !== 'trace')).toBe(true)
  })
  it('orders same-second credentials by parent links and audit events by sequence', () => {
    const root = savedSnapshot.credentials[0]
    const child = { ...root, credential_id: 'child', parent_credential_id: root.credential_id, delegation_depth: 1 }
    const steps = buildExecutionSteps({ ...savedSnapshot, credentials: [child, root],
      audit_events: [{ ...savedSnapshot.audit_events[0], event_sequence: 11 }, savedSnapshot.audit_events[0]] }, null)
    expect(steps.filter((item) => item.selection.kind === 'credential').map((item) => item.id)).toEqual(['credential-cred-root-test', 'credential-child'])
    expect(steps.filter((item) => item.selection.kind === 'audit').map((item) => item.id)).toEqual(['audit-10', 'audit-11'])
  })
  it('never links a trace by reason code even when only one execution has that reason', () => {
    const step = { sequence: 1, agent_id: 'agent-refund', action: 'gateway_decision', status: 'DENIED', details: { reason_code: 'PARAMETER_CONSTRAINT_VIOLATION' } }
    expect(executionForTrace(savedSnapshot, step)).toBeUndefined()
    const ambiguous = { ...savedSnapshot, executions: [...savedSnapshot.executions, { ...savedSnapshot.executions[0], execution_id: 'second' }] }
    expect(executionForTrace(ambiguous, step)).toBeUndefined()
  })
  it('does not pick a duplicate execution ID or fall back after an explicit reference is missing', () => {
    const execution = savedSnapshot.executions[0]
    const step = { sequence: 1, agent_id: 'agent-refund', action: 'gateway_decision', status: 'DENIED',
      details: { execution_id: execution.execution_id, reason_code: execution.reason_code } }
    expect(executionForTrace(savedSnapshot, step)).toBe(execution)
    expect(executionForTrace({ ...savedSnapshot, executions: [execution, execution] }, step)).toBeUndefined()
    expect(executionForTrace(savedSnapshot, { ...step, details: { ...step.details, execution_id: 'missing' } })).toBeUndefined()
  })
  it('does not fall back by reason when an execution reference is explicitly malformed', () => {
    const base = { sequence: 1, agent_id: 'agent-refund', action: 'gateway_decision', status: 'DENIED',
      details: { reason_code: 'PARAMETER_CONSTRAINT_VIOLATION' } }
    expect(executionForTrace(savedSnapshot, { ...base, details: { ...base.details, execution_id: null } })).toBeUndefined()
    expect(executionForTrace(savedSnapshot, { ...base, details: { ...base.details, execution_id: 123 } })).toBeUndefined()
    expect(executionForTrace(savedSnapshot, { ...base, details: { ...base.details, execution_id: '' } })).toBeUndefined()
    expect(executionForTrace(savedSnapshot, { ...base, details: { ...base.details, execution_id: undefined } })).toBeUndefined()
  })
})
