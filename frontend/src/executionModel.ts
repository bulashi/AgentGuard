import { actionLabel, agentLabel, eventLabel, toolLabel } from './labels'
import type { AuditEventView, CredentialView, DemoResult, ExecutionView, Overview, ReceiptView, SecurityScenario, TaskSnapshot, TraceStep } from './types'
import { observeReceipt } from './sourceVerification'
import { businessOutcome } from './workflowModel'

export type StageKey = 'request' | 'authorization' | 'agents' | 'gateway' | 'tools' | 'evidence'

export type EvidenceSelection = (
  { kind: 'agent'; agentId: string }
  | { kind: 'workflow'; runId: string; sequence?: number }
  | { kind: 'business'; resource: 'ticket' | 'knowledge' | 'result' | 'notifications' }
  | { kind: 'task' }
  | { kind: 'stage'; stage: StageKey; auditEvents?: AuditEventView[] }
  | { kind: 'trace'; step: TraceStep }
  | { kind: 'credential'; credential: CredentialView }
  | { kind: 'execution'; execution: ExecutionView }
  | { kind: 'receipt'; receipt: ReceiptView }
  | { kind: 'audit'; event: AuditEventView }
  | { kind: 'scenario'; scenario: SecurityScenario }
  | { kind: 'pipeline'; title: string; value: unknown }
) & { taskId?: string }

export interface ExecutionStep {
  id: string
  title: string
  subtitle: string
  stage: StageKey
  status: string
  timestamp?: number
  selection: EvidenceSelection
}

export function credentialLevel(credential: CredentialView, credentials: CredentialView[]): number | null {
  let current = credential
  let level = 0
  const visited = new Set([current.credential_id])
  while (current.parent_credential_id) {
    const parent = credentials.find((item) => item.credential_id === current.parent_credential_id)
    if (!parent || visited.has(parent.credential_id)) return null
    visited.add(parent.credential_id)
    current = parent
    level += 1
  }
  return level
}

export function executionForTrace(snapshot: TaskSnapshot | null, step: TraceStep) {
  const hasExecutionReference = Object.prototype.hasOwnProperty.call(step.details, 'execution_id')
  const id = step.details.execution_id
  if (hasExecutionReference) {
    if (typeof id !== 'string' || id.length === 0) return undefined
    const matches = snapshot?.executions.filter((item) => item.execution_id === id) ?? []
    return matches.length === 1 ? matches[0] : undefined
  }
  return undefined
}

export function traceStage(step: TraceStep): StageKey {
  const action = step.action.toLowerCase()
  if (action === 'gateway_decision' || action === 'admission' || action === 'verify') return 'gateway'
  if (action === 'call_tool' || action === 'execute') return 'tools'
  if (action === 'receipt') return 'evidence'
  if (action === 'authorize') return 'authorization'
  return 'agents'
}

export function isCoauthorizationAuditEvent(event: AuditEventView): boolean {
  return event.event_type === 'COAUTH_ROOT_AUTHORIZED'
    && event.schema_version === '2.0'
    && event.execution_id === null
    && typeof event.evidence_binding_valid === 'boolean'
}

export function coauthorizationRoot(event: AuditEventView, credentials: CredentialView[]) {
  if (!isCoauthorizationAuditEvent(event) || event.evidence_binding_valid !== true) return undefined
  const evidence = event.coauthorization_evidence
  const rootId = evidence?.root_credential_id
  const rootHash = evidence?.root_credential_hash
  if (rootId !== event.evidence_reference || typeof rootHash !== 'string') return undefined
  const matches = credentials.filter((credential) => credential.credential_id === event.evidence_reference)
  const root = matches.length === 1 ? matches[0] : undefined
  return root?.credential_type === 'ROOT' && root.signed_object_hash === rootHash
    && root.stored_hash_valid === true ? root : undefined
}

export function coauthorizationBindingStatus(event: AuditEventView): 'BINDING_CHECKED' | 'INVALID' | 'NOT_CHECKED' {
  if (!isCoauthorizationAuditEvent(event)) return 'NOT_CHECKED'
  if (event.evidence_binding_valid === false) return 'INVALID'
  return event.coauthorization_evidence && event.evidence_binding_valid === true ? 'BINDING_CHECKED' : 'NOT_CHECKED'
}

export function auditChainIsConsistent(overview: Overview | null): boolean {
  const verification = overview?.audit.verification
  return verification?.valid === true && verification.rollback_detected === false
    && verification.first_invalid_sequence === null
}

export function taskAuditNeedsRefresh(snapshot: TaskSnapshot | null, overview: Overview | null): boolean {
  const events = snapshot?.audit_events ?? []
  if (!events.length) return false
  const end = overview?.audit.verification?.latest_event_sequence
  return typeof end !== 'number' || !Number.isSafeInteger(end)
    || events.some((event) => !Number.isSafeInteger(event.event_sequence) || event.event_sequence > end)
}

export function visibleAuditEvents(snapshot: TaskSnapshot | null, credentials: CredentialView[], executions: ExecutionView[], replay: boolean): AuditEventView[] {
  const executionIds = new Set(executions.map((execution) => execution.execution_id))
  return snapshot?.audit_events.filter((event) => {
    if (!replay) return true
    if (isCoauthorizationAuditEvent(event)) return Boolean(coauthorizationRoot(event, credentials))
    return typeof event.execution_id === 'string' && executionIds.has(event.execution_id)
  }) ?? []
}

export function buildExecutionSteps(snapshot: TaskSnapshot | null, demo: DemoResult | null): ExecutionStep[] {
  if (!snapshot) return []
  if (demo?.task_id === snapshot.task.task_id && demo.trace.length) {
    return demo.trace.map((step) => ({
      id: `trace-${step.sequence}`,
      title: `${agentLabel(step.agent_id)} · ${actionLabel(step.action)}`,
      subtitle: typeof step.details.tool === 'string' ? toolLabel(step.details.tool)
        : typeof step.details.child_agent_id === 'string' ? `委托给${agentLabel(step.details.child_agent_id)}`
          : typeof step.details.reason_code === 'string' ? step.details.reason_code
            : typeof step.details.planner === 'string' ? step.details.planner === 'llm' ? 'AI 候选动作' : '确定性候选' : `步骤 ${step.sequence}`,
      stage: traceStage(step),
      status: step.status,
      selection: { kind: 'trace', step },
    }))
  }

  const records: ExecutionStep[] = [{
    id: `task-${snapshot.task.task_id}`, title: '创建业务任务',
    subtitle: `${snapshot.task.ticket_id} / ${snapshot.task.customer_id}`, stage: 'request',
    status: 'RECEIVED', timestamp: snapshot.task.created_at, selection: { kind: 'task' },
  }]
  for (const credential of snapshot.credentials) {
    records.push({ id: `credential-${credential.credential_id}`, title: credential.parent_credential_id ? '签发委托授权' : '签发根授权',
      subtitle: agentLabel(credential.holder_agent_id), stage: credential.parent_credential_id ? 'agents' : 'authorization',
      status: 'RECORDED',
      timestamp: credential.issued_at, selection: { kind: 'credential', credential } })
  }
  const audited = new Set(snapshot.audit_events.flatMap((item) => typeof item.execution_id === 'string' ? [item.execution_id] : []))
  for (const execution of snapshot.executions) {
    if (!audited.has(execution.execution_id)) records.push({ id: `execution-${execution.execution_id}`,
      title: toolLabel(execution.tool_name), subtitle: execution.reason_code ?? execution.execution_id,
      stage: execution.decision === 'DENY' ? 'gateway' : 'tools', status: execution.state,
      timestamp: execution.updated_at, selection: { kind: 'execution', execution } })
  }
  for (const event of snapshot.audit_events) {
    const coauthorized = isCoauthorizationAuditEvent(event)
    const execution = typeof event.execution_id === 'string' ? snapshot.executions.find((item) => item.execution_id === event.execution_id) : undefined
    const denied = event.event_type === 'EXECUTION_DENIED' || event.event_type === 'AUTHORIZATION_DENIED'
    records.push({ id: `audit-${event.event_sequence}`, title: eventLabel(event.event_type),
      subtitle: `${coauthorized ? '根授权' : execution ? toolLabel(execution.tool_name) : '执行事件'} · #${event.event_sequence}`,
      stage: coauthorized ? 'authorization' : ['EXECUTION_COMPLETED', 'EXECUTION_COMMITTED'].includes(event.event_type) ? 'tools' : ['RECEIPT_ISSUED', 'RECEIPT_SIGNED'].includes(event.event_type) ? 'evidence' : 'gateway',
      status: coauthorized ? coauthorizationBindingStatus(event) === 'INVALID' ? 'INVALID' : 'RECORDED' : denied ? 'DENIED' : 'RECORDED',
      timestamp: event.timestamp, selection: { kind: 'audit', event } })
  }
  for (const receipt of snapshot.receipts) records.push({ id: `receipt-${receipt.receipt_id}`, title: '签名执行回执',
    subtitle: receipt.decision === 'DENY' ? '拒绝回执' : '执行结果回执', stage: 'evidence',
    status: observeReceipt(receipt).status === 'VALID' ? 'SIGNED' : observeReceipt(receipt).status, timestamp: receipt.created_at, selection: { kind: 'receipt', receipt } })
  const tieOrder = (step: ExecutionStep) => {
    if (step.selection.kind === 'task') return 0
    if (step.selection.kind === 'credential') return 1 + (credentialLevel(step.selection.credential, snapshot.credentials) ?? 10)
    if (step.selection.kind === 'execution') return 20
    if (step.selection.kind === 'audit') return 30
    return 40
  }
  // Stored timestamps have second precision; parent links and audit sequence resolve ties without inventing Agent actions.
  return records.sort((a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0) || tieOrder(a) - tieOrder(b)
    || (a.selection.kind === 'audit' && b.selection.kind === 'audit' ? a.selection.event.event_sequence - b.selection.event.event_sequence : 0))
}

export function runOutcome(snapshot: TaskSnapshot | null) {
  const business = businessOutcome(snapshot)
  const committed = snapshot?.executions.filter((item) => item.state === 'COMMITTED').length ?? 0
  const denied = snapshot?.executions.filter((item) => item.decision === 'DENY').length ?? 0
  if (business.status === 'BUSINESS_STOPPED') return { label: business.label, status: 'DENIED' }
  if (business.status === 'INCONSISTENT') return { label: business.label, status: 'PENDING' }
  if (committed && denied) return { label: '部分拒绝', status: 'DENIED' }
  if (denied) return { label: '已拒绝', status: 'DENIED' }
  if (committed && snapshot?.executions.every((item) => item.state === 'COMMITTED')) return { label: '已提交', status: 'COMPLETED' }
  if (snapshot?.executions.length) return { label: '处理中', status: 'PENDING' }
  return { label: snapshot?.task.status === 'PENDING_AUTHORIZATION' ? '待授权' : '待执行', status: snapshot?.task.status ?? 'PENDING' }
}
