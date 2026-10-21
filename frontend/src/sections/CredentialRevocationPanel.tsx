import { fenToYuan } from '../money'
import { useEffect, useId, useRef, useState } from 'react'
import { Alert, Checkbox, Descriptions, Empty, Modal, Segmented, Select, Tag, Tooltip } from 'antd'
import { ArrowUpRight, FileJson, RefreshCw, ShieldCheck, ShieldX } from 'lucide-react'
import { ApiError } from '../api'
import { LiquidGlassButton } from '../components/LiquidGlassButton'
import { TimeValue } from '../components/Evidence'
import type { EvidenceSelection } from '../executionModel'
import type { AuditEventView, CredentialView, TaskSnapshot } from '../types'
import './credential-revocation.css'

export interface CredentialRevocationRequest { confirmed: true; reason: string }

export interface CredentialRevocationResult {
  schema_version: '1.0'
  task_id: string
  credential_id: string
  status: 'REVOKED'
  revoked_by: string
  revoked_at: number
  revocation_reason: string
  descendant_count: number
  already_revoked: boolean
  boundary: 'DISPATCH_BOUNDARY_NO_ROLLBACK'
  audit_status: 'PENDING' | 'RECORDED'
  audit_event_ids: string[]
  cancellations: Array<{
    cancellation_id: string
    reason_code: 'ANCESTOR_REVOKED' | 'KEY_REVOKED'
    original_execution_id: string
    denied_execution_id: string
    denied_receipt_id: string | null
    audit_event_ids: string[]
  }>
  execution_observation: {
    scope: 'TASK_SNAPSHOT'
    released_count: number
    dispatched_or_unknown_count: number
    admitted_count: number
  }
}

export interface RevocationVerificationResult {
  schema_version: '1.0'
  task_id: string
  credential_id: string
  status: 'PASS' | 'FAIL'
  reason_code: string
  request_id: string
  request_hash: string
  holder_key_id: string
  holder_proof_valid: boolean
  chain_signature_valid: boolean
  receipt_valid: boolean
  record_binding_valid: boolean
  execution_id: string | null
  receipt_id: string | null
  before: { refund_rows: number; notification_rows: number; refund_amount_fen: number }
  after: { refund_rows: number; notification_rows: number; refund_amount_fen: number }
  budget_unchanged: boolean
  new_holder_proof: true
  observed_at_ms: number
}

export interface CredentialRevocationPanelProps {
  snapshot: TaskSnapshot | null
  task?: { task_id: string } | null
  credentials?: CredentialView[]
  // The parent supplies api.revokeCredential: authenticated same-origin POST, no browser signing.
  onRevoke?: (taskId: string, credentialId: string, body: CredentialRevocationRequest) => Promise<CredentialRevocationResult>
  onVerify?: (taskId: string, credentialId: string, body: { confirmed: true }) => Promise<RevocationVerificationResult>
  onChanged?: (taskId: string) => Promise<void>
  onInspect?: (selection: EvidenceSelection) => void
}

type Level = 'ROOT' | 'INTERMEDIATE' | 'LEAF'
type SavedCredential = CredentialView & { revoked_by?: string | null }
type CancellationLink = CredentialRevocationResult['cancellations'][number]
type RevocationIdentity = Pick<CredentialRevocationResult, 'task_id' | 'credential_id' | 'revoked_at' | 'revoked_by' | 'revocation_reason'>
const levelLabels: Record<Level, string> = { ROOT: '根凭证', INTERMEDIATE: '中间凭证', LEAF: '叶凭证' }
const identifier = (value: unknown): value is string => typeof value === 'string'
  && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)
const integer = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
const reasonValid = (value: unknown): value is string => typeof value === 'string'
  && Boolean(value.trim()) && Array.from(value).length <= 256

function exactKeys(value: unknown, keys: string[]): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key))
}

function validResult(value: unknown, taskId: string, credentialId: string): value is CredentialRevocationResult {
  if (!exactKeys(value, ['schema_version', 'task_id', 'credential_id', 'status', 'revoked_by', 'revoked_at',
    'revocation_reason', 'descendant_count', 'already_revoked', 'boundary', 'audit_status', 'audit_event_ids', 'cancellations', 'execution_observation'])) return false
  const observation = value.execution_observation
  return value.schema_version === '1.0' && value.task_id === taskId && value.credential_id === credentialId
    && value.status === 'REVOKED' && identifier(value.revoked_by) && integer(value.revoked_at)
    && reasonValid(value.revocation_reason) && integer(value.descendant_count) && typeof value.already_revoked === 'boolean'
    && value.boundary === 'DISPATCH_BOUNDARY_NO_ROLLBACK' && (value.audit_status === 'PENDING' || value.audit_status === 'RECORDED')
    && Array.isArray(value.audit_event_ids) && value.audit_event_ids.every(identifier)
    && exactKeys(observation, ['scope', 'released_count', 'dispatched_or_unknown_count', 'admitted_count'])
    && observation.scope === 'TASK_SNAPSHOT' && integer(observation.released_count)
    && integer(observation.dispatched_or_unknown_count) && integer(observation.admitted_count)
    && Array.isArray(value.cancellations) && value.cancellations.every((link) =>
      exactKeys(link, ['cancellation_id', 'reason_code', 'original_execution_id', 'denied_execution_id', 'denied_receipt_id', 'audit_event_ids'])
      && identifier(link.cancellation_id) && identifier(link.original_execution_id) && identifier(link.denied_execution_id)
      && (link.reason_code === 'ANCESTOR_REVOKED' || link.reason_code === 'KEY_REVOKED')
      && (link.denied_receipt_id === null || identifier(link.denied_receipt_id))
      && Array.isArray(link.audit_event_ids) && link.audit_event_ids.every(identifier))
}

function validVerificationResult(value: unknown, taskId: string, credentialId: string): value is RevocationVerificationResult {
  if (!exactKeys(value, ['schema_version', 'task_id', 'credential_id', 'status', 'reason_code', 'request_id', 'request_hash', 'holder_key_id',
    'holder_proof_valid', 'chain_signature_valid', 'receipt_valid', 'record_binding_valid', 'execution_id', 'receipt_id', 'before', 'after',
    'budget_unchanged', 'new_holder_proof', 'observed_at_ms'])) return false
  const fields = ['refund_rows', 'notification_rows', 'refund_amount_fen']
  if (value.schema_version !== '1.0' || value.task_id !== taskId || value.credential_id !== credentialId
    || (value.status !== 'PASS' && value.status !== 'FAIL') || typeof value.reason_code !== 'string' || !/^[A-Z][A-Z0-9_]{0,127}$/.test(value.reason_code)
    || !identifier(value.request_id) || typeof value.request_hash !== 'string' || !/^[0-9a-f]{64}$/.test(value.request_hash)
    || !identifier(value.holder_key_id) || (value.execution_id !== null && !identifier(value.execution_id))
    || (value.receipt_id !== null && !identifier(value.receipt_id)) || value.new_holder_proof !== true || !integer(value.observed_at_ms)
    || !['holder_proof_valid', 'chain_signature_valid', 'receipt_valid', 'record_binding_valid', 'budget_unchanged'].every((key) => typeof value[key] === 'boolean')
    || !exactKeys(value.before, fields) || !exactKeys(value.after, fields)
    || !fields.every((key) => integer((value.before as Record<string, unknown>)[key]) && integer((value.after as Record<string, unknown>)[key]))) return false
  return value.status === 'FAIL' || ((value.reason_code === 'ANCESTOR_REVOKED' || value.reason_code === 'KEY_REVOKED')
    && value.holder_proof_valid === true && value.chain_signature_valid === true && value.receipt_valid === true
    && value.record_binding_valid === true && value.budget_unchanged === true && value.execution_id !== null && value.receipt_id !== null
    && fields.every((key) => (value.before as Record<string, unknown>)[key] === (value.after as Record<string, unknown>)[key]))
}

function credentialLevel(credential: CredentialView): Level {
  return credential.credential_type === 'ROOT' ? 'ROOT' : credential.delegation_depth > 0 ? 'INTERMEDIATE' : 'LEAF'
}

function ancestry(credentials: CredentialView[]): Map<string, Set<string>> | null {
  const byId = new Map(credentials.map((item) => [item.credential_id, item]))
  if (byId.size !== credentials.length || credentials.some((item) => !identifier(item.credential_id))) return null
  const descendants = new Map(credentials.map((item) => [item.credential_id, new Set<string>()]))
  for (const credential of credentials) {
    let current = credential
    const visited = new Set<string>()
    while (true) {
      if (visited.has(current.credential_id)) return null
      visited.add(current.credential_id)
      if (current.credential_id !== credential.credential_id) descendants.get(current.credential_id)?.add(credential.credential_id)
      if (current.credential_type === 'ROOT' && current.parent_credential_id === null) break
      const parent = current.parent_credential_id ? byId.get(current.parent_credential_id) : null
      if (current.credential_type !== 'DELEGATION' || !parent) return null
      current = parent
    }
  }
  return descendants
}

function uniqueRecords<T>(records: T[], id: (record: T) => string): T[] {
  const counts = new Map<string, number>()
  for (const record of records) counts.set(id(record), (counts.get(id(record)) ?? 0) + 1)
  return records.filter((record) => identifier(id(record)) && counts.get(id(record)) === 1)
}

function savedCancellationLinks(snapshot: TaskSnapshot, record: RevocationIdentity): CancellationLink[] {
  const rows = uniqueRecords(uniqueRecords(snapshot.dispatch_cancellations ?? [], (row) => row.cancellation_id), (row) => row.execution_id)
  const executions = uniqueRecords(snapshot.executions, (item) => item.execution_id)
  return rows.filter((row) => {
    const evidence = row.evidence
    const original = executions.find((item) => item.execution_id === row.execution_id)
    const denied = executions.find((item) => item.execution_id === row.denial_execution_id)
    return evidence?.schema_version === '1.0' && evidence.record_type === 'DISPATCH_CANCELLED_V1'
      && evidence.task_id === record.task_id && evidence.admission_decision === 'ALLOW' && evidence.dispatch_decision === 'DENY'
      && (row.reason_code === 'ANCESTOR_REVOKED' || row.reason_code === 'KEY_REVOKED')
      && identifier(row.execution_id) && identifier(row.denial_execution_id) && row.execution_id !== row.denial_execution_id
      && original?.state === 'RELEASED' && original.decision === 'ALLOW' && denied?.state === 'DENIED'
      && denied.decision === 'DENY' && denied.reason_code === row.reason_code
      && original.request_hash === row.request_hash && denied.request_hash === row.request_hash
      && original.credential_chain_hash === row.credential_chain_hash && denied.credential_chain_hash === row.credential_chain_hash
      && ['cancellation_id', 'execution_id', 'denial_execution_id', 'request_id', 'request_hash', 'credential_chain_hash', 'reason_code', 'cancelled_at']
        .every((key) => evidence[key] === row[key as keyof typeof row])
      && Array.isArray(evidence.revocations) && evidence.revocations.some((item: unknown) => {
        if (!item || typeof item !== 'object') return false
        const revoked = item as Record<string, unknown>
        return revoked.credential_id === record.credential_id && revoked.revoked_at === record.revoked_at
          && revoked.revoked_by === record.revoked_by && revoked.reason === record.revocation_reason
      })
  }).map((row) => ({ cancellation_id: row.cancellation_id, reason_code: row.reason_code as CancellationLink['reason_code'],
    original_execution_id: row.execution_id, denied_execution_id: row.denial_execution_id,
    denied_receipt_id: null, audit_event_ids: [] }))
}

function revocationAuditEvents(snapshot: TaskSnapshot, credential: CredentialView, record: RevocationIdentity, knownIds: string[]): AuditEventView[] {
  return uniqueRecords(snapshot.audit_events, (event) => event.event_id).filter((event) => {
    if (event.schema_version !== '4.0' || event.event_type !== 'CREDENTIAL_REVOKED' || event.execution_id !== null
      || event.evidence_reference !== record.credential_id || event.evidence_binding_valid === false) return false
    const evidence = event.credential_revocation_evidence
    if (!evidence) return knownIds.includes(event.event_id)
    return event.evidence_binding_valid === true && evidence.schema_version === '1.0' && evidence.record_type === 'CREDENTIAL_REVOKED_V1'
      && evidence.task_id === record.task_id && evidence.credential_id === record.credential_id
      && evidence.credential_type === credential.credential_type && evidence.parent_credential_id === credential.parent_credential_id
      && evidence.revoked_at === record.revoked_at && evidence.revoked_by === record.revoked_by && evidence.reason === record.revocation_reason
  })
}

export function CredentialRevocationPanel(props: CredentialRevocationPanelProps) {
  const task = props.task === undefined ? props.snapshot?.task : props.task
  // A task change remounts the controls, so an old mutation reply cannot populate the new task.
  return <RevocationControls key={task?.task_id ?? 'no-task'} {...props} task={task ?? null} />
}

function RevocationControls({ snapshot, task, credentials, onRevoke, onVerify, onChanged, onInspect }: CredentialRevocationPanelProps) {
  const headingId = useId()
  const allCredentials = snapshot?.credentials ?? []
  const selectable = credentials ?? allCredentials
  const scope = ancestry(allCredentials)
  const taskId = task?.task_id ?? ''
  const scoped = Boolean(snapshot && taskId && snapshot.task.task_id === taskId && scope)
    && new Set(selectable.map((item) => item.credential_id)).size === selectable.length
    && selectable.every((item) => allCredentials.some((saved) => saved.credential_id === item.credential_id
      && saved.signed_object_hash === item.signed_object_hash))
  const [level, setLevel] = useState<Level>('ROOT')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const reason = '用户主动撤销授权'
  const [confirmation, setConfirmation] = useState<string | null>(null)
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [reading, setReading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [refreshError, setRefreshError] = useState<string | null>(null)
  const [uncertainSnapshot, setUncertainSnapshot] = useState<TaskSnapshot | null>(null)
  const [result, setResult] = useState<CredentialRevocationResult | null>(null)
  const [verifyConfirmation, setVerifyConfirmation] = useState<string | null>(null)
  const [verifyConfirmed, setVerifyConfirmed] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [verifyError, setVerifyError] = useState<string | null>(null)
  const [verificationResult, setVerificationResult] = useState<RevocationVerificationResult | null>(null)
  const [verificationRefreshed, setVerificationRefreshed] = useState(false)
  const [uncertainVerificationSnapshot, setUncertainVerificationSnapshot] = useState<TaskSnapshot | null>(null)
  const mounted = useRef(true)
  const inFlight = useRef(false)
  const inspectedVerification = useRef<string | null>(null)
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])

  const selectableIds = new Set(selectable.map((item) => item.credential_id))
  const options = allCredentials.filter((item) => selectableIds.has(item.credential_id) && credentialLevel(item) === level)
  const selected = scoped ? (selectedId === null ? options[0] : options.find((item) => item.credential_id === selectedId)) : undefined
  const descendants = selected ? [...(scope?.get(selected.credential_id) ?? [])].sort() : []
  const binding = selected ? JSON.stringify([taskId, selected.credential_id, selected.signed_object_hash, descendants,
    selected.revoked_at, selected.revocation_reason]) : null
  const displayedResult = result?.task_id === taskId && result.credential_id === selected?.credential_id ? result : null
  const revoked = selected?.revoked_at !== null && selected?.revoked_at !== undefined
  const unconfirmed = Boolean(uncertainSnapshot && uncertainSnapshot === snapshot)
  const ready = Boolean(scoped && selected && onRevoke && !revoked && !displayedResult
    && !busy && !verifying && !reading && !unconfirmed && verifyConfirmation === null)
  const revocationBlockedReason = !scoped ? '任务或凭证链快照尚未确认'
    : !selected ? '请选择要撤销的凭证'
      : !onRevoke ? '撤销服务不可用'
        : revoked || displayedResult ? '该凭证已有撤销记录'
            : unconfirmed ? '当前任务状态待确认，请先刷新任务记录'
              : busy || reading || verifying ? '正在读取或提交，请等待当前操作结束'
                : verifyConfirmation !== null ? '请先完成当前确认' : null
  const verificationUnconfirmed = Boolean(uncertainVerificationSnapshot && uncertainVerificationSnapshot === snapshot)
  const verifyReady = Boolean(scoped && selected && onVerify && (revoked || displayedResult) && !busy && !verifying && !reading
    && !verificationUnconfirmed && confirmation === null)
  const staleConfirmation = confirmation !== null && confirmation !== binding
  const staleVerifyConfirmation = verifyConfirmation !== null && verifyConfirmation !== binding
  const current = useRef({ binding, ready, verifyReady })
  current.current = { binding, ready, verifyReady }

  async function refresh() {
    if (!onChanged || reading || inFlight.current) return
    setReading(true); setRefreshError(null)
    try { await onChanged(taskId); if (mounted.current) setVerificationRefreshed(true) }
    catch { if (mounted.current) setRefreshError('最新任务记录读取失败；当前仍为上次快照。') }
    finally { if (mounted.current) setReading(false) }
  }

  async function submit() {
    if (!selected || !onRevoke || !confirmed || !ready || confirmation !== binding
      || current.current.binding !== confirmation || !current.current.ready || inFlight.current) return
    inFlight.current = true
    setBusy(true); setError(null); setRefreshError(null)
    try {
      const reply = await onRevoke(taskId, selected.credential_id, { confirmed: true, reason })
      if (!mounted.current) return
      if (!validResult(reply, taskId, selected.credential_id)) throw new Error('Unconfirmed revocation reply')
      setResult(reply); setConfirmation(null); setConfirmed(false); setUncertainSnapshot(null)
      if (onChanged) {
        setReading(true)
        try { await onChanged(taskId) }
        catch { if (mounted.current) setRefreshError('已收到撤销回复；最新任务与审计记录仍待刷新。') }
      }
    } catch (failure) {
      if (!mounted.current) return
      const rejected = failure instanceof ApiError && [400, 401, 403, 404, 409, 422].includes(failure.status)
      const code = failure instanceof ApiError && /^[A-Z][A-Z0-9_]{0,127}$/.test(failure.reasonCode) ? failure.reasonCode : 'REQUEST_REJECTED'
      setError(rejected ? `撤销请求被拒绝（${code}）；请刷新任务记录后核对。`
        : '撤销结果未确认；请刷新保存记录，不自动重试。')
      if (!rejected) setUncertainSnapshot(snapshot)
      setConfirmed(false)
    } finally {
      inFlight.current = false
      if (mounted.current) { setBusy(false); setReading(false) }
    }
  }

  async function verify() {
    if (!selected || !onVerify || !verifyConfirmed || !verifyReady || verifyConfirmation !== binding
      || current.current.binding !== verifyConfirmation || !current.current.verifyReady || inFlight.current) return
    inFlight.current = true
    setVerifying(true); setVerifyError(null); setRefreshError(null); setVerificationResult(null); setVerificationRefreshed(false)
    try {
      const reply = await onVerify(taskId, selected.credential_id, { confirmed: true })
      if (!mounted.current) return
      if (!validVerificationResult(reply, taskId, selected.credential_id)) throw new Error('Unconfirmed verification reply')
      setVerificationResult(reply); setVerifyConfirmation(null); setVerifyConfirmed(false); setUncertainVerificationSnapshot(null)
      if (onChanged) {
        setReading(true)
        try { await onChanged(taskId); if (mounted.current) setVerificationRefreshed(true) }
        catch { if (mounted.current) setRefreshError('已收到独立验证回复；实际执行与回执记录仍待刷新。') }
      }
    } catch (failure) {
      if (!mounted.current) return
      const rejected = failure instanceof ApiError && [400, 401, 403, 404, 409, 422].includes(failure.status)
      const code = failure instanceof ApiError && /^[A-Z][A-Z0-9_]{0,127}$/.test(failure.reasonCode) ? failure.reasonCode : 'REQUEST_REJECTED'
      setVerifyError(rejected ? code === 'REVOCATION_PROBE_CHAIN_UNAVAILABLE'
        ? '验证请求被拒绝（REVOCATION_PROBE_CHAIN_UNAVAILABLE）；退款链不受支持或已过期，不能确认通过。'
        : `验证请求被拒绝（${code}）；不能确认通过。`
        : '独立验证结果未确认；请刷新保存记录，不自动重试。')
      if (!rejected) setUncertainVerificationSnapshot(snapshot)
      setVerifyConfirmed(false)
    } finally {
      inFlight.current = false
      if (mounted.current) { setVerifying(false); setReading(false) }
    }
  }

  function select(nextLevel: Level, id: string | null) {
    setLevel(nextLevel); setSelectedId(id); setConfirmation(null); setConfirmed(false); setError(null)
    setVerifyConfirmation(null); setVerifyConfirmed(false); setVerificationResult(null); setVerificationRefreshed(false); setVerifyError(null)
  }

  const saved = selected as SavedCredential | undefined
  const revokedAt = displayedResult?.revoked_at ?? saved?.revoked_at
  const revokedBy = displayedResult?.revoked_by ?? (identifier(saved?.revoked_by) ? saved.revoked_by : null)
  const savedReason = displayedResult?.revocation_reason ?? saved?.revocation_reason
  const observation = displayedResult?.execution_observation
  const record: RevocationIdentity | null = selected && integer(revokedAt) && identifier(revokedBy) && reasonValid(savedReason)
    ? { task_id: taskId, credential_id: selected.credential_id, revoked_at: revokedAt, revoked_by: revokedBy, revocation_reason: savedReason } : null
  const savedLinks = snapshot && record ? savedCancellationLinks(snapshot, record) : []
  const replyLinks = displayedResult?.cancellations ?? []
  const cancellationLinks = uniqueRecords([...replyLinks, ...savedLinks.filter((link) => !replyLinks.some((reply) => reply.cancellation_id === link.cancellation_id))],
    (link) => link.cancellation_id)
  const executions = uniqueRecords(snapshot?.executions ?? [], (item) => item.execution_id)
  const receipts = uniqueRecords(snapshot?.receipts ?? [], (item) => item.receipt_id)
  const events = uniqueRecords(snapshot?.audit_events ?? [], (item) => item.event_id)
  const credentialAudits = snapshot && selected && record
    ? revocationAuditEvents(snapshot, selected, record, displayedResult?.audit_event_ids ?? []) : []
  const cancellations = cancellationLinks.map((link) => {
    const original = executions.find((item) => item.execution_id === link.original_execution_id)
    const denied = executions.find((item) => item.execution_id === link.denied_execution_id)
    const matched = original?.state === 'RELEASED' && original.decision === 'ALLOW' && denied?.state === 'DENIED'
      && denied.decision === 'DENY' && denied.reason_code === link.reason_code
      && original.execution_id !== denied.execution_id
      && [original.request_hash, original.credential_chain_hash].every((hash) => /^[0-9a-f]{64}$/.test(hash))
      && original.request_hash === denied.request_hash && original.credential_chain_hash === denied.credential_chain_hash
    const matchingReceipts = matched ? receipts.filter((item) => item.execution_id === link.denied_execution_id
      && (link.denied_receipt_id === null || item.receipt_id === link.denied_receipt_id)
      && item.decision === 'DENY' && item.reason_code === link.reason_code) : []
    const auditEvents = matched ? events.filter((event) => event.execution_id === link.original_execution_id
      && event.event_type === 'EXECUTION_RELEASED' && event.evidence_reference === link.cancellation_id && event.evidence_binding_valid !== false
      && (link.audit_event_ids.includes(event.event_id) || (event.evidence_binding_valid === true && savedLinks.some((saved) => saved.cancellation_id === link.cancellation_id
        && saved.original_execution_id === link.original_execution_id && saved.denied_execution_id === link.denied_execution_id
        && saved.reason_code === link.reason_code)))) : []
    return { link, denied: matched ? denied : undefined, receipt: matchingReceipts.length === 1 ? matchingReceipts[0] : undefined, auditEvents }
  })
  const auditRecorded = credentialAudits.length > 0 || cancellations.some((item) => item.auditEvents.length > 0)
  const verification = verificationResult?.task_id === taskId && verificationResult.credential_id === selected?.credential_id ? verificationResult : null
  const verifiedExecution = verification ? executions.find((item) => item.execution_id === verification.execution_id
    && item.request_hash === verification.request_hash && item.state === 'DENIED' && item.decision === 'DENY'
    && item.reason_code === verification.reason_code) : undefined
  const verifiedReceipt = verification && verifiedExecution ? receipts.find((item) => item.receipt_id === verification.receipt_id
    && item.execution_id === verifiedExecution.execution_id && item.decision === 'DENY' && item.reason_code === verification.reason_code) : undefined
  useEffect(() => {
    if (!verification || !verificationRefreshed || !onInspect || inspectedVerification.current === verification.request_id) return
    if (verifiedReceipt) onInspect({ kind: 'receipt', taskId, receipt: verifiedReceipt })
    else if (verifiedExecution) onInspect({ kind: 'execution', taskId, execution: verifiedExecution })
    else return
    inspectedVerification.current = verification.request_id
  }, [verification, verificationRefreshed, verifiedExecution, verifiedReceipt, onInspect, taskId])

  return <section className="credential-revocation" aria-labelledby={headingId} data-testid="credential-revocation">
    <div className="revocation-heading">
      <h2 id={headingId}><ShieldX size={18} /> 凭证撤销</h2>
      <Tag color={revoked || displayedResult ? 'default' : 'blue'}>{revoked || displayedResult ? '已撤销' : '当前任务快照'}</Tag>
    </div>
    {!snapshot || !task ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="请选择任务并读取凭证快照" /> : <>
      {!scoped ? <Alert type="error" showIcon message="任务或凭证链快照不一致，不能确认撤销范围。" /> : null}
      <div className="revocation-controls">
        <div className="revocation-target">
          <label>目标层级</label>
          <Segmented<Level> data-testid="revocation-level" aria-label="撤销目标层级" value={level} disabled={busy || verifying || reading}
            onChange={(value) => select(value, null)} options={(['ROOT', 'INTERMEDIATE', 'LEAF'] as const)
              .map((value) => ({ value, label: levelLabels[value] }))} />
          <label htmlFor={`${headingId}-credential`}>目标凭证</label>
          <Select data-testid="revocation-credential" id={`${headingId}-credential`} aria-label="目标凭证" value={selected?.credential_id}
            placeholder="此层级暂无凭证" disabled={!scoped || busy || verifying || reading || !options.length}
            onChange={(id) => select(level, id)} options={options.map((item) => ({ value: item.credential_id,
              label: `${item.credential_id} · ${item.holder_agent_id}` }))} />
        </div>
        <dl className="revocation-scope">
          <dt>所属任务</dt><dd className="mono">{taskId}</dd>
          <dt>凭证持有者</dt><dd>{selected?.holder_agent_id ?? '未选择'}</dd>
          <dt>当前后代范围</dt><dd>{selected ? `${descendants.length} 个后代` : '未确认'}</dd>
          <dt>独立撤销状态</dt><dd>{selected ? revoked || displayedResult ? '已撤销' : '未单独撤销' : '未读取'}</dd>
        </dl>
        <div className="revocation-reason">
          <div className="revocation-actions">
            <LiquidGlassButton data-testid="revocation-refresh" icon={<RefreshCw size={15} />} loading={reading} disabled={!onChanged || busy || verifying || reading}
              onClick={() => void refresh()}>刷新任务记录</LiquidGlassButton>
            <Tooltip title={!ready ? revocationBlockedReason : undefined}>
              <span>
                <LiquidGlassButton data-testid="revocation-open-confirm" type="primary" icon={<ShieldX size={15} />} disabled={!ready} loading={busy}
                  onClick={() => { setConfirmation(binding); setConfirmed(false) }}>撤销所选凭证</LiquidGlassButton>
              </span>
            </Tooltip>
          </div>
          {!ready && revocationBlockedReason ? <p className="detail-muted" data-testid="revocation-block-reason">当前不可撤销：{revocationBlockedReason}</p> : null}
        </div>
      </div>
      {error ? <Alert className="revocation-feedback" type="error" showIcon message={error} /> : null}
      {refreshError ? <Alert className="revocation-feedback" type="warning" showIcon message={refreshError} /> : null}
      {busy || reading ? <p role="status">{reading ? '正在读取保存记录' : '正在提交撤销，等待服务端回复'}</p> : null}
      {revoked || displayedResult ? <div data-testid="revocation-saved-record" className="revocation-saved" aria-label="保存的撤销记录">
        <div className="revocation-saved-heading">
          <h3>{displayedResult ? displayedResult.already_revoked ? '保留原撤销记录' : '服务端已确认撤销' : '已有撤销记录'}</h3>
          <LiquidGlassButton icon={<FileJson size={15} />} disabled={!onInspect}
            onClick={() => onInspect?.({ kind: 'pipeline', taskId, title: '凭证撤销记录', value: displayedResult ?? {
              task_id: taskId, credential_id: selected?.credential_id, revoked_at: revokedAt,
              revoked_by: revokedBy, revocation_reason: savedReason, descendant_count: descendants.length,
              boundary: 'DISPATCH_BOUNDARY_NO_ROLLBACK', source: 'SAVED_TASK_SNAPSHOT',
            } })}>撤销详情</LiquidGlassButton>
        </div>
        <Descriptions column={1} size="small" items={[
          { key: 'credential', label: '目标凭证', children: displayedResult?.credential_id ?? selected?.credential_id },
          { key: 'operator', label: '可信操作者', children: revokedBy ?? '原操作者待读取' },
          { key: 'time', label: '保存时间', children: <TimeValue value={revokedAt} /> },
          { key: 'reason', label: '原撤销原因', children: savedReason ?? '待读取' },
          { key: 'audit', label: '关联审计记录', children: auditRecorded ? '已保存，检查点覆盖另行核验'
            : displayedResult?.audit_status === 'RECORDED' ? '服务端已保存关联，当前快照待核对' : '待追加或待核对关联' },
        ]} />
        {onInspect ? credentialAudits.map((event) => <LiquidGlassButton key={event.event_id} icon={<ArrowUpRight size={14} />}
          onClick={() => onInspect({ kind: 'audit', taskId, event })}>撤销审计 {event.event_id}</LiquidGlassButton>) : null}
        {observation ? <p className="revocation-observation">撤销回复时任务保存状态：{observation.released_count} 个已释放，{observation.dispatched_or_unknown_count} 个已派发或结果未知，{observation.admitted_count} 个待派发。计数覆盖整个任务。</p> : null}
        {cancellations.map(({ link, denied, receipt, auditEvents }) => <div className="revocation-cancellation" key={link.cancellation_id}>
            <span>预派发取消：<span className="mono">{link.original_execution_id}</span>（历史 ALLOW 保留）</span>
            <span>拒绝原因：<code>{link.reason_code}</code></span>
            {denied ? onInspect ? <LiquidGlassButton icon={<ArrowUpRight size={14} />}
              onClick={() => onInspect({ kind: 'execution', taskId, execution: denied })}>独立拒绝记录</LiquidGlassButton>
              : <span>独立拒绝记录已保存</span> : <span>取消记录关联待刷新</span>}
            {receipt ? onInspect ? <LiquidGlassButton icon={<ArrowUpRight size={14} />}
              onClick={() => onInspect({ kind: 'receipt', taskId, receipt })}>独立拒绝回执</LiquidGlassButton>
              : <span>独立拒绝回执已保存</span> : <span>独立拒绝回执待保存或待核对</span>}
            {onInspect ? auditEvents.map((event) => <LiquidGlassButton key={event.event_id} icon={<ArrowUpRight size={14} />}
              onClick={() => onInspect({ kind: 'audit', taskId, event })}>审计记录 {event.event_id}</LiquidGlassButton>) : null}
          </div>)}
      </div> : null}
      <div data-testid="revocation-verification" className="revocation-verification" aria-label="独立撤销拦截验证">
        <div className="revocation-saved-heading">
          <h3><ShieldCheck size={17} /> 新鲜签名重试验证</h3>
          <LiquidGlassButton data-testid="revocation-verify-open-confirm" icon={<ShieldCheck size={15} />} disabled={!verifyReady} loading={verifying}
            onClick={() => { setVerifyConfirmation(binding); setVerifyConfirmed(false); setVerifyError(null) }}>验证撤销拦截</LiquidGlassButton>
        </div>
        {verifyError ? <Alert type="error" showIcon message={verifyError} /> : null}
        {verifying ? <p role="status">正在等待 Agent 新鲜签名与网关实际裁决</p> : null}
        {verification ? <>
          <Alert data-testid="revocation-verification-result" type={verification.status === 'PASS' ? 'success' : 'error'} showIcon
            message={verification.status === 'PASS' ? '独立撤销拦截验证通过' : `独立撤销拦截验证未通过（${verification.reason_code}）`} />
          <Descriptions column={1} size="small" items={[
            { key: 'request', label: '本次请求', children: <span className="mono">{verification.request_id}</span> },
            { key: 'reason', label: '实际拒绝原因', children: verification.reason_code },
            { key: 'holder', label: 'Agent 持有者密钥', children: verification.holder_key_id },
            { key: 'checks', label: '服务端核验', children: `新 Holder Proof ${verification.holder_proof_valid ? '有效' : '未通过'} · 原链签名 ${verification.chain_signature_valid ? '有效' : '未通过'} · 回执 ${verification.receipt_valid ? '有效' : '未通过'} · 记录绑定 ${verification.record_binding_valid ? '有效' : '未通过'}` },
            { key: 'effects', label: '业务观察（前 → 后）', children: `退款 ${verification.before.refund_rows} → ${verification.after.refund_rows} 笔 · 通知 ${verification.before.notification_rows} → ${verification.after.notification_rows} 条 · 退款金额 ${fenToYuan(verification.before.refund_amount_fen)} → ${fenToYuan(verification.after.refund_amount_fen)} 元` },
            { key: 'budget', label: '预算', children: verification.budget_unchanged ? '保持不变' : '发生变化或未确认' },
            { key: 'time', label: '观察时间', children: <TimeValue value={verification.observed_at_ms / 1000} /> },
          ]} />
          <div className="revocation-actions">
            <LiquidGlassButton data-testid="revocation-verify-details" icon={<FileJson size={15} />} disabled={!onInspect}
              onClick={() => onInspect?.({ kind: 'pipeline', taskId, title: '独立撤销拦截验证回复', value: verification })}>验证详情</LiquidGlassButton>
            {onInspect && verifiedExecution ? <LiquidGlassButton data-testid="revocation-verify-execution" icon={<ArrowUpRight size={15} />}
              onClick={() => onInspect({ kind: 'execution', taskId, execution: verifiedExecution })}>本次验证执行</LiquidGlassButton> : null}
            {onInspect && verifiedReceipt ? <LiquidGlassButton data-testid="revocation-verify-receipt" icon={<ArrowUpRight size={15} />}
              onClick={() => onInspect({ kind: 'receipt', taskId, receipt: verifiedReceipt })}>本次验证回执</LiquidGlassButton> : null}
          </div>
          {!verifiedExecution || (verification.receipt_id !== null && !verifiedReceipt) ? <p>本次验证执行或回执关联待刷新，不能使用历史取消记录替代。</p> : null}
        </> : null}
      </div>
      <div className="revocation-boundary">
        <p>准入时复查授权，派发线性化前再次复查。撤销提交后，尚处于 ADMITTED 的关联执行可取消，原 ALLOW 裁决保留并转为 RELEASED；独立 DENY 记录另行保存。</p>
        <p>派发后的 DISPATCHED / UNKNOWN 执行不释放、不回退；已提交业务效果不撤回。</p>
        <p><strong>{verification?.status === 'PASS' ? '新鲜签名重试验证：通过。' : verification?.status === 'FAIL' ? '新鲜签名重试验证：未通过。' : '新鲜签名重试验证：待验证。'}</strong> 这是独立步骤，需要 Agent 生成新的 Holder Proof，并核对保存的请求、拒绝执行和回执；现有取消记录不替代该验证。</p>
      </div>
    </>}
    <Modal open={confirmation !== null} title="确认撤销凭证" className="credential-revocation-modal" width={600}
      onCancel={() => { if (!inFlight.current) { setConfirmation(null); setConfirmed(false) } }}
      closable={!busy} maskClosable={!busy} keyboard={!busy}
      footer={<><LiquidGlassButton disabled={busy} onClick={() => { setConfirmation(null); setConfirmed(false) }}>取消</LiquidGlassButton>
        <LiquidGlassButton data-testid="revocation-submit" type="primary" icon={<ShieldX size={15} />} loading={busy}
          disabled={!ready || !confirmed || staleConfirmation} onClick={() => void submit()}>确认撤销</LiquidGlassButton></>}>
      <Descriptions column={1} size="small" items={[
        { key: 'task', label: '任务', children: taskId },
        { key: 'credential', label: '目标凭证', children: selected?.credential_id ?? '目标已不可用' },
        { key: 'level', label: '层级', children: levelLabels[level] },
        { key: 'reason', label: '撤销原因', children: reason },
      ]} />
      <p>撤销覆盖目标凭证及其全部后代。当前快照包含 <strong>{descendants.length} 个后代</strong>：</p>
      {descendants.length ? <ul className="revocation-descendants">{descendants.map((id) => <li className="mono" key={id}>{id}</li>)}</ul> : <p>当前没有已保存后代；本凭证将停止新的受保护准入。</p>}
      <Alert type="warning" showIcon message="已提交的业务效果不会撤回"
        description="准入复查后，派发线性化前仍需复查授权。取消仅针对仍为 ADMITTED 的关联执行，原 ALLOW 保留为 RELEASED；派发后的 DISPATCHED / UNKNOWN 不释放、不回退。" />
      {staleConfirmation ? <Alert className="revocation-feedback" type="error" showIcon message="凭证或后代范围已变化，请关闭后重新确认。" /> : null}
      {error ? <Alert className="revocation-feedback" type="error" showIcon message={error} /> : null}
      <Checkbox data-testid="revocation-confirm-scope" checked={confirmed} disabled={!ready || staleConfirmation} onChange={(event) => setConfirmed(event.target.checked)}>
        我确认撤销目标及全部后代，并了解已提交效果不会撤回
      </Checkbox>
    </Modal>
    <Modal open={verifyConfirmation !== null} title="确认验证撤销拦截" className="credential-revocation-modal" width={600}
      onCancel={() => { if (!inFlight.current) { setVerifyConfirmation(null); setVerifyConfirmed(false) } }}
      closable={!verifying} maskClosable={!verifying} keyboard={!verifying}
      footer={<><LiquidGlassButton disabled={verifying} onClick={() => { setVerifyConfirmation(null); setVerifyConfirmed(false) }}>取消</LiquidGlassButton>
        <LiquidGlassButton data-testid="revocation-verify-submit" type="primary" icon={<ShieldCheck size={15} />} loading={verifying}
          disabled={!verifyReady || !verifyConfirmed || staleVerifyConfirmation} onClick={() => void verify()}>确认发送验证请求</LiquidGlassButton></>}>
      <Descriptions column={1} size="small" items={[
        { key: 'task', label: '任务', children: taskId },
        { key: 'credential', label: '已撤销目标', children: selected?.credential_id ?? '目标已不可用' },
      ]} />
      <p>仅发送一条新请求：原 refund-agent 读取受影响的 coordinator → case → refund 三层保存链，生成新鲜 SM2 Holder Proof，由网关重新裁决。不创建新授权，不调用模型，浏览器不生成或重放签名。</p>
      <Alert type="warning" showIcon message="不会撤回既有退款"
        description="预期为真实 DENY、零新增业务效果和预算不变。若拦截失效，可能产生新增业务效果并导致验证失败；已派发或结果未知的执行不回退。" />
      {staleVerifyConfirmation ? <Alert className="revocation-feedback" type="error" showIcon message="目标凭证或撤销范围已变化，请重新确认验证。" /> : null}
      {verifyError ? <Alert className="revocation-feedback" type="error" showIcon message={verifyError} /> : null}
      <Checkbox data-testid="revocation-verify-confirm-scope" checked={verifyConfirmed} disabled={!verifyReady || staleVerifyConfirmation} onChange={(event) => setVerifyConfirmed(event.target.checked)}>
        我确认发送一条新签名请求，并了解不会撤回既有退款
      </Checkbox>
    </Modal>
  </section>
}
