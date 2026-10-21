import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App } from 'antd'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '../api'
import { workflowSnapshot } from '../test/fixtures'
import type { AuditEventView, CredentialView, TaskSnapshot } from '../types'
import { CredentialRevocationPanel, type CredentialRevocationResult, type RevocationVerificationResult } from './CredentialRevocationPanel'

const ROOT = workflowSnapshot.credentials[0].credential_id
const TASK = workflowSnapshot.task.task_id

function snapshot(): TaskSnapshot { return structuredClone(workflowSnapshot) }

function reply(credentialId = ROOT, taskId = TASK): CredentialRevocationResult {
  return {
    schema_version: '1.0', task_id: taskId, credential_id: credentialId, status: 'REVOKED',
    revoked_by: 'trusted-local-operator', revoked_at: 1790000003, revocation_reason: '用户主动撤销授权',
    descendant_count: credentialId === ROOT ? 3 : credentialId === 'cred-case' ? 1 : 0,
    already_revoked: false, boundary: 'DISPATCH_BOUNDARY_NO_ROLLBACK', audit_status: 'PENDING',
    audit_event_ids: [], cancellations: [], execution_observation: { scope: 'TASK_SNAPSHOT', released_count: 0, dispatched_or_unknown_count: 0, admitted_count: 0 },
  }
}

function revocationEvent(value: TaskSnapshot, credentialId = ROOT): AuditEventView {
  const credential = value.credentials.find((item) => item.credential_id === credentialId)!
  const record = reply(credentialId)
  return { ...value.audit_events[0], schema_version: '4.0', event_id: 'AUDIT-credential-revoked', execution_id: null,
    event_type: 'CREDENTIAL_REVOKED', evidence_reference: credentialId, evidence_binding_valid: true,
    credential_revocation_evidence: { schema_version: '1.0', record_type: 'CREDENTIAL_REVOKED_V1', task_id: TASK,
      credential_id: credentialId, credential_type: credential.credential_type, parent_credential_id: credential.parent_credential_id,
      revoked_at: record.revoked_at, revoked_by: record.revoked_by, reason: record.revocation_reason } }
}

function cancellationFixture(credentialId = ROOT, reasonCode: 'ANCESTOR_REVOKED' | 'KEY_REVOKED' = 'ANCESTOR_REVOKED') {
  const value = snapshot()
  const original = { ...value.executions[0], execution_id: 'EXEC-original', state: 'RELEASED', decision: 'ALLOW' as const }
  const denied = { ...original, execution_id: 'EXEC-denied', state: 'DENIED', decision: 'DENY' as const, reason_code: reasonCode }
  const receipt = { ...value.receipts[0], receipt_id: 'RECEIPT-denied', execution_id: denied.execution_id, decision: 'DENY' as const, reason_code: reasonCode }
  const event = { ...value.audit_events[0], event_id: 'AUDIT-released', execution_id: original.execution_id,
    event_type: 'EXECUTION_RELEASED', evidence_reference: 'CANCEL-unit' }
  const record: CredentialRevocationResult = { ...reply(credentialId), audit_status: 'RECORDED', cancellations: [{ cancellation_id: 'CANCEL-unit', reason_code: reasonCode,
    original_execution_id: original.execution_id, denied_execution_id: denied.execution_id, denied_receipt_id: receipt.receipt_id, audit_event_ids: [event.event_id] }] }
  const row = { cancellation_id: 'CANCEL-unit', execution_id: original.execution_id, denial_execution_id: denied.execution_id,
    request_id: 'REQUEST-unit', request_hash: original.request_hash, credential_chain_hash: original.credential_chain_hash,
    reason_code: reasonCode, cancelled_at: record.revoked_at }
  value.executions = [original, denied]
  value.receipts = [receipt]
  value.audit_events = [event]
  value.dispatch_cancellations = [{ ...row, evidence: { ...row, schema_version: '1.0', record_type: 'DISPATCH_CANCELLED_V1', task_id: TASK,
    admission_decision: 'ALLOW', dispatch_decision: 'DENY', released_budgets: [],
    revocations: [{ credential_id: credentialId, revoked_at: record.revoked_at, revoked_by: record.revoked_by, reason: record.revocation_reason }] } }]
  return { value, original, denied, receipt, event, record }
}

function markSavedRevocation(value: TaskSnapshot, record: CredentialRevocationResult) {
  const credential = value.credentials.find((item) => item.credential_id === record.credential_id)!
  credential.revoked_at = record.revoked_at
  credential.revoked_by = record.revoked_by
  credential.revocation_reason = record.revocation_reason
}

async function selectTarget(level: 'ROOT' | 'INTERMEDIATE' | 'LEAF') {
  if (level === 'ROOT') return
  fireEvent.click(screen.getByText(level === 'INTERMEDIATE' ? '中间凭证' : '叶凭证'))
  if (level === 'INTERMEDIATE') {
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '目标凭证' }))
    fireEvent.click(await screen.findByText('cred-case · agent-case'))
  }
}

function verificationReply(credentialId = ROOT): RevocationVerificationResult {
  const observation = { refund_rows: 2, notification_rows: 1, refund_amount_fen: 7000 }
  return { schema_version: '1.0', task_id: TASK, credential_id: credentialId, status: 'PASS',
    reason_code: credentialId === 'cred-refund' ? 'KEY_REVOKED' : 'ANCESTOR_REVOKED',
    request_id: 'REQUEST-fresh-verification', request_hash: '5'.repeat(64), holder_key_id: 'agent-refund-key-01',
    holder_proof_valid: true, chain_signature_valid: true, receipt_valid: true, record_binding_valid: true,
    execution_id: 'EXEC-fresh-verification', receipt_id: 'RECEIPT-fresh-verification', before: { ...observation }, after: { ...observation },
    budget_unchanged: true, new_holder_proof: true, observed_at_ms: 1790000006000 }
}

function revokedSnapshot(credentialId = ROOT) {
  const value = snapshot()
  markSavedRevocation(value, reply(credentialId))
  return value
}

async function openVerification() {
  fireEvent.click(screen.getByRole('button', { name: '验证撤销拦截' }))
  return await screen.findByRole('dialog', { name: '确认验证撤销拦截' })
}

function confirmVerification(dialog: HTMLElement) {
  fireEvent.click(within(dialog).getByRole('checkbox'))
  fireEvent.click(within(dialog).getByRole('button', { name: '确认发送验证请求' }))
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (failure: unknown) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

async function open() {
  fireEvent.click(screen.getByRole('button', { name: '撤销所选凭证' }))
  return await screen.findByRole('dialog', { name: '确认撤销凭证' })
}

function confirm(dialog: HTMLElement) {
  fireEvent.click(within(dialog).getByRole('checkbox'))
  fireEvent.click(within(dialog).getByRole('button', { name: '确认撤销' }))
}

beforeEach(() => { vi.stubGlobal('fetch', vi.fn()) })
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('CredentialRevocationPanel', () => {
  it('requires explicit confirmation of all descendants and the committed-effect boundary', async () => {
    const revoke = vi.fn().mockResolvedValue(reply())
    const changed = vi.fn().mockResolvedValue(undefined)
    render(<App><CredentialRevocationPanel snapshot={snapshot()} onRevoke={revoke} onChanged={changed} /></App>)
    const dialog = await open()
    expect(screen.getByTestId('credential-revocation')).toBeInTheDocument()
    expect(screen.getByTestId('revocation-level')).toBeInTheDocument()
    expect(screen.getByTestId('revocation-credential')).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: '撤销原因' })).not.toBeInTheDocument()
    expect(within(dialog).getByText('用户主动撤销授权')).toBeInTheDocument()
    expect(screen.getByTestId('revocation-refresh')).toBeEnabled()
    expect(screen.getByTestId('revocation-open-confirm')).toBeInTheDocument()
    expect(within(dialog).getByTestId('revocation-submit')).toBeDisabled()
    expect(within(dialog).getByTestId('revocation-confirm-scope')).not.toBeChecked()
    expect(within(dialog).getByText('3 个后代')).toBeInTheDocument()
    for (const id of ['cred-knowledge', 'cred-case', 'cred-refund']) expect(within(dialog).getByText(id)).toBeInTheDocument()
    expect(within(dialog).getByText('已提交的业务效果不会撤回')).toBeInTheDocument()
    expect(within(dialog).getByText(/派发线性化前仍需复查授权/)).toBeInTheDocument()
    expect(within(dialog).getByText(/DISPATCHED \/ UNKNOWN 不释放、不回退/)).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '确认撤销' })).toBeDisabled()
    expect(revoke).not.toHaveBeenCalled()
    confirm(dialog)
    expect(await screen.findByText('服务端已确认撤销')).toBeInTheDocument()
    expect(revoke).toHaveBeenCalledExactlyOnceWith(TASK, ROOT, { confirmed: true, reason: '用户主动撤销授权' })
    expect(changed).toHaveBeenCalledExactlyOnceWith(TASK)
    expect(fetch).not.toHaveBeenCalled()
    expect(screen.getByText('新鲜签名重试验证：待验证。')).toBeInTheDocument()
  })

  it('can cancel without a request or optimistic success', async () => {
    const revoke = vi.fn()
    render(<CredentialRevocationPanel snapshot={snapshot()} onRevoke={revoke} />)
    const dialog = await open()
    fireEvent.click(within(dialog).getByRole('button', { name: '取消' }))
    expect(revoke).not.toHaveBeenCalled()
    expect(screen.queryByText('服务端已确认撤销')).not.toBeInTheDocument()
  })

  it('allows revocation without typing a reason and retains a truthful automatic audit reason', async () => {
    const revoke = vi.fn().mockResolvedValue(reply())
    render(<CredentialRevocationPanel snapshot={snapshot()} onRevoke={revoke} />)
    expect(screen.queryByRole('textbox', { name: '撤销原因' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '撤销所选凭证' })).toBeEnabled()
    confirm(await open())
    await waitFor(() => expect(revoke).toHaveBeenCalledWith(TASK, ROOT, { confirmed: true, reason: '用户主动撤销授权' }))
    expect(await screen.findByText('服务端已确认撤销')).toBeInTheDocument()
    expect(within(screen.getByTestId('revocation-saved-record')).getByText('用户主动撤销授权')).toBeInTheDocument()
  })

  it.each(['INTERMEDIATE', 'LEAF'] as const)('selects a %s target from the saved hierarchy', async (level) => {
    const identifier = level === 'INTERMEDIATE' ? 'cred-case' : 'cred-refund'
    const revoke = vi.fn().mockResolvedValue(reply(identifier))
    render(<CredentialRevocationPanel snapshot={snapshot()} onRevoke={revoke} />)
    fireEvent.click(screen.getByText(level === 'INTERMEDIATE' ? '中间凭证' : '叶凭证'))
    if (level === 'INTERMEDIATE') {
      fireEvent.mouseDown(screen.getByRole('combobox', { name: '目标凭证' }))
      fireEvent.click(await screen.findByText('cred-case · agent-case'))
    }
    const dialog = await open()
    expect(within(dialog).getByText(identifier)).toBeInTheDocument()
    expect(within(dialog).getByText(level === 'INTERMEDIATE' ? '1 个后代' : '0 个后代')).toBeInTheDocument()
    confirm(dialog)
    await waitFor(() => expect(revoke).toHaveBeenCalledWith(TASK, identifier, { confirmed: true, reason: '用户主动撤销授权' }))
  })

  it('blocks duplicate clicks synchronously and remains pending until a real response', async () => {
    const pending = deferred<CredentialRevocationResult>()
    const revoke = vi.fn().mockReturnValue(pending.promise)
    render(<CredentialRevocationPanel snapshot={snapshot()} onRevoke={revoke} />)
    const dialog = await open()
    fireEvent.click(within(dialog).getByRole('checkbox'))
    const action = within(dialog).getByRole('button', { name: '确认撤销' })
    fireEvent.click(action); fireEvent.click(action)
    expect(revoke).toHaveBeenCalledOnce()
    expect(action).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '取消' })).toBeDisabled()
    expect(screen.queryByText('服务端已确认撤销')).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('等待服务端回复')
    await act(async () => { pending.resolve(reply()); await pending.promise })
    expect(await screen.findByText('服务端已确认撤销')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '撤销所选凭证' })).toBeDisabled()
  })

  it('marks an uncertain mutation and waits for a new snapshot before another confirmation', async () => {
    const value = snapshot()
    const revoke = vi.fn().mockRejectedValue(new Error('private-key-sentinel'))
    const changed = vi.fn().mockResolvedValue(undefined)
    const { rerender } = render(<CredentialRevocationPanel snapshot={value} onRevoke={revoke} onChanged={changed} />)
    const dialog = await open()
    confirm(dialog)
    await waitFor(() => expect(within(dialog).getByRole('checkbox')).toBeDisabled())
    expect(screen.getAllByText('撤销结果未确认；请刷新保存记录，不自动重试。').length).toBeGreaterThan(0)
    expect(screen.queryByText('private-key-sentinel')).not.toBeInTheDocument()
    expect(screen.queryByText('服务端已确认撤销')).not.toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '取消' }))
    fireEvent.click(screen.getByRole('button', { name: '刷新任务记录' }))
    await waitFor(() => expect(changed).toHaveBeenCalledWith(TASK))
    expect(screen.getByRole('button', { name: '撤销所选凭证' })).toBeDisabled()
    rerender(<CredentialRevocationPanel snapshot={snapshot()} onRevoke={revoke} onChanged={changed} />)
    expect(screen.getByRole('button', { name: '撤销所选凭证' })).toBeEnabled()
    expect(revoke).toHaveBeenCalledOnce()
  })

  it('shows an authenticated rejection without substituting success or exposing raw error text', async () => {
    const revoke = vi.fn().mockRejectedValue(new ApiError(401, 'OPERATOR_SESSION_REQUIRED', 'secret-sentinel'))
    render(<CredentialRevocationPanel snapshot={snapshot()} onRevoke={revoke} />)
    const dialog = await open()
    confirm(dialog)
    expect((await screen.findAllByText('撤销请求被拒绝（OPERATOR_SESSION_REQUIRED）；请刷新任务记录后核对。')).length).toBeGreaterThan(0)
    expect(screen.queryByText('secret-sentinel')).not.toBeInTheDocument()
    expect(screen.queryByText('服务端已确认撤销')).not.toBeInTheDocument()
    expect(screen.getByText('新鲜签名重试验证：待验证。')).toBeInTheDocument()
  })

  it.each(['wrong-task', 'wrong-credential', 'raw-credential', 'bad-boundary', 'legacy-boundary', 'string-time'])(
    'rejects a %s reply without recording success', async (condition) => {
      const invalid: Record<string, unknown> = { ...reply() }
      if (condition === 'wrong-task') invalid.task_id = 'OTHER-task'
      else if (condition === 'wrong-credential') invalid.credential_id = 'OTHER-credential'
      else if (condition === 'raw-credential') invalid.credential_chain = [{ private_key: 'raw-secret-sentinel' }]
      else if (condition === 'bad-boundary') invalid.boundary = 'ALL_EFFECTS_RECALLED'
      else if (condition === 'legacy-boundary') invalid.boundary = 'ADMISSION_BOUNDARY_NO_ROLLBACK'
      else invalid.revoked_at = '1790000003'
      render(<CredentialRevocationPanel snapshot={snapshot()}
        onRevoke={vi.fn().mockResolvedValue(invalid as unknown as CredentialRevocationResult)} />)
      const dialog = await open()
      confirm(dialog)
      expect((await screen.findAllByText('撤销结果未确认；请刷新保存记录，不自动重试。')).length).toBeGreaterThan(0)
      expect(screen.queryByText('服务端已确认撤销')).not.toBeInTheDocument()
      expect(screen.queryByText('raw-secret-sentinel')).not.toBeInTheDocument()
    },
  )

  it('requires reconfirmation if descendants change while the dialog is open', async () => {
    const revoke = vi.fn()
    const value = snapshot()
    const { rerender } = render(<CredentialRevocationPanel snapshot={value} onRevoke={revoke} />)
    const dialog = await open()
    fireEvent.click(within(dialog).getByRole('checkbox'))
    const changed = snapshot()
    changed.credentials.push({ ...changed.credentials[0], credential_id: 'new-leaf', credential_type: 'DELEGATION',
      parent_credential_id: ROOT, delegation_depth: 0 })
    rerender(<CredentialRevocationPanel snapshot={changed} onRevoke={revoke} />)
    expect(within(dialog).getByText('凭证或后代范围已变化，请关闭后重新确认。')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '确认撤销' })).toBeDisabled()
    expect(revoke).not.toHaveBeenCalled()
  })

  it('does not let a late reply or refresh callback affect a newly selected task', async () => {
    const pending = deferred<CredentialRevocationResult>()
    const changed = vi.fn()
    const revoke = vi.fn().mockReturnValue(pending.promise)
    const { rerender } = render(<CredentialRevocationPanel snapshot={snapshot()} onRevoke={revoke} onChanged={changed} />)
    confirm(await open())
    const next = snapshot()
    next.task.task_id = 'TASK-new-selection'
    rerender(<CredentialRevocationPanel snapshot={next} onRevoke={revoke} onChanged={changed} />)
    await act(async () => { pending.resolve(reply()); await pending.promise })
    expect(screen.queryByText('服务端已确认撤销')).not.toBeInTheDocument()
    expect(screen.getByText('TASK-new-selection')).toBeInTheDocument()
    expect(changed).not.toHaveBeenCalled()
    expect(screen.queryByRole('textbox', { name: '撤销原因' })).not.toBeInTheDocument()
  })

  it('keeps a confirmed response distinct from a failed task refresh', async () => {
    render(<CredentialRevocationPanel snapshot={snapshot()} onRevoke={vi.fn().mockResolvedValue(reply())}
      onChanged={vi.fn().mockRejectedValue(new Error('refresh failed'))} />)
    confirm(await open())
    expect(await screen.findByText('服务端已确认撤销')).toBeInTheDocument()
    expect(await screen.findByText('已收到撤销回复；最新任务与审计记录仍待刷新。')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '撤销所选凭证' })).toBeDisabled()
  })

  it('shows a saved revocation at time zero without repeating it or replacing the operator', () => {
    const value = snapshot()
    value.credentials[0] = { ...value.credentials[0], revoked_at: 0, revocation_reason: 'Original reason',
      revoked_by: 'first-trusted-operator' } as CredentialView
    const revoke = vi.fn()
    const inspect = vi.fn()
    render(<CredentialRevocationPanel snapshot={value} onRevoke={revoke} onInspect={inspect} />)
    expect(screen.getByText('已有撤销记录')).toBeInTheDocument()
    expect(screen.getByText('first-trusted-operator')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '撤销所选凭证' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '撤销详情' }))
    expect(inspect).toHaveBeenCalledWith(expect.objectContaining({ taskId: TASK, kind: 'pipeline',
      value: expect.objectContaining({ revoked_at: 0, revoked_by: 'first-trusted-operator', revocation_reason: 'Original reason' }) }))
    expect(revoke).not.toHaveBeenCalled()
  })

  it('uses the current snapshot for revocation status even when credential props are stale', () => {
    const value = snapshot()
    value.credentials[0].revoked_at = 1790000003
    value.credentials[0].revocation_reason = 'Current saved reason'
    render(<CredentialRevocationPanel snapshot={value} credentials={workflowSnapshot.credentials} onRevoke={vi.fn()} />)
    expect(screen.getByText('已有撤销记录')).toBeInTheDocument()
    expect(screen.getByText('Current saved reason')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '撤销所选凭证' })).toBeDisabled()
  })

  it('retains first evidence from an idempotent server reply', async () => {
    const original = { ...reply(), already_revoked: true, revoked_by: 'first-trusted-operator', revocation_reason: 'First committed reason' }
    render(<CredentialRevocationPanel snapshot={snapshot()} onRevoke={vi.fn().mockResolvedValue(original)} />)
    confirm(await open())
    expect(await screen.findByText('保留原撤销记录')).toBeInTheDocument()
    expect(screen.getByText('first-trusted-operator')).toBeInTheDocument()
    expect(screen.getByText('First committed reason')).toBeInTheDocument()
  })

  it.each(['mismatched-task', 'foreign-selection', 'duplicate-id', 'orphan', 'missing-api', 'no-task'])(
    'fails closed for %s controls', (condition) => {
      const value = condition === 'no-task' ? null : snapshot()
      const foreign = [{ ...workflowSnapshot.credentials[0], credential_id: 'foreign-credential' }]
      if (condition === 'duplicate-id') value?.credentials.push({ ...value.credentials[0] })
      if (condition === 'orphan' && value) value.credentials[1].parent_credential_id = 'missing-parent'
      const revoke = vi.fn()
      render(<CredentialRevocationPanel snapshot={value}
        task={condition === 'mismatched-task' ? { task_id: 'other-task' } : undefined}
        credentials={condition === 'foreign-selection' ? foreign : undefined}
        onRevoke={condition === 'missing-api' ? undefined : revoke} />)
      if (condition === 'no-task') expect(screen.getByText('请选择任务并读取凭证快照')).toBeInTheDocument()
      else {
        expect(screen.getByRole('button', { name: '撤销所选凭证' })).toBeDisabled()
      }
      expect(revoke).not.toHaveBeenCalled()
    },
  )

  it('opens only saved cancellation, denial receipt, and audit objects while retaining historical ALLOW', async () => {
    const value = snapshot()
    const original = { ...value.executions[0], execution_id: 'EXEC-original', state: 'RELEASED', decision: 'ALLOW' as const }
    const denied = { ...original, execution_id: 'EXEC-denied', state: 'DENIED', decision: 'DENY' as const, reason_code: 'ANCESTOR_REVOKED' }
    const receipt = { ...value.receipts[0], receipt_id: 'RECEIPT-denied', execution_id: denied.execution_id, decision: 'DENY' as const, reason_code: 'ANCESTOR_REVOKED' }
    const event = { ...value.audit_events[0], event_id: 'AUDIT-released', execution_id: original.execution_id,
      event_type: 'EXECUTION_RELEASED', evidence_reference: 'CANCEL-unit' }
    value.executions = [original, denied]
    value.receipts = [receipt]
    value.audit_events = [event]
    const record = { ...reply(), audit_status: 'RECORDED' as const, cancellations: [{ cancellation_id: 'CANCEL-unit', reason_code: 'ANCESTOR_REVOKED' as const, original_execution_id: original.execution_id,
      denied_execution_id: denied.execution_id, denied_receipt_id: receipt.receipt_id, audit_event_ids: [event.event_id] }],
    execution_observation: { scope: 'TASK_SNAPSHOT' as const, released_count: 1, dispatched_or_unknown_count: 2, admitted_count: 0 } }
    const inspect = vi.fn()
    render(<CredentialRevocationPanel snapshot={value} onRevoke={vi.fn().mockResolvedValue(record)} onInspect={inspect} />)
    confirm(await open())
    fireEvent.click(await screen.findByRole('button', { name: '独立拒绝记录' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'execution', taskId: TASK, execution: denied })
    fireEvent.click(screen.getByRole('button', { name: '独立拒绝回执' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'receipt', taskId: TASK, receipt })
    fireEvent.click(screen.getByRole('button', { name: '审计记录 AUDIT-released' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'audit', taskId: TASK, event })
    expect(original.decision).toBe('ALLOW')
    expect(screen.getByText(/2 个已派发或结果未知/)).toHaveTextContent('计数覆盖整个任务')
    expect(screen.getByText('新鲜签名重试验证：待验证。')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /重放|生成.*Proof|签名重试/ })).not.toBeInTheDocument()
  })

  it('does not manufacture an audit link from a reply identifier absent in the current snapshot', async () => {
    const record = { ...reply(), audit_status: 'RECORDED' as const, cancellations: [{ cancellation_id: 'CANCEL-missing', reason_code: 'ANCESTOR_REVOKED' as const, original_execution_id: 'missing-original',
      denied_execution_id: 'missing-denied', denied_receipt_id: 'missing-receipt', audit_event_ids: ['missing-audit'] }] }
    render(<CredentialRevocationPanel snapshot={snapshot()} onRevoke={vi.fn().mockResolvedValue(record)} onInspect={vi.fn()} />)
    confirm(await open())
    expect(await screen.findByText('取消记录关联待刷新')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /审计记录 missing-audit/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '独立拒绝回执' })).not.toBeInTheDocument()
  })

  it('links a saved credential revocation event separately from cancellation evidence', async () => {
    const value = snapshot()
    const event = revocationEvent(value)
    value.audit_events.push(event)
    const inspect = vi.fn()
    render(<CredentialRevocationPanel snapshot={value} onInspect={inspect}
      onRevoke={vi.fn().mockResolvedValue({ ...reply(), audit_status: 'RECORDED', audit_event_ids: [event.event_id] })} />)
    confirm(await open())
    fireEvent.click(await screen.findByRole('button', { name: '撤销审计 AUDIT-credential-revoked' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'audit', taskId: TASK, event })
    expect(screen.getByText('已保存，检查点覆盖另行核验')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '独立拒绝回执' })).not.toBeInTheDocument()
  })

  it('keeps a saved cancellation visible while its separate denial receipt is pending', async () => {
    const value = snapshot()
    const original = { ...value.executions[0], execution_id: 'EXEC-original', state: 'RELEASED', decision: 'ALLOW' as const }
    const denied = { ...original, execution_id: 'EXEC-denied', state: 'DENIED', decision: 'DENY' as const, reason_code: 'ANCESTOR_REVOKED' }
    value.executions = [original, denied]
    value.receipts = []
    const record = { ...reply(), cancellations: [{ cancellation_id: 'CANCEL-unit', reason_code: 'ANCESTOR_REVOKED' as const, original_execution_id: original.execution_id,
      denied_execution_id: denied.execution_id, denied_receipt_id: null, audit_event_ids: [] }] }
    render(<CredentialRevocationPanel snapshot={value} onInspect={vi.fn()} onRevoke={vi.fn().mockResolvedValue(record)} />)
    confirm(await open())
    expect(await screen.findByRole('button', { name: '独立拒绝记录' })).toBeEnabled()
    expect(screen.getByText('独立拒绝回执待保存或待核对')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '独立拒绝回执' })).not.toBeInTheDocument()
  })

  it.each([
    ['ROOT', ROOT, 'ANCESTOR_REVOKED'],
    ['INTERMEDIATE', 'cred-case', 'ANCESTOR_REVOKED'],
    ['LEAF', 'cred-refund', 'KEY_REVOKED'],
  ] as const)('preserves the frozen reason for a %s cancellation and its real receipt', async (level, credentialId, reasonCode) => {
    const { value, record, denied, receipt } = cancellationFixture(credentialId, reasonCode)
    const inspect = vi.fn()
    render(<CredentialRevocationPanel snapshot={value} onInspect={inspect} onRevoke={vi.fn().mockResolvedValue(record)} />)
    await selectTarget(level)
    confirm(await open())
    fireEvent.click(await screen.findByRole('button', { name: '独立拒绝记录' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'execution', taskId: TASK, execution: denied })
    fireEvent.click(screen.getByRole('button', { name: '独立拒绝回执' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'receipt', taskId: TASK, receipt })
    expect(screen.getByText(reasonCode)).toBeInTheDocument()
    expect(screen.queryByText(reasonCode === 'KEY_REVOKED' ? 'ANCESTOR_REVOKED' : 'KEY_REVOKED')).not.toBeInTheDocument()
  })

  it('resolves a previously pending denial receipt from a refreshed saved snapshot without retrying', async () => {
    const { value, record, receipt } = cancellationFixture('cred-refund', 'KEY_REVOKED')
    value.receipts = []
    record.cancellations[0].denied_receipt_id = null
    const revoke = vi.fn().mockResolvedValue(record)
    const inspect = vi.fn()
    const { rerender } = render(<CredentialRevocationPanel snapshot={value} onInspect={inspect} onRevoke={revoke} />)
    await selectTarget('LEAF')
    confirm(await open())
    expect(await screen.findByText('独立拒绝回执待保存或待核对')).toBeInTheDocument()
    const refreshed = structuredClone(value)
    refreshed.receipts = [receipt]
    markSavedRevocation(refreshed, record)
    rerender(<CredentialRevocationPanel snapshot={refreshed} onInspect={inspect} onRevoke={revoke} />)
    fireEvent.click(screen.getByRole('button', { name: '独立拒绝回执' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'receipt', taskId: TASK, receipt })
    expect(screen.queryByText('独立拒绝回执待保存或待核对')).not.toBeInTheDocument()
    expect(screen.getByText('新鲜签名重试验证：待验证。')).toBeInTheDocument()
    expect(revoke).toHaveBeenCalledOnce()
  })

  it.each(['denial-reason', 'receipt-reason', 'duplicate-receipt', 'ambiguous-receipt', 'fixed-receipt-id'])(
    'does not replace a pending or mismatched %s linkage with another reason or receipt', async (condition) => {
      const { value, record, receipt } = cancellationFixture('cred-refund', 'KEY_REVOKED')
      if (condition === 'denial-reason') value.executions[1].reason_code = 'ANCESTOR_REVOKED'
      else if (condition === 'receipt-reason') value.receipts[0].reason_code = 'ANCESTOR_REVOKED'
      else if (condition === 'duplicate-receipt') value.receipts.push(structuredClone(receipt))
      else if (condition === 'ambiguous-receipt') {
        value.receipts.push({ ...receipt, receipt_id: 'RECEIPT-another' })
        record.cancellations[0].denied_receipt_id = null
      } else record.cancellations[0].denied_receipt_id = 'RECEIPT-original-missing'
      render(<CredentialRevocationPanel snapshot={value} onInspect={vi.fn()} onRevoke={vi.fn().mockResolvedValue(record)} />)
      await selectTarget('LEAF')
      confirm(await open())
      expect(await screen.findByText('独立拒绝回执待保存或待核对')).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '独立拒绝回执' })).not.toBeInTheDocument()
      if (condition === 'denial-reason') expect(screen.queryByRole('button', { name: '独立拒绝记录' })).not.toBeInTheDocument()
    },
  )

  it('clears pending audit when the refreshed 4.0 projection binds the original saved revocation', async () => {
    const value = snapshot()
    const revoke = vi.fn().mockResolvedValue(reply())
    const inspect = vi.fn()
    const { rerender } = render(<CredentialRevocationPanel snapshot={value} onInspect={inspect} onRevoke={revoke} />)
    confirm(await open())
    expect(await screen.findByText('待追加或待核对关联')).toBeInTheDocument()
    const refreshed = snapshot()
    markSavedRevocation(refreshed, reply())
    const event = revocationEvent(refreshed)
    refreshed.audit_events.push(event)
    rerender(<CredentialRevocationPanel snapshot={refreshed} onInspect={inspect} onRevoke={revoke} />)
    fireEvent.click(screen.getByRole('button', { name: '撤销审计 AUDIT-credential-revoked' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'audit', taskId: TASK, event })
    expect(screen.getByText('已保存，检查点覆盖另行核验')).toBeInTheDocument()
    expect(screen.queryByText('待追加或待核对关联')).not.toBeInTheDocument()
    expect(screen.getByText('新鲜签名重试验证：待验证。')).toBeInTheDocument()
    expect(revoke).toHaveBeenCalledOnce()
  })

  it.each(['false-binding', 'unreviewed-binding', 'wrong-task', 'wrong-reason', 'wrong-operator', 'wrong-parent', 'legacy-schema', 'duplicate-event'])(
    'keeps a saved %s revocation audit unlinked rather than claiming it is recorded', (condition) => {
      const value = snapshot()
      markSavedRevocation(value, reply())
      const event = revocationEvent(value)
      if (condition === 'false-binding') event.evidence_binding_valid = false
      else if (condition === 'unreviewed-binding') event.evidence_binding_valid = null
      else if (condition === 'wrong-task') event.credential_revocation_evidence!.task_id = 'TASK-other'
      else if (condition === 'wrong-reason') event.credential_revocation_evidence!.reason = 'Another reason'
      else if (condition === 'wrong-operator') event.credential_revocation_evidence!.revoked_by = 'another-operator'
      else if (condition === 'wrong-parent') event.credential_revocation_evidence!.parent_credential_id = 'other-parent'
      else if (condition === 'legacy-schema') event.schema_version = '3.0'
      value.audit_events = condition === 'duplicate-event' ? [event, structuredClone(event)] : [event]
      render(<CredentialRevocationPanel snapshot={value} onInspect={vi.fn()} />)
      expect(screen.queryByRole('button', { name: /撤销审计/ })).not.toBeInTheDocument()
      expect(screen.getByText('待追加或待核对关联')).toBeInTheDocument()
    },
  )

  it('uses saved executor and revocation audit records when reopening an already revoked leaf', async () => {
    const { value, record, denied, receipt } = cancellationFixture('cred-refund', 'KEY_REVOKED')
    markSavedRevocation(value, record)
    const event = revocationEvent(value, 'cred-refund')
    value.audit_events.push(event)
    const inspect = vi.fn()
    const revoke = vi.fn()
    render(<CredentialRevocationPanel snapshot={value} onInspect={inspect} onRevoke={revoke} />)
    await selectTarget('LEAF')
    fireEvent.click(screen.getByRole('button', { name: '独立拒绝记录' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'execution', taskId: TASK, execution: denied })
    fireEvent.click(screen.getByRole('button', { name: '独立拒绝回执' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'receipt', taskId: TASK, receipt })
    fireEvent.click(screen.getByRole('button', { name: '撤销审计 AUDIT-credential-revoked' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'audit', taskId: TASK, event })
    expect(screen.getByText('已有撤销记录')).toBeInTheDocument()
    expect(screen.getByText('KEY_REVOKED')).toBeInTheDocument()
    expect(revoke).not.toHaveBeenCalled()
    expect(fetch).not.toHaveBeenCalled()
  })

  it.each(['unrevoked', 'revoked', 'missing-api', 'foreign-task'])(
    'bounds independent verification to the selected revoked credential with %s controls', (condition) => {
      const verify = vi.fn()
      const value = condition === 'unrevoked' ? snapshot() : revokedSnapshot()
      render(<CredentialRevocationPanel snapshot={value}
        task={condition === 'foreign-task' ? { task_id: 'TASK-other' } : undefined}
        onVerify={condition === 'missing-api' ? undefined : verify} />)
      const action = screen.getByRole('button', { name: '验证撤销拦截' })
      if (condition === 'revoked') expect(action).toBeEnabled()
      else expect(action).toBeDisabled()
      expect(verify).not.toHaveBeenCalled()
      expect(screen.queryByText('独立撤销拦截验证通过')).not.toBeInTheDocument()
    },
  )

  it('requires a separate bounded confirmation, waits for the real reply, refreshes, and opens only the new saved receipt', async () => {
    const value = revokedSnapshot('cred-refund')
    const record = verificationReply('cred-refund')
    const pending = deferred<RevocationVerificationResult>()
    const refreshed = deferred<void>()
    const verify = vi.fn().mockReturnValue(pending.promise)
    const changed = vi.fn().mockReturnValue(refreshed.promise)
    const inspect = vi.fn()
    const { rerender } = render(<CredentialRevocationPanel snapshot={value} onVerify={verify} onChanged={changed} onInspect={inspect} />)
    await selectTarget('LEAF')
    const dialog = await openVerification()
    expect(screen.getByTestId('revocation-saved-record')).toBeInTheDocument()
    expect(screen.getByTestId('revocation-verification')).toBeInTheDocument()
    expect(screen.getByTestId('revocation-verify-open-confirm')).toBeInTheDocument()
    expect(within(dialog).getByTestId('revocation-verify-submit')).toBeDisabled()
    expect(within(dialog).getByTestId('revocation-verify-confirm-scope')).not.toBeChecked()
    expect(within(dialog).getByText('不会撤回既有退款')).toBeInTheDocument()
    expect(within(dialog).getByText(/仅发送一条新请求/)).toHaveTextContent('不调用模型，浏览器不生成或重放签名')
    expect(within(dialog).getByRole('button', { name: '确认发送验证请求' })).toBeDisabled()
    expect(verify).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('checkbox'))
    const action = within(dialog).getByRole('button', { name: '确认发送验证请求' })
    fireEvent.click(action); fireEvent.click(action)
    expect(verify).toHaveBeenCalledExactlyOnceWith(TASK, 'cred-refund', { confirmed: true })
    expect(action).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '取消' })).toBeDisabled()
    expect(screen.getByRole('status')).toHaveTextContent('Agent 新鲜签名')
    expect(changed).not.toHaveBeenCalled()
    expect(inspect).not.toHaveBeenCalled()
    expect(screen.queryByText('独立撤销拦截验证通过')).not.toBeInTheDocument()
    await act(async () => { pending.resolve(record); await pending.promise })
    expect(await screen.findByText('独立撤销拦截验证通过')).toBeInTheDocument()
    expect(screen.getByTestId('revocation-verification-result')).toHaveTextContent('独立撤销拦截验证通过')
    expect(changed).toHaveBeenCalledExactlyOnceWith(TASK)
    expect(inspect).not.toHaveBeenCalled()
    const saved = structuredClone(value)
    const execution = { ...saved.executions[0], execution_id: record.execution_id!, request_hash: record.request_hash,
      state: 'DENIED', decision: 'DENY' as const, reason_code: record.reason_code }
    const receipt = { ...saved.receipts[0], receipt_id: record.receipt_id!, execution_id: record.execution_id!, decision: 'DENY' as const, reason_code: record.reason_code }
    saved.executions.push(execution)
    saved.receipts.push(receipt)
    rerender(<CredentialRevocationPanel snapshot={saved} onVerify={verify} onChanged={changed} onInspect={inspect} />)
    expect(inspect).not.toHaveBeenCalled()
    await act(async () => { refreshed.resolve(undefined); await refreshed.promise })
    await waitFor(() => expect(inspect).toHaveBeenCalledExactlyOnceWith({ kind: 'receipt', taskId: TASK, receipt }))
    expect(screen.getByText('新鲜签名重试验证：通过。')).toBeInTheDocument()
    expect(screen.getByText(/退款 2 → 2 笔/)).toHaveTextContent('退款金额 70.00 → 70.00 元')
    expect(screen.getByRole('button', { name: '本次验证执行' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '本次验证回执' })).toBeEnabled()
    expect(screen.getByTestId('revocation-verify-execution')).toBeEnabled()
    expect(screen.getByTestId('revocation-verify-receipt')).toBeEnabled()
    expect(screen.getByTestId('revocation-verify-details')).toBeEnabled()
    expect(screen.queryByText(/本次验证执行或回执关联待刷新/)).not.toBeInTheDocument()
    rerender(<CredentialRevocationPanel snapshot={structuredClone(saved)} onVerify={verify} onChanged={changed} onInspect={inspect} />)
    expect(inspect).toHaveBeenCalledOnce()
    expect(fetch).not.toHaveBeenCalled()
  })

  it('can cancel verification without a new Holder Proof request', async () => {
    const verify = vi.fn()
    render(<CredentialRevocationPanel snapshot={revokedSnapshot()} onVerify={verify} />)
    const dialog = await openVerification()
    fireEvent.click(within(dialog).getByRole('button', { name: '取消' }))
    expect(verify).not.toHaveBeenCalled()
    expect(screen.getByText('新鲜签名重试验证：待验证。')).toBeInTheDocument()
  })

  it.each(['REVOCATION_PROBE_CHAIN_UNAVAILABLE', 'CREDENTIAL_EXPIRED', 'OPERATOR_SESSION_REQUIRED'])(
    'shows %s as a verification error, never as PASS', async (reasonCode) => {
      const verify = vi.fn().mockRejectedValue(new ApiError(409, reasonCode, 'raw-private-message'))
      render(<CredentialRevocationPanel snapshot={revokedSnapshot()} onVerify={verify} />)
      confirmVerification(await openVerification())
      expect((await screen.findAllByText(new RegExp(`验证请求被拒绝（${reasonCode}）`))).length).toBeGreaterThan(0)
      expect(screen.queryByText('raw-private-message')).not.toBeInTheDocument()
      expect(screen.queryByText('独立撤销拦截验证通过')).not.toBeInTheDocument()
      expect(screen.getByText('新鲜签名重试验证：待验证。')).toBeInTheDocument()
    },
  )

  it('retains a real FAIL response and failed checks without manufacturing a successful verification', async () => {
    const record: RevocationVerificationResult = { ...verificationReply(), status: 'FAIL', reason_code: 'INVALID_SIGNATURE',
      holder_proof_valid: false, receipt_valid: false, record_binding_valid: false, execution_id: null, receipt_id: null }
    const changed = vi.fn().mockResolvedValue(undefined)
    const inspect = vi.fn()
    render(<CredentialRevocationPanel snapshot={revokedSnapshot()} onVerify={vi.fn().mockResolvedValue(record)} onChanged={changed} onInspect={inspect} />)
    confirmVerification(await openVerification())
    expect(await screen.findByText('独立撤销拦截验证未通过（INVALID_SIGNATURE）')).toBeInTheDocument()
    expect(screen.getByText('新鲜签名重试验证：未通过。')).toBeInTheDocument()
    expect(screen.queryByText('独立撤销拦截验证通过')).not.toBeInTheDocument()
    expect(changed).toHaveBeenCalledOnce()
    expect(inspect).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: '验证详情' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'pipeline', taskId: TASK, title: '独立撤销拦截验证回复', value: record })
  })

  it.each(['wrong-task', 'wrong-credential', 'raw-credential', 'false-holder', 'false-chain', 'false-receipt', 'false-binding',
    'old-proof', 'changed-budget', 'added-refund', 'added-notification', 'changed-amount', 'other-deny', 'missing-receipt', 'missing-execution'])(
    'rejects an inconsistent %s PASS verification instead of trusting its status alone', async (condition) => {
      const invalid: Record<string, unknown> = { ...structuredClone(verificationReply()) }
      if (condition === 'wrong-task') invalid.task_id = 'TASK-other'
      else if (condition === 'wrong-credential') invalid.credential_id = 'credential-other'
      else if (condition === 'raw-credential') invalid.holder_proof = { private_key: 'raw-proof-sentinel' }
      else if (condition === 'false-holder') invalid.holder_proof_valid = false
      else if (condition === 'false-chain') invalid.chain_signature_valid = false
      else if (condition === 'false-receipt') invalid.receipt_valid = false
      else if (condition === 'false-binding') invalid.record_binding_valid = false
      else if (condition === 'old-proof') invalid.new_holder_proof = false
      else if (condition === 'changed-budget') invalid.budget_unchanged = false
      else if (condition === 'added-refund') (invalid.after as Record<string, number>).refund_rows += 1
      else if (condition === 'added-notification') (invalid.after as Record<string, number>).notification_rows += 1
      else if (condition === 'changed-amount') (invalid.after as Record<string, number>).refund_amount_fen += 1
      else if (condition === 'other-deny') invalid.reason_code = 'CREDENTIAL_EXPIRED'
      else if (condition === 'missing-receipt') invalid.receipt_id = null
      else invalid.execution_id = null
      render(<CredentialRevocationPanel snapshot={revokedSnapshot()} onVerify={vi.fn().mockResolvedValue(invalid as unknown as RevocationVerificationResult)} />)
      confirmVerification(await openVerification())
      expect((await screen.findAllByText('独立验证结果未确认；请刷新保存记录，不自动重试。')).length).toBeGreaterThan(0)
      expect(screen.queryByText('独立撤销拦截验证通过')).not.toBeInTheDocument()
      expect(screen.queryByText('raw-proof-sentinel')).not.toBeInTheDocument()
    },
  )

  it('does not silently retry an unknown verification and requires a refreshed snapshot', async () => {
    const verify = vi.fn().mockRejectedValue(new Error('gateway outcome unknown'))
    const changed = vi.fn().mockResolvedValue(undefined)
    const { rerender } = render(<CredentialRevocationPanel snapshot={revokedSnapshot()} onVerify={verify} onChanged={changed} />)
    const dialog = await openVerification()
    confirmVerification(dialog)
    await waitFor(() => expect(within(dialog).getByRole('checkbox')).toBeDisabled())
    fireEvent.click(within(dialog).getByRole('button', { name: '取消' }))
    expect(screen.getByRole('button', { name: '验证撤销拦截' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '刷新任务记录' }))
    await waitFor(() => expect(changed).toHaveBeenCalledOnce())
    expect(screen.getByRole('button', { name: '验证撤销拦截' })).toBeDisabled()
    rerender(<CredentialRevocationPanel snapshot={revokedSnapshot()} onVerify={verify} onChanged={changed} />)
    expect(screen.getByRole('button', { name: '验证撤销拦截' })).toBeEnabled()
    expect(verify).toHaveBeenCalledOnce()
  })

  it('requires reconfirmation when the revoked credential binding changes', async () => {
    const verify = vi.fn()
    const value = revokedSnapshot()
    const { rerender } = render(<CredentialRevocationPanel snapshot={value} onVerify={verify} />)
    const dialog = await openVerification()
    fireEvent.click(within(dialog).getByRole('checkbox'))
    const changed = structuredClone(value)
    changed.credentials[0].signed_object_hash = '7'.repeat(64)
    rerender(<CredentialRevocationPanel snapshot={changed} onVerify={verify} />)
    expect(within(dialog).getByText('目标凭证或撤销范围已变化，请重新确认验证。')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '确认发送验证请求' })).toBeDisabled()
    expect(verify).not.toHaveBeenCalled()
  })

  it('ignores a late verification reply after the task changes', async () => {
    const pending = deferred<RevocationVerificationResult>()
    const verify = vi.fn().mockReturnValue(pending.promise)
    const changed = vi.fn()
    const inspect = vi.fn()
    const { rerender } = render(<CredentialRevocationPanel snapshot={revokedSnapshot()} onVerify={verify} onChanged={changed} onInspect={inspect} />)
    confirmVerification(await openVerification())
    const next = revokedSnapshot()
    next.task.task_id = 'TASK-next'
    rerender(<CredentialRevocationPanel snapshot={next} onVerify={verify} onChanged={changed} onInspect={inspect} />)
    await act(async () => { pending.resolve(verificationReply()); await pending.promise })
    expect(screen.queryByText('独立撤销拦截验证通过')).not.toBeInTheDocument()
    expect(changed).not.toHaveBeenCalled()
    expect(inspect).not.toHaveBeenCalled()
  })

  it.each(['wrong-request-hash', 'wrong-denial-reason', 'duplicate-execution', 'missing-receipt'])(
    'does not use a %s snapshot object for the new verification evidence', async (condition) => {
      const value = revokedSnapshot()
      const record = verificationReply()
      const execution = { ...value.executions[0], execution_id: record.execution_id!, request_hash: record.request_hash,
        state: 'DENIED', decision: 'DENY' as const, reason_code: record.reason_code }
      const receipt = { ...value.receipts[0], receipt_id: record.receipt_id!, execution_id: record.execution_id!, decision: 'DENY' as const, reason_code: record.reason_code }
      if (condition === 'wrong-request-hash') execution.request_hash = 'a'.repeat(64)
      else if (condition === 'wrong-denial-reason') execution.reason_code = 'KEY_REVOKED'
      value.executions = condition === 'duplicate-execution' ? [execution, structuredClone(execution)] : [execution]
      value.receipts = condition === 'missing-receipt' ? [] : [receipt]
      const inspect = vi.fn()
      render(<CredentialRevocationPanel snapshot={value} onVerify={vi.fn().mockResolvedValue(record)} onChanged={vi.fn().mockResolvedValue(undefined)} onInspect={inspect} />)
      confirmVerification(await openVerification())
      expect(await screen.findByText('独立撤销拦截验证通过')).toBeInTheDocument()
      expect(screen.getByText(/本次验证执行或回执关联待刷新/)).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '本次验证回执' })).not.toBeInTheDocument()
      if (condition === 'missing-receipt') await waitFor(() => expect(inspect).toHaveBeenCalledExactlyOnceWith({ kind: 'execution', taskId: TASK, execution }))
      else expect(inspect).not.toHaveBeenCalled()
    },
  )

  it('keeps the verification reply distinct from a failed refresh without opening stale records', async () => {
    const inspect = vi.fn()
    render(<CredentialRevocationPanel snapshot={revokedSnapshot()} onVerify={vi.fn().mockResolvedValue(verificationReply())}
      onChanged={vi.fn().mockRejectedValue(new Error('refresh failed'))} onInspect={inspect} />)
    confirmVerification(await openVerification())
    expect(await screen.findByText('独立撤销拦截验证通过')).toBeInTheDocument()
    expect(await screen.findByText('已收到独立验证回复；实际执行与回执记录仍待刷新。')).toBeInTheDocument()
    expect(inspect).not.toHaveBeenCalled()
  })
})
