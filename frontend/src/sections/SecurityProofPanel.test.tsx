import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App } from 'antd'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import type { SecurityProofReport } from '../types'
import { SecurityProofPanel } from './SecurityProofPanel'

function fixture(): SecurityProofReport {
  const observation = { observed_at_ms: 1791440000000, scope: { type: 'task' as const, task_id: 'TASK-proof' },
    budgets: [], refund_rows: 0, notification_rows: 0, refund_amount_fen: 0 }
  const attempt = { kind: 'wrong_customer', request: { canonical_parameters: { ticket_id: 'T-proof', customer_id: 'OTHER', amount_fen: 7000 },
    credential_ids: ['root', 'branch', 'leaf'], credential_chain_hash: 'a'.repeat(64), holder_signature: { fingerprint_sm3: 'b'.repeat(64) } },
    http_status: 403, gateway: { decision: 'DENY', state: 'DENIED', reason_code: 'RESOURCE_NOT_ALLOWED', receipt: {} },
    holder_proof_valid: true, chain_valid: true, receipt_valid: true, record_binding_valid: true,
    budget_unchanged: true, before: observation, after: observation, refund_delta: 0, notification_delta: 0 }
  return { schema_version: '1.0', proof_id: 'PROOF-' + '1'.repeat(32), profile: 'AGENTGUARD_DETERMINISTIC_SECURITY_PROOF_V1',
    candidate_origin: 'deterministic_security_probe', llm_required: false,
    observation_kind: 'operational_test_observation_not_signed_authorization', created_at_ms: 1791440000000,
    kind: 'wrong_customer', task_id: 'TASK-proof', tenant_id: 'tenant-A', ticket_id: 'T-proof', customer_id: 'C-proof',
    refund_limit_fen: 7000, status: 'PASS', attack: attempt,
    control: { ...attempt, kind: 'legal_control', refund_delta: 1, gateway: { decision: 'ALLOW', state: 'COMMITTED' } },
    checks: { denied_without_effect: true, legal_control_committed: true } }
}

beforeEach(() => {
  vi.restoreAllMocks()
  vi.spyOn(api, 'securityProofs').mockResolvedValue({ items: [] })
})

describe('deterministic security proof controls', () => {
  it('labels a selected saved record without rerunning its legal control', async () => {
    vi.mocked(api.securityProofs).mockResolvedValue({ items: [fixture()] })
    const run = vi.spyOn(api, 'securityProof')
    render(<App><SecurityProofPanel /></App>)
    await waitFor(() => expect(screen.getByRole('combobox', { name: '历史验证记录' })).toBeEnabled())
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '历史验证记录' }))
    fireEvent.click(screen.getByText(/客户越界 · PASS/))
    expect(await screen.findByText('已保存核验证据')).toBeInTheDocument()
    expect(screen.getByText('已保存验证记录')).toBeInTheDocument()
    expect(run).not.toHaveBeenCalled()
  })
  it('requires an explicit confirmation before the real positive-control request', async () => {
    const run = vi.spyOn(api, 'securityProof').mockResolvedValue(fixture())
    const ready = vi.fn().mockResolvedValue(undefined)
    const inspect = vi.fn()
    render(<App><SecurityProofPanel onReady={ready} onInspect={inspect} /></App>)
    fireEvent.click(screen.getByRole('button', { name: /验证拒绝与合法对照/ }))
    expect(run).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: /确认验证/ }))
    await waitFor(() => expect(ready).toHaveBeenCalledWith('TASK-proof'))
    expect(run).toHaveBeenCalledWith('wrong_customer')
    expect(screen.getAllByText('0 笔退款')).toHaveLength(1)
    expect(screen.getAllByText('1 笔退款')).toHaveLength(1)
    expect(screen.getAllByText('RESOURCE_NOT_ALLOWED')).toHaveLength(2)
    expect(screen.queryByText('AI 规划器')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /请求与签名/ }))
    expect(inspect).toHaveBeenCalledWith(expect.objectContaining({ taskId: 'TASK-proof',
      value: expect.objectContaining({ source_kind: 'BFF_public_projection' }) }))
  })

  it('can cancel confirmation without creating a task or using the API', () => {
    const run = vi.spyOn(api, 'securityProof')
    render(<App><SecurityProofPanel /></App>)
    fireEvent.click(screen.getByRole('button', { name: /验证拒绝与合法对照/ }))
    fireEvent.click(screen.getByRole('button', { name: /取\s*消/ }))
    expect(run).not.toHaveBeenCalled()
  })

  it('shows a real request failure without substituting zero side effects or PASS', async () => {
    vi.spyOn(api, 'securityProof').mockRejectedValue(new Error('结果未知'))
    render(<App><SecurityProofPanel /></App>)
    fireEvent.click(screen.getByRole('button', { name: /验证拒绝与合法对照/ }))
    fireEvent.click(screen.getByRole('button', { name: /确认验证/ }))
    expect(await screen.findByText('结果未知')).toBeInTheDocument()
    expect(screen.queryByText('0 笔退款')).not.toBeInTheDocument()
    expect(screen.queryByText('本次核验证据')).not.toBeInTheDocument()
  })

  it('does not label a skipped positive control as successful', async () => {
    const failure = { ...fixture(), status: 'FAIL' as const, control: null,
      checks: { denied_without_effect: false, legal_control_committed: false } }
    vi.spyOn(api, 'securityProof').mockResolvedValue(failure)
    render(<App><SecurityProofPanel /></App>)
    fireEvent.click(screen.getByRole('button', { name: /验证拒绝与合法对照/ }))
    fireEvent.click(screen.getByRole('button', { name: /确认验证/ }))
    await screen.findByText('本次核验证据')
    expect(screen.getAllByText('未执行').length).toBeGreaterThan(0)
    expect(screen.queryByText('1 笔退款')).not.toBeInTheDocument()
  })
})
