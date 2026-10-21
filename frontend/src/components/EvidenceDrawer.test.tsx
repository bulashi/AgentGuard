import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { EvidenceDrawer } from './EvidenceDrawer'
import { savedSnapshot, workflowSnapshot } from '../test/fixtures'
import type { TaskSnapshot } from '../types'

const notificationTemplate = { template_id: 'REFUND_SUCCESS', version: 'v1', title: '退款成功通知', content_template: '客户 {customer_id}，退款 {refund_id} 已提交。' }

function notificationSnapshot(): TaskSnapshot {
  return { ...workflowSnapshot, business_context: { ...workflowSnapshot.business_context!, notification_templates: [notificationTemplate] },
    executions: [...workflowSnapshot.executions, { ...workflowSnapshot.executions[0], execution_id: 'exec-notice',
      tool_name: 'notification.send_template', business_effect_id: 'notice-1' }],
    business_effects: { ...workflowSnapshot.business_effects, notifications: [{ notification_id: 'notice-1', execution_id: 'exec-notice',
      template_id: 'REFUND_SUCCESS', template_version: 'v1', customer_id: 'C9527', content: 'C9527 客户，退款 refund-1 已提交。',
      related_business_effect_id: 'refund-1', status: 'SENT', created_at: 1790000002 }] } }
}

describe('EvidenceDrawer', () => {
  it('opens the business outcome separately from an empty saved notification list', async () => {
    render(<EvidenceDrawer selection={{ kind: 'business', resource: 'notifications' }}
      snapshot={{ ...savedSnapshot, business_context: { ticket: null, documents: [], notification_templates: [notificationTemplate] } }}
      overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(screen.getByText('客户通知记录')).toBeInTheDocument()
    const preview = within(detail).getByRole('region', { name: '办理结果通知' })
    const saved = within(detail).getByRole('region', { name: '已保存通知' })
    expect(within(preview).getByLabelText('办理结果通知正文')).toHaveTextContent('本次未办理退款')
    expect(within(saved).getByText('暂无已保存通知')).toBeInTheDocument()
    expect(within(saved).queryByText('通知已发送')).not.toBeInTheDocument()
    expect(within(saved).queryByLabelText('已保存通知正文')).not.toBeInTheDocument()
  })

  it('displays stored notification text and exports the original catalog and records', async () => {
    const snapshot = notificationSnapshot()
    const inspect = vi.fn()
    render(<EvidenceDrawer selection={{ kind: 'business', resource: 'notifications' }} snapshot={snapshot}
      overview={null} onSelect={inspect} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    const saved = within(detail).getByRole('region', { name: '已保存通知' })
    expect(within(saved).getByLabelText('已保存通知正文').textContent).toBe(snapshot.business_effects.notifications[0].content)
    expect(saved).toHaveTextContent('客户 C9527 · 关联退款 refund-1')
    expect(within(saved).getByText('通知已发送')).toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('tab', { name: '关联记录' }))
    fireEvent.click(within(detail).getByRole('button', { name: /发送退款通知/ }))
    expect(inspect).toHaveBeenCalledWith({ kind: 'execution', execution: snapshot.executions[1] })
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(JSON.parse(within(detail).getByTestId('evidence-json').textContent!)).toEqual({
      notification_templates: [notificationTemplate], notifications: snapshot.business_effects.notifications,
    })
  })

  it('keeps an unbound SENT row visible without labeling it as sent success', async () => {
    const snapshot = notificationSnapshot()
    snapshot.executions = workflowSnapshot.executions
    render(<EvidenceDrawer selection={{ kind: 'business', resource: 'notifications' }} snapshot={snapshot}
      overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    const saved = within(detail).getByRole('region', { name: '已保存通知' })
    expect(within(saved).getByText('通知记录不一致')).toBeInTheDocument()
    expect(within(saved).queryByText('通知已发送')).not.toBeInTheDocument()
    expect(within(saved).getByLabelText('已保存通知正文').textContent).toBe(snapshot.business_effects.notifications[0].content)
  })

  it('uses the business result title for saved business records', async () => {
    render(<EvidenceDrawer selection={{ kind: 'business', resource: 'result' }} snapshot={workflowSnapshot}
      overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    await screen.findByTestId('evidence-detail')
    expect(screen.getByText('业务结果')).toBeInTheDocument()
    expect(screen.queryByText('模拟业务落库记录')).not.toBeInTheDocument()
  })
  it('refreshes credential details from the current snapshot rather than the captured selection', async () => {
    const credential = savedSnapshot.credentials[0]
    const props = { selection: { kind: 'credential' as const, credential }, overview: null, onSelect: vi.fn(), onClose: vi.fn(), observedAt: credential.not_before }
    const { rerender } = render(<EvidenceDrawer {...props} snapshot={savedSnapshot} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('当前时间窗开放')).toBeInTheDocument()
    const revoked = { ...savedSnapshot, credentials: savedSnapshot.credentials.map((item) => item.credential_id === credential.credential_id ? { ...item, revoked_at: 0 } : item) }
    rerender(<EvidenceDrawer {...props} snapshot={revoked} />)
    expect(within(detail).getByText('凭证已撤销')).toBeInTheDocument()
    expect(within(detail).queryByText('当前时间窗开放')).not.toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('"revoked_at": 0')
  })

  it('does not label a captured credential as current when it is absent from the snapshot', async () => {
    render(<EvidenceDrawer selection={{ kind: 'credential', credential: savedSnapshot.credentials[0] }}
      snapshot={{ ...savedSnapshot, credentials: [] }} overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('所选凭证不在当前任务快照中')).toBeInTheDocument()
    expect(within(detail).queryByText('当前时间窗开放')).not.toBeInTheDocument()
  })

  it('uses a Chinese granted reason while retaining the protocol code', async () => {
    const execution = { ...workflowSnapshot.executions[0], reason_code: 'ALLOWED' }
    render(<EvidenceDrawer selection={{ kind: 'execution', execution }} snapshot={{ ...workflowSnapshot, executions: [execution] }} overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('授权检查通过')).toBeInTheDocument()
    expect(within(detail).getByText('ALLOWED')).toBeInTheDocument()
    expect(within(detail).getByText('ALLOWED').closest('.detail-verdict')).toHaveClass('allowed')
    expect(within(detail).getByText('ALLOWED').closest('.detail-verdict')).not.toHaveClass('denied')
  })

  it('refreshes execution state, receipt status and business result from one current projection', async () => {
    const committed = workflowSnapshot.executions[0]
    const pending = { ...committed, state: 'UNKNOWN', receipt_status: 'PENDING', business_effect_id: null, business_result_hash: null }
    const props = { selection: { kind: 'execution' as const, execution: pending, taskId: workflowSnapshot.task.task_id }, overview: null, onSelect: vi.fn(), onClose: vi.fn() }
    const { rerender } = render(<EvidenceDrawer {...props} snapshot={{ ...workflowSnapshot, executions: [pending], receipts: [], business_effects: { refunds: [], notifications: [] } }} />)
    const detail = await screen.findByTestId('evidence-detail')
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('"state": "UNKNOWN"')
    rerender(<EvidenceDrawer {...props} snapshot={workflowSnapshot} />)
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('"state": "COMMITTED"')
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('"receipt_status": "SIGNED"')
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('"business_effect_id": "refund-1"')
    expect(within(detail).getByTestId('evidence-json')).not.toHaveTextContent('"state": "UNKNOWN"')
    fireEvent.click(within(detail).getByRole('tab', { name: '关联记录' }))
    expect(within(detail).getByRole('button', { name: /执行结果回执/ })).toBeInTheDocument()
    expect(within(detail).getAllByLabelText('refund-1').length).toBeGreaterThan(0)
  })

  it('refreshes the projected receipt verification flag without claiming client signature verification', async () => {
    const receipt = savedSnapshot.receipts[0]
    const props = { selection: { kind: 'receipt' as const, receipt }, overview: null, onSelect: vi.fn(), onClose: vi.fn() }
    const { rerender } = render(<EvidenceDrawer {...props} snapshot={savedSnapshot} />)
    const detail = await screen.findByTestId('evidence-detail')
    const invalid = { ...receipt, signature: { ...receipt.signature, valid: false } }
    rerender(<EvidenceDrawer {...props} snapshot={{ ...savedSnapshot, receipts: [invalid] }} />)
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('"valid": false')
    expect(within(detail).getByTestId('evidence-json')).not.toHaveTextContent('"valid": true')
  })

  it('does not give a valid signature the status of a bound receipt when the row differs or old flags are absent', async () => {
    const receipt = savedSnapshot.receipts[0]
    const props = { selection: { kind: 'receipt' as const, receipt }, overview: null, onSelect: vi.fn(), onClose: vi.fn() }
    const { rerender } = render(<EvidenceDrawer {...props} snapshot={savedSnapshot} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('签名与绑定一致')).toBeInTheDocument()
    const changed = { ...receipt, source_verification: { ...receipt.source_verification!, row_binding_valid: false } }
    rerender(<EvidenceDrawer {...props} snapshot={{ ...savedSnapshot, receipts: [changed] }} />)
    expect(within(detail).getByText('核对未通过')).toBeInTheDocument()
    expect(within(detail).queryByText('签名与绑定一致')).not.toBeInTheDocument()
    rerender(<EvidenceDrawer {...props} snapshot={{ ...savedSnapshot, receipts: [{ ...receipt, source_verification: undefined }] }} />)
    expect(within(detail).getByText('核对信息不完整')).toBeInTheDocument()
    expect(within(detail).getAllByText('未核对')).toHaveLength(4)
  })

  it('keeps a missing or ambiguous execution drawer open without exporting a captured record', async () => {
    const execution = savedSnapshot.executions[0]
    const props = { selection: { kind: 'execution' as const, execution }, overview: null, onSelect: vi.fn(), onClose: vi.fn() }
    const { rerender } = render(<EvidenceDrawer {...props} snapshot={{ ...savedSnapshot, executions: [] }} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('当前任务快照无法唯一关联所选记录')).toBeInTheDocument()
    expect(within(detail).queryByRole('tab', { name: '关联记录' })).not.toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('NOT_IN_CURRENT_SNAPSHOT_OR_AMBIGUOUS')
    expect(within(detail).getByTestId('evidence-json')).not.toHaveTextContent(execution.request_hash)
    rerender(<EvidenceDrawer {...props} snapshot={{ ...savedSnapshot, executions: [execution, execution] }} />)
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('NOT_IN_CURRENT_SNAPSHOT_OR_AMBIGUOUS')
  })

  it('does not replace a requested missing workflow event with the entire run', async () => {
    render(<EvidenceDrawer selection={{ kind: 'workflow', runId: 'RUN-fixture', sequence: 999 }} snapshot={workflowSnapshot}
      overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('当前任务快照无法唯一关联所选记录')).toBeInTheDocument()
    expect(within(detail).queryByText('模型配置')).not.toBeInTheDocument()
  })

  it('marks a captured pipeline observation as noncurrent in its view and exported JSON', async () => {
    const value = { state: 'INFERRED_PASS', evidence_type: 'inferred_from_first_failure' }
    render(<EvidenceDrawer selection={{ kind: 'pipeline', title: 'gateway', value }} snapshot={null}
      overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('点击时观测，不随任务快照刷新；非当前执行记录，非逐阶段验签结果。')).toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByText('点击时流水线观测（非当前 BFF 记录）')).toBeInTheDocument()
    expect(within(detail).queryByText('BFF 只读投影')).not.toBeInTheDocument()
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('CLICK_CAPTURED_PIPELINE_OBSERVATION')
  })

  it('opens full execution fields and links its signed receipt and audit event', async () => {
    const inspect = vi.fn()
    render(<EvidenceDrawer selection={{ kind: 'execution', execution: savedSnapshot.executions[0] }} snapshot={savedSnapshot} overview={null} onSelect={inspect} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('请求参数超出授权范围')).toBeInTheDocument()
    expect(within(detail).getByLabelText(savedSnapshot.executions[0].parameter_hash)).toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('tab', { name: '关联记录' }))
    fireEvent.click(within(detail).getByRole('button', { name: /拒绝回执/ }))
    expect(inspect).toHaveBeenCalledWith({ kind: 'receipt', receipt: savedSnapshot.receipts[0] })
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('execution-denied')
  })

  it('opens persisted role planning provenance and its recorded input', async () => {
    const inspect = vi.fn()
    const { rerender } = render(<EvidenceDrawer selection={{ kind: 'agent', agentId: 'agent-refund' }} snapshot={workflowSnapshot} overview={null} onSelect={inspect} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('AI 规划器 · 已记录响应')).toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('button', { name: /退款规划开始/ }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'workflow', runId: 'RUN-fixture', sequence: 10 })
    rerender(<EvidenceDrawer selection={{ kind: 'workflow', runId: 'RUN-fixture', sequence: 10 }} snapshot={workflowSnapshot} overview={null} onSelect={inspect} onClose={vi.fn()} />)
    fireEvent.click(screen.getByText('实际输入上下文'))
    expect(await screen.findByText('申请退回多扣金额')).toBeInTheDocument()
    expect(screen.getByText('按原路退款。')).toBeInTheDocument()
  })

  it.each(['deterministic', 'cloud'] as const)('explains a %s planning stop without asserting that a model performed the decision', async (runtimeMode) => {
    const original = workflowSnapshot.workflow_runs![0]
    const event = { ...original.events[0], sequence: 101, agent_id: 'agent-refund', action: 'plan', status: 'DENIED',
      details: { stage: 'refund', decision: 'decline', reason_code: 'PLANNER_DECLINED', intents: [],
        summary: '应退金额超过任务授权上限，停止办理。' } }
    const run = { ...original, runtime_mode: runtimeMode, model: runtimeMode === 'cloud' ? original.model : null,
      state: 'DENIED', reason_code: 'PLANNER_DECLINED', events: [event] }
    const snapshot = { ...workflowSnapshot, executions: [], receipts: [],
      business_effects: { refunds: [], notifications: [] }, workflow_runs: [run] }
    render(<EvidenceDrawer selection={{ kind: 'workflow', runId: run.run_id, sequence: event.sequence }}
      snapshot={snapshot} overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('规划未采纳请求并停止执行')).toBeInTheDocument()
    expect(detail).not.toHaveTextContent('模型未采纳请求')
    expect(within(detail).getByText('PLANNER_DECLINED')).toBeInTheDocument()
    if (runtimeMode === 'deterministic') expect(detail).toHaveTextContent('规则规划，无模型调用')
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('应退金额超过任务授权上限')
  })

  it('does not describe a candidate mismatch before gateway submission as an already committed refund', async () => {
    const original = workflowSnapshot.workflow_runs![0]
    const event = { ...original.events[0], sequence: 102, agent_id: 'agent-refund', action: 'run', status: 'FAILED',
      details: { reason_code: 'BUSINESS_RESULT_MISMATCH', message: '退款建议的金额与原始事实不一致，未提交退款' } }
    const run = { ...original, state: 'FAILED', reason_code: 'BUSINESS_RESULT_MISMATCH', events: [event] }
    const snapshot = { ...workflowSnapshot, executions: [], receipts: [],
      business_effects: { refunds: [], notifications: [] }, workflow_runs: [run] }
    render(<EvidenceDrawer selection={{ kind: 'workflow', runId: run.run_id, sequence: event.sequence }}
      snapshot={snapshot} overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('退款建议或执行结果未满足业务约束，已停止')).toBeInTheDocument()
    expect(detail).not.toHaveTextContent('已提交结果')
    expect(within(detail).getByText('BUSINESS_RESULT_MISMATCH')).toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('未提交退款')
  })

  it('links an operational gateway event to the actual execution and receipt', async () => {
    const inspect = vi.fn()
    render(<EvidenceDrawer selection={{ kind: 'workflow', runId: 'RUN-fixture', sequence: 13 }} snapshot={workflowSnapshot} overview={null} onSelect={inspect} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    fireEvent.click(within(detail).getByRole('tab', { name: '关联记录' }))
    fireEvent.click(within(detail).getByRole('button', { name: /执行结果回执/ }))
    expect(inspect).toHaveBeenCalledWith({ kind: 'receipt', receipt: workflowSnapshot.receipts[0] })
  })

  it('uses model aliases in the planning projection without modifying the stored run', async () => {
    const run = workflowSnapshot.workflow_runs![0]
    const original = JSON.stringify(run)
    render(<EvidenceDrawer selection={{ kind: 'workflow', runId: run.run_id }} snapshot={workflowSnapshot}
      overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('AI 规划器')
    expect(within(detail).getByTestId('evidence-json')).not.toHaveTextContent('Ollama')
    expect(JSON.stringify(run)).toBe(original)
    expect(run.model).toBe('deepseek-flash')
  })
})
